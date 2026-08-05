// RGB Consensus Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2024 Dr Maxim Orlovsky. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::num::NonZeroU32;
use std::rc::Rc;

use amplify::confinement::{Collection, ConfinedOrdMap};
use bitcoin::{Transaction as Tx, Txid};
use strict_types::TypeSystem;

use super::status::{Failure, Warning};
use super::{CheckedConsignment, ConsignmentApi, DbcProof, Status};
use crate::assignments::RevealedAssign;
use crate::commit_verify::mpc;
use crate::dbc::{self, Anchor};
use crate::operation::seal::ExposedSeal;
use crate::seals::txout::{CloseMethod, Witness};
use crate::single_use_seals::SealWitness;
use crate::txout::BlindSeal;
use crate::validation::{OpoutsDagInfo, Scripts};
use crate::vm::{ContractStateAccess, ContractStateEvolve, OrdOpRef, WitnessOrd};
use crate::{
    AssignmentType, Assignments, BundleId, ChainNet, ContractId, KnownTransition, OpId, Operation,
    Opout, RevealedState, SchemaId, TransitionBundle,
};

/// Error validating a consignment.
#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[allow(clippy::large_enum_variant)]
pub enum ValidationError {
    /// detected a failure that makes the consignment invalid
    InvalidConsignment(Failure),
    /// a likely temporary error occurred during validation
    ResolverError(WitnessResolverError),
}

/// Error resolving witness.
#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum WitnessResolverError {
    /// actual witness id {actual} doesn't match expected id {expected}.
    IdMismatch { actual: Txid, expected: Txid },
    /// unable to retrieve information from the resolver (TXID: {0:?}), {1}
    ResolverIssue(Option<Txid>, String),
    /// resolver returned invalid data
    InvalidResolverData,
    /// resolver is for another chain-network pair
    WrongChainNet,
}

/// Trait to provide the [`WitnessOrd`] for a specific TX.
pub trait WitnessOrdProvider {
    /// Provide the [`WitnessOrd`] for a TX with the given `witness_id`.
    fn witness_ord(&self, witness_id: Txid) -> Result<WitnessOrd, WitnessResolverError>;
}

/// Trait to resolve a witness TX.
pub trait ResolveWitness {
    /// Provide the [`WitnessStatus`] for a TX with the given `witness_id`.
    fn resolve_witness(&self, witness_id: Txid) -> Result<WitnessStatus, WitnessResolverError>;

    /// Check that the resolver works with the expected [`ChainNet`].
    fn check_chain_net(&self, chain_net: ChainNet) -> Result<(), WitnessResolverError>;
}

/// Resolve status of a witness TX.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Display, From)]
#[display(doc_comments)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum WitnessStatus {
    /// TX has not been found.
    Unresolved,
    /// TX has been found.
    Resolved(Tx, WitnessOrd),
}

impl WitnessStatus {
    /// Return the [`WitnessOrd`] for this [`WitnessStatus`].
    pub fn witness_ord(&self) -> WitnessOrd {
        match self {
            Self::Unresolved => WitnessOrd::Archived,
            Self::Resolved(_, ord) => *ord,
        }
    }
}

impl<T: ResolveWitness> ResolveWitness for &T {
    fn resolve_witness(&self, witness_id: Txid) -> Result<WitnessStatus, WitnessResolverError> {
        ResolveWitness::resolve_witness(*self, witness_id)
    }

    fn check_chain_net(&self, chain_net: ChainNet) -> Result<(), WitnessResolverError> {
        ResolveWitness::check_chain_net(*self, chain_net)
    }
}

struct CheckedWitnessResolver<R: ResolveWitness> {
    inner: R,
}

impl<R: ResolveWitness> From<R> for CheckedWitnessResolver<R> {
    fn from(inner: R) -> Self { Self { inner } }
}

impl<R: ResolveWitness> ResolveWitness for CheckedWitnessResolver<R> {
    #[inline]
    fn resolve_witness(&self, witness_id: Txid) -> Result<WitnessStatus, WitnessResolverError> {
        let witness_status = self.inner.resolve_witness(witness_id)?;
        if let WitnessStatus::Resolved(tx, _ord) = &witness_status {
            let actual_id = tx.compute_txid();
            if actual_id != witness_id {
                return Err(WitnessResolverError::IdMismatch {
                    actual: actual_id,
                    expected: witness_id,
                });
            }
        }
        Ok(witness_status)
    }

    fn check_chain_net(&self, chain_net: ChainNet) -> Result<(), WitnessResolverError> {
        self.inner.check_chain_net(chain_net)
    }
}

#[derive(Clone, Debug, Default)]
pub struct ValidationConfig {
    pub chain_net: ChainNet,
    pub safe_height: Option<NonZeroU32>,
    pub trusted_typesystem: TypeSystem,
    pub build_opouts_dag: bool,
}

pub struct Validator<
    'consignment,
    'resolver,
    S: ContractStateAccess + ContractStateEvolve,
    C: ConsignmentApi,
    R: ResolveWitness,
> {
    consignment: CheckedConsignment<'consignment, C>,

    status: RefCell<Status>,

    schema_id: SchemaId,
    contract_id: ContractId,
    chain_net: ChainNet,
    scripts: Scripts,

    contract_state: Rc<RefCell<S>>,

    input_opouts: RefCell<BTreeSet<Opout>>,

    opout_assigns: RefCell<BTreeMap<Opout, RevealedAssign>>,

    // Operations in this set will not be validated
    resolver: CheckedWitnessResolver<&'resolver R>,
    safe_height: Option<NonZeroU32>,
    trusted_typesystem: TypeSystem,
    opouts_dag_info: Option<RefCell<OpoutsDagInfo>>,
}

impl<
        'consignment,
        'resolver,
        S: ContractStateAccess + ContractStateEvolve,
        C: ConsignmentApi,
        R: ResolveWitness,
    > Validator<'consignment, 'resolver, S, C, R>
{
    fn init(
        consignment: &'consignment C,
        resolver: &'resolver R,
        context: S::Context<'_>,
        validation_config: &ValidationConfig,
    ) -> Self {
        // We use validation status object to store all detected failures and
        // warnings
        let status = Status::default();
        let consignment = CheckedConsignment::new(consignment);

        // Frequently used computation-heavy data
        let genesis = consignment.genesis();
        let contract_id = genesis.contract_id();
        let schema_id = genesis.schema_id;
        let chain_net = genesis.chain_net;
        let scripts =
            ConfinedOrdMap::from_iter_checked(consignment.scripts().map(|s| (s.id(), s.clone())));

        let input_opouts = RefCell::new(BTreeSet::<Opout>::new());

        let opout_assigns = RefCell::new(BTreeMap::<Opout, RevealedAssign>::new());

        let mut opouts_dag_info = None;
        if validation_config.build_opouts_dag {
            opouts_dag_info = Some(RefCell::new(OpoutsDagInfo::new()));
        }

        Self {
            consignment,
            status: RefCell::new(status),
            schema_id,
            contract_id,
            chain_net,
            scripts,
            input_opouts,
            opout_assigns,
            resolver: CheckedWitnessResolver::from(resolver),
            contract_state: Rc::new(RefCell::new(S::init(context))),
            safe_height: validation_config.safe_height,
            trusted_typesystem: validation_config.trusted_typesystem.clone(),
            opouts_dag_info,
        }
    }

    /// Validation procedure takes a schema object, root schema (if any),
    /// resolver function returning transaction and its fee for a given
    /// transaction id, and returns a validation object listing all detected
    /// failures, warnings and additional information.
    pub fn validate(
        consignment: &'consignment C,
        resolver: &'resolver R,
        context: S::Context<'_>,
        validation_config: &ValidationConfig,
    ) -> Result<Status, ValidationError> {
        let mut validator = Self::init(consignment, resolver, context, validation_config);
        // If the chain-network pair doesn't match there is no point in validating the contract
        // since all witness transactions will be missed.
        if validator.chain_net != validation_config.chain_net {
            return Err(ValidationError::InvalidConsignment(Failure::ContractChainNetMismatch(
                validation_config.chain_net,
            )));
        }
        if let Err(e) = resolver.check_chain_net(validation_config.chain_net) {
            return Err(ValidationError::ResolverError(e));
        }

        validator.validate_schema()?;

        validator.validate_genesis()?;

        validator.validate_bundles()?;

        // Done. Returning status report with all possible warnings and notifications.
        Ok(validator.status.into_inner())
    }

    // *** PART I: Schema validation
    fn validate_schema(&mut self) -> Result<(), ValidationError> {
        for (sem_id, consignment_type) in self.consignment.types().iter() {
            let trusted_type = self.trusted_typesystem.get(*sem_id);
            if trusted_type != Some(consignment_type) {
                return Err(ValidationError::InvalidConsignment(Failure::TypeSystemMismatch(
                    *sem_id,
                    Box::new(trusted_type.cloned()),
                    Box::new(consignment_type.clone()),
                )));
            }
        }
        self.consignment.schema().verify(&self.trusted_typesystem)?;
        Ok(())
    }

    // *** PART II: Validating business logic
    fn validate_genesis(&mut self) -> Result<(), ValidationError> {
        let schema = self.consignment.schema();

        // [VALIDATION]: Making sure that we were supplied with the schema
        //               that corresponds to the schema of the contract genesis
        if schema.schema_id() != self.schema_id {
            return Err(ValidationError::InvalidConsignment(Failure::SchemaMismatch {
                expected: self.schema_id,
                actual: schema.schema_id(),
            }));
        }

        // [VALIDATION]: Validate genesis
        let genesis = self.consignment.genesis().clone();
        schema.validate_state(
            &self.trusted_typesystem,
            &self.scripts,
            self.consignment.genesis(),
            OrdOpRef::Genesis(&genesis),
            self.contract_state.clone(),
            &BTreeMap::new(),
        )?;
        let contract_id = genesis.id();
        self.process_assignments(contract_id, None, &genesis.assignments)?;
        Ok(())
    }

    fn process_assignments(
        &self,
        opid: OpId,
        witness_id: Option<Txid>,
        assignments: &Assignments<impl ExposedSeal>,
    ) -> Result<(), ValidationError> {
        let mut output_nodes = Vec::new();
        for (ty, ass) in assignments.iter() {
            for no in 0..ass.len_u16() {
                let opout = Opout::new(opid, *ty, no);
                if let Some(dag_info) = &self.opouts_dag_info {
                    output_nodes.push(dag_info.borrow_mut().register_output(opout));
                }
                let Ok(revealed_assign) = ass.to_revealed_assign_at(no, witness_id) else {
                    continue;
                };
                self.opout_assigns
                    .borrow_mut()
                    .insert(opout, revealed_assign);
            }
        }
        if let Some(dag_info) = &self.opouts_dag_info {
            dag_info.borrow_mut().cache_outputs(&opid, output_nodes);
        }
        Ok(())
    }

    // *** PART III: Validating single-use-seals
    fn validate_bundles(&mut self) -> Result<(), ValidationError> {
        let mut unsafe_history_map: HashMap<u32, HashSet<Txid>> = HashMap::new();
        for (bundle, anchor, witness_id) in self.consignment.bundles_info() {
            let bundle_id = bundle.bundle_id();
            let (witness_tx, witness_ord) = self.resolve_witness(bundle_id, witness_id)?;
            if let Some(safe_height) = self.safe_height {
                match witness_ord {
                    WitnessOrd::Mined(witness_pos) => {
                        let witness_height = witness_pos.height();
                        if witness_height > safe_height {
                            unsafe_history_map
                                .entry(witness_height.into())
                                .or_default()
                                .insert(witness_id);
                        }
                    }
                    WitnessOrd::Tentative | WitnessOrd::Ignored | WitnessOrd::Archived => {
                        unsafe_history_map.entry(0).or_default().insert(witness_id);
                    }
                }
            }
            for known_transition in &bundle.known_transitions {
                self.validate_transition(
                    known_transition,
                    bundle,
                    &witness_tx,
                    &witness_ord,
                    anchor,
                )?;
                let KnownTransition { opid, transition } = known_transition;
                self.process_assignments(*opid, Some(witness_id), &transition.assignments)?;
                if let Some(ref mut dag_info) = self.opouts_dag_info {
                    dag_info.borrow_mut().connect_transition(transition, opid);
                }
            }
        }
        if self.safe_height.is_some() && !unsafe_history_map.is_empty() {
            self.status
                .borrow_mut()
                .add_warning(Warning::UnsafeHistory(unsafe_history_map));
        }
        if let Some(dag_info) = &self.opouts_dag_info {
            self.status.borrow_mut().dag_data_opt = Some(dag_info.borrow().to_opouts_dag_data());
        }
        Ok(())
    }

    fn resolve_witness(
        &self,
        bundle_id: BundleId,
        witness_id: Txid,
    ) -> Result<(Tx, WitnessOrd), ValidationError> {
        match self.resolver.resolve_witness(witness_id) {
            Err(err) => {
                // Unable to retrieve the corresponding transaction from the resolver.
                // Reporting this incident immediately.
                Err(ValidationError::ResolverError(err))
            }
            Ok(witness_status) => match witness_status {
                WitnessStatus::Resolved(tx, ord) if ord != WitnessOrd::Archived => {
                    self.status
                        .borrow_mut()
                        .tx_ord_map
                        .insert(tx.compute_txid(), ord);
                    Ok((tx, ord))
                }
                _ => Err(ValidationError::InvalidConsignment(Failure::SealNoPubWitness(
                    bundle_id, witness_id,
                ))),
            },
        }
    }

    /// Single-use-seal closing validation.
    ///
    /// Checks that the set of seals is closed over the message, which is
    /// multi-protocol commitment, by utilizing witness, consisting of
    /// transaction with deterministic bitcoin commitments (defined by
    /// generic type `Dbc`) and extra-transaction data, which are taken from
    /// anchor's DBC proof.
    ///
    /// Additionally, checks that the provided message contains commitment to
    /// the bundle under the current contract.
    fn validate_seal_closing<Dbc: dbc::Proof>(
        &self,
        seals: BTreeSet<BlindSeal<Txid>>,
        bundle_id: BundleId,
        witness: &Witness<Dbc>,
        mpc_proof: mpc::MerkleProof,
    ) -> Result<(), ValidationError>
    where
        Witness<Dbc>: SealWitness<BlindSeal<Txid>, Message = mpc::Commitment>,
    {
        let message = mpc::Message::from(bundle_id);
        let anchor = Anchor::new(mpc_proof, witness.proof.clone());
        // [VALIDATION]: Checking anchor MPC commitment
        match anchor.convolve(self.contract_id, message) {
            Err(err) => {
                // The operation is not committed to bitcoin transaction graph!
                // Ultimate failure. But continuing to detect the rest (after reporting it).
                return Err(ValidationError::InvalidConsignment(Failure::MpcInvalid(
                    bundle_id,
                    witness.txid,
                    Box::new(err),
                )));
            }
            Ok(commitment) => {
                // [VALIDATION]: Verify commitment
                let Some(output) =
                    witness.tx.output.iter().find(|out| {
                        out.script_pubkey.is_op_return() || out.script_pubkey.is_p2tr()
                    })
                else {
                    return Err(ValidationError::InvalidConsignment(Failure::NoDbcOutput(
                        witness.txid,
                    )));
                };
                let output_method = if output.script_pubkey.is_op_return() {
                    CloseMethod::OpretFirst
                } else {
                    CloseMethod::TapretFirst
                };
                let proof_method = witness.proof.method();
                if proof_method != output_method {
                    return Err(ValidationError::InvalidConsignment(Failure::InvalidProofType(
                        witness.txid,
                        proof_method,
                    )));
                }
                // [VALIDATION]: CHECKING SINGLE-USE-SEALS
                witness
                    .verify_many_seals(seals.iter(), &commitment)
                    .map_err(|err| {
                        ValidationError::InvalidConsignment(Failure::SealsInvalid(
                            bundle_id,
                            witness.txid,
                            err.to_string(),
                        ))
                    })?;
            }
        }
        Ok(())
    }

    fn validate_transition(
        &self,
        known_transition: &KnownTransition,
        bundle: &TransitionBundle,
        witness_tx: &Tx,
        witness_ord: &WitnessOrd,
        anchor: &Anchor<DbcProof>,
    ) -> Result<(), ValidationError> {
        let KnownTransition { opid, transition } = known_transition;
        let opid = *opid;
        if opid != transition.id() {
            return Err(ValidationError::InvalidConsignment(Failure::TransitionIdMismatch(
                opid,
                transition.id(),
            )));
        }
        if transition.contract_id() != self.contract_id {
            return Err(ValidationError::InvalidConsignment(Failure::ContractMismatch(
                opid,
                transition.contract_id(),
            )));
        }
        let bundle_id = bundle.bundle_id();

        let mut state_by_type = BTreeMap::<AssignmentType, Vec<RevealedState>>::new();
        let mut seals = BTreeSet::<BlindSeal<Txid>>::new();
        for input in &transition.inputs {
            if bundle.input_map.get(&input).is_none_or(|v| *v != opid) {
                return Err(ValidationError::InvalidConsignment(
                    Failure::InputMapTransitionMismatch(bundle.bundle_id(), opid, input),
                ));
            }
            let (seal, state) = self
                .opout_assigns
                .borrow_mut()
                .remove(&input)
                .and_then(RevealedAssign::into_revealed)
                .ok_or(ValidationError::InvalidConsignment(Failure::NoPrevState(opid, input)))?;
            seals.push(seal);
            state_by_type.entry(input.ty).or_default().push(state);
            if !self.input_opouts.borrow_mut().insert(input) {
                return Err(ValidationError::InvalidConsignment(Failure::CyclicGraph(input)));
            };
        }
        let witness = Witness::with(witness_tx.clone(), anchor.dbc_proof.clone());
        self.validate_seal_closing(seals, bundle_id, &witness, anchor.mpc_proof.clone())?;
        self.consignment.schema().validate_state(
            &self.trusted_typesystem,
            &self.scripts,
            self.consignment.genesis(),
            OrdOpRef::Transition(transition, witness.txid, *witness_ord, bundle_id),
            self.contract_state.clone(),
            &state_by_type,
        )?;
        Ok(())
    }
}
