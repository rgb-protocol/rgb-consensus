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

use amplify::confinement::Collection;
use bitcoin::{Transaction as Tx, Txid};

use super::status::{Failure, Warning};
use super::{CheckedConsignment, ConsignmentApi, DbcProof, Status};
use crate::assignments::RevealedAssign;
use crate::commit_verify::mpc;
use crate::dbc::{self, Anchor};
use crate::operation::seal::ExposedSeal;
use crate::seals::txout::{CloseMethod, Witness};
use crate::single_use_seals::SealWitness;
use crate::txout::BlindSeal;
use crate::validation::{OpoutsDagInfo, SchemaRules, SpvProof};
use crate::vm::{ContractStateAccess, ContractStateEvolve, ExternalAnchor, OrdOpRef, WitnessOrd};
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
    /// operation is not supported by this resolver
    NotSupported,
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

    /// Fetch the header of the block at `height` in the best chain. Used by the
    /// validator to verify SPV proofs without retrieving the witness TX itself.
    ///
    /// The returned header must be the one at `height` in the best known chain:
    /// this is what an SPV proof is checked against, so a resolver which serves a
    /// header from a stale block would accept proofs a reorg has invalidated.
    ///
    /// Returns `Err(NotSupported)` by default; resolvers that support header
    /// fetching should override this method.
    fn get_block_header(
        &self,
        _height: NonZeroU32,
    ) -> Result<bitcoin::block::Header, WitnessResolverError> {
        Err(WitnessResolverError::NotSupported)
    }

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

    fn get_block_header(
        &self,
        height: NonZeroU32,
    ) -> Result<bitcoin::block::Header, WitnessResolverError> {
        ResolveWitness::get_block_header(*self, height)
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

    fn get_block_header(
        &self,
        height: NonZeroU32,
    ) -> Result<bitcoin::block::Header, WitnessResolverError> {
        self.inner.get_block_header(height)
    }

    fn check_chain_net(&self, chain_net: ChainNet) -> Result<(), WitnessResolverError> {
        self.inner.check_chain_net(chain_net)
    }
}

#[derive(Clone, Debug, Default)]
pub struct ValidationConfig {
    pub chain_net: ChainNet,
    pub safe_height: Option<NonZeroU32>,
    pub build_opouts_dag: bool,
}

/// The witnesses phase 2 has to resolve, collected while walking the bundles.
type ToResolve = Vec<(BundleId, Txid, Option<SpvProof>)>;

pub struct Validator<'consignment, S: ContractStateAccess + ContractStateEvolve, C: ConsignmentApi>
{
    consignment: CheckedConsignment<'consignment, C>,

    status: RefCell<Status>,

    schema_rules: &'consignment SchemaRules,
    schema_id: SchemaId,
    contract_id: ContractId,
    chain_net: ChainNet,

    contract_state: Rc<RefCell<S>>,

    input_opouts: RefCell<BTreeSet<Opout>>,

    opout_assigns: RefCell<BTreeMap<Opout, RevealedAssign>>,

    safe_height: Option<NonZeroU32>,
    opouts_dag_info: Option<RefCell<OpoutsDagInfo>>,

    to_resolve: Option<ToResolve>,

    pending_external_anchors: RefCell<BTreeSet<ExternalAnchor>>,
}

impl<'consignment, S: ContractStateAccess + ContractStateEvolve, C: ConsignmentApi>
    Validator<'consignment, S, C>
{
    fn init(
        consignment: &'consignment C,
        schema_rules: &'consignment SchemaRules,
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

        let input_opouts = RefCell::new(BTreeSet::<Opout>::new());

        let opout_assigns = RefCell::new(BTreeMap::<Opout, RevealedAssign>::new());

        let mut opouts_dag_info = None;
        if validation_config.build_opouts_dag {
            opouts_dag_info = Some(RefCell::new(OpoutsDagInfo::new()));
        }

        Self {
            consignment,
            status: RefCell::new(status),
            schema_rules,
            schema_id,
            contract_id,
            chain_net,
            input_opouts,
            opout_assigns,
            contract_state: Rc::new(RefCell::new(S::init(context))),
            safe_height: validation_config.safe_height,
            opouts_dag_info,
            to_resolve: None,
            pending_external_anchors: RefCell::new(BTreeSet::new()),
        }
    }

    /// Validation procedure takes a schema object, root schema (if any),
    /// resolver function returning transaction and its fee for a given
    /// transaction id, and returns a validation object listing all detected
    /// failures, warnings and additional information.
    pub fn validate<'resolver, R: ResolveWitness>(
        consignment: &'consignment C,
        schema_rules: &'consignment SchemaRules,
        resolver: &'resolver R,
        context: S::Context<'_>,
        validation_config: &ValidationConfig,
    ) -> Result<Status, ValidationError> {
        let validator =
            Self::validate_deterministic(consignment, schema_rules, context, validation_config)?;
        validator.finalize_with_resolver(resolver)
    }

    /// Phase 1: validate everything that only depends on the consignment file.
    ///
    /// Returns `Self` so the caller can proceed to phase 2, which resolves the
    /// witness transactions.
    pub fn validate_deterministic(
        consignment: &'consignment C,
        schema_rules: &'consignment SchemaRules,
        context: S::Context<'_>,
        validation_config: &ValidationConfig,
    ) -> Result<Self, ValidationError> {
        let mut validator = Self::init(consignment, schema_rules, context, validation_config);
        // If the chain-network pair doesn't match there is no point in validating the contract
        // since all witness transactions will be missed.
        if validator.chain_net != validation_config.chain_net {
            return Err(ValidationError::InvalidConsignment(Failure::ContractChainNetMismatch(
                validation_config.chain_net,
            )));
        }

        validator.validate_genesis()?;

        validator.to_resolve = Some(validator.validate_bundles()?);

        Ok(validator)
    }

    /// Phase 2: resolve the witnesses.
    ///
    /// Must be called after [`Self::validate_deterministic`] succeeds. The resolver is
    /// used only to determine the [`WitnessOrd`] of each bundle's witness transaction.
    pub fn finalize_with_resolver<R: ResolveWitness>(
        mut self,
        resolver: &R,
    ) -> Result<Status, ValidationError> {
        if let Err(e) = resolver.check_chain_net(self.chain_net) {
            return Err(ValidationError::ResolverError(e));
        }
        let resolver = CheckedWitnessResolver::from(resolver);

        let to_resolve = self
            .to_resolve
            .take()
            .expect("the deterministic part of the validation must be executed first");
        let mut unsafe_history_map: HashMap<u32, HashSet<Txid>> = HashMap::new();
        for (bundle_id, witness_id, spv_proof) in to_resolve {
            let witness_ord = self.resolve_witness(&resolver, bundle_id, witness_id, spv_proof)?;
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
        }
        if self.safe_height.is_some() && !unsafe_history_map.is_empty() {
            self.status
                .borrow_mut()
                .add_warning(Warning::UnsafeHistory(unsafe_history_map));
        }

        let pending = self.pending_external_anchors.borrow().len();
        if pending > 0 {
            return Err(ValidationError::InvalidConsignment(Failure::ExternalAnchorsPending(
                pending,
            )));
        }

        // Done. Returning status report with all possible warnings and notifications.
        Ok(self.status.take())
    }

    /// Returns a snapshot of all external anchors accumulated during Phase 1 that have not yet
    /// been resolved. BFA callers should verify each anchor externally and then call
    /// [`Self::record_anchor_resolution`] for it before calling [`Self::finalize_with_resolver`].
    pub fn pending_external_anchors(&self) -> BTreeSet<ExternalAnchor> {
        self.pending_external_anchors.borrow().clone()
    }

    /// Remove a resolved anchor from the pending set.
    ///
    /// Call this once the external system (e.g. the Ethereum event log) has confirmed the anchor.
    pub fn record_anchor_resolution(&mut self, anchor: &ExternalAnchor) -> bool {
        self.pending_external_anchors.borrow_mut().remove(anchor)
    }

    // *** PART I: Validating business logic
    fn validate_genesis(&mut self) -> Result<(), ValidationError> {
        let schema = self.schema_rules.schema();

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
        let anchors = self.schema_rules.validate_state(
            self.consignment.genesis(),
            OrdOpRef::Genesis(&genesis),
            self.contract_state.clone(),
            &BTreeMap::new(),
        )?;
        self.pending_external_anchors.borrow_mut().extend(anchors);
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

    // *** PART II: Validating single-use-seals
    fn validate_bundles(&mut self) -> Result<ToResolve, ValidationError> {
        // Owned copy of the history terminals, drained as we visit the bundles they
        // reference. Each terminal seal is checked against its bundle's assignments;
        // any entry left over at the end references an absent bundle.
        let mut terminals = self.consignment.terminals();
        // Opouts the terminal seals resolve to, checked to be unspent once all the bundles
        // have been processed.
        let mut terminal_opouts = BTreeMap::<Opout, BundleId>::new();
        let mut to_resolve = ToResolve::new();
        for (bundle, anchor, witness_tx, spv_proof) in self.consignment.bundles_info() {
            let bundle_id = bundle.bundle_id();
            let witness_id = witness_tx.compute_txid();
            if let Some(seals) = terminals.remove(&bundle_id) {
                for seal in &seals {
                    let opouts = bundle.opouts_assigned_to(seal);
                    if opouts.is_empty() {
                        return Err(ValidationError::InvalidConsignment(
                            Failure::TerminalSealMismatch(bundle_id),
                        ));
                    }
                    terminal_opouts.extend(opouts.into_iter().map(|opout| (opout, bundle_id)));
                }
            }
            to_resolve.push((bundle_id, witness_id, spv_proof.cloned()));
            for known_transition in &bundle.known_transitions {
                self.validate_transition(known_transition, bundle, witness_tx, anchor)?;
                let KnownTransition { opid, transition } = known_transition;
                self.process_assignments(*opid, Some(witness_id), &transition.assignments)?;
                if let Some(ref mut dag_info) = self.opouts_dag_info {
                    dag_info.borrow_mut().connect_transition(transition, opid);
                }
            }
        }
        // Any remaining terminal must reference a bundle that is not present in the consignment.
        if let Some((bundle_id, _)) = terminals.into_iter().next() {
            return Err(ValidationError::InvalidConsignment(Failure::TerminalBundleAbsent(
                bundle_id,
            )));
        }
        // Terminals must be unspent.
        let input_opouts = self.input_opouts.borrow();
        if let Some((opout, bundle_id)) = terminal_opouts
            .into_iter()
            .find(|(opout, _)| input_opouts.contains(opout))
        {
            return Err(ValidationError::InvalidConsignment(Failure::TerminalSealSpent(
                bundle_id, opout,
            )));
        }
        if let Some(dag_info) = &self.opouts_dag_info {
            self.status.borrow_mut().dag_data_opt = Some(dag_info.borrow().to_opouts_dag_data());
        }
        Ok(to_resolve)
    }

    fn resolve_witness<R: ResolveWitness>(
        &self,
        resolver: &CheckedWitnessResolver<&R>,
        bundle_id: BundleId,
        witness_id: Txid,
        spv_proof_opt: Option<SpvProof>,
    ) -> Result<WitnessOrd, ValidationError> {
        // SPV
        if let Some(spv_proof) = spv_proof_opt {
            match resolver.get_block_header(spv_proof.block_height) {
                Ok(header) => {
                    // a proof which does not verify and a header which makes no
                    // position are the same thing here: neither yields an ord,
                    // and neither is a reason to reject
                    let witness_pos = spv_proof
                        .verified_pos(witness_id, &header, self.chain_net.layer1())
                        .ok()
                        .flatten();
                    match witness_pos {
                        Some(witness_pos) => {
                            let ord = WitnessOrd::Mined(witness_pos);
                            self.status.borrow_mut().tx_ord_map.insert(witness_id, ord);
                            return Ok(ord);
                        }
                        // A proof which does not verify is not a reason to reject the
                        // consignment: the header is the one at the proof's height in the
                        // resolver's best chain, so a reorg which moved the witness
                        // elsewhere invalidates a proof the sender stored in good faith.
                        // Carrying no proof at all is legal anyway, so the regular path is
                        // always reachable and refusing to take it here would only ever
                        // reject transfers which are otherwise valid.
                        None => {
                            self.status
                                .borrow_mut()
                                .add_warning(Warning::InvalidSpvProof(bundle_id, witness_id));
                        }
                    }
                }
                Err(WitnessResolverError::NotSupported) => { /* fall through to regular path */ }
                Err(err) => return Err(ValidationError::ResolverError(err)),
            }
        }

        // TX
        match resolver.resolve_witness(witness_id) {
            Err(err) => {
                // Unable to retrieve the corresponding transaction from the resolver.
                Err(ValidationError::ResolverError(err))
            }
            Ok(WitnessStatus::Resolved(_, ord)) if ord != WitnessOrd::Archived => {
                self.status.borrow_mut().tx_ord_map.insert(witness_id, ord);
                Ok(ord)
            }
            _ => Err(ValidationError::InvalidConsignment(Failure::SealNoPubWitness(
                bundle_id, witness_id,
            ))),
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
        let anchors = self.schema_rules.validate_state(
            self.consignment.genesis(),
            OrdOpRef::Transition(transition, witness.txid, bundle_id),
            self.contract_state.clone(),
            &state_by_type,
        )?;
        self.pending_external_anchors.borrow_mut().extend(anchors);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use bitcoin::block::{Header, Version};
    use bitcoin::hashes::Hash;
    use bitcoin::{BlockHash, CompactTarget, TxMerkleNode};

    use super::*;

    fn header() -> Header {
        Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1231006505,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 0,
        }
    }

    /// Resolver whose backend cannot serve block headers, hence not overriding
    /// [`ResolveWitness::get_block_header`].
    struct NoHeaders;
    impl ResolveWitness for NoHeaders {
        fn resolve_witness(&self, _: Txid) -> Result<WitnessStatus, WitnessResolverError> {
            Ok(WitnessStatus::Unresolved)
        }
        fn check_chain_net(&self, _: ChainNet) -> Result<(), WitnessResolverError> { Ok(()) }
    }

    /// Resolver which can serve block headers, hence able to verify SPV proofs.
    struct WithHeaders;
    impl ResolveWitness for WithHeaders {
        fn resolve_witness(&self, _: Txid) -> Result<WitnessStatus, WitnessResolverError> {
            Ok(WitnessStatus::Unresolved)
        }
        fn get_block_header(&self, _: NonZeroU32) -> Result<Header, WitnessResolverError> {
            Ok(header())
        }
        fn check_chain_net(&self, _: ChainNet) -> Result<(), WitnessResolverError> { Ok(()) }
    }

    fn get_block_header<R: ResolveWitness>(resolver: R) -> Result<Header, WitnessResolverError> {
        resolver.get_block_header(NonZeroU32::MIN)
    }

    #[test]
    fn header_support_is_opt_in() {
        assert_eq!(get_block_header(NoHeaders), Err(WitnessResolverError::NotSupported));
        assert_eq!(get_block_header(WithHeaders), Ok(header()));
    }

    #[test]
    fn reference_forwards_header_support() {
        assert_eq!(get_block_header(&NoHeaders), Err(WitnessResolverError::NotSupported));
        assert_eq!(get_block_header(&WithHeaders), Ok(header()));
    }

    #[test]
    fn checked_resolver_forwards_header_support() {
        assert_eq!(
            get_block_header(CheckedWitnessResolver::from(NoHeaders)),
            Err(WitnessResolverError::NotSupported)
        );
        assert_eq!(get_block_header(CheckedWitnessResolver::from(WithHeaders)), Ok(header()));
    }
}
