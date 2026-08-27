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
use crate::validation::{EAnchor, OpoutsDagData, OpoutsDagInfo, SchemaRules, SpvProof};
use crate::vm::{ContractStateAccess, ContractStateEvolve, ExternalAnchor, OrdOpRef, WitnessOrd};
use crate::{
    AssignmentType, Assignments, BuilderSeal, BundleId, ChainNet, ContractId, GraphSeal,
    KnownTransition, Layer1, OpId, Operation, Opout, RevealedState, SchemaId, TransitionBundle,
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
    /// a resolution was reported for witness {0}, which this validation is not waiting on
    UnknownWitness(Txid),
    /// a resolution was reported for an external anchor this validation is not waiting on
    UnknownAnchor,
    /// {0} external anchor(s) await confirmation, which a witness resolver cannot provide
    ExternalAnchorsPending(usize),
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

/// A resolver checked against the contract's chain-network pair.
///
/// Only [`PendingValidation::check_resolver`] hands one out, so a
/// [`WitnessTask`] cannot be resolved against a resolver nobody checked. It also
/// verifies that every witness the resolver returns has the id that was asked
/// for.
pub struct CheckedWitnessResolver<R: ResolveWitness> {
    inner: R,
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

/// A witness transaction the validation is still waiting on.
///
/// Self-contained on purpose: it carries everything [`Self::resolve`] needs, so
/// it can be handed to a worker thread, queued, or persisted while validation
/// carries on elsewhere. Nothing here borrows the consignment.
#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct WitnessTask {
    /// Bundle that anchors to this witness.
    pub bundle_id: BundleId,
    /// Id of the witness transaction.
    pub txid: Txid,
    /// SPV proof shipped with the bundle, if any.
    pub spv_proof: Option<SpvProof>,
    /// Layer 1 the witness lives on, taken from the contract's chain-net.
    pub layer1: Layer1,
}

/// The answer for one [`WitnessTask`], plus any warning raised while getting it.
#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct WitnessResolution {
    /// Witness the answer is about.
    pub txid: Txid,
    /// Ordering the resolver reported.
    pub ord: WitnessOrd,
    /// Raised when an SPV proof failed to verify and the plain resolver was
    /// used instead.
    pub warning: Option<Warning>,
}

impl WitnessTask {
    /// Resolves this witness against a resolver checked through
    /// [`PendingValidation::check_resolver`].
    ///
    /// Takes `&self`, so any number of tasks can be resolved concurrently.
    pub fn resolve<R: ResolveWitness>(
        &self,
        resolver: &CheckedWitnessResolver<R>,
    ) -> Result<WitnessResolution, ValidationError> {
        let mut warning = None;

        if let Some(spv_proof) = &self.spv_proof {
            match resolver.get_block_header(spv_proof.block_height) {
                Ok(header) => {
                    let witness_pos = spv_proof
                        .verified_pos(self.txid, &header, self.layer1)
                        .ok()
                        .flatten();
                    match witness_pos {
                        Some(witness_pos) => {
                            return Ok(WitnessResolution {
                                txid: self.txid,
                                ord: WitnessOrd::Mined(witness_pos),
                                warning: None,
                            });
                        }
                        // An invalid proof is not a reason to reject the consignment:
                        // a reorg can invalidate a proof the sender stored in good faith
                        // while the witness is still valid.
                        None => {
                            warning = Some(Warning::InvalidSpvProof(self.bundle_id, self.txid));
                        }
                    }
                }
                Err(WitnessResolverError::NotSupported) => { /* fall through to regular path */ }
                Err(err) => return Err(ValidationError::ResolverError(err)),
            }
        }

        // No valid SPV proof: ask the resolver for the witness status.
        match resolver.resolve_witness(self.txid) {
            Err(err) => Err(ValidationError::ResolverError(err)),
            Ok(WitnessStatus::Resolved(_, ord)) if ord != WitnessOrd::Archived => {
                Ok(WitnessResolution {
                    txid: self.txid,
                    ord,
                    warning,
                })
            }
            _ => Err(ValidationError::InvalidConsignment(Failure::SealNoPubWitness(
                self.bundle_id,
                self.txid,
            ))),
        }
    }
}

/// What [`PendingValidation::resolve_witness`] recorded about a witness.
///
/// Consensus only *warns* about an unsafe witness, through
/// [`Warning::UnsafeHistory`], because it cannot know what a given caller
/// considers acceptable. Reporting the verdict per witness is what lets a
/// caller apply a stricter policy - stopping at the first unsafe one instead of
/// resolving the rest and reading the warning afterwards.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Display)]
#[display(doc_comments)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum WitnessSafety {
    /// witness is within the configured safe height, or none was configured
    Safe,
    /// witness is mined above the safe height, or is not mined at all
    Unsafe,
}

/// A witness transaction phase 2 has to resolve, and the answer once it has
/// one.
///
/// A witness carries a single commitment, which commits to a single bundle per
/// contract, so there is one bundle per witness.
#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
struct PendingWitness {
    bundle_id: BundleId,
    spv_proof: Option<SpvProof>,
    ord: Option<WitnessOrd>,
}

/// Everything phase 1 established, and everything phase 2 still needs.
///
/// Produced by [`Validator::finish`] and consumed by [`Self::finalize`]. It owns
/// its data - no borrow of the consignment, the schema rules or the contract
/// state - so it can be held across an await, moved to another thread, or kept
/// while the caller decides whether resolving the witnesses is worth it at all.
///
/// Note it is deliberately *not* a [`Status`]: `Status::validity` reports
/// `Valid` whenever there are no warnings, and nothing here has been checked
/// against a chain yet. Only [`Self::finalize`] produces a `Status`.
#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct PendingValidation {
    /// Warnings raised so far.
    pub warnings: Vec<Warning>,
    /// The operations DAG, when `build_opouts_dag` was set.
    pub dag_data_opt: Option<OpoutsDagData>,

    chain_net: ChainNet,
    safe_height: Option<NonZeroU32>,
    // Keyed by witness txid: a transaction has one ordering.
    witnesses: BTreeMap<Txid, PendingWitness>,
    // Unique by construction, so confirming one is a move between the two.
    anchors_pending: BTreeSet<ExternalAnchor>,
    anchors_resolved: BTreeSet<ExternalAnchor>,
    unsafe_history: HashMap<u32, HashSet<Txid>>,
}

impl PendingValidation {
    /// The witnesses still waiting for an answer.
    pub fn unresolved_witnesses(&self) -> impl Iterator<Item = WitnessTask> + '_ {
        self.witnesses
            .iter()
            .filter(|(_, witness)| witness.ord.is_none())
            .map(|(txid, witness)| WitnessTask {
                bundle_id: witness.bundle_id,
                txid: *txid,
                spv_proof: witness.spv_proof.clone(),
                layer1: self.chain_net.layer1(),
            })
    }

    /// The external anchors still waiting to be confirmed.
    ///
    /// Consensus cannot resolve these itself: they reference systems it knows
    /// nothing about (e.g. an Ethereum event log). Same convention as
    /// [`Self::unresolved_witnesses`]: after a partial failure this is exactly
    /// what is left.
    pub fn unresolved_anchors(&self) -> impl Iterator<Item = &ExternalAnchor> + '_ {
        self.anchors_pending.iter()
    }

    /// Marks an external anchor as confirmed by the external system it lives on.
    ///
    /// Confirming the same anchor twice is harmless; one the validation never
    /// asked about is an error.
    pub fn resolve_anchor(&mut self, anchor: &ExternalAnchor) -> Result<(), ValidationError> {
        if let Some(anchor) = self.anchors_pending.take(anchor) {
            self.anchors_resolved.insert(anchor);
        } else if !self.anchors_resolved.contains(anchor) {
            return Err(ValidationError::UnknownAnchor);
        }
        Ok(())
    }

    /// Whether every witness has been resolved and every anchor confirmed.
    pub fn is_resolved(&self) -> bool {
        self.witnesses.values().all(|witness| witness.ord.is_some())
            && self.anchors_pending.is_empty()
    }

    /// Checks that `resolver` serves this contract's chain-network pair.
    ///
    /// A network round-trip on real indexers, so call it once per resolver and
    /// hand the result to every [`WitnessTask::resolve`]. [`Self::resolve_all`]
    /// does it for you.
    pub fn check_resolver<'r, R: ResolveWitness>(
        &self,
        resolver: &'r R,
    ) -> Result<CheckedWitnessResolver<&'r R>, ValidationError> {
        resolver
            .check_chain_net(self.chain_net)
            .map_err(ValidationError::ResolverError)?;
        Ok(CheckedWitnessResolver { inner: resolver })
    }

    /// Records the answer for one witness and applies the rules to it there and
    /// then.
    ///
    /// An archived witness fails here rather than at [`Self::finalize`], so the
    /// caller can stop instead of resolving the rest first. A witness above
    /// `safe_height` is noted for the `UnsafeHistory` warning as it arrives, so
    /// a caller with a stricter policy than consensus can act on it
    /// immediately.
    ///
    /// Returns whether the witness is within `safe_height`, so a caller with a
    /// policy stricter than consensus' can stop here.
    pub fn resolve_witness(
        &mut self,
        res: WitnessResolution,
    ) -> Result<WitnessSafety, ValidationError> {
        let Some(witness) = self.witnesses.get_mut(&res.txid) else {
            return Err(ValidationError::UnknownWitness(res.txid));
        };
        witness.ord = Some(res.ord);
        if res.ord == WitnessOrd::Archived {
            return Err(ValidationError::InvalidConsignment(Failure::SealNoPubWitness(
                witness.bundle_id,
                res.txid,
            )));
        }
        let mut safety = WitnessSafety::Safe;
        if let Some(safe_height) = self.safe_height {
            match res.ord {
                WitnessOrd::Mined(witness_pos) => {
                    let witness_height = witness_pos.height();
                    if witness_height > safe_height {
                        self.unsafe_history
                            .entry(witness_height.into())
                            .or_default()
                            .insert(res.txid);
                        safety = WitnessSafety::Unsafe;
                    }
                }
                WitnessOrd::Tentative | WitnessOrd::Ignored | WitnessOrd::Archived => {
                    self.unsafe_history.entry(0).or_default().insert(res.txid);
                    safety = WitnessSafety::Unsafe;
                }
            }
        }
        if let Some(warning) = res.warning {
            self.warnings.push(warning);
        }
        Ok(safety)
    }

    /// Resolves every outstanding witness sequentially.
    ///
    /// The convenience path. A caller wanting concurrency maps
    /// [`WitnessTask::resolve`] over [`Self::unresolved_witnesses`] instead and
    /// feeds the answers back through [`Self::resolve_witness`].
    pub fn resolve_all<R: ResolveWitness>(&mut self, resolver: &R) -> Result<(), ValidationError> {
        let resolver = self.check_resolver(resolver)?;
        let tasks = self.unresolved_witnesses().collect::<Vec<_>>();
        for task in tasks {
            let res = task.resolve(&resolver)?;
            // consensus policy is to warn and carry on; a caller wanting to stop
            // at the first unsafe witness drives the loop itself
            let _ = self.resolve_witness(res)?;
        }
        Ok(())
    }

    /// Phase 2: adjudicate and produce the status report.
    ///
    /// Consumes `self`, so it cannot be run twice.
    ///
    /// # Panics
    ///
    /// If a witness or an external anchor is still outstanding, see
    /// [`Self::is_resolved`]. That means the caller did not finish the protocol
    /// and says nothing about the consignment.
    pub fn finalize(mut self) -> Status {
        assert!(
            self.is_resolved(),
            "validation finalized with witnesses or external anchors still outstanding"
        );
        if self.safe_height.is_some() && !self.unsafe_history.is_empty() {
            self.warnings
                .push(Warning::UnsafeHistory(self.unsafe_history));
        }
        Status {
            warnings: self.warnings,
            tx_ord_map: self
                .witnesses
                .into_iter()
                .filter_map(|(txid, witness)| witness.ord.map(|ord| (txid, ord)))
                .collect(),
            dag_data_opt: self.dag_data_opt,
        }
    }
}

pub struct Validator<'consignment, S: ContractStateAccess + ContractStateEvolve, C: ConsignmentApi>
{
    consignment: CheckedConsignment<'consignment, C>,

    schema_rules: &'consignment SchemaRules,
    schema_id: SchemaId,
    contract_id: ContractId,
    chain_net: ChainNet,

    contract_state: Rc<RefCell<S>>,

    input_opouts: RefCell<BTreeSet<Opout>>,

    opout_assigns: RefCell<BTreeMap<Opout, RevealedAssign>>,

    safe_height: Option<NonZeroU32>,
    opouts_dag_info: Option<RefCell<OpoutsDagInfo>>,

    // Owned copy of the history terminals, drained as we visit the bundles they
    // reference. Each terminal seal is checked against its bundle's assignments;
    // any entry left over at the end references an absent bundle.
    terminals: BTreeMap<BundleId, BTreeSet<BuilderSeal<GraphSeal>>>,
    // Opouts the terminal seals resolve to, checked to be unspent once all the
    // bundles have been processed.
    terminal_opouts: BTreeMap<Opout, BundleId>,
    // The bundles left to process, so the walk can be resumed.
    bundles: Box<
        dyn Iterator<
                Item = (
                    &'consignment TransitionBundle,
                    &'consignment EAnchor,
                    &'consignment Tx,
                    Option<&'consignment SpvProof>,
                ),
            > + 'consignment,
    >,
    witnesses: BTreeMap<Txid, PendingWitness>,

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

        let terminals = consignment.terminals();

        let bundles = Box::new(consignment.bundles_info_ref());

        Self {
            consignment,
            schema_rules,
            schema_id,
            contract_id,
            chain_net,
            input_opouts,
            opout_assigns,
            contract_state: Rc::new(RefCell::new(S::init(context))),
            safe_height: validation_config.safe_height,
            opouts_dag_info,
            terminals,
            terminal_opouts: BTreeMap::new(),
            bundles,
            witnesses: BTreeMap::new(),
            pending_external_anchors: RefCell::new(BTreeSet::new()),
        }
    }

    /// Validation procedure takes a schema object, root schema (if any),
    /// resolver function returning transaction and its fee for a given
    /// transaction id, and returns a validation object listing all detected
    /// failures, warnings and additional information.
    pub fn validate<R: ResolveWitness>(
        consignment: &'consignment C,
        schema_rules: &'consignment SchemaRules,
        resolver: &R,
        context: S::Context<'_>,
        validation_config: &ValidationConfig,
    ) -> Result<Status, ValidationError> {
        let mut pending =
            Self::validate_deterministic(consignment, schema_rules, context, validation_config)?;
        pending.resolve_all(resolver)?;
        // whether there are any depends on the consignment, so this is not for `finalize` to
        // panic on
        let anchors = pending.unresolved_anchors().count();
        if anchors > 0 {
            return Err(ValidationError::ExternalAnchorsPending(anchors));
        }
        Ok(pending.finalize())
    }

    /// Runs the whole of phase 1 in one go.
    ///
    /// Equivalent to [`Self::start`] followed by [`Self::finish`]. Use those two
    /// directly to get hold of each witness as it is discovered.
    pub fn validate_deterministic(
        consignment: &'consignment C,
        schema_rules: &'consignment SchemaRules,
        context: S::Context<'_>,
        validation_config: &ValidationConfig,
    ) -> Result<PendingValidation, ValidationError> {
        Self::start(consignment, schema_rules, context, validation_config)?.finish()
    }

    /// Begins phase 1: validates the genesis and leaves the validator ready to
    /// walk the bundles.
    ///
    /// Nothing here touches a chain. Drive the walk with
    /// [`Self::next_bundle`], then close it with [`Self::finish`].
    pub fn start(
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

        Ok(validator)
    }

    /// Validates the next bundle and hands back the witness it waits on.
    ///
    /// Returns `None` once every bundle has been visited; calling it again then
    /// is harmless. The task is returned as soon as the bundle it belongs to has
    /// been validated, so a caller can start resolving it while the remaining
    /// bundles are still being checked.
    pub fn next_bundle(&mut self) -> Result<Option<WitnessTask>, ValidationError> {
        let Some((bundle, anchor, witness_tx, spv_proof)) = self.bundles.next() else {
            return Ok(None);
        };

        let bundle_id = bundle.bundle_id();
        let witness_id = witness_tx.compute_txid();
        if let Some(seals) = self.terminals.remove(&bundle_id) {
            for seal in &seals {
                let opouts = bundle.opouts_assigned_to(seal);
                if opouts.is_empty() {
                    return Err(ValidationError::InvalidConsignment(
                        Failure::TerminalSealMismatch(bundle_id),
                    ));
                }
                self.terminal_opouts
                    .extend(opouts.into_iter().map(|opout| (opout, bundle_id)));
            }
        }

        self.witnesses
            .entry(witness_id)
            .or_insert_with(|| PendingWitness {
                bundle_id,
                spv_proof: spv_proof.cloned(),
                ord: None,
            });
        let task = WitnessTask {
            bundle_id,
            txid: witness_id,
            spv_proof: spv_proof.cloned(),
            layer1: self.chain_net.layer1(),
        };

        for known_transition in &bundle.known_transitions {
            self.validate_transition(known_transition, bundle, witness_tx, anchor)?;
            let KnownTransition { opid, transition } = known_transition;
            self.process_assignments(*opid, Some(witness_id), &transition.assignments)?;
            if let Some(ref mut dag_info) = self.opouts_dag_info {
                dag_info.borrow_mut().connect_transition(transition, opid);
            }
        }

        Ok(Some(task))
    }

    /// Ends phase 1, validating any bundle not yet visited.
    ///
    /// Safe to call at any point: it drives [`Self::next_bundle`] to exhaustion
    /// first, so a caller that ignored the walk gets the same result as one that
    /// drove it to the end.
    pub fn finish(mut self) -> Result<PendingValidation, ValidationError> {
        while self.next_bundle()?.is_some() {}

        // Any remaining terminal must reference a bundle that is not present in the consignment.
        if let Some((bundle_id, _)) = self.terminals.iter().next() {
            return Err(ValidationError::InvalidConsignment(Failure::TerminalBundleAbsent(
                *bundle_id,
            )));
        }
        // Terminals must be unspent.
        {
            let input_opouts = self.input_opouts.borrow();
            if let Some((opout, bundle_id)) = self
                .terminal_opouts
                .iter()
                .find(|(opout, _)| input_opouts.contains(opout))
            {
                return Err(ValidationError::InvalidConsignment(Failure::TerminalSealSpent(
                    *bundle_id, *opout,
                )));
            }
        }

        let dag_data_opt = self
            .opouts_dag_info
            .as_ref()
            .map(|dag_info| dag_info.borrow().to_opouts_dag_data());

        Ok(PendingValidation {
            warnings: Vec::new(),
            dag_data_opt,
            chain_net: self.chain_net,
            safe_height: self.safe_height,
            witnesses: self.witnesses,
            anchors_pending: self.pending_external_anchors.into_inner(),
            anchors_resolved: BTreeSet::new(),
            unsafe_history: HashMap::new(),
        })
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
            get_block_header(CheckedWitnessResolver { inner: NoHeaders }),
            Err(WitnessResolverError::NotSupported)
        );
        assert_eq!(get_block_header(CheckedWitnessResolver { inner: WithHeaders }), Ok(header()));
    }
}
