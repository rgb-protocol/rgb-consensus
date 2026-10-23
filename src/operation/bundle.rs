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

use std::collections::{BTreeMap, BTreeSet};
use std::num::ParseIntError;
use std::str::FromStr;

use amplify::confinement::{Confined, NonEmptyOrdMap, NonEmptyVec, U16 as U16MAX};
use amplify::{Bytes32, Wrapper};
use strict_encoding::{StrictDumb, StrictEncode, LIB_NAME_BITCOIN};

use super::{GraphSeal, Opout};
use crate::commit_verify::{
    mpc, CommitEncode, CommitEngine, CommitId, CommitmentId, DigestExt, Sha256,
};
use crate::operation::operations::Operation;
use crate::{OpId, Transition, LIB_NAME_RGB_COMMIT};

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BITCOIN)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[display(inner)]
// 0xFFFFFFFF used in coinbase
pub struct Vout(u32);

impl Vout {
    pub const fn from_u32(u: u32) -> Self { Vout(u) }
    #[inline]
    pub const fn into_u32(self) -> u32 { self.0 }
    #[inline]
    pub const fn into_usize(self) -> usize { self.0 as usize }
    #[inline]
    pub const fn to_u32(&self) -> u32 { self.0 }
    #[inline]
    pub const fn to_usize(&self) -> usize { self.0 as usize }
}

impl FromStr for Vout {
    type Err = ParseIntError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> { s.parse().map(Self) }
}

pub type Vin = Vout;

/// Unique state transition bundle identifier equivalent to the bundle
/// commitment hash
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Display, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct BundleId(
    #[cfg_attr(feature = "serde", serde(with = "strict_encoding::serde_helpers::byte_array"))]
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl From<Sha256> for BundleId {
    fn from(hasher: Sha256) -> Self { hasher.finish().into() }
}

impl CommitmentId for BundleId {
    const TAG: &'static str = "urn:lnp-bp:rgb:bundle#2024-02-03";
}

impl From<BundleId> for mpc::Message {
    fn from(id: BundleId) -> Self { mpc::Message::from_inner(id.into_inner()) }
}

impl From<mpc::Message> for BundleId {
    fn from(id: mpc::Message) -> Self { BundleId(id.into_inner()) }
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error)]
#[display("state transition {0} is not a part of the bundle.")]
pub struct UnrelatedTransition(OpId);

#[derive(Clone, Eq, PartialEq, Debug, Display, Error)]
#[display("detected uncommitted state transitions.")]
pub struct UnrelatedTransitions;

#[derive(Clone, PartialEq, Eq, Debug, From)]
#[derive(StrictType, StrictEncode, StrictDecode, StrictDumb)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct KnownTransition {
    pub opid: OpId,
    pub transition: Transition,
}

impl KnownTransition {
    pub fn new(opid: OpId, transition: Transition) -> Self { Self { opid, transition } }
}

#[derive(Clone, PartialEq, Eq, Debug, From)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct TransitionBundle {
    #[cfg_attr(feature = "serde", serde(with = "strict_encoding::serde_helpers::confined"))]
    pub input_map: NonEmptyOrdMap<Opout, OpId, U16MAX>,
    #[cfg_attr(feature = "serde", serde(with = "strict_encoding::serde_helpers::confined"))]
    pub known_transitions: NonEmptyVec<KnownTransition, U16MAX>,
}

impl CommitEncode for TransitionBundle {
    type CommitmentId = BundleId;

    fn commit_encode(&self, e: &mut CommitEngine) { e.commit_to_map(&self.input_map); }
}

impl StrictDumb for TransitionBundle {
    fn strict_dumb() -> Self {
        Self {
            input_map: NonEmptyOrdMap::with_key_value(strict_dumb!(), strict_dumb!()),
            known_transitions: NonEmptyVec::with(strict_dumb!()),
        }
    }
}

impl TransitionBundle {
    pub fn bundle_id(&self) -> BundleId { self.commit_id() }

    pub fn input_map_opids(&self) -> BTreeSet<OpId> { self.input_map.values().copied().collect() }

    pub fn known_transitions_opids(&self) -> BTreeSet<OpId> {
        self.known_transitions
            .iter()
            .map(|kt| kt.opid)
            .collect::<BTreeSet<_>>()
    }

    pub fn check_opid_commitments(&self) -> Result<(), UnrelatedTransitions> {
        let ids1 = self.known_transitions_opids();
        let ids2 = self.input_map_opids();
        if !ids1.is_subset(&ids2) {
            return Err(UnrelatedTransitions);
        }
        Ok(())
    }

    pub fn known_transitions_contain_opid(&self, opid: &OpId) -> bool {
        self.known_transitions.iter().any(|kt| &kt.opid == opid)
    }

    pub fn get_transition(&self, opid: OpId) -> Option<&Transition> {
        self.known_transitions.iter().find_map(|kt| {
            if kt.opid == opid {
                Some(&kt.transition)
            } else {
                None
            }
        })
    }

    pub fn reveal_seal(&mut self, seal: GraphSeal) {
        self.known_transitions
            .iter_mut()
            .flat_map(|kt| kt.transition.assignments.values_mut())
            .for_each(|a| a.reveal_seal(seal));
    }

    pub fn reveal_transition(
        &mut self,
        transition: Transition,
    ) -> Result<bool, UnrelatedTransition> {
        let opid = transition.id();
        if !self.input_map_opids().contains(&opid) {
            return Err(UnrelatedTransition(opid));
        }
        if self.known_transitions_contain_opid(&opid) {
            return Ok(false);
        }
        let has_known_child = self.input_map.iter().any(|(opout, child_opid)| {
            opout.op == opid && self.known_transitions_contain_opid(child_opid)
        });
        self.known_transitions
            .push(KnownTransition { opid, transition })
            .expect("same size as input map");
        // keep bundle transitions sorted if they are interdependent
        if has_known_child {
            self.sort_known_transitions();
        }
        Ok(true)
    }

    /// Sorts the known transitions so that each follows the ones of the bundle it spends from,
    /// keeping their order otherwise.
    fn sort_known_transitions(&mut self) {
        let order = self
            .known_transitions
            .iter()
            .map(|kt| kt.opid)
            .collect::<Vec<_>>();
        let mut unsorted = self
            .known_transitions
            .to_unconfined()
            .into_iter()
            .map(|kt| (kt.opid, kt))
            .collect::<BTreeMap<_, _>>();
        let mut sorted = Vec::with_capacity(order.len());
        for opid in order {
            // depth-first, placing the unsorted parents of a transition before it. Opids commit
            // to the inputs, so transitions cannot spend from each other in a cycle
            let mut stack = vec![opid];
            while let Some(&top) = stack.last() {
                let Some(kt) = unsorted.get(&top) else {
                    stack.pop();
                    continue;
                };
                match kt
                    .transition
                    .inputs
                    .iter()
                    .find(|input| unsorted.contains_key(&input.op))
                {
                    Some(input) => stack.push(input.op),
                    None => {
                        stack.pop();
                        sorted.extend(unsorted.remove(&top));
                    }
                }
            }
        }
        // from_checked is safe because the transitions are the same
        self.known_transitions = Confined::from_checked(sorted);
    }

    pub fn to_concealed_except(&self, opid: OpId) -> Result<Self, UnrelatedTransition> {
        Ok(Self {
            input_map: self.input_map.clone(),
            known_transitions: Confined::try_from_iter(
                self.known_transitions
                    .as_unconfined()
                    .iter()
                    .filter(|kt| opid == kt.opid)
                    .cloned(),
            )
            .map_err(|e| match e {
                amplify::confinement::Error::Undersize { .. } => UnrelatedTransition(opid),
                _ => unreachable!("same size as input map"),
            })?,
        })
    }
}

#[cfg(test)]
mod test {
    use amplify::confinement::NonEmptyOrdSet;

    use super::*;
    use crate::{AssignmentType, Inputs};

    const A: AssignmentType = AssignmentType::with(4000);

    fn transition(nonce: u64, inputs: impl IntoIterator<Item = Opout>) -> Transition {
        let mut transition = Transition::strict_dumb();
        transition.nonce = nonce;
        transition.inputs = Inputs::from(NonEmptyOrdSet::from_iter_checked(inputs));
        transition
    }

    /// Every transition comes after the ones of the bundle it spends from.
    fn assert_sorted(bundle: &TransitionBundle) {
        let opids = bundle
            .known_transitions
            .iter()
            .map(|kt| kt.opid)
            .collect::<Vec<_>>();
        for (pos, kt) in bundle.known_transitions.iter().enumerate() {
            for input in &kt.transition.inputs {
                if let Some(parent_pos) = opids.iter().position(|opid| *opid == input.op) {
                    assert!(
                        parent_pos < pos,
                        "{} at {pos} spends {} at {parent_pos}: {opids:?}",
                        kt.opid,
                        input.op
                    );
                }
            }
        }
    }

    #[test]
    fn reveal_parent_of_two_children() {
        // a parent with two children in the same bundle
        let parent = transition(1, [Opout::new(OpId::from([1; 32]), A, 0)]);
        let parent_id = parent.id();
        let child_1 = transition(2, [Opout::new(parent_id, A, 0)]);
        let child_2 = transition(3, [Opout::new(parent_id, A, 1)]);
        let input_map = NonEmptyOrdMap::from_iter_checked(
            parent
                .inputs
                .iter()
                .map(|opout| (*opout, parent_id))
                .chain(child_1.inputs.iter().map(|opout| (*opout, child_1.id())))
                .chain(child_2.inputs.iter().map(|opout| (*opout, child_2.id()))),
        );

        // the bundle is revealed one transition at a time, the parent last
        let mut bundle = TransitionBundle {
            input_map,
            known_transitions: NonEmptyVec::with(KnownTransition::new(child_2.id(), child_2)),
        };
        assert!(bundle.reveal_transition(child_1).unwrap());
        assert_sorted(&bundle);
        assert!(bundle.reveal_transition(parent).unwrap());
        assert_sorted(&bundle);
    }

    #[test]
    fn reveal_middle_of_chain() {
        // a chain of three transitions in the same bundle
        let grandparent = transition(1, [Opout::new(OpId::from([1; 32]), A, 0)]);
        let parent = transition(2, [Opout::new(grandparent.id(), A, 0)]);
        let child = transition(3, [Opout::new(parent.id(), A, 0)]);
        let input_map = NonEmptyOrdMap::from_iter_checked(
            [&grandparent, &parent, &child]
                .into_iter()
                .flat_map(|t| t.inputs.iter().map(|opout| (*opout, t.id()))),
        );

        // the ends are revealed first, unrelated to each other, then the middle one
        let mut bundle = TransitionBundle {
            input_map,
            known_transitions: NonEmptyVec::with(KnownTransition::new(child.id(), child)),
        };
        assert!(bundle.reveal_transition(grandparent).unwrap());
        assert_sorted(&bundle);
        assert!(bundle.reveal_transition(parent).unwrap());
        assert_sorted(&bundle);
    }
}
