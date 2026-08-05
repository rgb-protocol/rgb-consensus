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

use std::collections::BTreeSet;
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
use crate::{BuilderSeal, OpId, Transition, LIB_NAME_RGB_COMMIT};

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

    /// Returns the opouts of the assignments of this bundle assigning some
    /// state to `seal`.
    ///
    /// Comparison is direct [`BuilderSeal`] equality: a revealed seal only
    /// matches an assignment with the same revealed seal, a concealed
    /// seal only matches an assignment with the same concealed seal.
    pub fn opouts_assigned_to(&self, seal: &BuilderSeal<GraphSeal>) -> BTreeSet<Opout> {
        let mut opouts = BTreeSet::new();
        for kt in &self.known_transitions {
            for (ty, ta) in kt.transition.assignments.iter() {
                for (no, s) in ta.seals().enumerate() {
                    if s == seal {
                        opouts.insert(Opout::new(kt.opid, *ty, no as u16));
                    }
                }
            }
        }
        opouts
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
        if let Some((_, child_opid)) = self.input_map.iter().find(|(opout, _)| opout.op == opid) {
            if let Some(pos) = self
                .known_transitions
                .iter()
                .position(|kt| kt.opid == *child_opid)
            {
                // keep bundle transitions sorted if they are interdependent
                let mut known_transitions = self.known_transitions.to_unconfined();
                known_transitions.insert(pos, KnownTransition { opid, transition });
                // from_checked is safe because known_transitions has same size as input map
                self.known_transitions = Confined::from_checked(known_transitions);
                return Ok(true);
            }
        }
        self.known_transitions
            .push(KnownTransition { opid, transition })
            .expect("same size as input map");
        Ok(true)
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
