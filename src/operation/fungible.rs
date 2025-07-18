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

//! This mod represents **atomic rational values** (or, simply just **value**),
//! it a value representing a portion of something whole with a certain fixed
//! level of precision (atomicity). Such values are commonly used to represent
//! some coins of fungible tokens, where each coin or token consists of an
//! integer number of atomic subdivisions of the total supply (like satoshis in
//! bitcoin represent just a portion, i.e. fixed-precision rational number, of
//! the total possible bitcoin supply). Such numbers demonstrate constant
//! properties regarding their total sum and, thus, can be made confidential
//! using elliptic curve homomorphic cryptography such as Pedesen commitments.

use core::fmt::Debug;
use core::num::ParseIntError;
use core::str::FromStr;
use std::hash::Hash;

use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};

use super::ExposedState;
use crate::{schema, RevealedState, StateType, LIB_NAME_RGB_COMMIT};

/// An atom of an additive state, which thus can be monomorphically encrypted.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From)]
#[display(inner)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT, tags = custom)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase", untagged)
)]
pub enum FungibleState {
    /// 64-bit value.
    #[from]
    #[strict_type(tag = 8)] // Matches strict types U64 primitive value
    Bits64(u64),
    // When/if adding more variants do not forget to re-write FromStr impl
}

impl Default for FungibleState {
    fn default() -> Self { FungibleState::Bits64(0) }
}

impl FromStr for FungibleState {
    type Err = ParseIntError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { s.parse().map(FungibleState::Bits64) }
}

impl From<FungibleState> for u64 {
    fn from(value: FungibleState) -> Self {
        match value {
            FungibleState::Bits64(val) => val,
        }
    }
}

impl FungibleState {
    pub fn fungible_type(&self) -> schema::FungibleType {
        match self {
            FungibleState::Bits64(_) => schema::FungibleType::Unsigned64Bit,
        }
    }

    pub fn as_u64(&self) -> u64 { (*self).into() }
}

/// State item for a homomorphically-encryptable state.
///
/// Consists of the 64-bit value and
#[derive(Wrapper, Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord, From, Display)]
#[display(inner)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[wrapper(Deref)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct RevealedValue(FungibleState);

impl RevealedValue {
    /// Convenience constructor.
    pub fn new(value: impl Into<FungibleState>) -> Self { Self(value.into()) }
}

impl ExposedState for RevealedValue {
    fn state_type(&self) -> StateType { StateType::Fungible }
    fn state_data(&self) -> RevealedState { RevealedState::Fungible(*self) }
}

impl From<u64> for RevealedValue {
    fn from(value: u64) -> Self { Self(FungibleState::Bits64(value)) }
}
