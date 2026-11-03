// RGB Consensus Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright (C) 2026 RGB-Tools developers. All rights reserved.
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

//! [`Claim`]: the one bridge-related type the consensus layer acts on.
//!
//! It is pushed by the `plc` AluVM opcode during validation and consumed by the caller's
//! claim resolver.

use bitcoin::Txid;

use crate::OpId;

/// A claim about an external system, pushed by the `plc` AluVM opcode.
///
/// Consensus cannot check it, so the caller must confirm it before validation
/// is finalised.
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum Claim {
    /// A lock of `amount` on the bridge, made for operation `opid` in witness transaction
    /// `witness_id` and recorded before block `before_block` of the bridge's chain.
    Lock {
        /// Id of the operation which pushed the claim; the lock must be made for the same id.
        opid: OpId,
        /// Id of the witness transaction of the operation which pushed the claim; the lock must be
        /// made for the same transaction.
        ///
        /// The operation id commits to the vout of a witness seal, not to the script it pays, so
        /// the same operation in another transaction could pay someone else.
        witness_id: Txid,
        /// Amount locked; the lock must carry exactly the same amount.
        amount: u64,
        /// Block number on the bridge's chain before which the lock must have been recorded,
        /// exclusive.
        before_block: u64,
    },
}
