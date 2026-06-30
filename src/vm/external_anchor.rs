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

//! [`ExternalAnchor`]: the one bridge-related type the consensus layer acts on.
//!
//! It is produced by the `pma` AluVM opcode during validation and consumed by the caller's
//! external-anchor resolver.

use crate::OpId;

/// External anchors are emitted by the `pma` AluVM opcode and must be resolved
/// by the caller before finalising BFA mint validation.
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum ExternalAnchor {
    /// A mint event on Ethereum for `amount`, to be looked for after block `after_block`.
    MintEvent {
        opid: OpId,
        amount: u64,
        after_block: u64,
    },
}
