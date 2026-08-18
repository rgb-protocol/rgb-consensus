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

use core::fmt::Debug;
use std::hash::Hash;

use bitcoin::Txid;
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode, StrictType};

use crate::commit_verify::Conceal;
pub use crate::seals::txout::blind::{ChainBlindSeal, ParseError, SingleBlindSeal};
pub use crate::seals::txout::TxoSeal;
use crate::seals::txout::{ExplicitSeal, SealTxid};
pub use crate::seals::SecretSeal;
use crate::txout::{BlindSeal, TxPtr};
use crate::LIB_NAME_RGB_COMMIT;

pub type GenesisSeal = SingleBlindSeal;
pub type GraphSeal = ChainBlindSeal;

pub type OutputSeal = ExplicitSeal<Txid>;

/// Bound bundling the requirements a [`BuilderSeal`] seal type must satisfy.
pub trait BuilderSealTy:
    TxoSeal
    + Copy
    + Ord
    + StrictType
    + StrictDumb
    + StrictEncode
    + StrictDecode
    + Conceal<Concealed = SecretSeal>
{
}
impl<T> BuilderSealTy for T where T: TxoSeal
        + Copy
        + Ord
        + StrictType
        + StrictDumb
        + StrictEncode
        + StrictDecode
        + Conceal<Concealed = SecretSeal>
{
}

/// A seal which can be either revealed (the full seal is known) or concealed
/// (only its secret hash is known).
///
/// It is the seal of an [`Assign`](super::Assign)ment, the seal produced by the
/// operation builder, and the element type of consignment history terminals.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(
    lib = LIB_NAME_RGB_COMMIT,
    tags = custom,
    dumb = Self::Concealed(SecretSeal::strict_dumb())
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(
        crate = "serde_crate",
        rename_all = "camelCase",
        bound = "Seal: serde::Serialize + serde::de::DeserializeOwned"
    )
)]
pub enum BuilderSeal<Seal: BuilderSealTy> {
    #[strict_type(tag = 0x00)]
    Revealed(Seal),
    #[from]
    #[strict_type(tag = 0x01)]
    Concealed(SecretSeal),
}

impl<Id: SealTxid> From<BlindSeal<Id>> for BuilderSeal<BlindSeal<Id>> {
    fn from(seal: BlindSeal<Id>) -> Self { BuilderSeal::Revealed(seal) }
}

impl<Seal: BuilderSealTy> Conceal for BuilderSeal<Seal> {
    type Concealed = SecretSeal;
    fn conceal(&self) -> SecretSeal { self.to_secret_seal() }
}

impl<Seal: BuilderSealTy> BuilderSeal<Seal> {
    /// Returns the revealed seal, if this is a [`BuilderSeal::Revealed`] variant.
    pub fn revealed(&self) -> Option<Seal> {
        match self {
            BuilderSeal::Revealed(seal) => Some(*seal),
            BuilderSeal::Concealed(_) => None,
        }
    }

    /// Returns a reference to the revealed seal, if this is a revealed variant.
    pub fn revealed_ref(&self) -> Option<&Seal> {
        match self {
            BuilderSeal::Revealed(seal) => Some(seal),
            BuilderSeal::Concealed(_) => None,
        }
    }

    /// Returns the secret seal *only* for the [`BuilderSeal::Concealed`] variant.
    ///
    /// Unlike [`BuilderSeal::to_secret_seal`], this does not conceal a revealed seal.
    pub fn concealed(&self) -> Option<SecretSeal> {
        match self {
            BuilderSeal::Concealed(secret) => Some(*secret),
            BuilderSeal::Revealed(_) => None,
        }
    }

    pub fn is_revealed(&self) -> bool { matches!(self, BuilderSeal::Revealed(_)) }

    /// Returns the concealed form of the seal.
    pub fn to_secret_seal(&self) -> SecretSeal {
        match self {
            BuilderSeal::Revealed(seal) => seal.conceal(),
            BuilderSeal::Concealed(secret) => *secret,
        }
    }

    /// If concealed and matching the commitment of `seal`, replaces self with the
    /// revealed variant.
    pub fn reveal(&mut self, seal: Seal) {
        if let BuilderSeal::Concealed(secret) = self {
            if *secret == seal.conceal() {
                *self = BuilderSeal::Revealed(seal);
            }
        }
    }
}

pub trait ExposedSeal:
    Debug
    + StrictDumb
    + StrictEncode
    + StrictDecode
    + Eq
    + Ord
    + Copy
    + Hash
    + TxoSeal
    + Conceal<Concealed = SecretSeal>
{
    #[inline]
    fn to_output_seal(self) -> Option<OutputSeal> {
        let outpoint = self.outpoint()?;
        Some(ExplicitSeal::new(outpoint))
    }

    fn to_output_seal_or_default(self, witness_id: Txid) -> OutputSeal {
        self.to_output_seal()
            .unwrap_or(ExplicitSeal::new(self.outpoint_or(witness_id)))
    }

    /// Resolves the seal to the outpoint it closes, falling back to
    /// `witness_id` when given one.
    ///
    /// `witness_id` is `None` for genesis seals, which always carry their own
    /// txid; passing `None` for a seal without one panics.
    fn to_output_seal_or(self, witness_id: Option<Txid>) -> OutputSeal {
        match witness_id {
            Some(witness_id) => self.to_output_seal_or_default(witness_id),
            None => self
                .to_output_seal()
                .expect("seal without a witness must have an outpoint"),
        }
    }

    /// Attempts to convert to a `BlindSeal<Txid>`,
    /// returning None if both self.txid() and witness_id are None
    fn with_witness_id(self, witness_id: Option<Txid>) -> Option<BlindSeal<Txid>>;
}

impl ExposedSeal for BlindSeal<TxPtr> {
    fn with_witness_id(self, witness_id: Option<Txid>) -> Option<BlindSeal<Txid>> {
        let txid = self.txid().or(witness_id)?;
        Some(BlindSeal::with_blinding(txid, self.vout, self.blinding))
    }
}

impl ExposedSeal for BlindSeal<Txid> {
    fn with_witness_id(self, _witness_id: Option<Txid>) -> Option<BlindSeal<Txid>> { Some(self) }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;
    use crate::seals::txout::{BlindSeal, TxPtr};
    use crate::Vout;

    #[test]
    fn secret_seal_is_sha256d() {
        let reveal = BlindSeal {
            blinding: 54683213134637,
            txid: TxPtr::Txid(
                Txid::from_str("646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839")
                    .unwrap(),
            ),
            vout: Vout::from(2),
        };
        let secret = reveal.to_secret_seal();
        assert_eq!(
            secret.to_string(),
            "utxob:nBRVm39A-ioJydHE-ug2d90m-aZyfPI0-MCc0ZNM-oMXMs2O-opKQ7"
        );
        assert_eq!(reveal.to_secret_seal(), reveal.conceal())
    }
}
