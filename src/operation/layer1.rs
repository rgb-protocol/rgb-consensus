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

use std::str::FromStr;

use bitcoin::constants::ChainHash;
use strict_encoding::{DefaultBasedStrictDumb, StrictDecode, StrictEncode, StrictType};

use crate::{LIB_NAME_RGB_COMMIT, LIB_NAME_RGB_LOGIC};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(lowercase)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_LOGIC, tags = repr, into_u8, try_from_u8)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[repr(u8)]
#[derive(Default)]
pub enum Layer1 {
    #[default]
    Bitcoin = 0,
    Liquid = 1,
}

// Sat Jan 03 18:15:05 2009 UTC
const BITCOIN_GENESIS_TIMESTAMP: i64 = 1231006505;

// Sat Jan 03 18:15:05 2009 UTC
const LIQUID_GENESIS_TIMESTAMP: i64 = 1296692202;

impl Layer1 {
    #[inline]
    pub fn genesis_timestamp(&self) -> i64 {
        match self {
            Layer1::Bitcoin => BITCOIN_GENESIS_TIMESTAMP,
            Layer1::Liquid => LIQUID_GENESIS_TIMESTAMP,
        }
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[display(inner)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT, tags = repr, into_u8, try_from_u8)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[repr(u8)]
#[derive(Default)]
pub enum ChainNet {
    BitcoinMainnet = 0,
    BitcoinTestnet3 = 1,
    #[default]
    BitcoinTestnet4 = 2,
    BitcoinSignet = 3,
    BitcoinRegtest = 4,
    LiquidMainnet = 5,
    LiquidTestnet = 6,
    BitcoinSignetCustom = 7,
}

impl DefaultBasedStrictDumb for ChainNet {}

impl ChainNet {
    pub fn prefix(&self) -> &str {
        match self {
            ChainNet::BitcoinMainnet => "bc",
            ChainNet::BitcoinTestnet3 => "tb3",
            ChainNet::BitcoinTestnet4 => "tb4",
            ChainNet::BitcoinRegtest => "bcrt",
            ChainNet::BitcoinSignet => "sb",
            ChainNet::BitcoinSignetCustom => "sbc",
            ChainNet::LiquidMainnet => "lq",
            ChainNet::LiquidTestnet => "tl",
        }
    }

    pub fn layer1(&self) -> Layer1 {
        match self {
            ChainNet::BitcoinMainnet
            | ChainNet::BitcoinTestnet3
            | ChainNet::BitcoinTestnet4
            | ChainNet::BitcoinSignet
            | ChainNet::BitcoinSignetCustom
            | ChainNet::BitcoinRegtest => Layer1::Bitcoin,
            ChainNet::LiquidMainnet | ChainNet::LiquidTestnet => Layer1::Liquid,
        }
    }

    pub fn chain_hash(&self) -> ChainHash {
        match self {
            ChainNet::BitcoinMainnet => ChainHash::BITCOIN,
            ChainNet::BitcoinTestnet3 => ChainHash::TESTNET3,
            ChainNet::BitcoinTestnet4 => ChainHash::TESTNET4,
            ChainNet::BitcoinSignet | ChainNet::BitcoinSignetCustom => ChainHash::SIGNET,
            ChainNet::BitcoinRegtest => ChainHash::REGTEST,
            ChainNet::LiquidMainnet => ChainHash::from([
                0x4f, 0x4e, 0xac, 0x81, 0xe5, 0xf9, 0xf0, 0x4f, 0x5d, 0x2a, 0x17, 0xb0, 0x3e, 0x67,
                0x26, 0xe6, 0xa1, 0xaf, 0x69, 0xd9, 0xc3, 0xf0, 0x0d, 0x82, 0x0f, 0x1c, 0x82, 0xfc,
                0xb6, 0x00, 0x00, 0x00,
            ]),
            ChainNet::LiquidTestnet => ChainHash::from([
                0xf9, 0xf2, 0x1a, 0x76, 0x36, 0xb3, 0x5c, 0x12, 0xf0, 0x80, 0xff, 0x73, 0xfc, 0x8b,
                0xb1, 0x6b, 0xb7, 0xc3, 0xce, 0xaf, 0xdc, 0x2e, 0xb1, 0xb6, 0x73, 0xf0, 0xea, 0x7a,
                0x40, 0xc0, 0x00, 0x00,
            ]),
        }
    }
}

#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ChainNetParseError {
    /// invalid chain-network pair {0}.
    Invalid(String),
}

impl FromStr for ChainNet {
    type Err = ChainNetParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.to_lowercase();
        match s.as_str() {
            x if ChainNet::BitcoinMainnet.prefix() == x => Ok(ChainNet::BitcoinMainnet),
            x if ChainNet::BitcoinRegtest.prefix() == x => Ok(ChainNet::BitcoinRegtest),
            x if ChainNet::BitcoinSignet.prefix() == x => Ok(ChainNet::BitcoinSignet),
            x if ChainNet::BitcoinSignetCustom.prefix() == x => Ok(ChainNet::BitcoinSignetCustom),
            x if ChainNet::BitcoinTestnet3.prefix() == x => Ok(ChainNet::BitcoinTestnet3),
            x if ChainNet::BitcoinTestnet4.prefix() == x => Ok(ChainNet::BitcoinTestnet4),
            x if ChainNet::LiquidMainnet.prefix() == x => Ok(ChainNet::LiquidMainnet),
            x if ChainNet::LiquidTestnet.prefix() == x => Ok(ChainNet::LiquidTestnet),
            _ => Err(ChainNetParseError::Invalid(s.to_owned())),
        }
    }
}
