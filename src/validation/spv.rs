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

use amplify::confinement::Confined;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::{Transaction, TxMerkleNode, Txid};
#[cfg(feature = "serde")]
use serde_crate::{Deserialize, Serialize};

use crate::dbc::LIB_NAME_BPCORE;
use crate::vm::{BlockHeight, WitnessPos};
use crate::Layer1;

/// Merkle inclusion proof for a bitcoin transaction
///
/// Contains the height of the block and the sibling-hash path needed to recompute its
/// merkle root
#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BPCORE)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct SpvProof {
    /// Height of the block that includes this proof
    #[strict_type(dumb = BlockHeight::MIN)]
    pub block_height: BlockHeight,
    /// Transaction's 0-based position within the block
    pub pos: u32,
    /// Sibling hashes along the merkle path
    #[cfg_attr(feature = "serde", serde(with = "strict_encoding::serde_helpers::confined"))]
    pub merkle: Confined<Vec<TxMerkleNode>, 0, 32>,
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error)]
#[display(doc_comments)]
pub enum SpvValidationError {
    /// transaction position is not reachable by a merkle path of the given length
    PositionOutOfBounds,
    /// recomputed merkle root does not match block header
    MerkleRootMismatch,
    /// merkle path goes through a node whose preimage is a valid 64-byte transaction
    InnerNodeIsTransaction,
}

impl SpvProof {
    /// Verify the proof of inclusion of `txid` in a block identified by `header`.
    ///
    /// `header` must be the one the resolver reports at [`SpvProof::block_height`] in the
    /// best chain; a proof which a reorg has invalidated then fails with
    /// [`SpvValidationError::MerkleRootMismatch`].
    ///
    /// A node's preimage is the concatenation of its children, which is 64 bytes long, just like
    /// some transactions. A mined 64-byte transaction would then let a proof extend one level
    /// below it, "proving" the inclusion of a TXID made of either of its halves
    /// (CVE-2017-12842). A path going through a node whose preimage is a valid transaction is
    /// therefore rejected with [`SpvValidationError::InnerNodeIsTransaction`]. An honest proof
    /// hits this only if a pair of hashes happens to decode as a transaction; callers treat it
    /// like any invalid proof, i.e. with a warning and a fallback to the resolver.
    pub fn validate(
        &self,
        txid: Txid,
        header: &bitcoin::block::Header,
    ) -> Result<(), SpvValidationError> {
        let mut hash = txid.to_raw_hash();
        let mut pos = self.pos;
        for sibling in self.merkle.iter() {
            let sib = sibling.to_raw_hash();
            let (left, right) = if pos & 1 == 0 { (hash, sib) } else { (sib, hash) };
            let mut node = [0u8; 64];
            node[..32].copy_from_slice(left.as_byte_array());
            node[32..].copy_from_slice(right.as_byte_array());
            if bitcoin::consensus::deserialize::<Transaction>(&node).is_ok() {
                return Err(SpvValidationError::InnerNodeIsTransaction);
            }
            hash = sha256d::Hash::hash(&node);
            pos >>= 1;
        }
        // Each sibling consumes one bit of the position, so a path of `n` siblings can
        // only authenticate leaves 0, ..., 2^n-1: any bit left over means the position is
        // out of reach of a path this long.
        if pos != 0 {
            return Err(SpvValidationError::PositionOutOfBounds);
        }
        if TxMerkleNode::from_raw_hash(hash) != header.merkle_root {
            return Err(SpvValidationError::MerkleRootMismatch);
        }
        Ok(())
    }

    /// The chain position `header` places `txid` at, if this proof verifies
    /// against it.
    pub fn verified_pos(
        &self,
        txid: Txid,
        header: &bitcoin::block::Header,
        layer1: Layer1,
    ) -> Result<Option<WitnessPos>, SpvValidationError> {
        self.validate(txid, header)?;
        Ok(WitnessPos::with(layer1, self.block_height, header.time as i64))
    }
}

#[cfg(test)]
mod test {
    use std::num::NonZeroU32;

    use bitcoin::block::{Header, Version};
    use bitcoin::hashes::HashEngine;
    use bitcoin::hex::FromHex;
    use bitcoin::{BlockHash, CompactTarget};

    use super::*;

    fn combine(left: sha256d::Hash, right: sha256d::Hash) -> sha256d::Hash {
        let mut engine = sha256d::Hash::engine();
        engine.input(&left.to_byte_array());
        engine.input(&right.to_byte_array());
        sha256d::Hash::from_engine(engine)
    }

    /// A 2-transaction block, together with the inclusion proof of its first TX.
    fn fixture() -> (Txid, Header, SpvProof) {
        let txid = Txid::from_byte_array([1u8; 32]);
        let sibling = Txid::from_byte_array([2u8; 32]);
        let merkle_root =
            TxMerkleNode::from_raw_hash(combine(txid.to_raw_hash(), sibling.to_raw_hash()));
        let header = Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root,
            time: 1231006505,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 0,
        };
        let proof = SpvProof {
            block_height: NonZeroU32::MIN,
            pos: 0,
            merkle: Confined::try_from(vec![TxMerkleNode::from_raw_hash(sibling.to_raw_hash())])
                .unwrap(),
        };
        (txid, header, proof)
    }

    #[test]
    fn validate_succeeds() {
        let (txid, header, proof) = fixture();
        assert!(proof.validate(txid, &header).is_ok());
    }

    #[test]
    fn validate_detects_swapped_position() {
        let (txid, header, mut proof) = fixture();
        // still within reach of a 1-sibling path, but hashes the pair the other way round
        proof.pos = 1;
        assert_eq!(proof.validate(txid, &header), Err(SpvValidationError::MerkleRootMismatch));
    }

    #[test]
    fn validate_detects_position_out_of_bounds() {
        let (txid, header, proof) = fixture();
        // a single sibling can only authenticate leaves 0 and 1
        for pos in [2, 3, u32::MAX] {
            let proof = SpvProof {
                pos,
                ..proof.clone()
            };
            assert_eq!(
                proof.validate(txid, &header),
                Err(SpvValidationError::PositionOutOfBounds),
                "pos {pos} should be out of bounds"
            );
        }
        // an empty path only authenticates a single-TX block, whose root is the TX itself
        let proof = SpvProof {
            pos: 1,
            merkle: Confined::try_from(vec![]).unwrap(),
            ..proof
        };
        assert_eq!(proof.validate(txid, &header), Err(SpvValidationError::PositionOutOfBounds));
    }

    /// CVE-2017-12842 test vectors from Electrum (`tests/test_verifier.py`): a 64-byte TX mined
    /// on testnet3, its merkle path and the merkle root of its block.
    const VALID_64_BYTE_TX: &str = "0200000001cb659c5528311901a7aada7db817bd6e3ce2f05d1c62c385b7caad\
                                    b65fac75201234000000fabcdefa01abcd1234010000000405060708fabcdefa";
    const MERKLE_BRANCH: [&str; 2] = [
        "f2994fd4546086b21b4916b76cf901afb5c4db1c3ecbfc91d6f4cae1186dfe12",
        "6b65935528311901c7acda7db817bd6e3ce2f05d1c62c385b7caadb65fac7520",
    ];
    const MERKLE_ROOT: &str = "11dbac015b6969ea75509dd1250f33c04ec4d562c2d895de139a65f62f808254";

    /// The 64-byte TX, the header of its block and the proof of a leaf at `pos` with path
    /// `[extra] ++ MERKLE_BRANCH`.
    fn cve_2017_12842_fixture(
        pos: u32,
        extra: Option<TxMerkleNode>,
    ) -> ([u8; 64], Header, SpvProof) {
        let tx_bytes: [u8; 64] = Vec::<u8>::from_hex(VALID_64_BYTE_TX)
            .unwrap()
            .try_into()
            .unwrap();
        let (_, header, _) = fixture();
        let header = Header {
            merkle_root: MERKLE_ROOT.parse().unwrap(),
            ..header
        };
        let merkle = extra
            .into_iter()
            .chain(MERKLE_BRANCH.iter().map(|node| node.parse().unwrap()))
            .collect::<Vec<_>>();
        let proof = SpvProof {
            block_height: NonZeroU32::MIN,
            pos,
            merkle: Confined::try_from(merkle).unwrap(),
        };
        (tx_bytes, header, proof)
    }

    #[test]
    fn validate_accepts_a_mined_64_byte_tx() {
        let (tx_bytes, header, proof) = cve_2017_12842_fixture(3, None);
        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&tx_bytes).unwrap();
        assert_eq!(proof.validate(tx.compute_txid(), &header), Ok(()));
    }

    #[test]
    fn validate_detects_a_64_byte_tx_as_inner_node() {
        let half = |bytes: &[u8]| <[u8; 32]>::try_from(bytes).unwrap();
        let (tx_bytes, _, _) = cve_2017_12842_fixture(3, None);
        let (first, second) = (half(&tx_bytes[..32]), half(&tx_bytes[32..]));
        // the fake leaf is either half of the TX, as a child of the TX itself
        for (pos, sibling, fake) in [(7, first, second), (6, second, first)] {
            let (_, header, proof) =
                cve_2017_12842_fixture(pos, Some(TxMerkleNode::from_byte_array(sibling)));
            assert_eq!(
                proof.validate(Txid::from_byte_array(fake), &header),
                Err(SpvValidationError::InnerNodeIsTransaction),
                "fake leaf at pos {pos} should be rejected"
            );
        }
    }

    #[test]
    fn validate_detects_a_header_from_another_block() {
        let (txid, header, proof) = fixture();
        let other = Header {
            merkle_root: TxMerkleNode::all_zeros(),
            ..header
        };
        assert_eq!(proof.validate(txid, &other), Err(SpvValidationError::MerkleRootMismatch));
    }
}
