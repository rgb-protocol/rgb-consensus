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
use bitcoin::hashes::{sha256d, Hash, HashEngine};
use bitcoin::{TxMerkleNode, Txid};
#[cfg(feature = "serde")]
use serde_crate::{Deserialize, Serialize};

use crate::dbc::LIB_NAME_BPCORE;
use crate::vm::BlockHeight;

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
}

impl SpvProof {
    /// Verify the proof of inclusion of `txid` in a block identified by `header`.
    ///
    /// `header` must be the one the resolver reports at [`SpvProof::block_height`] in the
    /// best chain; a proof which a reorg has invalidated then fails with
    /// [`SpvValidationError::MerkleRootMismatch`].
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
            let mut encoder = sha256d::Hash::engine();
            encoder.input(&left.to_byte_array());
            encoder.input(&right.to_byte_array());
            hash = sha256d::Hash::from_engine(encoder);
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
}

#[cfg(test)]
mod test {
    use std::num::NonZeroU32;

    use bitcoin::block::{Header, Version};
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
