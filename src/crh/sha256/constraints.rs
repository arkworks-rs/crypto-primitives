// This file was adapted from
// https://github.com/nanpuyue/sha256/blob/bf6656b7dc72e76bb617445a8865f906670e585b/src/lib.rs
// See LICENSE-MIT in the root directory for a copy of the license
// Thank you!

use crate::crh::sha256::r1cs_utils::UInt32Ext;

use core::iter;

use ark_ff::PrimeField;
use ark_r1cs_std::bits::{uint32::UInt32, uint8::UInt8};
use ark_std::{vec, vec::Vec};

const STATE_LEN: usize = 8;

type State = [u32; STATE_LEN];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H: State = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

#[derive(Clone)]
pub struct Sha256Gadget<ConstraintF: PrimeField> {
    state: Vec<UInt32<ConstraintF>>,
    completed_data_blocks: u64,
    pending: Vec<UInt8<ConstraintF>>,
    num_pending: usize,
}

impl<ConstraintF: PrimeField> Default for Sha256Gadget<ConstraintF> {
    fn default() -> Self {
        Self {
            state: H.iter().cloned().map(UInt32::constant).collect(),
            completed_data_blocks: 0,
            pending: iter::repeat(0u8).take(64).map(UInt8::constant).collect(),
            num_pending: 0,
        }
    }
}

// Wikipedia's pseudocode is a good companion for understanding the below
// https://en.wikipedia.org/wiki/SHA-2#Pseudocode
impl<ConstraintF: PrimeField> Sha256Gadget<ConstraintF> {
    fn update_state(state: &mut [UInt32<ConstraintF>], data: &[UInt8<ConstraintF>]) {
        assert_eq!(data.len(), 64);

        let mut w = vec![UInt32::constant(0); 64];
        for (word, chunk) in w.iter_mut().zip(data.chunks(4)) {
            *word = UInt32::from_be_bytes(chunk);
        }

        for i in 16..64 {
            let s0 = {
                let x1 = w[i - 15].rotr(7);
                let x2 = w[i - 15].rotr(18);
                let x3 = w[i - 15].shr(3);
                x1.xor(&x2).unwrap().xor(&x3).unwrap()
            };
            let s1 = {
                let x1 = w[i - 2].rotr(17);
                let x2 = w[i - 2].rotr(19);
                let x3 = w[i - 2].shr(10);
                x1.xor(&x2).unwrap().xor(&x3).unwrap()
            };
            w[i] = UInt32::addmany(&[w[i - 16].clone(), s0, w[i - 7].clone(), s1]).unwrap();
        }

        let mut h = state.to_vec();
        for i in 0..64 {
            let ch = {
                let x1 = h[4].bitand(&h[5]);
                let x2 = h[4].not().bitand(&h[6]);
                x1.xor(&x2).unwrap()
            };
            let ma = {
                let x1 = h[0].bitand(&h[1]);
                let x2 = h[0].bitand(&h[2]);
                let x3 = h[1].bitand(&h[2]);
                x1.xor(&x2).unwrap().xor(&x3).unwrap()
            };
            let s0 = {
                let x1 = h[0].rotr(2);
                let x2 = h[0].rotr(13);
                let x3 = h[0].rotr(22);
                x1.xor(&x2).unwrap().xor(&x3).unwrap()
            };
            let s1 = {
                let x1 = h[4].rotr(6);
                let x2 = h[4].rotr(11);
                let x3 = h[4].rotr(25);
                x1.xor(&x2).unwrap().xor(&x3).unwrap()
            };
            let t0 = UInt32::addmany(&[h[7].clone(), s1, ch, UInt32::constant(K[i]), w[i].clone()])
                .unwrap();
            let t1 = UInt32::addmany(&[s0, ma]).unwrap();

            h[7] = h[6].clone();
            h[6] = h[5].clone();
            h[5] = h[4].clone();
            h[4] = UInt32::addmany(&[h[3].clone(), t0.clone()]).unwrap();
            h[3] = h[2].clone();
            h[2] = h[1].clone();
            h[1] = h[0].clone();
            h[0] = UInt32::addmany(&[t0, t1]).unwrap();
        }

        for (s, hi) in state.iter_mut().zip(h.iter()) {
            *s = UInt32::addmany(&[s.clone(), hi.clone()]).unwrap();
        }
    }

    /// Consumes the given data and updates the internal state
    pub fn update(&mut self, data: &[UInt8<ConstraintF>]) {
        let mut offset = 0;
        if self.num_pending > 0 && self.num_pending + data.len() >= 64 {
            offset = 64 - self.num_pending;
            // If the inputted data pushes the pending buffer over the chunk size, process it all
            self.pending[self.num_pending..].clone_from_slice(&data[..offset]);
            Self::update_state(&mut self.state, &self.pending);

            self.completed_data_blocks += 1;
            self.num_pending = 0;
        }

        for chunk in data[offset..].chunks(64) {
            let chunk_size = chunk.len();

            if chunk_size == 64 {
                // If it's a full chunk, process it
                Self::update_state(&mut self.state, chunk);
                self.completed_data_blocks += 1;
            } else {
                // Otherwise, add the bytes to the `pending` buffer
                self.pending[self.num_pending..self.num_pending + chunk_size]
                    .clone_from_slice(chunk);
                self.num_pending += chunk_size;
            }
        }
    }

    /// Outputs the final digest of all the inputted data
    pub fn finalize(mut self) -> Vec<UInt8<ConstraintF>> {
        // Encode the number of processed bits as a u64, then serialize it to 8 big-endian bytes
        let data_bitlen = self.completed_data_blocks * 512 + self.num_pending as u64 * 8;
        let encoded_bitlen: Vec<UInt8<ConstraintF>> = {
            let bytes = data_bitlen.to_be_bytes();
            bytes.iter().map(|&b| UInt8::constant(b)).collect()
        };

        // Padding starts with a 1 followed by some number of zeros (0x80 = 0b10000000)
        let mut pending = vec![UInt8::constant(0); 72];
        pending[0] = UInt8::constant(0x80);

        // We'll either append to the 56+8 = 64 byte boundary or the 120+8 = 128 byte boundary,
        // depending on whether we have at least 56 unprocessed bytes
        let offset = if self.num_pending < 56 {
            56 - self.num_pending
        } else {
            120 - self.num_pending
        };

        // Write the bitlen to the end of the padding. Then process all the padding
        pending[offset..offset + 8].clone_from_slice(&encoded_bitlen);
        self.update(&pending[..offset + 8]);

        // Collect the state into big-endian bytes
        self.state.iter().flat_map(UInt32::to_be_bytes).collect()
    }

    /// Computes the digest of the given data. This is a shortcut for `default()` followed by
    /// `update()` followed by `finalize()`.
    pub fn digest(data: &[UInt8<ConstraintF>]) -> Vec<UInt8<ConstraintF>> {
        let mut sha256_var = Self::default();
        sha256_var.update(data);
        sha256_var.finalize()
    }
}

// All the tests below test against the RustCrypto sha2 implementation
#[cfg(test)]
mod test {
    use super::*;
    use crate::crh::sha256::{digest::Digest, Sha256};

    use ark_bls12_377::Fr;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::{
        ns,
        r1cs::{ConstraintSystem, Namespace},
    };
    use ark_std::rand::RngCore;

    /// Witnesses bytes
    fn to_byte_vars(cs: impl Into<Namespace<Fr>>, data: &[u8]) -> Vec<UInt8<Fr>> {
        let cs = cs.into().cs();
        UInt8::new_witness_vec(cs, data).unwrap()
    }

    /// Finalizes a SHA256 gadget and gets the bytes
    fn finalize_var(sha256_var: Sha256Gadget<Fr>) -> Vec<u8> {
        sha256_var
            .finalize()
            .into_iter()
            .map(|b| b.value().unwrap())
            .collect()
    }

    /// Finalizes a native SHA256 struct and gets the bytes
    fn finalize(sha256: Sha256) -> Vec<u8> {
        sha256.finalize().to_vec()
    }

    /// Tests the SHA256 of random strings of all lengths from 0 to 100
    #[test]
    fn varied_lengths() {
        let mut rng = ark_std::test_rng();
        let cs = ConstraintSystem::<Fr>::new_ref();

        for i in 0..=100 {
            let mut sha256 = Sha256::default();
            let mut sha256_var = Sha256Gadget::default();

            // Make a random string of length i
            let mut input_str = vec![0u8; i];
            rng.fill_bytes(&mut input_str);

            // Compute the hashes and assert consistency
            sha256_var.update(&to_byte_vars(ns!(cs, "input"), &input_str));
            sha256.update(input_str);
            assert_eq!(
                finalize_var(sha256_var),
                finalize(sha256),
                "error at length {}",
                i
            );
        }
    }

    /// Calls `update()` many times
    #[test]
    fn many_updates() {
        let mut rng = ark_std::test_rng();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut sha256 = Sha256::default();
        let mut sha256_var = Sha256Gadget::default();

        // Append the same 7-byte string 128 times
        for _ in 0..128 {
            let mut input_str = vec![0u8; 7];
            rng.fill_bytes(&mut input_str);

            sha256_var.update(&to_byte_vars(ns!(cs, "input"), &input_str));
            sha256.update(input_str);
        }

        // Make sure the result is consistent
        assert_eq!(finalize_var(sha256_var), finalize(sha256));
    }
}
