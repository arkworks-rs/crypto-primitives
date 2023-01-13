// This file was adapted from
// the sha384 code which was adapted from
// https://github.com/nanpuyue/sha384/blob/bf6656b7dc72e76bb617445a8865f906670e585b/src/lib.rs
// See LICENSE-MIT in the root directory for a copy of the license
// Thank you!

use crate::crh::{
    sha384::{r1cs_utils::UInt64Ext, Sha384},
    CRHSchemeGadget, TwoToOneCRHSchemeGadget,
};

use core::{borrow::Borrow, iter, marker::PhantomData};

use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    bits::{boolean::Boolean, uint64::UInt64, uint8::UInt8, ToBytesGadget},
    eq::EqGadget,
    select::CondSelectGadget,
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::{vec, vec::Vec};

const STATE_LEN: usize = 8;

type State = [u64; STATE_LEN];

const K: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
    0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
    0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
    0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
    0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
    0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
];

const H: State = [
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 
    0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
];

#[derive(Clone)]
pub struct Sha384Gadget<ConstraintF: PrimeField> {
    state: Vec<UInt64<ConstraintF>>,
    completed_data_blocks: u128,
    pending: Vec<UInt8<ConstraintF>>,
    num_pending: usize,
}

impl<ConstraintF: PrimeField> Default for Sha384Gadget<ConstraintF> {
    fn default() -> Self {
        Self {
            state: H.iter().cloned().map(UInt64::constant).collect(),
            completed_data_blocks: 0,
            pending: iter::repeat(0u8).take(128).map(UInt8::constant).collect(),
            num_pending: 0,
        }
    }
}

// Wikipedia's pseudocode is a good companion for understanding the below
// https://en.wikipedia.org/wiki/SHA-2#Pseudocode
impl<ConstraintF: PrimeField> Sha384Gadget<ConstraintF> {
    fn update_state(
        state: &mut [UInt64<ConstraintF>],
        data: &[UInt8<ConstraintF>],
    ) -> Result<(), SynthesisError> {
        assert_eq!(data.len(), 128);

        let mut w = vec![UInt64::constant(0); 80];
        for (word, chunk) in w.iter_mut().zip(data.chunks(8)) {
            *word = UInt64::from_bytes_be(chunk)?;
        }

        for i in 16..80 {
            let s0 = {
                let x1 = w[i - 15].rotr(1);
                let x2 = w[i - 15].rotr(8);
                let x3 = w[i - 15].shr(7);
                x1.xor(&x2)?.xor(&x3)?
            };
            let s1 = {
                let x1 = w[i - 2].rotr(19);
                let x2 = w[i - 2].rotr(61);
                let x3 = w[i - 2].shr(6);
                x1.xor(&x2)?.xor(&x3)?
            };
            w[i] = UInt64::addmany(&[w[i - 16].clone(), s0, w[i - 7].clone(), s1])?;
        }

        let mut h = state.to_vec();
        for i in 0..80 {
            let ch = {
                let x1 = h[4].bitand(&h[5])?;
                let x2 = h[4].not().bitand(&h[6])?;
                x1.xor(&x2)?
            };
            let ma = {
                let x1 = h[0].bitand(&h[1])?;
                let x2 = h[0].bitand(&h[2])?;
                let x3 = h[1].bitand(&h[2])?;
                x1.xor(&x2)?.xor(&x3)?
            };
            let s0 = {
                let x1 = h[0].rotr(28);
                let x2 = h[0].rotr(34);
                let x3 = h[0].rotr(39);
                x1.xor(&x2)?.xor(&x3)?
            };
            let s1 = {
                let x1 = h[4].rotr(14);
                let x2 = h[4].rotr(18);
                let x3 = h[4].rotr(41);
                x1.xor(&x2)?.xor(&x3)?
            };
            let t0 =
                UInt64::addmany(&[h[7].clone(), s1, ch, UInt64::constant(K[i]), w[i].clone()])?;
            let t1 = UInt64::addmany(&[s0, ma])?;

            h[7] = h[6].clone();
            h[6] = h[5].clone();
            h[5] = h[4].clone();
            h[4] = UInt64::addmany(&[h[3].clone(), t0.clone()])?;
            h[3] = h[2].clone();
            h[2] = h[1].clone();
            h[1] = h[0].clone();
            h[0] = UInt64::addmany(&[t0, t1])?;
        }

        for (s, hi) in state.iter_mut().zip(h.iter()) {
            *s = UInt64::addmany(&[s.clone(), hi.clone()])?;
        }

        Ok(())
    }

    /// Consumes the given data and updates the internal state
    pub fn update(&mut self, data: &[UInt8<ConstraintF>]) -> Result<(), SynthesisError> {
        let mut offset = 0;
        if self.num_pending > 0 && self.num_pending + data.len() >= 128 {
            offset = 128 - self.num_pending;
            // If the inputted data pushes the pending buffer over the chunk size, process it all
            self.pending[self.num_pending..].clone_from_slice(&data[..offset]);
            Self::update_state(&mut self.state, &self.pending)?;

            self.completed_data_blocks += 1;
            self.num_pending = 0;
        }

        for chunk in data[offset..].chunks(128) {
            let chunk_size = chunk.len();

            if chunk_size == 128 {
                // If it's a full chunk, process it
                Self::update_state(&mut self.state, chunk)?;
                self.completed_data_blocks += 1;
            } else {
                // Otherwise, add the bytes to the `pending` buffer
                self.pending[self.num_pending..self.num_pending + chunk_size]
                    .clone_from_slice(chunk);
                self.num_pending += chunk_size;
            }
        }

        Ok(())
    }

    /// Outputs the final digest of all the inputted data
    pub fn finalize(mut self) -> Result<DigestVar<ConstraintF>, SynthesisError> {
        // Encode the number of processed bits as a u128, then serialize it to 16 big-endian bytes
        let data_bitlen = self.completed_data_blocks * 1024 + self.num_pending as u128 * 8;
        let encoded_bitlen: Vec<UInt8<ConstraintF>> = {
            let bytes = data_bitlen.to_be_bytes();
            bytes.iter().map(|&b| UInt8::constant(b)).collect()
        };

        // Padding starts with a 1 followed by some number of zeros (0x80 = 0b10000000)
        let mut pending = vec![UInt8::constant(0); 144];
        pending[0] = UInt8::constant(0x80);

        // We'll either append to the 112+16 = 128 byte boundary or the 240+16=256 byte boundary,
        // depending on whether we have at least 112 unprocessed bytes
        let offset = if self.num_pending < 112 {
            112 - self.num_pending
        } else {
            240 - self.num_pending
        };

        // Write the bitlen to the end of the padding. Then process all the padding
        pending[offset..offset + 16].clone_from_slice(&encoded_bitlen);
        self.update(&pending[..offset + 16])?;

        // Collect the state into big-endian bytes
        let bytes: Vec<_> = self.state.iter().flat_map(UInt64::to_bytes_be).collect();
        Ok(DigestVar(bytes))
    }

    /// Computes the digest of the given data. This is a shortcut for `default()` followed by
    /// `update()` followed by `finalize()`.
    pub fn digest(data: &[UInt8<ConstraintF>]) -> Result<DigestVar<ConstraintF>, SynthesisError> {
        let mut sha384_var = Self::default();
        sha384_var.update(data)?;
        sha384_var.finalize()
    }
}

// Now implement the CRH traits for SHA384

/// Contains a 64-byte SHA384 digest
#[derive(Clone, Debug)]
pub struct DigestVar<ConstraintF: PrimeField>(pub Vec<UInt8<ConstraintF>>);

impl<ConstraintF> EqGadget<ConstraintF> for DigestVar<ConstraintF>
where
    ConstraintF: PrimeField,
{
    fn is_eq(&self, other: &Self) -> Result<Boolean<ConstraintF>, SynthesisError> {
        self.0.is_eq(&other.0)
    }
}

impl<ConstraintF: PrimeField> ToBytesGadget<ConstraintF> for DigestVar<ConstraintF> {
    fn to_bytes(&self) -> Result<Vec<UInt8<ConstraintF>>, SynthesisError> {
        Ok(self.0.clone())
    }
}

impl<ConstraintF: PrimeField> CondSelectGadget<ConstraintF> for DigestVar<ConstraintF>
where
    Self: Sized,
    Self: Clone,
{
    fn conditionally_select(
        cond: &Boolean<ConstraintF>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        let bytes: Result<Vec<_>, _> = true_value
            .0
            .iter()
            .zip(false_value.0.iter())
            .map(|(t, f)| UInt8::conditionally_select(cond, t, f))
            .collect();
        bytes.map(DigestVar)
    }
}

/// The unit type for circuit variables. This contains no data.
#[derive(Clone, Debug, Default)]
pub struct UnitVar<ConstraintF: PrimeField>(PhantomData<ConstraintF>);

impl<ConstraintF: PrimeField> AllocVar<(), ConstraintF> for UnitVar<ConstraintF> {
    // Allocates 64 UInt8s
    fn new_variable<T: Borrow<()>>(
        _cs: impl Into<Namespace<ConstraintF>>,
        _f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        Ok(UnitVar(PhantomData))
    }
}

impl<ConstraintF: PrimeField> AllocVar<Vec<u8>, ConstraintF> for DigestVar<ConstraintF> {
    // Allocates 64 UInt8s
    fn new_variable<T: Borrow<Vec<u8>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let native_bytes = f();

        if native_bytes
            .as_ref()
            .map(|b| b.borrow().len())
            .unwrap_or(64)
            != 64
        {
            panic!("DigestVar must be allocated with precisely 64 bytes");
        }

        // For each i, allocate the i-th byte
        let var_bytes: Result<Vec<_>, _> = (0..64)
            .map(|i| {
                UInt8::new_variable(
                    cs.clone(),
                    || native_bytes.as_ref().map(|v| v.borrow()[i]).map_err(|e| *e),
                    mode,
                )
            })
            .collect();

        var_bytes.map(DigestVar)
    }
}

impl<ConstraintF: PrimeField> R1CSVar<ConstraintF> for DigestVar<ConstraintF> {
    type Value = [u8; 48];

    fn cs(&self) -> ConstraintSystemRef<ConstraintF> {
        let mut result = ConstraintSystemRef::None;
        for var in &self.0 {
            result = var.cs().or(result);
        }
        result
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let mut buf = [0u8; 48];
        for (b, var) in buf.iter_mut().zip(self.0.iter()) {
            *b = var.value()?;
        }

        Ok(buf)
    }
}

impl<ConstraintF> CRHSchemeGadget<Sha384, ConstraintF> for Sha384Gadget<ConstraintF>
where
    ConstraintF: PrimeField,
{
    type InputVar = [UInt8<ConstraintF>];
    type OutputVar = DigestVar<ConstraintF>;
    type ParametersVar = UnitVar<ConstraintF>;

    #[tracing::instrument(target = "r1cs", skip(_parameters))]
    fn evaluate(
        _parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        Self::digest(input)
    }
}

impl<ConstraintF> TwoToOneCRHSchemeGadget<Sha384, ConstraintF> for Sha384Gadget<ConstraintF>
where
    ConstraintF: PrimeField,
{
    type InputVar = [UInt8<ConstraintF>];
    type OutputVar = DigestVar<ConstraintF>;
    type ParametersVar = UnitVar<ConstraintF>;

    #[tracing::instrument(target = "r1cs", skip(_parameters))]
    fn evaluate(
        _parameters: &Self::ParametersVar,
        left_input: &Self::InputVar,
        right_input: &Self::InputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        let mut h = Self::default();
        h.update(left_input)?;
        h.update(right_input)?;
        h.finalize()
    }

    #[tracing::instrument(target = "r1cs", skip(parameters))]
    fn compress(
        parameters: &Self::ParametersVar,
        left_input: &Self::OutputVar,
        right_input: &Self::OutputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        // Convert output to bytes
        let left_input = left_input.to_bytes()?;
        let right_input = right_input.to_bytes()?;
        <Self as TwoToOneCRHSchemeGadget<Sha384, ConstraintF>>::evaluate(
            parameters,
            &left_input,
            &right_input,
        )
    }
}

// All the tests below test against the RustCrypto sha2 implementation
#[cfg(test)]
mod test {
    use super::*;
    use crate::crh::{
        sha384::{digest::Digest, Sha384},
        CRHScheme, CRHSchemeGadget, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget,
    };

    use ark_bls12_377::Fr;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::{
        ns,
        r1cs::{ConstraintSystem, Namespace},
    };
    use ark_std::rand::RngCore;

    const TEST_LENGTHS: &[usize] = &[
        0, 1, 2, 4, 8, 16, 20, 40, 55, 56, 57, 63, 64, 65, 80, 90,
        100, 111, 112, 113, 127, 128, 129, 180, 200, 255, 256, 257,
    ];

    /// Witnesses bytes
    fn to_byte_vars(cs: impl Into<Namespace<Fr>>, data: &[u8]) -> Vec<UInt8<Fr>> {
        let cs = cs.into().cs();
        UInt8::new_witness_vec(cs, data).unwrap()
    }

    /// Finalizes a SHA384 gadget and gets the bytes
    fn finalize_var(sha384_var: Sha384Gadget<Fr>) -> Vec<u8> {
        sha384_var.finalize().unwrap().value().unwrap().to_vec()
    }

    /// Finalizes a native SHA384 struct and gets the bytes
    fn finalize(sha384: Sha384) -> Vec<u8> {
        sha384.finalize().to_vec()
    }

    /// Tests the SHA384 of random strings of varied lengths
    #[test]
    fn varied_lengths() {
        let mut rng = ark_std::test_rng();
        let cs = ConstraintSystem::<Fr>::new_ref();

        for &len in TEST_LENGTHS {
            let mut sha384 = Sha384::default();
            let mut sha384_var = Sha384Gadget::default();

            // Make a random string of the given length
            let mut input_str = vec![0u8; len];
            rng.fill_bytes(&mut input_str);

            // Compute the hashes and assert consistency
            sha384_var
                .update(&to_byte_vars(ns!(cs, "input"), &input_str))
                .unwrap();
            sha384.update(input_str);
            assert_eq!(
                finalize_var(sha384_var),
                finalize(sha384),
                "error at length {}",
                len
            );
        }
    }

    /// Calls `update()` many times
    #[test]
    fn many_updates() {
        let mut rng = ark_std::test_rng();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut sha384 = Sha384::default();
        let mut sha384_var = Sha384Gadget::default();

        // Append the same 7-byte string 20 times
        for _ in 0..20 {
            let mut input_str = vec![0u8; 7];
            rng.fill_bytes(&mut input_str);

            sha384_var
                .update(&to_byte_vars(ns!(cs, "input"), &input_str))
                .unwrap();
            sha384.update(input_str);
        }

        // Make sure the result is consistent
        assert_eq!(finalize_var(sha384_var), finalize(sha384));
    }

    /// Tests the CRHCheme trait
    #[test]
    fn crh() {
        let mut rng = ark_std::test_rng();
        let cs = ConstraintSystem::<Fr>::new_ref();

        // CRH parameters are nothing
        let unit = ();
        let unit_var = UnitVar::default();

        for &len in TEST_LENGTHS {
            // Make a random string of the given length
            let mut input_str = vec![0u8; len];
            rng.fill_bytes(&mut input_str);

            // Compute the hashes and assert consistency
            let computed_output = <Sha384Gadget<Fr> as CRHSchemeGadget<Sha384, Fr>>::evaluate(
                &unit_var,
                &to_byte_vars(ns!(cs, "input"), &input_str),
            )
            .unwrap();
            let expected_output = <Sha384 as CRHScheme>::evaluate(&unit, input_str).unwrap();
            assert_eq!(
                computed_output.value().unwrap().to_vec(),
                expected_output,
                "CRH error at length {}",
                len
            )
        }
    }

    /// Tests the TwoToOneCRHScheme trait
    #[test]
    fn to_to_one_crh() {
        let mut rng = ark_std::test_rng();
        let cs = ConstraintSystem::<Fr>::new_ref();

        // CRH parameters are nothing
        let unit = ();
        let unit_var = UnitVar::default();

        for &len in TEST_LENGTHS {
            // Make random strings of the given length
            let mut left_input = vec![0u8; len];
            let mut right_input = vec![0u8; len];
            rng.fill_bytes(&mut left_input);
            rng.fill_bytes(&mut right_input);

            // Compute the hashes and assert consistency
            let computed_output =
                <Sha384Gadget<Fr> as TwoToOneCRHSchemeGadget<Sha384, Fr>>::evaluate(
                    &unit_var,
                    &to_byte_vars(ns!(cs, "left input"), &left_input),
                    &to_byte_vars(ns!(cs, "right input"), &right_input),
                )
                .unwrap();
            let expected_output =
                <Sha384 as TwoToOneCRHScheme>::evaluate(&unit, left_input, right_input).unwrap();
            assert_eq!(
                computed_output.value().unwrap().to_vec(),
                expected_output,
                "TwoToOneCRH error at length {}",
                len
            )
        }
    }

    /// Tests the EqGadget impl of DigestVar
    #[test]
    fn digest_eq() {
        let mut rng = ark_std::test_rng();
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Make two distinct digests
        let mut digest1 = [0u8; 64];
        let mut digest2 = [0u8; 64];
        rng.fill_bytes(&mut digest1);
        rng.fill_bytes(&mut digest2);

        // Witness them
        let digest1_var = DigestVar::new_witness(cs.clone(), || Ok(digest1.to_vec())).unwrap();
        let digest2_var = DigestVar::new_witness(cs.clone(), || Ok(digest2.to_vec())).unwrap();

        // Assert that the distinct digests are distinct
        assert!(!digest1_var.is_eq(&digest2_var).unwrap().value().unwrap());

        // Now assert that a digest equals itself
        assert!(digest1_var.is_eq(&digest1_var).unwrap().value().unwrap());
    }
}
