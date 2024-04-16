#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;
use blake2::{Blake2s256 as B2s, Blake2sMac};
use digest::Digest;

use super::PRF;
use crate::Error;

#[cfg(feature = "r1cs")]
pub mod constraints;

#[derive(Clone)]
pub struct Blake2s;

impl PRF for Blake2s {
    type Input = [u8; 32];
    type Output = [u8; 32];
    type Seed = [u8; 32];

    fn evaluate(seed: &Self::Seed, input: &Self::Input) -> Result<Self::Output, Error> {
        let eval_time = start_timer!(|| "Blake2s::Eval");
        let mut h = B2s::new();
        h.update(seed.as_ref());
        h.update(input.as_ref());
        let mut result = [0u8; 32];
        result.copy_from_slice(&h.finalize());
        end_timer!(eval_time);
        Ok(result)
    }
}

#[derive(Clone)]
pub struct Blake2sWithParameterBlock {
    pub output_size: u8,
    pub key_size: u8,
    pub salt: [u8; 8],
    pub personalization: [u8; 8],
}

impl Blake2sWithParameterBlock {
    pub fn evaluate(&self, input: &[u8]) -> Vec<u8> {
        use digest::{typenum::U32, FixedOutput, Update};
        let eval_time = start_timer!(|| "Blake2sWithParameterBlock::Eval");
        let mut h =
            Blake2sMac::<U32>::new_with_salt_and_personal(&[], &self.salt, &self.personalization)
                .unwrap();
        h.update(input.as_ref());
        end_timer!(eval_time);
        h.finalize_fixed().into_iter().collect()
    }
}
