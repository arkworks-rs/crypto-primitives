use ark_ff::bytes::ToBytes;
use ark_std::hash::Hash;
use ark_std::rand::Rng;

pub mod bowe_hopwood;
pub mod injective_map;
pub mod pedersen;

use crate::Error;

#[cfg(feature = "r1cs")]
pub mod constraints;
#[cfg(feature = "r1cs")]
pub use constraints::*;

pub trait CRH {
    const INPUT_SIZE_BITS: usize;

    type Output: ToBytes + Clone + Eq + core::fmt::Debug + Hash + Default;
    type Parameters: Clone + Default;

    fn setup<R: Rng>(r: &mut R) -> Result<Self::Parameters, Error>;
    fn evaluate(parameters: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error>;
}

pub trait TwoToOneCRH {
    /// The size for length input and right input
    const INPUT_SIZE_BITS: usize;

    type Output: ToBytes + Clone + Eq + core::fmt::Debug + Hash + Default;
    type Parameters: Clone + Default;

    fn setup<R: Rng>(r: &mut R) -> Result<Self::Parameters, Error>;
    fn evaluate(
        parameters: &Self::Parameters,
        left_input: &[u8],
        right_input: &[u8],
    ) -> Result<Self::Output, Error>;
}
