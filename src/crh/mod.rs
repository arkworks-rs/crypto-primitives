#![allow(clippy::upper_case_acronyms)]

use ark_ff::bytes::ToBytes;
use ark_std::hash::Hash;
use ark_std::rand::Rng;

pub mod bowe_hopwood;
pub mod injective_map;
pub mod pedersen;
pub mod poseidon;

use crate::Error;

#[cfg(feature = "r1cs")]
pub mod constraints;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
#[cfg(feature = "r1cs")]
pub use constraints::*;

/// Interface to CRH. Note that in this release, while all implementations of `CRH` have fixed length,
/// variable length CRH may also implement this trait in future.
pub trait CRH {
    const INPUT_SIZE_BITS: usize;

    type Output: ToBytes
        + Clone
        + Eq
        + core::fmt::Debug
        + Hash
        + Default
        + CanonicalSerialize
        + CanonicalDeserialize;
    type Parameters: Clone + Default;

    fn setup<R: Rng>(r: &mut R) -> Result<Self::Parameters, Error>;
    fn evaluate(parameters: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error>;
}

pub trait TwoToOneCRH {
    /// The bit size of the left input.
    const LEFT_INPUT_SIZE_BITS: usize;
    /// The bit size of the right input.
    const RIGHT_INPUT_SIZE_BITS: usize;

    type Output: ToBytes
        + Clone
        + Eq
        + core::fmt::Debug
        + Hash
        + Default
        + CanonicalSerialize
        + CanonicalDeserialize;
    type Parameters: Clone + Default;

    fn setup<R: Rng>(r: &mut R) -> Result<Self::Parameters, Error>;
    /// Evaluates this CRH on the left and right inputs.
    ///
    /// # Panics
    ///
    /// If `left_input.len() != Self::LEFT_INPUT_SIZE_BITS`, or if
    /// `right_input.len() != Self::RIGHT_INPUT_SIZE_BITS`, then this method panics.
    fn evaluate(
        parameters: &Self::Parameters,
        left_input: &[u8],
        right_input: &[u8],
    ) -> Result<Self::Output, Error>;
}
