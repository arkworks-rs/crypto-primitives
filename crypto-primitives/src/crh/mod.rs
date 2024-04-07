#![allow(clippy::upper_case_acronyms)]

use ark_std::hash::Hash;
use ark_std::rand::Rng;
pub mod bowe_hopwood;
pub mod injective_map;
pub mod pedersen;
pub mod poseidon;
pub mod sha256;

use crate::Error;

#[cfg(feature = "r1cs")]
pub mod constraints;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::borrow::Borrow;
#[cfg(feature = "r1cs")]
pub use constraints::*;

/// Interface to CRH. Note that in this release, while all implementations of `CRH` have fixed length,
/// variable length CRH may also implement this trait in future.
pub trait CRHScheme {
    type Input: ?Sized + Send;
    type Output: Clone
        + Eq
        + core::fmt::Debug
        + Hash
        + Default
        + CanonicalSerialize
        + CanonicalDeserialize;
    type Parameters: Clone + CanonicalSerialize + CanonicalDeserialize + Sync;

    fn setup<R: Rng>(r: &mut R) -> Result<Self::Parameters, Error>;
    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error>;
}

/// CRH used by merkle tree inner hash. Merkle tree will convert leaf output to bytes first.
pub trait TwoToOneCRHScheme {
    /// Raw Input type of TwoToOneCRH
    type Input: ?Sized;
    /// Raw Output type of TwoToOneCRH
    type Output: Clone
        + Eq
        + core::fmt::Debug
        + Hash
        + Default
        + CanonicalSerialize
        + CanonicalDeserialize;
    type Parameters: Clone + CanonicalSerialize + CanonicalDeserialize + Sync;

    fn setup<R: Rng>(r: &mut R) -> Result<Self::Parameters, Error>;

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error>;

    fn compress<T: Borrow<Self::Output>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error>;
}
