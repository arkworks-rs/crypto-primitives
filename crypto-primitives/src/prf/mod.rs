#![allow(clippy::upper_case_acronyms)]
use crate::Error;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{fmt::Debug, hash::Hash};

#[cfg(feature = "r1cs")]
pub mod constraints;
#[cfg(feature = "r1cs")]
pub use constraints::*;

pub mod blake2s;
pub use self::blake2s::*;

pub trait PRF {
    type Input: CanonicalDeserialize + Default;
    type Output: CanonicalSerialize + Eq + Clone + Debug + Default + Hash;
    type Seed: CanonicalDeserialize + CanonicalSerialize + Clone + Default + Debug;

    fn evaluate(seed: &Self::Seed, input: &Self::Input) -> Result<Self::Output, Error>;
}
