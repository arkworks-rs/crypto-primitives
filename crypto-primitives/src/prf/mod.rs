#![allow(clippy::upper_case_acronyms)]
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use core::{fmt::Debug, hash::Hash};

use crate::Error;

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
