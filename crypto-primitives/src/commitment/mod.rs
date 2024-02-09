use ark_ff::UniformRand;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;
use ark_std::{fmt::Debug, hash::Hash};

pub mod blake2s;
pub mod injective_map;
pub mod pedersen;

#[cfg(feature = "r1cs")]
pub mod constraints;
#[cfg(feature = "r1cs")]
pub use constraints::*;

use crate::Error;

pub trait CommitmentScheme {
    type Output: CanonicalSerialize + Clone + Default + Eq + Hash + Debug;
    type Parameters: Clone;
    type Randomness: CanonicalSerialize + Clone + Default + Eq + UniformRand + Debug;

    fn setup<R: Rng>(r: &mut R) -> Result<Self::Parameters, Error>;

    fn commit(
        parameters: &Self::Parameters,
        input: &[u8],
        r: &Self::Randomness,
    ) -> Result<Self::Output, Error>;
}
