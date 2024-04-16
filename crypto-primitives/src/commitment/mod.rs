use crate::Error;
use ark_ff::UniformRand;
use ark_serialize::CanonicalSerialize;
use ark_std::{fmt::Debug, hash::Hash, rand::Rng};

pub mod blake2s;
pub mod injective_map;
pub mod pedersen;

#[cfg(feature = "r1cs")]
pub mod constraints;
#[cfg(feature = "r1cs")]
pub use constraints::*;

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
