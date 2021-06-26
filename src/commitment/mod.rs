use ark_ff::UniformRand;
use ark_std::rand::Rng;
use ark_std::{fmt::Debug, hash::Hash};

use ark_ff::bytes::ToBytes;

// TODO: uncomment those after refactoring
pub mod blake2s;
// pub mod injective_map;
pub mod pedersen;

#[cfg(feature = "r1cs")]
pub mod constraints;
#[cfg(feature = "r1cs")]
pub use constraints::*;

use crate::Error;

pub trait CommitmentScheme {
    type Output: ToBytes + Clone + Default + Eq + Hash + Debug;
    type Parameters: Clone;
    type Randomness: Clone + ToBytes + Default + Eq + UniformRand + Debug;

    fn setup<R: Rng>(r: &mut R) -> Result<Self::Parameters, Error>;

    fn commit(
        parameters: &Self::Parameters,
        input: &[u8],
        r: &Self::Randomness,
    ) -> Result<Self::Output, Error>;
}
