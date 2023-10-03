pub mod poseidon;

#[cfg(feature = "r1cs")]
pub mod constraints;

use ark_std::borrow::Borrow;

use ark_std::rand::Rng;

/// Any cryptographic hash implementation will satisfy those two properties:
/// - **Preimage Resistance**: For all adversary, given y = H(x) where x is
///   random, the probability to find z such that H(z) = y is negligible.
/// - **Collision Resistant**: It's computationally infeasible to find two
///   distinct inputs to lead to same output. This property is also satisfied by
///   CRH trait implementors.
/// - **One-way**:
pub trait CryptoHash {
    /// Parameter for the crypto hash.
    type Parameters: Sync;
    /// Input of the hash.
    type Input: Sync + ?Sized;
    /// Output of the Hash.
    type Output;
    /// Generate the parameter for the crypto hash using `rng`.
    fn setup<R: Rng>(rng: &mut R) -> &Self::Parameters;

    /// Given the input and parameters, compute the output.
    fn digest<T: Borrow<Self::Input>>(param: &Self::Parameters, input: T) -> Self::Output;
}
