pub mod constraints;
pub mod poseidon;

use ark_std::borrow::Borrow;

use ark_std::rand::Rng;

use ark_std::vec::Vec;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Any cryptographic hash implementation will satisfy those two properties:
/// - **Preimage Resistance**: For all adversary, given y = H(x) where x is
///   random, the probability to find z such that H(z) = y is negligible.
/// - **Collision Resistant**: It's computationally infeasible to find two
///   distinct inputs to lead to same output. This property is also satisfied by
///   CRH trait implementors.
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

/// An extension trait for `CryptoHash`. Any implementation can be used for
/// proof of work.
///
/// A valid proof of work with difficulty `k` will have `H(M||Nonce)` that make
/// `verify(M, Nonce,  k)` output true. In most cases, `verify` outputs true
/// when the bit composition of output has `k` trailing zeroes, but this trait
/// allows implementation to implement their own `verify` logic.
pub trait PoW: CryptoHash {
    /// Nonce used with input, such that a valid proof of work for input `M` and
    /// difficulty `k` will have `H(M||Nonce)` that make `verify(M, Nonce,
    /// k)` output true. In most cases, `verify` outputs true when the bit
    /// composition of output has `k` trailing zeroes, but this trait allows
    /// implementation to implement their own `verify` logic.
    type Nonce: Clone + Sync;

    /// Given input and nonce, check whether `H(input||nonce)` is a valid proof
    /// of work under certain difficulty.
    fn verify(
        param: &Self::Parameters,
        input: &Self::Input,
        nonce: &Self::Nonce,
        difficulty: usize,
    ) -> bool;

    /// Given input and a list of nonces, batch verify the correctness of nonce
    /// under given difficulty.
    fn batch_verify(
        param: &Self::Parameters,
        input: &Self::Input,
        nonces: &[Self::Nonce],
        difficulty: usize,
    ) -> Vec<bool> {
        cfg_iter!(nonces)
            .map(|nonce| Self::verify(param, input, nonce, difficulty))
            .collect()
    }

    /// Return the initial nonce that can be used for PoW generation.
    fn initial_nonce<R: Rng>(param: &Self::Parameters, rng: &mut R) -> Self::Nonce;

    /// Return the next nonce for PoW Generation.
    fn next_nonce(param: &Self::Parameters, nonce: &Self::Nonce) -> Self::Nonce;

    /// Generate initial batch of nonces.
    fn batch_nonce(
        param: &Self::Parameters,
        initial_nonce: Self::Nonce,
        batch_size: usize,
    ) -> Vec<Self::Nonce> {
        let mut result = Vec::with_capacity(batch_size);
        result.push(initial_nonce);
        for _ in 0..batch_size - 1 {
            result.push(Self::next_nonce(param, result.last().unwrap()));
        }

        result
    }

    /// Generate the nonce as proof of work such that H(input||nonce) is valid
    /// under given difficulty.
    /// This function will repeatedly run `verify` on a batch of `nonces`, and
    /// return the first nonce that successfully let `verify` return true.
    ///
    /// This function return the first valid nonce and number of batches it has
    /// iterated.
    ///
    /// When `parallel` feature is on, for each batch, all nonces will be
    /// checked in parallel.
    fn generate_pow<R: Rng>(
        param: &Self::Parameters,
        rng: &mut R,
        input: &Self::Input,
        difficulty: usize,
        batch_size: usize,
    ) -> (Self::Nonce, usize) {
        let mut nonces = Self::batch_nonce(param, Self::initial_nonce(param, rng), batch_size);
        let mut counter = 0;
        loop {
            if let Some((i, _)) = Self::batch_verify(param, input, &nonces, difficulty)
                .into_iter()
                .enumerate()
                .filter(|(_, v)| *v)
                .next()
            {
                return (nonces[i].clone(), counter);
            };
            let last_nonce = nonces.last().unwrap().clone();
            nonces = Self::batch_nonce(param, Self::next_nonce(param, &last_nonce), batch_size);
            counter += 1;
        }
    }
}
