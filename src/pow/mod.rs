use ark_std::rand::Rng;

/// Any cryptographic hash implementation will satisfy those two properties:
/// - **Preimage Resistance**: For all adversary, given y = H(x) where x is
///   random, the probability to find z such that H(z) = y is negligible.
/// - **Collision Resistant**: It's computationally infeasible to find two
///   distinct inputs to lead to same output. This property is also satisfied by
///   CRH trait implementors.
pub trait CryptoHash {
    /// Parameter for the crypto hash.
    type Parameters;
    /// Input of the hash.
    type Input;
    /// Output of the Hash.
    type Output;
    /// Generate the parameter for the crypto hash using `rng`.
    fn setup<R: Rng>(rng: &mut R) -> &Self::Parameters;

    /// Given the input and parameters, compute the output.
    fn digest(param: &Self::Parameters, input: &Self::Input) -> Self::Output;
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
    type Nonce;

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
    fn initial_nonce(param: &Self::Parameters) -> Self::Nonce;

    /// Return the next nonce for PoW Generation.
    fn next_nonce(param: &Self::Parameters, nonce: Self::Nonce) -> Self::Nonce;

    /// Generate initial batch of nonces.
    fn initial_nonce_batch(param: &Self::Parameters, batch_size: usize) -> Vec<Self::Nonce> {
        todo!()
    }

    /// Given the last element of previous batch, return the next nonce batch.
    fn next_nonce_batch(
        param: &Self::Parameters,
        prev_nonce: Self::Nonce,
        batch_size: usize,
    ) -> Vec<Self::Nonce> {
        todo!()
    }

    /// Generate the nonce as proof of work such that H(input||nonce) is valid
    /// under given difficulty.
    /// This function will run `verify` on a batch of `nonces` for iteration.
    fn generate_pow(
        param: &Self::Parameters,
        input: &Self::Input,
        difficulty: usize,
        batch_size: usize,
    ) -> Self::Nonce {
        todo!()
    }
}
