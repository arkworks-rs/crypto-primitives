use crate::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    Error,
};
#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;
use ark_std::{borrow::Borrow, rand::Rng};
use sha2::digest::Digest;

// Re-export the RustCrypto Sha256 type and its associated traits
pub use sha2::{digest, Sha256};

#[cfg(feature = "r1cs")]
pub mod constraints;

// Implement the CRH traits for SHA-256
impl CRHScheme for Sha256 {
    type Input = [u8];
    // This is always 32 bytes. It has to be a Vec to impl CanonicalSerialize
    type Output = Vec<u8>;
    // There are no parameters for SHA256
    type Parameters = ();

    // There are no parameters for SHA256
    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    // Evaluates SHA256(input)
    fn evaluate<T: Borrow<Self::Input>>(
        _parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        Ok(Sha256::digest(input.borrow()).to_vec())
    }
}

impl TwoToOneCRHScheme for Sha256 {
    type Input = [u8];
    // This is always 32 bytes. It has to be a Vec to impl CanonicalSerialize
    type Output = Vec<u8>;
    // There are no parameters for SHA256
    type Parameters = ();

    // There are no parameters for SHA256
    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    // Evaluates SHA256(left_input || right_input)
    fn evaluate<T: Borrow<Self::Input>>(
        _parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error> {
        let left_input = left_input.borrow();
        let right_input = right_input.borrow();

        // Process the left input then the right input
        let mut h = Sha256::default();
        h.update(left_input);
        h.update(right_input);
        Ok(h.finalize().to_vec())
    }

    // Evaluates SHA256(left_input || right_input)
    fn compress<T: Borrow<Self::Output>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error> {
        <Self as TwoToOneCRHScheme>::evaluate(
            parameters,
            left_input.borrow().as_slice(),
            right_input.borrow().as_slice(),
        )
    }
}
