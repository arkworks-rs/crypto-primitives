use crate::crh::{CRHScheme, TwoToOneCRHScheme};
use crate::Error;

use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_std::rand::Rng;

// Re-export the RustCrypto Sha384 type and its associated traits
pub use sha2::{digest, Sha384};

#[cfg(feature = "r1cs")]
pub mod constraints;

// Implement the CRH traits for SHA-384

use core::borrow::Borrow;
use sha2::digest::Digest;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct Output(pub [u8; 48]);

impl Default for Output {
    fn default() -> Self {
        Self([0u8; 48])
    }
}

impl AsRef<[u8]> for Output {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<sha2::digest::Output<Sha384>> for Output {
    fn from(output: sha2::digest::Output<Sha384>) -> Self {
        Self(output.into())
    }
}

impl CRHScheme for Sha384 {
    type Input = [u8];
    // This is always 48 bytes. It has to be a Vec to impl CanonicalSerialize
    type Output = Output;
    // There are no parameters for SHA384
    type Parameters = ();

    // There are no parameters for SHA384
    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    // Evaluates SHA384(input)
    fn evaluate<T: Borrow<Self::Input>>(
        _parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        Ok(Sha384::digest(input.borrow()).into())
    }
}

impl TwoToOneCRHScheme for Sha384 {
    type Input = [u8];
    type Output = Output;
    // There are no parameters for SHA384
    type Parameters = ();

    // There are no parameters for SHA384
    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    // Evaluates SHA384(left_input || right_input)
    fn evaluate<T: Borrow<Self::Input>>(
        _parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error> {
        let left_input = left_input.borrow();
        let right_input = right_input.borrow();

        // Process the left input then the right input
        let mut h = Sha384::default();
        h.update(left_input);
        h.update(right_input);
        Ok(h.finalize().into())
    }

    // Evaluates SHA384(left_input || right_input)
    fn compress<T: Borrow<Self::Output>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error> {
        <Self as TwoToOneCRHScheme>::evaluate(
            parameters,
            left_input.borrow().0.as_slice(),
            right_input.borrow().0.as_slice(),
        )
    }
}
