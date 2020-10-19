use ark_ff::bytes::ToBytes;
use rand::Rng;

#[cfg(feature = "r1cs")]
pub mod constraints;
#[cfg(feature = "r1cs")]
pub use constraints::*;

use crate::Error;

pub trait NIZK {
    type Circuit;
    type AssignedCircuit;
    type VerifierInput: ?Sized;
    type ProvingParameters: Clone;
    type VerificationParameters: Clone + Default + From<Self::PreparedVerificationParameters>;
    type PreparedVerificationParameters: Clone + Default + From<Self::VerificationParameters>;
    type Proof: ToBytes + Clone + Default;

    fn setup<R: Rng>(
        circuit: Self::Circuit,
        rng: &mut R,
    ) -> Result<
        (
            Self::ProvingParameters,
            Self::PreparedVerificationParameters,
        ),
        Error,
    >;

    fn prove<R: Rng>(
        parameter: &Self::ProvingParameters,
        input_and_witness: Self::AssignedCircuit,
        rng: &mut R,
    ) -> Result<Self::Proof, Error>;

    fn verify(
        verifier_key: &Self::PreparedVerificationParameters,
        input: &Self::VerifierInput,
        proof: &Self::Proof,
    ) -> Result<bool, Error>;
}
