use ark_std::borrow::Borrow;

use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

pub mod poseidon;

/// R1CS Gadget for Crypto Hash.
pub trait CryptoHashGadget<CF: PrimeField> {
    type Parameters;
    /// Input of the hash
    type InputVar: ?Sized;
    /// Outout of the Hash
    type OutputVar;

    /// Given the input var and parameters, compute the output var.
    fn digest<T: Borrow<Self::InputVar>>(
        cs: ConstraintSystemRef<CF>,
        param: &Self::Parameters,
        input: T,
    ) -> Result<Self::OutputVar, SynthesisError>;
}
