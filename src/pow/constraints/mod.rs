pub mod poseidon;

use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, boolean::Boolean};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::borrow::Borrow;

use super::{CryptoHash, PoW};

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

/// R1CS Gadget for Proof of Work
pub trait PoWGadget<CF: PrimeField>: CryptoHashGadget<CF> {
    type NonceVar;
    /// Given input var and nonce var, check whether `H(input||nonce)` is a
    /// valid proof of work under certain difficulty.
    fn verify(
        cs: ConstraintSystemRef<CF>,
        param: &Self::Parameters,
        input: &Self::InputVar,
        nonce: &Self::NonceVar,
        difficulty: usize,
    ) -> Result<Boolean<CF>, SynthesisError>;
}

/// Extension trait for crypto hash to get the gadget.
pub trait CryptoHashWithGadget<CF: PrimeField>: CryptoHash
where
    <Self::Gadget as CryptoHashGadget<CF>>::OutputVar: AllocVar<Self::Output, CF>,
{
    type Gadget: CryptoHashGadget<CF, Parameters = Self::Parameters>;
}

/// Extension trait for PoW to get the gadget.
pub trait PoWWithGadget<CF: PrimeField>: PoW
where
    <Self::Gadget as CryptoHashGadget<CF>>::OutputVar: AllocVar<Self::Output, CF>,
{
    type Gadget: PoWGadget<CF, Parameters = Self::Parameters>;
}
