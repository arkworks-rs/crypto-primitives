use ark_ff::Field;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::SynthesisError;

use crate::{signature::SignatureScheme, Gadget};

pub trait SigVerifyWithGadget<ConstraintF: Field>: SignatureScheme {
    type ParametersVar: AllocVar<Self::Parameters, ConstraintF> + Clone;

    type PublicKeyVar: ToBytesGadget<ConstraintF> + AllocVar<Self::PublicKey, ConstraintF> + Clone;

    type SignatureVar: ToBytesGadget<ConstraintF> + AllocVar<Self::Signature, ConstraintF> + Clone;

    fn verify_gadget(
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        // TODO: Should we make this take in bytes or something different?
        message: &[UInt8<ConstraintF>],
        signature: &Self::SignatureVar,
    ) -> Result<Boolean<ConstraintF>, SynthesisError>;
}

pub trait SigVerifyGadget<ConstraintF: Field> {
    type Native: SigVerifyWithGadget<
        ConstraintF,
        ParametersVar = Self::ParametersVar,
        PublicKeyVar = Self::PublicKeyVar,
        SignatureVar = Self::SignatureVar,
    >;
    type ParametersVar: AllocVar<<Self::Native as SignatureScheme>::Parameters, ConstraintF> + Clone;

    type PublicKeyVar: ToBytesGadget<ConstraintF>
        + AllocVar<<Self::Native as SignatureScheme>::PublicKey, ConstraintF>
        + Clone;

    type SignatureVar: ToBytesGadget<ConstraintF>
        + AllocVar<<Self::Native as SignatureScheme>::Signature, ConstraintF>
        + Clone;

    fn verify(
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        // TODO: Should we make this take in bytes or something different?
        message: &[UInt8<ConstraintF>],
        signature: &Self::SignatureVar,
    ) -> Result<Boolean<ConstraintF>, SynthesisError> {
        Self::Native::verify_gadget(parameters, public_key, message, signature)
    }
}

impl<S, ConstraintF> SigVerifyGadget<ConstraintF> for Gadget<S>
where
    S: SigVerifyWithGadget<ConstraintF>,
    ConstraintF: Field,
{
    type Native = S;
    type ParametersVar = S::ParametersVar;
    type PublicKeyVar = S::PublicKeyVar;
    type SignatureVar = S::SignatureVar;
}

pub trait SigRandomizePkGadget<S: SignatureScheme, ConstraintF: Field> {
    type ParametersVar: AllocVar<S::Parameters, ConstraintF> + Clone;

    type PublicKeyVar: ToBytesGadget<ConstraintF>
        + EqGadget<ConstraintF>
        + AllocVar<S::PublicKey, ConstraintF>
        + Clone;

    fn randomize(
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        randomness: &[UInt8<ConstraintF>],
    ) -> Result<Self::PublicKeyVar, SynthesisError>;
}
