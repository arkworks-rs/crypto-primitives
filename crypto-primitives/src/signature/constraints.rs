use ark_ff::Field;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::SynthesisError;

use crate::signature::SignatureScheme;

pub trait SigVerifyGadget<S: SignatureScheme, ConstraintF: Field> {
    type ParametersVar: AllocVar<S::Parameters, ConstraintF> + Clone;

    type PublicKeyVar: ToBytesGadget<ConstraintF> + AllocVar<S::PublicKey, ConstraintF> + Clone;

    type SignatureVar: ToBytesGadget<ConstraintF> + AllocVar<S::Signature, ConstraintF> + Clone;

    fn verify(
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        // TODO: Should we make this take in bytes or something different?
        message: &[UInt8<ConstraintF>],
        signature: &Self::SignatureVar,
    ) -> Result<Boolean<ConstraintF>, SynthesisError>;
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
