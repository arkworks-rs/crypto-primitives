use ark_ff::Field;
use ark_relations::r1cs::SynthesisError;
use ark_r1cs_std::prelude::*;

use crate::signature::SignatureScheme;

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
