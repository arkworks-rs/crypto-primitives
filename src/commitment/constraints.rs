use crate::commitment::CommitmentScheme;
use ark_ff::Field;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::SynthesisError;
use core::fmt::Debug;

pub trait CommitmentGadget<ConstraintF: Field>: CommitmentScheme {
    type OutputVar: EqGadget<ConstraintF>
        + ToBytesGadget<ConstraintF>
        + AllocVar<Self::Output, ConstraintF>
        + R1CSVar<ConstraintF>
        + Clone
        + Sized
        + Debug;
    type ParametersVar: AllocVar<Self::Parameters, ConstraintF> + Clone;
    type RandomnessVar: AllocVar<Self::Randomness, ConstraintF> + Clone;

    fn commit(
        parameters: &Self::ParametersVar,
        input: &[UInt8<ConstraintF>],
        r: &Self::RandomnessVar,
    ) -> Result<Self::OutputVar, SynthesisError>;
}
