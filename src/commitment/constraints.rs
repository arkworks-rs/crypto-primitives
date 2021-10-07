use crate::commitment::CommitmentScheme;
use ark_ff::Field;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::SynthesisError;
use core::fmt::Debug;

pub trait CommitmentWithGadget<ConstraintF: Field>: CommitmentScheme {
    type OutputVar: EqGadget<ConstraintF>
        + ToBytesGadget<ConstraintF>
        + AllocVar<Self::Output, ConstraintF>
        + R1CSVar<ConstraintF>
        + Clone
        + Sized
        + Debug;
    type ParametersVar: AllocVar<Self::Parameters, ConstraintF> + Clone;
    type RandomnessVar: AllocVar<Self::Randomness, ConstraintF> + Clone;

    fn commit_gadget(
        parameters: &Self::ParametersVar,
        input: &[UInt8<ConstraintF>],
        r: &Self::RandomnessVar,
    ) -> Result<Self::OutputVar, SynthesisError>;
}

pub trait CommitmentGadget<ConstraintF: Field> {
    type Native: CommitmentWithGadget<
        ConstraintF,
        OutputVar = Self::OutputVar,
        ParametersVar = Self::ParametersVar,
        RandomnessVar = Self::RandomnessVar,
    >;
    type OutputVar: EqGadget<ConstraintF>
        + ToBytesGadget<ConstraintF>
        + AllocVar<<Self::Native as CommitmentScheme>::Output, ConstraintF>
        + R1CSVar<ConstraintF>
        + Clone
        + Sized
        + Debug;
    type ParametersVar: AllocVar<<Self::Native as CommitmentScheme>::Parameters, ConstraintF>
        + Clone;
    type RandomnessVar: AllocVar<<Self::Native as CommitmentScheme>::Randomness, ConstraintF>
        + Clone;

    fn commit(
        parameters: &Self::ParametersVar,
        input: &[UInt8<ConstraintF>],
        r: &Self::RandomnessVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        Self::Native::commit_gadget(parameters, input, r)
    }
}

impl<C, ConstraintF> CommitmentGadget<ConstraintF> for crate::Gadget<C>
where
    C: CommitmentWithGadget<ConstraintF>,
    ConstraintF: Field,
{
    type Native = C;
    type OutputVar = C::OutputVar;
    type ParametersVar = C::ParametersVar;
    type RandomnessVar = C::RandomnessVar;
}
