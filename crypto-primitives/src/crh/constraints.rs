use crate::crh::{CRHScheme, TwoToOneCRHScheme};
use ark_ff::Field;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::SynthesisError;
use ark_std::fmt::Debug;

pub trait CRHSchemeGadget<H: CRHScheme, ConstraintF: Field>: Sized {
    type InputVar: ?Sized;
    type OutputVar: EqGadget<ConstraintF>
        + ToBytesGadget<ConstraintF>
        + CondSelectGadget<ConstraintF>
        + AllocVar<H::Output, ConstraintF>
        + R1CSVar<ConstraintF>
        + Debug
        + Clone
        + Sized;
    type ParametersVar: AllocVar<H::Parameters, ConstraintF> + Clone;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, SynthesisError>;
}

pub trait TwoToOneCRHSchemeGadget<H: TwoToOneCRHScheme, ConstraintF: Field>: Sized {
    type InputVar: ?Sized;
    type OutputVar: EqGadget<ConstraintF>
        + ToBytesGadget<ConstraintF>
        + CondSelectGadget<ConstraintF>
        + AllocVar<H::Output, ConstraintF>
        + R1CSVar<ConstraintF>
        + Debug
        + Clone
        + Sized;

    type ParametersVar: AllocVar<H::Parameters, ConstraintF> + Clone;

    fn evaluate(
        parameters: &Self::ParametersVar,
        left_input: &Self::InputVar,
        right_input: &Self::InputVar,
    ) -> Result<Self::OutputVar, SynthesisError>;

    fn compress(
        parameters: &Self::ParametersVar,
        left_input: &Self::OutputVar,
        right_input: &Self::OutputVar,
    ) -> Result<Self::OutputVar, SynthesisError>;
}
