use ark_ff::Field;
use core::fmt::Debug;

use crate::crh::{TwoToOneCRH, CRH};
use ark_relations::r1cs::SynthesisError;

use ark_r1cs_std::prelude::*;

pub trait CRHGadget<H: CRH, ConstraintF: Field>: Sized
{
    type InputVar;
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

pub trait TwoToOneCRHGadget<H: TwoToOneCRH, ConstraintF: Field>: Sized
{
    type InputVar;
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
}

pub trait CompressibleTwoToOneCRHGadget<H: TwoToOneCRH, ConstraintF: Field>: TwoToOneCRHGadget<H, ConstraintF>{
    fn compress(
        parameters: &Self::ParametersVar,
        left_input: &Self::OutputVar,
        right_input: &Self::OutputVar,
    ) -> Result<Self::OutputVar, SynthesisError>;
}
