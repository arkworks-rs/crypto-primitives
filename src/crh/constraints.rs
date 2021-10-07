use ark_ff::Field;
use core::fmt::Debug;

use crate::{
    crh::{TwoToOneCRH, CRH},
    Gadget,
};
use ark_relations::r1cs::SynthesisError;

use ark_r1cs_std::prelude::*;

pub trait CRHWithGadget<ConstraintF: Field>: CRH {
    type InputVar: ?Sized;
    type OutputVar: EqGadget<ConstraintF>
        + ToBytesGadget<ConstraintF>
        + CondSelectGadget<ConstraintF>
        + AllocVar<Self::Output, ConstraintF>
        + R1CSVar<ConstraintF>
        + Debug
        + Clone
        + Sized;
    type ParametersVar: AllocVar<Self::Parameters, ConstraintF> + Clone;

    fn evaluate_gadget(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, SynthesisError>;
}

pub trait CRHGadget<ConstraintF: Field> {
    type Native: CRHWithGadget<
        ConstraintF,
        InputVar = Self::InputVar,
        OutputVar = Self::OutputVar,
        ParametersVar = Self::ParametersVar,
    >;
    type InputVar: ?Sized;
    type OutputVar: EqGadget<ConstraintF>
        + ToBytesGadget<ConstraintF>
        + CondSelectGadget<ConstraintF>
        + AllocVar<<Self::Native as CRH>::Output, ConstraintF>
        + R1CSVar<ConstraintF>
        + Debug
        + Clone
        + Sized;
    type ParametersVar: AllocVar<<Self::Native as CRH>::Parameters, ConstraintF> + Clone;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        Self::Native::evaluate_gadget(parameters, input)
    }
}

pub trait TwoToOneCRHWithGadget<ConstraintF: Field>: TwoToOneCRH {
    type InputVar: ?Sized;
    type OutputVar: EqGadget<ConstraintF>
        + ToBytesGadget<ConstraintF>
        + CondSelectGadget<ConstraintF>
        + AllocVar<Self::Output, ConstraintF>
        + R1CSVar<ConstraintF>
        + Debug
        + Clone
        + Sized;

    type ParametersVar: AllocVar<Self::Parameters, ConstraintF> + Clone;

    fn evaluate_gadget(
        parameters: &Self::ParametersVar,
        left: &Self::InputVar,
        right: &Self::InputVar,
    ) -> Result<Self::OutputVar, SynthesisError>;

    fn compress_gadget(
        parameters: &Self::ParametersVar,
        left: &Self::OutputVar,
        right: &Self::OutputVar,
    ) -> Result<Self::OutputVar, SynthesisError>;
}
pub trait TwoToOneCRHGadget<ConstraintF: Field> {
    type Native: TwoToOneCRHWithGadget<
        ConstraintF,
        InputVar = Self::InputVar,
        OutputVar = Self::OutputVar,
        ParametersVar = Self::ParametersVar,
    >;
    type InputVar: ?Sized;
    type OutputVar: EqGadget<ConstraintF>
        + ToBytesGadget<ConstraintF>
        + CondSelectGadget<ConstraintF>
        + AllocVar<<Self::Native as TwoToOneCRH>::Output, ConstraintF>
        + R1CSVar<ConstraintF>
        + Debug
        + Clone
        + Sized;

    type ParametersVar: AllocVar<<Self::Native as TwoToOneCRH>::Parameters, ConstraintF> + Clone;

    fn evaluate(
        parameters: &Self::ParametersVar,
        left: &Self::InputVar,
        right: &Self::InputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        Self::Native::evaluate_gadget(parameters, left, right)
    }

    fn compress(
        parameters: &Self::ParametersVar,
        left: &Self::OutputVar,
        right: &Self::OutputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        Self::Native::compress_gadget(parameters, left, right)
    }
}

impl<H, ConstraintF> CRHGadget<ConstraintF> for Gadget<H>
where
    H: CRHWithGadget<ConstraintF>,
    ConstraintF: Field,
{
    type Native = H;
    type InputVar = H::InputVar;
    type ParametersVar = H::ParametersVar;
    type OutputVar = H::OutputVar;
}

impl<H, ConstraintF> TwoToOneCRHGadget<ConstraintF> for Gadget<H>
where
    H: TwoToOneCRHWithGadget<ConstraintF>,
    ConstraintF: Field,
{
    type Native = H;
    type InputVar = H::InputVar;
    type ParametersVar = H::ParametersVar;
    type OutputVar = H::OutputVar;
}
