use crate::{Gadget, crh::{
    CRHGadget,
    TwoToOneCRHGadget,
    constraints,
    injective_map::{InjectiveMap, PedersenCRHCompressor, TECompressor},
    pedersen::{self, constraints as ped_constraints, Window},
}};
use core::fmt::Debug;

use crate::crh::injective_map::PedersenTwoToOneCRHCompressor;
use ark_ec::{
    models::TEModelParameters, twisted_edwards_extended::GroupProjective as TEProjective,
    ModelParameters, ProjectiveCurve,
};
use ark_ff::fields::{Field, PrimeField, SquareRootField};
use ark_r1cs_std::{groups::curves::twisted_edwards::AffineVar as TEVar, prelude::*};
use ark_relations::r1cs::SynthesisError;

type ConstraintF<C> = <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField;

pub trait InjectiveMapGadget<C: CurveWithVar<ConstraintF<C>>>: InjectiveMap<C> {
    type OutputVar: EqGadget<ConstraintF<C>>
        + ToBytesGadget<ConstraintF<C>>
        + CondSelectGadget<ConstraintF<C>>
        + AllocVar<Self::Output, ConstraintF<C>>
        + R1CSVar<ConstraintF<C>, Value = Self::Output>
        + Debug
        + Clone
        + Sized;

    fn evaluate(ge: &C::Var) -> Result<Self::OutputVar, SynthesisError>;
}

type BFVar<P> = <<P as ModelParameters>::BaseField as FieldWithVar>::Var;

impl<P> InjectiveMapGadget<TEProjective<P>> for TECompressor
where
    P: TEModelParameters,
    BFVar<P>:
        TwoBitLookupGadget<<P::BaseField as Field>::BasePrimeField, TableConstant = P::BaseField>,
    for<'a> &'a BFVar<P>: FieldOpsBounds<'a, P::BaseField, BFVar<P>>,
    P::BaseField: FieldWithVar + PrimeField + SquareRootField,
{
    type OutputVar = BFVar<P>;

    fn evaluate(ge: &TEVar<P>) -> Result<Self::OutputVar, SynthesisError> {
        Ok(ge.x.clone())
    }
}

impl<C, I, W> constraints::CRHWithGadget<ConstraintF<C>> for PedersenCRHCompressor<C, I, W>
where
    C: CurveWithVar<ConstraintF<C>>,
    for<'a> &'a C::Var: GroupOpsBounds<'a, C, C::Var>,
    I: InjectiveMapGadget<C>,
    W: Window,
{
    type InputVar = [UInt8<ConstraintF<C>>];

    type OutputVar = I::OutputVar;
    type ParametersVar = ped_constraints::CRHParametersVar<C>;

    #[tracing::instrument(target = "r1cs", skip(parameters, input))]
    fn evaluate_gadget(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        let result = Gadget::<pedersen::CRH<C, W>>::evaluate(parameters, input)?;
        I::evaluate(&result)
    }
}

impl<C, I, W> constraints::TwoToOneCRHWithGadget<ConstraintF<C>>
    for PedersenTwoToOneCRHCompressor<C, I, W>
where
    C: CurveWithVar<ConstraintF<C>>,
    I: InjectiveMapGadget<C>,
    for<'a> &'a C::Var: GroupOpsBounds<'a, C, C::Var>,
    W: Window,
{
    type InputVar = [UInt8<ConstraintF<C>>];

    type OutputVar = I::OutputVar;
    type ParametersVar = ped_constraints::CRHParametersVar<C>;

    #[tracing::instrument(target = "r1cs", skip(parameters))]
    fn evaluate_gadget(
        parameters: &Self::ParametersVar,
        left: &Self::InputVar,
        right: &Self::InputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        // assume equality of left and right length
        assert_eq!(left.len(), right.len());
        let result = Gadget::<pedersen::TwoToOneCRH<C, W>>::evaluate(parameters, left, right)?;
        I::evaluate(&result)
    }

    #[tracing::instrument(target = "r1cs", skip(parameters))]
    fn compress_gadget(
        parameters: &Self::ParametersVar,
        left: &Self::OutputVar,
        right: &Self::OutputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        let left= left.to_non_unique_bytes()?;
        let right= right.to_non_unique_bytes()?;
        Gadget::<Self>::evaluate(
            parameters,
            &left,
            &right,
        )
    }
}
