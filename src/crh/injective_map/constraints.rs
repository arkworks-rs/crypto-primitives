use crate::crh::{
    constraints,
    injective_map::{InjectiveMap, PedersenCRHCompressor, TECompressor},
    pedersen::{self, constraints as ped_constraints, Window},
    TwoToOneCRHSchemeGadget,
};
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

impl<C, I, W> constraints::CRHSchemeGadget<ConstraintF<C>> for PedersenCRHCompressor<C, I, W>
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
    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        let result = pedersen::CRH::<C, W>::evaluate(parameters, input)?;
        I::evaluate(&result)
    }
}

impl<C, I, W> constraints::TwoToOneCRHSchemeGadget<ConstraintF<C>>
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
    fn evaluate(
        parameters: &Self::ParametersVar,
        left_input: &Self::InputVar,
        right_input: &Self::InputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        // assume equality of left and right length
        assert_eq!(left_input.len(), right_input.len());
        let result = pedersen::TwoToOneCRH::<C, W>::evaluate(parameters, left_input, right_input)?;
        I::evaluate(&result)
    }

    fn compress(
        parameters: &Self::ParametersVar,
        left_input: &Self::OutputVar,
        right_input: &Self::OutputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        let left_input_bytes = left_input.to_non_unique_bytes()?;
        let right_input_bytes = right_input.to_non_unique_bytes()?;
        <Self as TwoToOneCRHSchemeGadget<_>>::evaluate(
            parameters,
            &left_input_bytes,
            &right_input_bytes,
        )
    }
}
