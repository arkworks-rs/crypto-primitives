use core::{fmt::Debug, marker::PhantomData};

use crate::crh::{
    constraints,
    injective_map::{InjectiveMap, PedersenCRHCompressor, TECompressor},
    pedersen::{constraints as ped_constraints, Window},
};

use ark_ec::{
    models::{ModelParameters, TEModelParameters},
    twisted_edwards_extended::GroupProjective as TEProjective,
    ProjectiveCurve,
};
use ark_ff::fields::{Field, PrimeField, SquareRootField};
use ark_r1cs_std::{
    fields::fp::FpVar,
    groups::{curves::twisted_edwards::AffineVar as TEVar, CurveVar},
    prelude::*,
};
use ark_relations::r1cs::SynthesisError;

type ConstraintF<C> = <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField;

pub trait InjectiveMapGadget<
    C: ProjectiveCurve,
    I: InjectiveMap<C>,
    GG: CurveVar<C, ConstraintF<C>>,
> where
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    type OutputVar: EqGadget<ConstraintF<C>>
        + ToBytesGadget<ConstraintF<C>>
        + CondSelectGadget<ConstraintF<C>>
        + AllocVar<I::Output, ConstraintF<C>>
        + R1CSVar<ConstraintF<C>, Value = I::Output>
        + Debug
        + Clone
        + Sized;

    fn evaluate(ge: &GG) -> Result<Self::OutputVar, SynthesisError>;
}

pub struct TECompressorGadget;

impl<F, P> InjectiveMapGadget<TEProjective<P>, TECompressor, TEVar<P, FpVar<F>>>
    for TECompressorGadget
where
    F: PrimeField + SquareRootField,
    P: TEModelParameters + ModelParameters<BaseField = F>,
{
    type OutputVar = FpVar<F>;

    fn evaluate(ge: &TEVar<P, FpVar<F>>) -> Result<Self::OutputVar, SynthesisError> {
        Ok(ge.x.clone())
    }
}

pub struct PedersenCRHCompressorGadget<C, I, W, GG, IG>
where
    C: ProjectiveCurve,
    I: InjectiveMap<C>,
    W: Window,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
    IG: InjectiveMapGadget<C, I, GG>,
{
    #[doc(hidden)]
    _compressor: PhantomData<I>,
    #[doc(hidden)]
    _compressor_gadget: PhantomData<IG>,
    #[doc(hidden)]
    _crh: ped_constraints::CRHGadget<C, GG, W>,
}

impl<C, I, GG, IG, W> constraints::CRHGadget<PedersenCRHCompressor<C, I, W>, ConstraintF<C>>
    for PedersenCRHCompressorGadget<C, I, W, GG, IG>
where
    C: ProjectiveCurve,
    I: InjectiveMap<C>,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
    IG: InjectiveMapGadget<C, I, GG>,
    W: Window,
{
    type OutputVar = IG::OutputVar;
    type ParametersVar = ped_constraints::CRHParametersVar<C, GG>;

    #[tracing::instrument(target = "r1cs", skip(parameters, input))]
    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &[UInt8<ConstraintF<C>>],
    ) -> Result<Self::OutputVar, SynthesisError> {
        let result = ped_constraints::CRHGadget::<C, GG, W>::evaluate(parameters, input)?;
        IG::evaluate(&result)
    }
}

impl<C, I, GG, IG, W> constraints::TwoToOneCRHGadget<PedersenCRHCompressor<C, I, W>, ConstraintF<C>>
    for PedersenCRHCompressorGadget<C, I, W, GG, IG>
where
    C: ProjectiveCurve,
    I: InjectiveMap<C>,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
    IG: InjectiveMapGadget<C, I, GG>,
    W: Window,
{
    type OutputVar = IG::OutputVar;
    type ParametersVar = ped_constraints::CRHParametersVar<C, GG>;

    #[tracing::instrument(target = "r1cs", skip(parameters))]
    fn evaluate(
        parameters: &Self::ParametersVar,
        left_input: &[UInt8<ConstraintF<C>>],
        right_input: &[UInt8<ConstraintF<C>>],
    ) -> Result<Self::OutputVar, SynthesisError> {
        // assume equality of left and right length
        assert_eq!(left_input.len(), right_input.len());
        let result =
            ped_constraints::CRHGadget::<C, GG, W>::evaluate(parameters, left_input, right_input)?;
        IG::evaluate(&result)
    }
}
