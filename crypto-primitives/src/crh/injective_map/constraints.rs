use crate::crh::{
    constraints,
    injective_map::{
        InjectiveMap, PedersenCRHCompressor, PedersenTwoToOneCRHCompressor, TECompressor,
    },
    pedersen::{constraints as ped_constraints, Window},
    CRHSchemeGadget, TwoToOneCRHSchemeGadget,
};
use ark_ec::{
    twisted_edwards::{Projective as TEProjective, TECurveConfig},
    CurveConfig, CurveGroup,
};
use ark_ff::fields::{Field, PrimeField};
use ark_r1cs_std::{
    fields::fp::FpVar, groups::curves::twisted_edwards::AffineVar as TEVar, prelude::*,
};
use ark_relations::r1cs::SynthesisError;
use ark_std::{fmt::Debug, marker::PhantomData};

type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

pub trait InjectiveMapGadget<C: CurveGroup, I: InjectiveMap<C>, GG: CurveVar<C, ConstraintF<C>>>
where
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
    F: PrimeField,
    P: TECurveConfig + CurveConfig<BaseField = F>,
{
    type OutputVar = FpVar<F>;

    fn evaluate(ge: &TEVar<P, FpVar<F>>) -> Result<Self::OutputVar, SynthesisError> {
        Ok(ge.x.clone())
    }
}

pub struct PedersenCRHCompressorGadget<C, I, W, GG, IG>
where
    C: CurveGroup,
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

impl<C, I, GG, IG, W> constraints::CRHSchemeGadget<PedersenCRHCompressor<C, I, W>, ConstraintF<C>>
    for PedersenCRHCompressorGadget<C, I, W, GG, IG>
where
    C: CurveGroup,
    I: InjectiveMap<C>,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
    IG: InjectiveMapGadget<C, I, GG>,
    W: Window,
{
    type InputVar = [UInt8<ConstraintF<C>>];

    type OutputVar = IG::OutputVar;
    type ParametersVar = ped_constraints::CRHParametersVar<C, GG>;

    #[tracing::instrument(target = "r1cs", skip(parameters, input))]
    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        let result = <ped_constraints::CRHGadget<C, GG, W> as CRHSchemeGadget<_, _>>::evaluate(
            parameters, input,
        )?;
        IG::evaluate(&result)
    }
}

pub struct PedersenTwoToOneCRHCompressorGadget<C, I, W, GG, IG>
where
    C: CurveGroup,
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

impl<C, I, GG, IG, W>
    constraints::TwoToOneCRHSchemeGadget<PedersenTwoToOneCRHCompressor<C, I, W>, ConstraintF<C>>
    for PedersenTwoToOneCRHCompressorGadget<C, I, W, GG, IG>
where
    C: CurveGroup,
    I: InjectiveMap<C>,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
    IG: InjectiveMapGadget<C, I, GG>,
    W: Window,
{
    type InputVar = [UInt8<ConstraintF<C>>];

    type OutputVar = IG::OutputVar;
    type ParametersVar = ped_constraints::CRHParametersVar<C, GG>;

    #[tracing::instrument(target = "r1cs", skip(parameters))]
    fn evaluate(
        parameters: &Self::ParametersVar,
        left_input: &Self::InputVar,
        right_input: &Self::InputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        // assume equality of left and right length
        assert_eq!(left_input.len(), right_input.len());
        let result = ped_constraints::TwoToOneCRHGadget::<C, GG, W>::evaluate(
            parameters,
            left_input,
            right_input,
        )?;
        IG::evaluate(&result)
    }

    fn compress(
        parameters: &Self::ParametersVar,
        left_input: &Self::OutputVar,
        right_input: &Self::OutputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        let left_input_bytes = left_input.to_non_unique_bytes_le()?;
        let right_input_bytes = right_input.to_non_unique_bytes_le()?;
        <Self as TwoToOneCRHSchemeGadget<_, _>>::evaluate(
            parameters,
            &left_input_bytes,
            &right_input_bytes,
        )
    }
}
