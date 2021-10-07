use crate::{CryptoError, Error};
use ark_ff::bytes::ToBytes;
use ark_std::rand::Rng;
use ark_std::{fmt::Debug, hash::Hash, marker::PhantomData};

use super::{pedersen, CRHScheme, TwoToOneCRHScheme};
use ark_ec::{
    models::{ModelParameters, TEModelParameters},
    twisted_edwards_extended::{GroupAffine as TEAffine, GroupProjective as TEProjective},
    ProjectiveCurve,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::borrow::Borrow;
use ark_std::vec::Vec;
#[cfg(feature = "r1cs")]
pub mod constraints;

pub trait InjectiveMap<C: ProjectiveCurve> {
    type Output: ToBytes
        + Clone
        + Eq
        + Hash
        + Default
        + Debug
        + CanonicalSerialize
        + CanonicalDeserialize;

    fn injective_map(ge: &C::Affine) -> Result<Self::Output, CryptoError>;
}

pub struct TECompressor;

impl<P: TEModelParameters> InjectiveMap<TEProjective<P>> for TECompressor {
    type Output = <P as ModelParameters>::BaseField;

    fn injective_map(ge: &TEAffine<P>) -> Result<Self::Output, CryptoError> {
        debug_assert!(ge.is_in_correct_subgroup_assuming_on_curve());
        Ok(ge.x)
    }
}

pub struct PedersenCRHCompressor<C: ProjectiveCurve, I: InjectiveMap<C>, W: pedersen::Window> {
    _group: PhantomData<C>,
    _compressor: PhantomData<I>,
    _window: PhantomData<W>,
}

impl<C: ProjectiveCurve, I: InjectiveMap<C>, W: pedersen::Window> CRHScheme
    for PedersenCRHCompressor<C, I, W>
{
    type Input = <pedersen::CRH<C, W> as CRHScheme>::Input;
    type Output = I::Output;
    type Parameters = pedersen::Parameters<C>;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error> {
        let time = start_timer!(|| format!("PedersenCRHCompressor::Setup"));
        let params = pedersen::CRH::<C, W>::setup(rng);
        end_timer!(time);
        params
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let eval_time = start_timer!(|| "PedersenCRHCompressor::Eval");
        let result = I::injective_map(&pedersen::CRH::<C, W>::evaluate(parameters, input)?)?;
        end_timer!(eval_time);
        Ok(result)
    }
}

pub struct PedersenTwoToOneCRHCompressor<
    C: ProjectiveCurve,
    I: InjectiveMap<C>,
    W: pedersen::Window,
> {
    _group: PhantomData<C>,
    _compressor: PhantomData<I>,
    _window: PhantomData<W>,
}

impl<C: ProjectiveCurve, I: InjectiveMap<C>, W: pedersen::Window> TwoToOneCRHScheme
    for PedersenTwoToOneCRHCompressor<C, I, W>
{
    type Input = <pedersen::TwoToOneCRH<C, W> as TwoToOneCRHScheme>::Input;
    type Output = I::Output;
    type Parameters = pedersen::Parameters<C>;

    fn setup<R: Rng>(r: &mut R) -> Result<Self::Parameters, Error> {
        pedersen::TwoToOneCRH::<C, W>::setup(r)
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        left: T,
        right: T,
    ) -> Result<Self::Output, Error> {
        let eval_time = start_timer!(|| "PedersenCRHCompressor::Eval");
        let result = I::injective_map(&pedersen::TwoToOneCRH::<C, W>::evaluate(
            parameters, left, right,
        )?)?;
        end_timer!(eval_time);
        Ok(result)
    }

    fn compress<T: Borrow<Self::Output>>(
        parameters: &Self::Parameters,
        left: T,
        right: T,
    ) -> Result<Self::Output, Error> {
        // convert output to input
        Self::evaluate(
            parameters,
            crate::to_unchecked_bytes!(left)?,
            crate::to_unchecked_bytes!(right)?,
        )
    }
}
