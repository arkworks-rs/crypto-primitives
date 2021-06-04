use crate::{CryptoError, Error};
use ark_ff::bytes::ToBytes;
use ark_std::rand::Rng;
use ark_std::{fmt::Debug, hash::Hash, marker::PhantomData};

use super::{pedersen, TwoToOneCRH, CRH};
use ark_ec::{
    models::{ModelParameters, TEModelParameters},
    twisted_edwards_extended::{GroupAffine as TEAffine, GroupProjective as TEProjective},
    ProjectiveCurve,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

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
    _crh: pedersen::CRH<C, W>,
}

impl<C: ProjectiveCurve, I: InjectiveMap<C>, W: pedersen::Window> CRH
    for PedersenCRHCompressor<C, I, W>
{
    const INPUT_SIZE_BITS: usize = pedersen::CRH::<C, W>::INPUT_SIZE_BITS;
    type Output = I::Output;
    type Parameters = pedersen::Parameters<C>;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error> {
        let time = start_timer!(|| format!("PedersenCRHCompressor::Setup"));
        let params = <pedersen::CRH<C, W> as CRH>::setup(rng);
        end_timer!(time);
        params
    }

    fn evaluate(parameters: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error> {
        let eval_time = start_timer!(|| "PedersenCRHCompressor::Eval");
        let result = I::injective_map(&<pedersen::CRH<C, W> as CRH>::evaluate(parameters, input)?)?;
        end_timer!(eval_time);
        Ok(result)
    }
}

impl<C: ProjectiveCurve, I: InjectiveMap<C>, W: pedersen::Window> TwoToOneCRH
    for PedersenCRHCompressor<C, I, W>
{
    const LEFT_INPUT_SIZE_BITS: usize = pedersen::CRH::<C, W>::LEFT_INPUT_SIZE_BITS;
    const RIGHT_INPUT_SIZE_BITS: usize = pedersen::CRH::<C, W>::RIGHT_INPUT_SIZE_BITS;
    type Output = I::Output;
    type Parameters = pedersen::Parameters<C>;

    fn setup<R: Rng>(r: &mut R) -> Result<Self::Parameters, Error> {
        <pedersen::CRH<C, W> as TwoToOneCRH>::setup(r)
    }

    /// A simple implementation method: just concat the left input and right input together
    ///
    /// `evaluate` requires that `left_input` and `right_input` are of equal length.
    fn evaluate(
        parameters: &Self::Parameters,
        left_input: &[u8],
        right_input: &[u8],
    ) -> Result<Self::Output, Error> {
        let eval_time = start_timer!(|| "PedersenCRHCompressor::Eval");
        let result = I::injective_map(&<pedersen::CRH<C, W> as TwoToOneCRH>::evaluate(
            parameters,
            left_input,
            right_input,
        )?)?;
        end_timer!(eval_time);
        Ok(result)
    }
}
