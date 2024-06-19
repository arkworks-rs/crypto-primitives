use crate::{
    crh::{pedersen, CRHScheme, TwoToOneCRHScheme},
    Error,
};
use ark_ec::{
    twisted_edwards::{Affine as TEAffine, Projective as TEProjective, TECurveConfig},
    CurveConfig, CurveGroup,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;
use ark_std::{borrow::Borrow, fmt::Debug, hash::Hash, marker::PhantomData, rand::Rng};
#[cfg(feature = "r1cs")]
pub mod constraints;

pub trait InjectiveMap<C: CurveGroup> {
    type Output: Clone + Eq + Hash + Default + Debug + CanonicalSerialize + CanonicalDeserialize;

    fn injective_map(ge: &C::Affine) -> Result<Self::Output, Error>;
}

pub struct TECompressor;

impl<P: TECurveConfig> InjectiveMap<TEProjective<P>> for TECompressor {
    type Output = <P as CurveConfig>::BaseField;

    fn injective_map(ge: &TEAffine<P>) -> Result<Self::Output, Error> {
        debug_assert!(ge.is_in_correct_subgroup_assuming_on_curve());
        Ok(ge.x)
    }
}

pub struct PedersenCRHCompressor<C: CurveGroup, I: InjectiveMap<C>, W: pedersen::Window> {
    _group: PhantomData<C>,
    _compressor: PhantomData<I>,
    _window: PhantomData<W>,
}

impl<C: CurveGroup, I: InjectiveMap<C>, W: pedersen::Window> CRHScheme
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

pub struct PedersenTwoToOneCRHCompressor<C: CurveGroup, I: InjectiveMap<C>, W: pedersen::Window> {
    _group: PhantomData<C>,
    _compressor: PhantomData<I>,
    _window: PhantomData<W>,
}

impl<C: CurveGroup, I: InjectiveMap<C>, W: pedersen::Window> TwoToOneCRHScheme
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
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error> {
        let eval_time = start_timer!(|| "PedersenCRHCompressor::Eval");
        let result = I::injective_map(&pedersen::TwoToOneCRH::<C, W>::evaluate(
            parameters,
            left_input,
            right_input,
        )?)?;
        end_timer!(eval_time);
        Ok(result)
    }

    fn compress<T: Borrow<Self::Output>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error> {
        // convert output to input
        Self::evaluate(
            parameters,
            crate::to_uncompressed_bytes!(left_input)?,
            crate::to_uncompressed_bytes!(right_input)?,
        )
    }
}
