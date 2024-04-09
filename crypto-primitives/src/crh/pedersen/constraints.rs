use crate::crh::{
    pedersen::{Parameters, Window},
    CRHSchemeGadget as CRHGadgetTrait,
};
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{Namespace, SynthesisError};
#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;

use crate::crh::pedersen::{TwoToOneCRH, CRH};
use crate::crh::{CRHSchemeGadget, TwoToOneCRHSchemeGadget};
use core::{borrow::Borrow, iter, marker::PhantomData};

#[derive(Derivative)]
#[derivative(Clone(bound = "C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>"))]
pub struct CRHParametersVar<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    params: Parameters<C>,
    #[doc(hidden)]
    _group_g: PhantomData<GG>,
}

type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;
pub struct CRHGadget<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>, W: Window>
where
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    #[doc(hidden)]
    _group: PhantomData<*const C>,
    #[doc(hidden)]
    _group_var: PhantomData<*const GG>,
    #[doc(hidden)]
    _window: PhantomData<*const W>,
}

impl<C, GG, W> CRHSchemeGadget<CRH<C, W>, ConstraintF<C>> for CRHGadget<C, GG, W>
where
    C: CurveGroup,
    GG: CurveVar<C, ConstraintF<C>>,
    W: Window,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    type InputVar = [UInt8<ConstraintF<C>>];
    type OutputVar = GG;
    type ParametersVar = CRHParametersVar<C, GG>;

    #[tracing::instrument(target = "r1cs", skip(parameters, input))]
    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        assert!((input.len() * 8) <= (W::WINDOW_SIZE * W::NUM_WINDOWS));

        // Convert input bytes to little-endian bits
        let mut input_in_bits: Vec<Boolean<_>> = input
            .iter()
            .flat_map(|byte| byte.to_bits_le().unwrap())
            .collect();

        // Pad input to `W::WINDOW_SIZE * W::NUM_WINDOWS`.
        let padding_size = (W::WINDOW_SIZE * W::NUM_WINDOWS) - input_in_bits.len();
        input_in_bits.extend(iter::repeat(Boolean::FALSE).take(padding_size));

        // Sanity checks
        assert_eq!(input_in_bits.len(), W::WINDOW_SIZE * W::NUM_WINDOWS);
        assert_eq!(parameters.params.generators.len(), W::NUM_WINDOWS);

        // Compute the Pedersen CRH. Chunk the input bits into correctly sized windows
        let input_in_bits = input_in_bits.chunks(W::WINDOW_SIZE);

        let result =
            GG::precomputed_base_multiscalar_mul_le(&parameters.params.generators, input_in_bits)?;

        Ok(result)
    }
}

pub struct TwoToOneCRHGadget<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>, W: Window>
where
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    #[doc(hidden)]
    _group: PhantomData<*const C>,
    #[doc(hidden)]
    _group_var: PhantomData<*const GG>,
    #[doc(hidden)]
    _window: PhantomData<*const W>,
}

impl<C, GG, W> TwoToOneCRHSchemeGadget<TwoToOneCRH<C, W>, ConstraintF<C>>
    for TwoToOneCRHGadget<C, GG, W>
where
    C: CurveGroup,
    GG: CurveVar<C, ConstraintF<C>>,
    W: Window,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    type InputVar = [UInt8<ConstraintF<C>>];
    type OutputVar = GG;
    type ParametersVar = CRHParametersVar<C, GG>;

    #[tracing::instrument(target = "r1cs", skip(parameters))]
    fn evaluate(
        parameters: &Self::ParametersVar,
        left_input: &Self::InputVar,
        right_input: &Self::InputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        // assume equality of left and right length
        assert_eq!(left_input.len(), right_input.len());
        let chained_input: Vec<_> = left_input
            .to_vec()
            .into_iter()
            .chain(right_input.to_vec().into_iter())
            .collect();
        CRHGadget::<C, GG, W>::evaluate(parameters, &chained_input)
    }

    #[tracing::instrument(target = "r1cs", skip(parameters))]
    fn compress(
        parameters: &Self::ParametersVar,
        left_input: &Self::OutputVar,
        right_input: &Self::OutputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        // convert output to bytes
        let left_input = left_input.to_bytes_le()?;
        let right_input = right_input.to_bytes_le()?;
        Self::evaluate(parameters, &left_input, &right_input)
    }
}

impl<C, GG> AllocVar<Parameters<C>, ConstraintF<C>> for CRHParametersVar<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    #[tracing::instrument(target = "r1cs", skip(_cs, f))]
    fn new_variable<T: Borrow<Parameters<C>>>(
        _cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let params = f()?.borrow().clone();
        Ok(CRHParametersVar {
            params,
            _group_g: PhantomData,
        })
    }
}

#[cfg(test)]
mod test {
    use crate::crh::{
        pedersen, CRHScheme, CRHSchemeGadget, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget,
    };
    use ark_ec::CurveGroup;
    use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective as JubJub, Fq as Fr};
    use ark_r1cs_std::prelude::*;
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
    use ark_std::rand::Rng;
    use ark_std::{test_rng, UniformRand};

    type TestCRH = pedersen::CRH<JubJub, Window>;
    type TestCRHGadget = pedersen::constraints::CRHGadget<JubJub, EdwardsVar, Window>;

    type TestTwoToOneCRH = pedersen::TwoToOneCRH<JubJub, Window>;
    type TestTwoToOneCRHGadget =
        pedersen::constraints::TwoToOneCRHGadget<JubJub, EdwardsVar, Window>;

    #[derive(Clone, PartialEq, Eq, Hash)]
    pub(super) struct Window;

    impl pedersen::Window for Window {
        const WINDOW_SIZE: usize = 127;
        const NUM_WINDOWS: usize = 9;
    }

    fn generate_u8_input<R: Rng>(
        cs: ConstraintSystemRef<Fr>,
        size: usize,
        rng: &mut R,
    ) -> (Vec<u8>, Vec<UInt8<Fr>>) {
        let mut input = vec![1u8; size];
        rng.fill_bytes(&mut input);

        let mut input_bytes = vec![];
        for byte in input.iter() {
            input_bytes.push(UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap());
        }
        (input, input_bytes)
    }

    fn generate_affine<R: Rng>(
        cs: ConstraintSystemRef<Fr>,
        rng: &mut R,
    ) -> (<JubJub as CurveGroup>::Affine, EdwardsVar) {
        let val = <JubJub as CurveGroup>::Affine::rand(rng);
        let val_var = EdwardsVar::new_witness(cs.clone(), || Ok(val.clone())).unwrap();
        (val, val_var)
    }

    #[test]
    fn test_native_equality() {
        let rng = &mut test_rng();
        let cs = ConstraintSystem::<Fr>::new_ref();

        let (input, input_var) = generate_u8_input(cs.clone(), 128, rng);

        let parameters = TestCRH::setup(rng).unwrap();
        let primitive_result = TestCRH::evaluate(&parameters, input.as_slice()).unwrap();

        let parameters_var = pedersen::constraints::CRHParametersVar::new_constant(
            ark_relations::ns!(cs, "CRH Parameters"),
            &parameters,
        )
        .unwrap();

        let result_var = TestCRHGadget::evaluate(&parameters_var, &input_var).unwrap();

        let primitive_result = primitive_result;
        assert_eq!(primitive_result, result_var.value().unwrap());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_naive_two_to_one_equality() {
        let rng = &mut test_rng();
        let cs = ConstraintSystem::<Fr>::new_ref();

        let (left_input, left_input_var) = generate_affine(cs.clone(), rng);
        let (right_input, right_input_var) = generate_affine(cs.clone(), rng);
        let parameters = TestTwoToOneCRH::setup(rng).unwrap();
        let primitive_result =
            TestTwoToOneCRH::compress(&parameters, left_input, right_input).unwrap();

        let parameters_var = pedersen::constraints::CRHParametersVar::new_constant(
            ark_relations::ns!(cs, "CRH Parameters"),
            &parameters,
        )
        .unwrap();

        let result_var =
            TestTwoToOneCRHGadget::compress(&parameters_var, &left_input_var, &right_input_var)
                .unwrap();

        let primitive_result = primitive_result;
        assert_eq!(primitive_result, result_var.value().unwrap().into_affine());
        assert!(cs.is_satisfied().unwrap());
    }
}
