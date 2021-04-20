use crate::{
    crh::{
        pedersen::{Parameters, Window, CRH},
        CRHGadget as CRHGadgetTrait,
    },
    Vec,
};
use ark_ec::ProjectiveCurve;
use ark_ff::Field;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{Namespace, SynthesisError};

use crate::crh::TwoToOneCRHGadget;
use core::{borrow::Borrow, marker::PhantomData};

#[derive(Derivative)]
#[derivative(Clone(bound = "C: ProjectiveCurve, GG: CurveVar<C, ConstraintF<C>>"))]
pub struct CRHParametersVar<C: ProjectiveCurve, GG: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    params: Parameters<C>,
    #[doc(hidden)]
    _group_g: PhantomData<GG>,
}

type ConstraintF<C> = <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField;
pub struct CRHGadget<C: ProjectiveCurve, GG: CurveVar<C, ConstraintF<C>>, W: Window>
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

impl<C, GG, W> CRHGadgetTrait<CRH<C, W>, ConstraintF<C>> for CRHGadget<C, GG, W>
where
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintF<C>>,
    W: Window,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    type OutputVar = GG;
    type ParametersVar = CRHParametersVar<C, GG>;

    #[tracing::instrument(target = "r1cs", skip(parameters, input))]
    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &[UInt8<ConstraintF<C>>],
    ) -> Result<Self::OutputVar, SynthesisError> {
        let mut padded_input = input.to_vec();
        // Pad the input if it is not the current length.
        if input.len() * 8 < W::WINDOW_SIZE * W::NUM_WINDOWS {
            let current_length = input.len();
            for _ in current_length..(W::WINDOW_SIZE * W::NUM_WINDOWS / 8) {
                padded_input.push(UInt8::constant(0u8));
            }
        }
        assert_eq!(padded_input.len() * 8, W::WINDOW_SIZE * W::NUM_WINDOWS);
        assert_eq!(parameters.params.generators.len(), W::NUM_WINDOWS);

        // Allocate new variable for the result.
        let input_in_bits: Vec<Boolean<_>> = padded_input
            .iter()
            .flat_map(|b| b.to_bits_le().unwrap())
            .collect();
        let input_in_bits = input_in_bits.chunks(W::WINDOW_SIZE);
        let result =
            GG::precomputed_base_multiscalar_mul_le(&parameters.params.generators, input_in_bits)?;
        Ok(result)
    }
}

impl<C, GG, W> TwoToOneCRHGadget<CRH<C, W>, ConstraintF<C>> for CRHGadget<C, GG, W>
where
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintF<C>>,
    W: Window,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    type OutputVar = GG;
    type ParametersVar = CRHParametersVar<C, GG>;

    #[tracing::instrument(target = "r1cs", skip(parameters))]
    fn evaluate(
        parameters: &Self::ParametersVar,
        left_input: &[UInt8<ConstraintF<C>>],
        right_input: &[UInt8<ConstraintF<C>>],
    ) -> Result<Self::OutputVar, SynthesisError> {
        // assume equality of left and right length
        assert_eq!(left_input.len(), right_input.len());
        let chained_input: Vec<_> = left_input
            .to_vec()
            .into_iter()
            .chain(right_input.to_vec().into_iter())
            .collect();
        <Self as CRHGadgetTrait<_, _>>::evaluate(parameters, &chained_input)
    }
}

impl<C, GG> AllocVar<Parameters<C>, ConstraintF<C>> for CRHParametersVar<C, GG>
where
    C: ProjectiveCurve,
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
    use crate::crh::{pedersen, CRHGadget, TwoToOneCRH, TwoToOneCRHGadget, CRH};
    use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective as JubJub, Fq as Fr};
    use ark_r1cs_std::prelude::*;
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
    use ark_std::rand::Rng;
    use ark_std::test_rng;

    type TestCRH = pedersen::CRH<JubJub, Window>;
    type TestCRHGadget = pedersen::constraints::CRHGadget<JubJub, EdwardsVar, Window>;

    #[derive(Clone, PartialEq, Eq, Hash)]
    pub(super) struct Window;

    impl pedersen::Window for Window {
        const WINDOW_SIZE: usize = 128;
        const NUM_WINDOWS: usize = 8;
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

    #[test]
    fn test_native_equality() {
        let rng = &mut test_rng();
        let cs = ConstraintSystem::<Fr>::new_ref();

        let (input, input_var) = generate_u8_input(cs.clone(), 128, rng);

        let parameters = <TestCRH as CRH>::setup(rng).unwrap();
        let primitive_result = <TestCRH as CRH>::evaluate(&parameters, &input).unwrap();

        let parameters_var = pedersen::constraints::CRHParametersVar::new_constant(
            ark_relations::ns!(cs, "CRH Parameters"),
            &parameters,
        )
        .unwrap();

        let result_var =
            <TestCRHGadget as CRHGadget<_, _>>::evaluate(&parameters_var, &input_var).unwrap();

        let primitive_result = primitive_result;
        assert_eq!(primitive_result, result_var.value().unwrap());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_naive_two_to_one_equality() {
        let rng = &mut test_rng();
        let cs = ConstraintSystem::<Fr>::new_ref();

        let (left_input, left_input_var) = generate_u8_input(cs.clone(), 64, rng);
        let (right_input, right_input_var) = generate_u8_input(cs.clone(), 64, rng);
        let parameters = <TestCRH as TwoToOneCRH>::setup(rng).unwrap();
        let primitive_result =
            <TestCRH as TwoToOneCRH>::evaluate(&parameters, &left_input, &right_input).unwrap();

        let parameters_var = pedersen::constraints::CRHParametersVar::new_constant(
            ark_relations::ns!(cs, "CRH Parameters"),
            &parameters,
        )
        .unwrap();

        let result_var = <TestCRHGadget as TwoToOneCRHGadget<_, _>>::evaluate(
            &parameters_var,
            &left_input_var,
            &right_input_var,
        )
        .unwrap();

        let primitive_result = primitive_result;
        assert_eq!(primitive_result, result_var.value().unwrap());
        assert!(cs.is_satisfied().unwrap());
    }
}
