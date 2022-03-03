use crate::{
    crh::{
        pedersen::{Parameters, TwoToOneCRH, Window, CRH},
        CRHWithGadget, TwoToOneCRHWithGadget,
    },
    Vec,
};
use ark_ec::ProjectiveCurve;
use ark_ff::Field;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{Namespace, SynthesisError};

use core::{borrow::Borrow, iter};

type ConstraintF<C> = <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField;
#[derive(Derivative)]
#[derivative(Clone(bound = "C: CurveWithVar<ConstraintF<C>>"))]
pub struct CRHParametersVar<C: CurveWithVar<ConstraintF<C>>> {
    params: Parameters<C>,
}

impl<C, W> CRHWithGadget<ConstraintF<C>> for CRH<C, W>
where
    C: CurveWithVar<ConstraintF<C>>,
    W: Window,
    for<'a> &'a C::Var: GroupOpsBounds<'a, C, C::Var>,
{
    type InputVar = [UInt8<ConstraintF<C>>];
    type OutputVar = C::Var;
    type ParametersVar = CRHParametersVar<C>;

    #[tracing::instrument(target = "r1cs", skip(parameters, input))]
    fn evaluate_gadget(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
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
        let result = C::Var::precomputed_base_multiscalar_mul_le(
            &parameters.params.generators,
            input_in_bits,
        )?;
        Ok(result)
    }
}

impl<C, W> TwoToOneCRHWithGadget<ConstraintF<C>> for TwoToOneCRH<C, W>
where
    C: CurveWithVar<ConstraintF<C>>,
    W: Window,
    for<'a> &'a C::Var: GroupOpsBounds<'a, C, C::Var>,
{
    type InputVar = [UInt8<ConstraintF<C>>];
    type OutputVar = C::Var;
    type ParametersVar = CRHParametersVar<C>;

    #[tracing::instrument(target = "r1cs", skip(parameters, left, right))]
    fn evaluate_gadget(
        parameters: &Self::ParametersVar,
        left: &Self::InputVar,
        right: &Self::InputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        // assume equality of left and right length
        assert_eq!(left.len(), right.len());
        let input_size_bytes = CRH::<C, W>::INPUT_SIZE_BITS / 8;
        let num_trailing_zeros = input_size_bytes - 2 * left.len();
        let chained: Vec<_> = left
            .iter()
            .chain(right.iter())
            .cloned()
            .chain(iter::repeat(UInt8::constant(0u8)).take(num_trailing_zeros))
            .collect();
        CRH::<C, W>::evaluate_gadget(parameters, &chained)
    }

    #[tracing::instrument(target = "r1cs", skip(parameters, left, right))]
    fn compress_gadget(
        parameters: &Self::ParametersVar,
        left: &Self::OutputVar,
        right: &Self::OutputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        // convert output to bytes
        let left = left.to_bytes()?;
        let right = right.to_bytes()?;
        Self::evaluate_gadget(parameters, &left, &right)
    }
}

impl<C> AllocVar<Parameters<C>, ConstraintF<C>> for CRHParametersVar<C>
where
    C: CurveWithVar<ConstraintF<C>>,
{
    #[tracing::instrument(target = "r1cs", skip(_cs, f))]
    fn new_variable<T: Borrow<Parameters<C>>>(
        _cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let params = f()?.borrow().clone();
        Ok(CRHParametersVar { params })
    }
}

#[cfg(test)]
mod test {
    use crate::{
        crh::{pedersen, CRHGadget, TwoToOneCRH, TwoToOneCRHGadget, CRH},
        Gadget,
    };
    use ark_ec::ProjectiveCurve;
    use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective as JubJub, Fq as Fr};
    use ark_r1cs_std::prelude::*;
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
    use ark_std::rand::Rng;
    use ark_std::{test_rng, UniformRand};

    type TestCRH = pedersen::CRH<JubJub, Window>;

    type TestTwoToOneCRH = pedersen::TwoToOneCRH<JubJub, Window>;

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

    fn generate_affine<R: Rng>(
        cs: ConstraintSystemRef<Fr>,
        rng: &mut R,
    ) -> (<JubJub as ProjectiveCurve>::Affine, EdwardsVar) {
        let val = <JubJub as ProjectiveCurve>::Affine::rand(rng);
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

        let result_var = Gadget::<TestCRH>::evaluate(&parameters_var, &input_var).unwrap();

        let primitive_result = primitive_result;
        assert_eq!(primitive_result, result_var.value().unwrap());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_naive_two_to_one_equality() {
        let rng = &mut test_rng();
        let cs = ConstraintSystem::<Fr>::new_ref();

        let (left, left_var) = generate_affine(cs.clone(), rng);
        let (right, right_var) = generate_affine(cs.clone(), rng);
        let parameters = TestTwoToOneCRH::setup(rng).unwrap();
        let primitive_result = TestTwoToOneCRH::compress(&parameters, left, right).unwrap();

        let parameters_var = pedersen::constraints::CRHParametersVar::new_constant(
            ark_relations::ns!(cs, "CRH Parameters"),
            &parameters,
        )
        .unwrap();

        let result_var =
            Gadget::<TestTwoToOneCRH>::compress(&parameters_var, &left_var, &right_var).unwrap();

        let primitive_result = primitive_result;
        assert_eq!(primitive_result, result_var.value().unwrap());
        assert!(cs.is_satisfied().unwrap());
    }
}
