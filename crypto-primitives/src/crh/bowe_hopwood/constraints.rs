use crate::crh::{
    bowe_hopwood::{Parameters, TwoToOneCRH, CHUNK_SIZE, CRH},
    pedersen::{self, Window},
    CRHSchemeGadget, TwoToOneCRHSchemeGadget,
};
use ark_ec::{
    twisted_edwards::{Projective as TEProjective, TECurveConfig},
    CurveConfig,
};
use ark_ff::Field;
use ark_r1cs_std::{groups::curves::twisted_edwards::AffineVar, prelude::*};
use ark_relations::r1cs::{Namespace, SynthesisError};
#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;
use ark_std::{borrow::Borrow, iter, marker::PhantomData};

type ConstraintF<P> = <<P as CurveConfig>::BaseField as Field>::BasePrimeField;

#[derive(Derivative)]
#[derivative(Clone(bound = "P: TECurveConfig, W: Window"))]
pub struct ParametersVar<P: TECurveConfig, W: Window> {
    params: Parameters<P>,
    #[doc(hidden)]
    _window: PhantomData<W>,
}

pub struct CRHGadget<P: TECurveConfig, F: FieldVar<P::BaseField, ConstraintF<P>>>
where
    for<'a> &'a F: FieldOpsBounds<'a, P::BaseField, F>,
{
    #[doc(hidden)]
    _params: PhantomData<P>,
    #[doc(hidden)]
    _base_field: PhantomData<F>,
}

impl<P, F, W> CRHSchemeGadget<CRH<P, W>, ConstraintF<P>> for CRHGadget<P, F>
where
    for<'a> &'a F: FieldOpsBounds<'a, P::BaseField, F>,
    F: FieldVar<P::BaseField, ConstraintF<P>>,
    F: TwoBitLookupGadget<ConstraintF<P>, TableConstant = P::BaseField>
        + ThreeBitCondNegLookupGadget<ConstraintF<P>, TableConstant = P::BaseField>,
    P: TECurveConfig,
    W: Window,
{
    type InputVar = [UInt8<ConstraintF<P>>];

    type OutputVar = F;
    type ParametersVar = ParametersVar<P, W>;

    #[tracing::instrument(target = "r1cs", skip(parameters, input))]
    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        if (input.len() * 8) > W::WINDOW_SIZE * W::NUM_WINDOWS * CHUNK_SIZE {
            panic!(
                "incorrect input bitlength {:?} for window params {:?}x{:?}x{}",
                input.len() * 8,
                W::WINDOW_SIZE,
                W::NUM_WINDOWS,
                CHUNK_SIZE,
            );
        }

        // Pad the input if it is not the current length.
        let mut input_in_bits: Vec<Boolean<_>> = input
            .iter()
            .flat_map(|byte| byte.to_bits_le().unwrap())
            .collect();
        if (input_in_bits.len()) % CHUNK_SIZE != 0 {
            let current_length = input_in_bits.len();
            for _ in 0..(CHUNK_SIZE - current_length % CHUNK_SIZE) {
                input_in_bits.push(Boolean::constant(false));
            }
        }
        assert!(input_in_bits.len() % CHUNK_SIZE == 0);
        assert_eq!(parameters.params.generators.len(), W::NUM_WINDOWS);
        for generators in parameters.params.generators.iter() {
            assert_eq!(generators.len(), W::WINDOW_SIZE);
        }

        // Allocate new variable for the result.
        let input_in_bits = input_in_bits
            .chunks(W::WINDOW_SIZE * CHUNK_SIZE)
            .map(|x| x.chunks(CHUNK_SIZE).collect::<Vec<_>>())
            .collect::<Vec<_>>();
        let result = AffineVar::precomputed_base_3_bit_signed_digit_scalar_mul(
            &parameters.params.generators,
            &input_in_bits,
        )?;

        Ok(result.x)
    }
}

pub struct TwoToOneCRHGadget<P: TECurveConfig, F: FieldVar<P::BaseField, ConstraintF<P>>>
where
    for<'a> &'a F: FieldOpsBounds<'a, P::BaseField, F>,
{
    #[doc(hidden)]
    _params: PhantomData<P>,
    #[doc(hidden)]
    _base_field: PhantomData<F>,
}

impl<P, F, W> TwoToOneCRHSchemeGadget<TwoToOneCRH<P, W>, ConstraintF<P>> for TwoToOneCRHGadget<P, F>
where
    for<'a> &'a F: FieldOpsBounds<'a, P::BaseField, F>,
    F: FieldVar<P::BaseField, ConstraintF<P>>,
    F: TwoBitLookupGadget<ConstraintF<P>, TableConstant = P::BaseField>
        + ThreeBitCondNegLookupGadget<ConstraintF<P>, TableConstant = P::BaseField>,
    P: TECurveConfig,
    W: Window,
{
    type InputVar = [UInt8<ConstraintF<P>>];
    type OutputVar = F;
    type ParametersVar = ParametersVar<P, W>;

    #[tracing::instrument(target = "r1cs", skip(parameters))]
    fn evaluate(
        parameters: &Self::ParametersVar,
        left_input: &Self::InputVar,
        right_input: &Self::InputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        let input_size_bytes = pedersen::CRH::<TEProjective<P>, W>::INPUT_SIZE_BITS / 8;

        // assume equality of left and right length
        assert_eq!(left_input.len(), right_input.len());
        // assume sum of left and right length is at most the CRH length limit
        assert!(left_input.len() + right_input.len() <= input_size_bytes);

        let num_trailing_zeros = input_size_bytes - (left_input.len() + right_input.len());
        let chained_input: Vec<_> = left_input
            .to_vec()
            .into_iter()
            .chain(right_input.to_vec().into_iter())
            .chain(iter::repeat(UInt8::constant(0u8)).take(num_trailing_zeros))
            .collect();
        CRHGadget::<P, F>::evaluate(parameters, &chained_input)
    }

    fn compress(
        parameters: &Self::ParametersVar,
        left_input: &Self::OutputVar,
        right_input: &Self::OutputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        let left_input_bytes = left_input.to_bytes_le()?;
        let right_input_bytes = right_input.to_bytes_le()?;
        Self::evaluate(parameters, &left_input_bytes, &right_input_bytes)
    }
}

impl<P, W> AllocVar<Parameters<P>, ConstraintF<P>> for ParametersVar<P, W>
where
    P: TECurveConfig,
    W: Window,
{
    #[tracing::instrument(target = "r1cs", skip(_cs, f))]
    fn new_variable<T: Borrow<Parameters<P>>>(
        _cs: impl Into<Namespace<ConstraintF<P>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let params = f()?.borrow().clone();
        Ok(ParametersVar {
            params,
            _window: PhantomData,
        })
    }
}

#[cfg(test)]
mod test {
    use ark_std::rand::Rng;

    use crate::crh::bowe_hopwood;
    use crate::crh::{pedersen, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget};
    use crate::crh::{CRHScheme, CRHSchemeGadget};
    use ark_ed_on_bls12_381::{constraints::FqVar, EdwardsConfig, Fq as Fr};
    use ark_r1cs_std::{alloc::AllocVar, uint8::UInt8, R1CSVar};
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
    use ark_std::test_rng;

    type TestCRH = bowe_hopwood::CRH<EdwardsConfig, Window>;
    type TestCRHGadget = bowe_hopwood::constraints::CRHGadget<EdwardsConfig, FqVar>;

    type TestTwoToOneCRH = bowe_hopwood::TwoToOneCRH<EdwardsConfig, Window>;
    type TestTwoToOneCRHGadget = bowe_hopwood::constraints::TwoToOneCRHGadget<EdwardsConfig, FqVar>;

    #[derive(Clone, PartialEq, Eq, Hash)]
    pub(super) struct Window;

    impl pedersen::Window for Window {
        const WINDOW_SIZE: usize = 63;
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

        let (input, input_var) = generate_u8_input(cs.clone(), 189, rng);
        println!("number of constraints for input: {}", cs.num_constraints());

        let parameters = TestCRH::setup(rng).unwrap();
        let primitive_result = TestCRH::evaluate(&parameters, input.as_slice()).unwrap();

        let parameters_var =
            <TestCRHGadget as CRHSchemeGadget<TestCRH, Fr>>::ParametersVar::new_witness(
                ark_relations::ns!(cs, "parameters_var"),
                || Ok(&parameters),
            )
            .unwrap();
        println!(
            "number of constraints for input + params: {}",
            cs.num_constraints()
        );

        let result_var = TestCRHGadget::evaluate(&parameters_var, &input_var).unwrap();

        println!("number of constraints total: {}", cs.num_constraints());

        assert_eq!(primitive_result, result_var.value().unwrap());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_native_two_to_one_equality() {
        let rng = &mut test_rng();
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Max input size is 63 bytes. That leaves 31 for the left half, 31 for the right, and 1
        // byte of padding.
        let (left_input, left_input_var) = generate_u8_input(cs.clone(), 31, rng);
        let (right_input, right_input_var) = generate_u8_input(cs.clone(), 31, rng);
        let parameters = TestTwoToOneCRH::setup(rng).unwrap();
        let primitive_result =
            TestTwoToOneCRH::evaluate(&parameters, left_input.as_slice(), right_input.as_slice())
                .unwrap();

        let parameters_var = <TestTwoToOneCRHGadget as TwoToOneCRHSchemeGadget<
            TestTwoToOneCRH,
            Fr,
        >>::ParametersVar::new_witness(
            ark_relations::ns!(cs, "parameters_var"),
            || Ok(&parameters),
        )
        .unwrap();

        let result_var =
            TestTwoToOneCRHGadget::evaluate(&parameters_var, &left_input_var, &right_input_var)
                .unwrap();

        let primitive_result = primitive_result;
        assert_eq!(primitive_result, result_var.value().unwrap());
        assert!(cs.is_satisfied().unwrap());
    }

    #[should_panic]
    #[test]
    fn test_input_size_check() {
        // Pick parameters that are far too small for a CRH
        #[derive(Clone, PartialEq, Eq, Hash)]
        pub(super) struct TooSmallWindow;
        impl pedersen::Window for TooSmallWindow {
            const WINDOW_SIZE: usize = 1;
            const NUM_WINDOWS: usize = 1;
        }
        type TestCRH = bowe_hopwood::CRH<EdwardsConfig, TooSmallWindow>;
        type TestCRHGadget = bowe_hopwood::constraints::CRHGadget<EdwardsConfig, FqVar>;

        let rng = &mut test_rng();
        let cs = ConstraintSystem::<Fr>::new_ref();

        let (_, input_var) = generate_u8_input(cs.clone(), 189, rng);
        println!("number of constraints for input: {}", cs.num_constraints());

        let parameters = TestCRH::setup(rng).unwrap();
        let parameters_var =
            <TestCRHGadget as CRHSchemeGadget<TestCRH, Fr>>::ParametersVar::new_witness(
                ark_relations::ns!(cs, "parameters_var"),
                || Ok(&parameters),
            )
            .unwrap();
        let _ = TestCRHGadget::evaluate(&parameters_var, &input_var).unwrap();
    }
}
