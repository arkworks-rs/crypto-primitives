use core::{borrow::Borrow, iter, marker::PhantomData};

use crate::{
    crh::{
        bowe_hopwood::{self, Parameters, TwoToOneCRH, CHUNK_SIZE, CRH},
        pedersen::Window,
        CRHWithGadget, TwoToOneCRHWithGadget,
    },
    Vec,
};
use ark_ec::{ModelParameters, TEModelParameters};
use ark_ff::Field;
use ark_r1cs_std::{
    alloc::AllocVar, groups::curves::twisted_edwards::AffineVar, prelude::*, uint8::UInt8,
};
use ark_relations::r1cs::{Namespace, SynthesisError};

use ark_r1cs_std::bits::boolean::Boolean;

type ConstraintF<P> = <<P as ModelParameters>::BaseField as Field>::BasePrimeField;

#[derive(Derivative)]
#[derivative(Clone(bound = "P: TEModelParameters, W: Window"))]
pub struct ParametersVar<P: TEModelParameters, W: Window> {
    params: Parameters<P>,
    #[doc(hidden)]
    _window: PhantomData<W>,
}

type BF<P> = <P as ModelParameters>::BaseField;
type BFVar<P> = <BF<P> as FieldWithVar>::Var;

impl<P, W> CRHWithGadget<ConstraintF<P>> for CRH<P, W>
where
    BF<P>: FieldWithVar,
    BFVar<P>: TwoBitLookupGadget<ConstraintF<P>, TableConstant = BF<P>>
        + ThreeBitCondNegLookupGadget<ConstraintF<P>, TableConstant = BF<P>>,

    for<'a> &'a BFVar<P>: FieldOpsBounds<'a, BF<P>, BFVar<P>>,
    P: TEModelParameters,
    W: Window,
{
    type InputVar = [UInt8<ConstraintF<P>>];

    type OutputVar = BFVar<P>;
    type ParametersVar = ParametersVar<P, W>;

    #[tracing::instrument(target = "r1cs", skip(parameters, input))]
    fn evaluate_gadget(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
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

impl<P, W> TwoToOneCRHWithGadget<ConstraintF<P>> for TwoToOneCRH<P, W>
where
    BF<P>: FieldWithVar,
    BFVar<P>: TwoBitLookupGadget<ConstraintF<P>, TableConstant = BF<P>>
        + ThreeBitCondNegLookupGadget<ConstraintF<P>, TableConstant = BF<P>>,

    for<'a> &'a BFVar<P>: FieldOpsBounds<'a, BF<P>, BFVar<P>>,
    P: TEModelParameters,
    W: Window,
{
    type InputVar = [UInt8<ConstraintF<P>>];
    type OutputVar = BFVar<P>;
    type ParametersVar = ParametersVar<P, W>;

    #[tracing::instrument(target = "r1cs", skip(parameters))]
    fn evaluate_gadget(
        parameters: &Self::ParametersVar,
        left: &Self::InputVar,
        right: &Self::InputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        let input_size_bytes = bowe_hopwood::CRH::<P, W>::INPUT_SIZE_BITS / 8;

        // assume equality of left and right length
        assert_eq!(left.len(), right.len());
        // assume sum of left and right length is at most the CRH length limit
        assert!(left.len() + right.len() <= input_size_bytes);

        let num_trailing_zeros = input_size_bytes - (left.len() + right.len());
        let chained: Vec<_> = left
            .into_iter()
            .chain(right.into_iter())
            .cloned()
            .chain(iter::repeat(UInt8::constant(0u8)).take(num_trailing_zeros))
            .collect();
        CRH::<P, W>::evaluate_gadget(parameters, &chained)
    }

    #[tracing::instrument(target = "r1cs", skip(parameters, left, right))]
    fn compress_gadget(
        parameters: &Self::ParametersVar,
        left: &Self::OutputVar,
        right: &Self::OutputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        let left = left.to_bytes()?;
        let right = right.to_bytes()?;
        Self::evaluate_gadget(parameters, &left, &right)
    }
}

impl<P, W> AllocVar<Parameters<P>, ConstraintF<P>> for ParametersVar<P, W>
where
    P: TEModelParameters,
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

    use crate::crh::{pedersen, TwoToOneCRHGadget, TwoToOneCRHScheme};
    use crate::{crh::bowe_hopwood, Gadget};
    use crate::{CRHGadget, CRHScheme};
    use ark_ed_on_bls12_381::{EdwardsParameters, Fq as Fr};
    use ark_r1cs_std::{alloc::AllocVar, uint8::UInt8, R1CSVar};
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
    use ark_std::test_rng;

    type TestCRH = bowe_hopwood::CRH<EdwardsParameters, Window>;

    type TestTwoToOneCRH = bowe_hopwood::TwoToOneCRH<EdwardsParameters, Window>;

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

        let parameters_var = <Gadget<TestCRH> as CRHGadget<Fr>>::ParametersVar::new_witness(
            ark_relations::ns!(cs, "parameters_var"),
            || Ok(&parameters),
        )
        .unwrap();
        println!(
            "number of constraints for input + params: {}",
            cs.num_constraints()
        );

        let result_var = Gadget::<TestCRH>::evaluate(&parameters_var, &input_var).unwrap();

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
        let (left, left_var) = generate_u8_input(cs.clone(), 31, rng);
        let (right, right_var) = generate_u8_input(cs.clone(), 31, rng);
        let parameters = TestTwoToOneCRH::setup(rng).unwrap();
        let primitive_result =
            TestTwoToOneCRH::evaluate(&parameters, left.as_slice(), right.as_slice()).unwrap();

        let parameters_var =
            <Gadget<TestTwoToOneCRH> as TwoToOneCRHGadget<Fr>>::ParametersVar::new_witness(
                ark_relations::ns!(cs, "parameters_var"),
                || Ok(&parameters),
            )
            .unwrap();

        let result_var =
            Gadget::<TestTwoToOneCRH>::evaluate(&parameters_var, &left_var, &right_var).unwrap();

        let primitive_result = primitive_result;
        assert_eq!(primitive_result, result_var.value().unwrap());
        assert!(cs.is_satisfied().unwrap());
    }
}
