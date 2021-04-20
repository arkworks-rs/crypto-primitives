use super::sbox::constraints::SboxConstraints;
use super::PoseidonRoundParams;
use super::{Poseidon, CRH};
use crate::CRHGadget as CRHGadgetTrait;
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::uint8::UInt8;
use ark_r1cs_std::ToConstraintFieldGadget;
use ark_r1cs_std::{alloc::AllocVar, fields::FieldVar, prelude::*};
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::vec::Vec;

use crate::crh::TwoToOneCRHGadget;
use ark_std::borrow::ToOwned;
use ark_std::marker::PhantomData;
use core::borrow::Borrow;

#[derive(Derivative, Clone)]
pub struct PoseidonRoundParamsVar<F: PrimeField, P: PoseidonRoundParams<F>> {
    params: Poseidon<F, P>,
}

pub struct CRHGadget<F: PrimeField, P: PoseidonRoundParams<F>> {
    field: PhantomData<F>,
    params: PhantomData<PoseidonRoundParamsVar<F, P>>,
}

impl<F: PrimeField, P: PoseidonRoundParams<F>> PoseidonRoundParamsVar<F, P> {
    fn permute(&self, input: Vec<FpVar<F>>) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let width = P::WIDTH;
        assert_eq!(input.len(), width);

        let full_rounds_beginning = P::FULL_ROUNDS_BEGINNING;
        let partial_rounds = P::PARTIAL_ROUNDS;
        let full_rounds_end = P::FULL_ROUNDS_END;

        let mut input_vars: Vec<FpVar<F>> = input;

        let mut round_keys_offset = 0;

        // ------------ First rounds with full SBox begin --------------------

        for _k in 0..full_rounds_beginning {
            // TODO: Check if Scalar::default() can be replaced by FpVar<F>::one() or FpVar<F>::zero()
            let mut sbox_outputs: Vec<FpVar<F>> = vec![FpVar::<F>::one(); width];

            // Substitution (S-box) layer
            for i in 0..width {
                let round_key = self.params.round_keys[round_keys_offset];
                sbox_outputs[i] = P::SBOX
                    .synthesize_sbox(input_vars[i].clone(), round_key)?
                    .into();

                round_keys_offset += 1;
            }

            // TODO: Check if Scalar::default() can be replaced by FpVar<F>::one()
            let mut next_input_vars: Vec<FpVar<F>> = vec![FpVar::<F>::one(); width];

            self.apply_linear_layer(
                width,
                sbox_outputs,
                &mut next_input_vars,
                &self.params.mds_matrix,
            );

            for i in 0..width {
                // replace input_vars with next_input_vars
                input_vars[i] = next_input_vars.remove(0);
            }
        }

        // ------------ First rounds with full SBox begin --------------------

        // ------------ Middle rounds with partial SBox begin --------------------

        for _k in full_rounds_beginning..(full_rounds_beginning + partial_rounds) {
            let mut sbox_outputs: Vec<FpVar<F>> = vec![FpVar::<F>::one(); width];

            // Substitution (S-box) layer
            for i in 0..width {
                let round_key = self.params.round_keys[round_keys_offset];

                // apply Sbox to only 1 element of the state.
                // Here the last one is chosen but the choice is arbitrary.
                if i == width - 1 {
                    sbox_outputs[i] = P::SBOX
                        .synthesize_sbox(input_vars[i].clone(), round_key)?
                        .into();
                } else {
                    sbox_outputs[i] = input_vars[i].clone() + round_key;
                }

                round_keys_offset += 1;
            }

            // Linear layer
            // TODO: Check if Scalar::default() can be replaced by FpVar<F>::one()
            let mut next_input_vars: Vec<FpVar<F>> = vec![FpVar::<F>::one(); width];

            self.apply_linear_layer(
                width,
                sbox_outputs,
                &mut next_input_vars,
                &self.params.mds_matrix,
            );

            for i in 0..width {
                // replace input_vars with simplified next_input_vars
                input_vars[i] = next_input_vars.remove(0);
            }
        }

        // ------------ Middle rounds with partial SBox end --------------------

        // ------------ Last rounds with full SBox begin --------------------

        for _k in (full_rounds_beginning + partial_rounds)
            ..(full_rounds_beginning + partial_rounds + full_rounds_end)
        {
            // TODO: Check if Scalar::default() can be replaced by FpVar<F>::one()
            let mut sbox_outputs: Vec<FpVar<F>> = vec![FpVar::<F>::one(); width];

            // Substitution (S-box) layer
            for i in 0..width {
                let round_key = self.params.round_keys[round_keys_offset];
                sbox_outputs[i] = P::SBOX
                    .synthesize_sbox(input_vars[i].clone(), round_key)?
                    .into();

                round_keys_offset += 1;
            }

            // Linear layer
            // TODO: Check if Scalar::default() can be replaced by FpVar<F>::one()
            let mut next_input_vars: Vec<FpVar<F>> = vec![FpVar::<F>::one(); width];

            self.apply_linear_layer(
                width,
                sbox_outputs,
                &mut next_input_vars,
                &self.params.mds_matrix,
            );

            for i in 0..width {
                // replace input_vars with next_input_vars
                input_vars[i] = next_input_vars.remove(0);
            }
        }

        // ------------ Last rounds with full SBox end --------------------

        Ok(input_vars)
    }

    fn apply_linear_layer(
        &self,
        width: usize,
        sbox_outs: Vec<FpVar<F>>,
        next_inputs: &mut Vec<FpVar<F>>,
        mds_matrix: &Vec<Vec<F>>,
    ) {
        for j in 0..width {
            for i in 0..width {
                next_inputs[i] = next_inputs[i].clone()
                    + sbox_outs[j].clone() * &FpVar::<F>::Constant(mds_matrix[i][j]);
            }
        }
    }

    fn hash_2(
        &self,
        xl: FpVar<F>,
        xr: FpVar<F>,
        statics: Vec<FpVar<F>>,
    ) -> Result<FpVar<F>, SynthesisError> {
        let width = P::WIDTH;
        // Only 2 inputs to the permutation are set to the input of this hash
        // function.
        assert_eq!(statics.len(), width - 2);

        // Always keep the 1st input as 0
        let mut inputs = vec![statics[0].to_owned()];
        inputs.push(xl);
        inputs.push(xr);

        // statics correspond to committed variables with values as PADDING_CONST
        // and 0s and randomness as 0
        for i in 1..statics.len() {
            inputs.push(statics[i].to_owned());
        }
        let permutation_output = self.permute(inputs)?;
        Ok(permutation_output[1].clone())
    }

    fn hash_4(
        &self,
        input: &[FpVar<F>],
        statics: Vec<FpVar<F>>,
    ) -> Result<FpVar<F>, SynthesisError> {
        assert_eq!(input.len(), 4);
        let width = P::WIDTH;
        // Only 4 inputs to the permutation are set to the input of this hash
        // function.
        assert_eq!(statics.len(), width - 4);
        // Always keep the 1st input as 0
        let mut inputs = vec![statics[0].to_owned()];
        inputs.push(input[0].clone());
        inputs.push(input[1].clone());
        inputs.push(input[2].clone());
        inputs.push(input[3].clone());

        // statics correspond to committed variables with values as PADDING_CONST
        // and 0s and randomness as 0
        for i in 1..statics.len() {
            inputs.push(statics[i].to_owned());
        }

        let permutation_output = self.permute(inputs)?;
        Ok(permutation_output[1].to_owned())
    }
}

// https://github.com/arkworks-rs/r1cs-std/blob/master/src/bits/uint8.rs#L343
impl<F: PrimeField, P: PoseidonRoundParams<F>> CRHGadgetTrait<CRH<F, P>, F> for CRHGadget<F, P> {
    type OutputVar = FpVar<F>;
    type ParametersVar = PoseidonRoundParamsVar<F, P>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &[UInt8<F>],
    ) -> Result<Self::OutputVar, SynthesisError> {
        let f_var_vec: Vec<FpVar<F>> = input.to_constraint_field()?;

        // Choice is arbitrary
        let padding_const: F = F::from(101u32);
        let zero_const: F = F::zero();

        let statics = match f_var_vec.len() {
            2 => {
                vec![
                    FpVar::<F>::Constant(zero_const),
                    FpVar::<F>::Constant(padding_const),
                    FpVar::<F>::Constant(zero_const),
                    FpVar::<F>::Constant(zero_const),
                ]
            }
            4 => {
                vec![
                    FpVar::<F>::Constant(zero_const),
                    FpVar::<F>::Constant(padding_const),
                ]
            }
            _ => panic!("incorrect number (elements) for poseidon hash"),
        };

        let result = match f_var_vec.len() {
            2 => parameters.hash_2(f_var_vec[0].clone(), f_var_vec[1].clone(), statics),
            4 => parameters.hash_4(&f_var_vec, statics),
            _ => panic!("incorrect number (elements) for poseidon hash"),
        };
        Ok(result.unwrap_or(Self::OutputVar::zero()))
    }
}

impl<F: PrimeField, P: PoseidonRoundParams<F>> TwoToOneCRHGadget<CRH<F, P>, F> for CRHGadget<F, P> {
    type OutputVar = FpVar<F>;
    type ParametersVar = PoseidonRoundParamsVar<F, P>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        left_input: &[UInt8<F>],
        right_input: &[UInt8<F>],
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

impl<F: PrimeField, P: PoseidonRoundParams<F>> AllocVar<Poseidon<F, P>, F>
    for PoseidonRoundParamsVar<F, P>
{
    #[tracing::instrument(target = "r1cs", skip(_cs, f))]
    fn new_variable<T: Borrow<Poseidon<F, P>>>(
        _cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let params = f()?.borrow().clone();
        Ok(Self { params })
    }
}
