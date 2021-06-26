use crate::crh::poseidon::sbox::PoseidonSbox;
use crate::{Error, Vec, CRH as CRHTrait};
use ark_std::marker::PhantomData;
use ark_std::rand::Rng;

use crate::crh::TwoToOneCRH;
use ark_ff::fields::PrimeField;
use ark_ff::ToConstraintField;

pub mod sbox;

#[cfg(feature = "r1cs")]
pub mod constraints;

// Choice is arbitrary
pub const PADDING_CONST: u64 = 101;
pub const ZERO_CONST: u64 = 0;

pub trait PoseidonRoundParams<F: PrimeField>: Default + Clone {
    /// The size of the permutation, in field elements.
    const WIDTH: usize;
    /// Number of full SBox rounds in beginning
    const FULL_ROUNDS_BEGINNING: usize;
    /// Number of full SBox rounds in end
    const FULL_ROUNDS_END: usize;
    /// Number of partial rounds
    const PARTIAL_ROUNDS: usize;
    /// The S-box to apply in the sub words layer.
    const SBOX: PoseidonSbox;
}

/// The Poseidon permutation.
#[derive(Default, Clone)]
pub struct Poseidon<F, P> {
    pub params: P,
    /// The round key constants
    pub round_keys: Vec<F>,
    /// The MDS matrix to apply in the mix layer.
    pub mds_matrix: Vec<Vec<F>>,
}

impl<F: PrimeField, P: PoseidonRoundParams<F>> Poseidon<F, P> {
    fn permute(&self, input: &[F]) -> Vec<F> {
        let width = P::WIDTH;
        assert_eq!(input.len(), width);

        let full_rounds_beginning = P::FULL_ROUNDS_BEGINNING;
        let partial_rounds = P::PARTIAL_ROUNDS;
        let full_rounds_end = P::FULL_ROUNDS_END;

        let mut current_state = input.to_vec();
        let mut current_state_temp = vec![F::zero(); width];

        let mut round_keys_offset = 0;

        // full Sbox rounds
        for _ in 0..full_rounds_beginning {
            // Sbox layer
            for i in 0..width {
                current_state[i] += self.round_keys[round_keys_offset];
                current_state[i] = P::SBOX.apply_sbox(current_state[i]);
                round_keys_offset += 1;
            }

            // linear layer
            for j in 0..width {
                for i in 0..width {
                    current_state_temp[i] += current_state[j] * self.mds_matrix[i][j];
                }
            }

            // Output of this round becomes input to next round
            for i in 0..width {
                current_state[i] = current_state_temp[i];
                current_state_temp[i] = F::zero();
            }
        }

        // middle partial Sbox rounds
        for _ in full_rounds_beginning..(full_rounds_beginning + partial_rounds) {
            for i in 0..width {
                current_state[i] += &self.round_keys[round_keys_offset];
                round_keys_offset += 1;
            }

            // partial Sbox layer, apply Sbox to only 1 element of the state.
            // Here the last one is chosen but the choice is arbitrary.
            current_state[width - 1] = P::SBOX.apply_sbox(current_state[width - 1]);

            // linear layer
            for j in 0..width {
                for i in 0..width {
                    current_state_temp[i] += current_state[j] * self.mds_matrix[i][j];
                }
            }

            // Output of this round becomes input to next round
            for i in 0..width {
                current_state[i] = current_state_temp[i];
                current_state_temp[i] = F::zero();
            }
        }

        // last full Sbox rounds
        for _ in full_rounds_beginning + partial_rounds
            ..(full_rounds_beginning + partial_rounds + full_rounds_end)
        {
            // Sbox layer
            for i in 0..width {
                current_state[i] += self.round_keys[round_keys_offset];
                current_state[i] = P::SBOX.apply_sbox(current_state[i]);
                round_keys_offset += 1;
            }

            // linear layer
            for j in 0..width {
                for i in 0..width {
                    current_state_temp[i] += current_state[j] * self.mds_matrix[i][j];
                }
            }

            // Output of this round becomes input to next round
            for i in 0..width {
                current_state[i] = current_state_temp[i];
                current_state_temp[i] = F::zero();
            }
        }

        // Finally the current_state becomes the output
        current_state
    }

    pub fn hash_2(&self, xl: F, xr: F) -> F {
        // Only 2 inputs to the permutation are set to the input of this hash
        // function, one is set to the padding constant and rest are 0. Always keep
        // the 1st input as 0
        let input = vec![
            F::from(ZERO_CONST),
            xl,
            xr,
            F::from(PADDING_CONST),
            F::from(ZERO_CONST),
            F::from(ZERO_CONST),
        ];

        // Never take the first output
        self.permute(&input)[1]
    }

    pub fn hash_4(&self, inputs: [F; 4]) -> F {
        // Only 4 inputs to the permutation are set to the input of this hash
        // function, one is set to the padding constant and one is set to 0. Always
        // keep the 1st input as 0
        let input = vec![
            F::from(ZERO_CONST),
            inputs[0],
            inputs[1],
            inputs[2],
            inputs[3],
            F::from(PADDING_CONST),
        ];

        // Never take the first output
        self.permute(&input)[1]
    }
}

pub struct CRH<F: PrimeField, P: PoseidonRoundParams<F>> {
    field: PhantomData<F>,
    params: PhantomData<P>,
}

impl<F: PrimeField, P: PoseidonRoundParams<F>> CRHTrait for CRH<F, P> {
    const INPUT_SIZE_BITS: usize = 32;
    type Output = F;
    type Parameters = Poseidon<F, P>;

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        // automatic generation of parameters are not implemented yet
        // therefore, the developers must specify the parameters themselves
        unimplemented!()
    }

    // https://github.com/arkworks-rs/algebra/blob/master/ff/src/to_field_vec.rs
    fn evaluate(parameters: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error> {
        let eval_time = start_timer!(|| "PoseidonCRH::Eval");
        let elts: Vec<F> = input.to_field_elements().unwrap_or_default();
        let result = match elts.len() {
            2 => parameters.hash_2(elts[0], elts[1]),
            4 => parameters.hash_4([elts[0], elts[1], elts[2], elts[3]]),
            _ => panic!("incorrect number of windows (elements) for poseidon hash"),
        };

        end_timer!(eval_time);

        Ok(result)
    }
}

impl<F: PrimeField, P: PoseidonRoundParams<F>> TwoToOneCRH for CRH<F, P> {
    const LEFT_INPUT_SIZE_BITS: usize = Self::INPUT_SIZE_BITS / 2;
    const RIGHT_INPUT_SIZE_BITS: usize = Self::INPUT_SIZE_BITS / 2;
    type Output = F;
    type Parameters = Poseidon<F, P>;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error> {
        <Self as CRHTrait>::setup(rng)
    }

    /// A simple implementation of TwoToOneCRH by asserting left and right input has same length and chain them together.
    fn evaluate(
        parameters: &Self::Parameters,
        left_input: &[u8],
        right_input: &[u8],
    ) -> Result<Self::Output, Error> {
        assert_eq!(left_input.len(), right_input.len());
        assert!(left_input.len() * 8 <= Self::LEFT_INPUT_SIZE_BITS);
        let chained: Vec<_> = left_input
            .iter()
            .chain(right_input.iter())
            .copied()
            .collect();

        <Self as CRHTrait>::evaluate(parameters, &chained)
    }
}
