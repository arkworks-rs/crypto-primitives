use crate::{Error, Vec};
use ark_std::rand::Rng;
use ark_std::{
    marker::PhantomData,
};
use crate::crh::FixedLengthCRH;
use crate::crh::poseidon::sbox::PoseidonSbox;

use ark_ff::{fields::PrimeField};

pub mod sbox;
pub mod constraints;

// Choice is arbitrary
pub const PADDING_CONST: u64 = 101;
pub const ZERO_CONST: u64 = 0;

pub trait Window: Clone {
    const WINDOW_SIZE: usize;
    const NUM_WINDOWS: usize;
}

pub trait PoseidonRoundParams: Clone {
    const WIDTH: usize;
    const FULL_ROUND_BEGINNING: usize;
    const FULL_ROUND_END: usize;
    const PARTIAL_ROUNDS: usize;
    const SBOX: PoseidonSbox;
}

/// The Poseidon permutation.
#[derive(Clone)]
pub struct Poseidon<F> {
    /// The size of the permutation, in field elements.
    pub width: usize,
    /// Number of full SBox rounds in beginning
    pub full_rounds_beginning: usize,
    /// Number of full SBox rounds in end
    pub full_rounds_end: usize,
    /// Number of partial rounds
    pub partial_rounds: usize,
    /// The S-box to apply in the sub words layer.
    pub sbox: PoseidonSbox,
    /// The round key constants
    pub round_keys: Vec<F>,
    /// The MDS matrix to apply in the mix layer.
    pub mds_matrix: Vec<Vec<F>>,
}

impl<F: PrimeField, W: Window> Poseidon<F> {
	fn permute(&self, input: &[F]) -> Vec<F> {
	    let width = self.width;
	    assert_eq!(input.len(), width);

	    let full_rounds_beginning = self.full_rounds_beginning;
	    let partial_rounds = self.partial_rounds;
	    let full_rounds_end = self.full_rounds_end;

	    let mut current_state = input.to_owned();
	    let mut current_state_temp = vec![F::zero(); width];

	    let mut round_keys_offset = 0;

	    // full Sbox rounds
	    for _ in 0..full_rounds_beginning {
	        // Sbox layer
	        for i in 0..width {
	            current_state[i] += self.round_keys[round_keys_offset];
	            current_state[i] = self.sbox.apply_sbox(&current_state[i]);
	            round_keys_offset += 1;
	        }

	        // linear layer
	        for j in 0..width {
	            for i in 0..width {
	                current_state_temp[i] +=
	                    current_state[j] * self.mds_matrix[i][j];
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
	        current_state[width - 1] =
	            self.sbox.apply_sbox(&current_state[width - 1]);

	        // linear layer
	        for j in 0..width {
	            for i in 0..width {
	                current_state_temp[i] +=
	                    current_state[j] * self.mds_matrix[i][j];
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
	            current_state[i] = self.sbox.apply_sbox(&current_state[i]);
	            round_keys_offset += 1;
	        }

	        // linear layer
	        for j in 0..width {
	            for i in 0..width {
	                current_state_temp[i] +=
	                    current_state[j] * self.mds_matrix[i][j];
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

pub struct PoseidonCRH<F: PrimeField, W: Window, P: PoseidonRoundParams> {
    field: PhantomData<F>,
    window: PhantomData<W>,
    params: PhantomData<P>
}

impl<F: PrimeField, W: Window, P: PoseidonRoundParams> PoseidonCRH<F, W, P> {
    pub fn create_mds<R: Rng>(rng: &mut R) -> Vec<Vec<F>> {
        let mut mds_matrix = Vec::new();
        mds_matrix
    }

    pub fn create_round_consts<R: Rng>(rng: &mut R) -> Vec<F> {
        let mut round_consts = Vec::new();
        round_consts
    }
}


impl<F: PrimeField, W: Window, P: PoseidonRoundParams> FixedLengthCRH for PoseidonCRH<F, W, P> {
    const INPUT_SIZE_BITS: usize = W::WINDOW_SIZE * W::NUM_WINDOWS;
    type Output = F;
    type Parameters = Poseidon<F>;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error> {
        let time = start_timer!(|| format!(
            "Poseidon::Setup: {} {}-bit windows; {{0,1}}^{{{}}} -> C",
            W::NUM_WINDOWS,
            W::WINDOW_SIZE,
            W::NUM_WINDOWS * W::WINDOW_SIZE
        ));
        
        let mds = Self::create_mds(rng);
        let rc = Self::create_round_consts(rng);
        Ok(Self::Parameters {
		    width: P::WIDTH,
		    full_rounds_beginning: P::FULL_ROUND_BEGINNING,
		    full_rounds_end: P::FULL_ROUND_END,
		    partial_rounds: P::PARTIAL_ROUNDS,
		    sbox: P::SBOX,
		    round_keys: rc,
		    mds_matrix: mds,
        })
    }

    // https://github.com/arkworks-rs/algebra/blob/master/ff/src/to_field_vec.rs
    fn evaluate(parameters: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error> {
        let eval_time = start_timer!(|| "PedersenCRH::Eval");

        if (input.len() * 8) > W::WINDOW_SIZE * W::NUM_WINDOWS {
            panic!(
                "incorrect input length {:?} for window params {:?}✕{:?}",
                input.len(),
                W::WINDOW_SIZE,
                W::NUM_WINDOWS
            );
        }

        let mut padded_input = Vec::with_capacity(input.len());
        let mut input = input;
        // Pad the input if it is not the current length.
        if (input.len() * 8) < W::WINDOW_SIZE * W::NUM_WINDOWS {
            padded_input.extend_from_slice(input);
            let padded_length = (W::WINDOW_SIZE * W::NUM_WINDOWS) / 8;
            padded_input.resize(padded_length, 0u8);
            input = padded_input.as_slice();
        }

        let chunked: Vec<F> = input.chunk(W::WINDOW_SIZE).map(|x| F::from(x));
        let result = match W::NUM_WINDOWS {
        	2 => parameters.hash_2(chunked[0], chunked[1]),
        	4 => parameters.hash_4(&chunked),
        	_ => panic!(
        		"incorrect number of windows (elements) for poseidon hash"
        	),
        };

        end_timer!(eval_time);

        Ok(result.into())
    }
}