use crate::crh::poseidon::sbox::PoseidonSbox;
use crate::{Error, Vec, CRH as CRHTrait};
use ark_ff::fields::PrimeField;
use ark_ff::BigInteger;
use ark_std::error::Error as ArkError;
use ark_std::marker::PhantomData;
use ark_std::rand::Rng;

use crate::crh::TwoToOneCRH;

pub mod sbox;

#[cfg(test)]
pub mod test_data;

#[cfg(feature = "r1cs")]
pub mod constraints;

#[derive(Debug)]
pub enum PoseidonError {
    InvalidSboxSize(usize),
    InvalidParameters,
    ApplySboxFailed,
    InvalidInputs,
}

impl core::fmt::Display for PoseidonError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use PoseidonError::*;
        let msg = match self {
            InvalidSboxSize(s) => format!("sbox is not supported: {}", s),
            ApplySboxFailed => format!("failed to apply sbox"),
            InvalidInputs => format!("invalid poseidon inputs"),
            InvalidParameters => format!("invalid poseidon parameters"),
        };
        write!(f, "{}", msg)
    }
}

impl ArkError for PoseidonError {}

// Choice is arbitrary
pub const PADDING_CONST: u64 = 101;
pub const ZERO_CONST: u64 = 0;

pub trait Rounds: Default + Clone {
    /// The size of the permutation, in field elements.
    const WIDTH: usize;
    /// Number of full SBox rounds
    const FULL_ROUNDS: usize;
    /// Number of partial rounds
    const PARTIAL_ROUNDS: usize;
    /// The S-box to apply in the sub words layer.
    const SBOX: PoseidonSbox;
}

/// The Poseidon permutation.
#[derive(Default, Clone)]
pub struct PoseidonParameters<F> {
    /// The round key constants
    pub round_keys: Vec<F>,
    /// The MDS matrix to apply in the mix layer.
    pub mds_matrix: Vec<Vec<F>>,
}

impl<F: PrimeField> PoseidonParameters<F> {
    pub fn new(round_keys: Vec<F>, mds_matrix: Vec<Vec<F>>) -> Self {
        Self {
            round_keys,
            mds_matrix,
        }
    }

    pub fn generate<R: Rng>(rng: &mut R) -> Self {
        Self {
            round_keys: Self::create_round_keys(rng),
            mds_matrix: Self::create_mds(rng),
        }
    }
    pub fn create_mds<R: Rng>(_rng: &mut R) -> Vec<Vec<F>> {
        todo!();
    }

    pub fn create_round_keys<R: Rng>(_rng: &mut R) -> Vec<F> {
        todo!();
    }
}

pub struct CRH<F: PrimeField, P: Rounds> {
    field: PhantomData<F>,
    rounds: PhantomData<P>,
}

impl<F: PrimeField, P: Rounds> CRH<F, P> {
    fn permute(params: &PoseidonParameters<F>, mut state: Vec<F>) -> Result<Vec<F>, PoseidonError> {
        let width = P::WIDTH;

        let mut round_keys_offset = 0;

        // full Sbox rounds
        for _ in 0..(P::FULL_ROUNDS / 2) {
            // Sbox layer
            for i in 0..width {
                state[i] += params.round_keys[round_keys_offset];
                state[i] = P::SBOX.apply_sbox(state[i])?;
                round_keys_offset += 1;
            }
            // linear layer
            state = Self::apply_linear_layer(&state, &params.mds_matrix);
        }

        // middle partial Sbox rounds
        for _ in 0..P::PARTIAL_ROUNDS {
            for i in 0..width {
                state[i] += params.round_keys[round_keys_offset];
                round_keys_offset += 1;
            }
            // partial Sbox layer, apply Sbox to only 1 element of the state.
            // Here the last one is chosen but the choice is arbitrary.
            state[0] = P::SBOX.apply_sbox(state[0])?;
            // linear layer
            state = Self::apply_linear_layer(&state, &params.mds_matrix);
        }

        // last full Sbox rounds
        for _ in 0..(P::FULL_ROUNDS / 2) {
            // Sbox layer
            for i in 0..width {
                state[i] += params.round_keys[round_keys_offset];
                state[i] = P::SBOX.apply_sbox(state[i])?;
                round_keys_offset += 1;
            }
            // linear layer
            state = Self::apply_linear_layer(&state, &params.mds_matrix);
        }

        // Finally the current_state becomes the output
        Ok(state)
    }

    fn apply_linear_layer(state: &[F], mds: &[Vec<F>]) -> Vec<F> {
        let mut new_state: Vec<F> = Vec::new();
        for i in 0..state.len() {
            let mut sc = F::zero();
            for j in 0..state.len() {
                let mij = mds[i][j];
                sc += mij * state[j];
            }
            new_state.push(sc);
        }
        new_state
    }
}

impl<F: PrimeField, P: Rounds> CRHTrait for CRH<F, P> {
    const INPUT_SIZE_BITS: usize = F::BigInt::NUM_LIMBS * 8 * P::WIDTH * 8;
    type Output = F;
    type Parameters = PoseidonParameters<F>;

    // Not sure what's the purpose of this function of we are going to pass parameters
    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error> {
        Ok(Self::Parameters::generate(rng))
    }

    fn evaluate(parameters: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error> {
        let eval_time = start_timer!(|| "PoseidonCRH::Eval");

        if parameters.round_keys.len() != P::PARTIAL_ROUNDS * P::WIDTH + P::FULL_ROUNDS * P::WIDTH {
            return Err(PoseidonError::InvalidParameters.into());
        }

        if parameters.mds_matrix.len() != P::WIDTH {
            return Err(PoseidonError::InvalidParameters.into());
        }

        for m in &parameters.mds_matrix {
            if m.len() != P::WIDTH {
                return Err(PoseidonError::InvalidParameters.into());
            }
        }

        let max_size_bytes = F::BigInt::NUM_LIMBS * 8;
        let f_inputs = input
            .chunks(max_size_bytes)
            .map(|chunk| F::read(chunk))
            .collect::<Result<Vec<_>, _>>()?;

        if f_inputs.len() > P::WIDTH {
            return Err(PoseidonError::InvalidInputs.into());
        }

        let mut buffer = vec![F::zero(); P::WIDTH];
        buffer.iter_mut().zip(f_inputs).for_each(|(p, v)| *p = v);

        let result = Self::permute(&parameters, buffer)?;

        end_timer!(eval_time);

        Ok(result.get(0).cloned().ok_or(PoseidonError::InvalidInputs)?)
    }
}

impl<F: PrimeField, P: Rounds> TwoToOneCRH for CRH<F, P> {
    const LEFT_INPUT_SIZE_BITS: usize = Self::INPUT_SIZE_BITS / 2;
    const RIGHT_INPUT_SIZE_BITS: usize = Self::INPUT_SIZE_BITS / 2;
    type Output = F;
    type Parameters = PoseidonParameters<F>;

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
            .map(|x| *x)
            .collect();

        <Self as CRHTrait>::evaluate(parameters, &chained)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_ed_on_bn254::Fq;
    use ark_ff::{to_bytes, Zero};

    use test_data::{
        get_mds_3, get_mds_5, get_results_3, get_results_5, get_rounds_3, get_rounds_5,
    };

    #[derive(Default, Clone)]
    struct PoseidonRounds3;
    #[derive(Default, Clone)]
    struct PoseidonRounds5;

    impl Rounds for PoseidonRounds3 {
        const WIDTH: usize = 3;
        const PARTIAL_ROUNDS: usize = 57;
        const FULL_ROUNDS: usize = 8;
        const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
    }

    impl Rounds for PoseidonRounds5 {
        const WIDTH: usize = 5;
        const PARTIAL_ROUNDS: usize = 60;
        const FULL_ROUNDS: usize = 8;
        const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
    }

    type PoseidonCRH3 = CRH<Fq, PoseidonRounds3>;
    type PoseidonCRH5 = CRH<Fq, PoseidonRounds5>;

    #[test]
    fn test_width_3_bn_254() {
        let rounds = get_rounds_3::<Fq>();
        let mds = get_mds_3::<Fq>();
        let res = get_results_3::<Fq>();

        let params = PoseidonParameters::<Fq>::new(rounds, mds);

        let input_bytes = to_bytes![Fq::zero(), Fq::from(1u128), Fq::from(2u128)].unwrap();

        let poseidon_res = <PoseidonCRH3 as CRHTrait>::evaluate(&params, &input_bytes).unwrap();
        assert_eq!(res[0], poseidon_res);
    }

    #[test]
    fn test_width_5_bn_254() {
        let rounds = get_rounds_5::<Fq>();
        let mds = get_mds_5::<Fq>();
        let res = get_results_5::<Fq>();

        let params = PoseidonParameters::<Fq>::new(rounds, mds);

        let input_bytes = to_bytes![
            Fq::zero(),
            Fq::from(1u128),
            Fq::from(2u128),
            Fq::from(3u128),
            Fq::from(4u128)
        ]
        .unwrap();

        let poseidon_res = <PoseidonCRH5 as CRHTrait>::evaluate(&params, &input_bytes).unwrap();
        assert_eq!(res[0], poseidon_res);
    }
}
