use crate::sponge::{
    field_cast, squeeze_field_elements_with_sizes_default_impl, Absorb, CryptographicSponge,
    DuplexSpongeMode, FieldBasedCryptographicSponge, FieldElementSize, SpongeExt,
};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::any::TypeId;
#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;

/// constraints for Poseidon
#[cfg(feature = "r1cs")]
pub mod constraints;
#[cfg(test)]
mod tests;
#[cfg(test)]
pub(crate) use tests::poseidon_parameters_for_test;

/// default parameters traits for Poseidon
pub mod traits;
pub use traits::*;

mod grain_lfsr;

/// Config and RNG used
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PoseidonConfig<F: PrimeField> {
    /// Number of rounds in a full-round operation.
    pub full_rounds: usize,
    /// Number of rounds in a partial-round operation.
    pub partial_rounds: usize,
    /// Exponent used in S-boxes.
    pub alpha: u64,
    /// Additive Round keys. These are added before each MDS matrix application to make it an affine shift.
    /// They are indexed by `ark[round_num][state_element_index]`
    pub ark: Vec<Vec<F>>,
    /// Maximally Distance Separating (MDS) Matrix.
    pub mds: Vec<Vec<F>>,
    /// The rate (in terms of number of field elements).
    /// See [On the Indifferentiability of the Sponge Construction](https://iacr.org/archive/eurocrypt2008/49650180/49650180.pdf)
    /// for more details on the rate and capacity of a sponge.
    pub rate: usize,
    /// The capacity (in terms of number of field elements).
    pub capacity: usize,
}

#[derive(Clone)]
/// A duplex sponge based using the Poseidon permutation.
///
/// This implementation of Poseidon is entirely from Fractal's implementation in [COS20][cos]
/// with small syntax changes.
///
/// [cos]: https://eprint.iacr.org/2019/1076
pub struct PoseidonSponge<F: PrimeField> {
    /// Sponge Config
    pub parameters: PoseidonConfig<F>,

    // Sponge State
    /// Current sponge's state (current elements in the permutation block)
    pub state: Vec<F>,
    /// Current mode (whether its absorbing or squeezing)
    pub mode: DuplexSpongeMode,
}

impl<F: PrimeField> PoseidonSponge<F> {
    fn apply_s_box(&self, state: &mut [F], is_full_round: bool) {
        // Full rounds apply the S Box (x^alpha) to every element of state
        if is_full_round {
            for elem in state {
                *elem = elem.pow(&[self.parameters.alpha]);
            }
        }
        // Partial rounds apply the S Box (x^alpha) to just the first element of state
        else {
            state[0] = state[0].pow(&[self.parameters.alpha]);
        }
    }

    fn apply_ark(&self, state: &mut [F], round_number: usize) {
        for (i, state_elem) in state.iter_mut().enumerate() {
            state_elem.add_assign(&self.parameters.ark[round_number][i]);
        }
    }

    fn apply_mds(&self, state: &mut [F]) {
        let mut new_state = Vec::new();
        for i in 0..state.len() {
            let mut cur = F::zero();
            for (j, state_elem) in state.iter().enumerate() {
                let term = state_elem.mul(&self.parameters.mds[i][j]);
                cur.add_assign(&term);
            }
            new_state.push(cur);
        }
        state.clone_from_slice(&new_state[..state.len()])
    }

    fn permute(&mut self) {
        let full_rounds_over_2 = self.parameters.full_rounds / 2;
        let mut state = self.state.clone();
        for i in 0..full_rounds_over_2 {
            self.apply_ark(&mut state, i);
            self.apply_s_box(&mut state, true);
            self.apply_mds(&mut state);
        }

        for i in full_rounds_over_2..(full_rounds_over_2 + self.parameters.partial_rounds) {
            self.apply_ark(&mut state, i);
            self.apply_s_box(&mut state, false);
            self.apply_mds(&mut state);
        }

        for i in (full_rounds_over_2 + self.parameters.partial_rounds)
            ..(self.parameters.partial_rounds + self.parameters.full_rounds)
        {
            self.apply_ark(&mut state, i);
            self.apply_s_box(&mut state, true);
            self.apply_mds(&mut state);
        }
        self.state = state;
    }

    // Absorbs everything in elements, this does not end in an absorbtion.
    fn absorb_internal(&mut self, mut rate_start_index: usize, elements: &[F]) {
        let mut remaining_elements = elements;

        loop {
            // if we can finish in this call
            if rate_start_index + remaining_elements.len() <= self.parameters.rate {
                for (i, element) in remaining_elements.iter().enumerate() {
                    self.state[self.parameters.capacity + i + rate_start_index] += element;
                }
                self.mode = DuplexSpongeMode::Absorbing {
                    next_absorb_index: rate_start_index + remaining_elements.len(),
                };

                return;
            }
            // otherwise absorb (rate - rate_start_index) elements
            let num_elements_absorbed = self.parameters.rate - rate_start_index;
            for (i, element) in remaining_elements
                .iter()
                .enumerate()
                .take(num_elements_absorbed)
            {
                self.state[self.parameters.capacity + i + rate_start_index] += element;
            }
            self.permute();
            // the input elements got truncated by num elements absorbed
            remaining_elements = &remaining_elements[num_elements_absorbed..];
            rate_start_index = 0;
        }
    }

    // Squeeze |output| many elements. This does not end in a squeeze
    fn squeeze_internal(&mut self, mut rate_start_index: usize, output: &mut [F]) {
        let mut output_remaining = output;
        loop {
            // if we can finish in this call
            if rate_start_index + output_remaining.len() <= self.parameters.rate {
                output_remaining.clone_from_slice(
                    &self.state[self.parameters.capacity + rate_start_index
                        ..(self.parameters.capacity + output_remaining.len() + rate_start_index)],
                );
                self.mode = DuplexSpongeMode::Squeezing {
                    next_squeeze_index: rate_start_index + output_remaining.len(),
                };
                return;
            }
            // otherwise squeeze (rate - rate_start_index) elements
            let num_elements_squeezed = self.parameters.rate - rate_start_index;
            output_remaining[..num_elements_squeezed].clone_from_slice(
                &self.state[self.parameters.capacity + rate_start_index
                    ..(self.parameters.capacity + num_elements_squeezed + rate_start_index)],
            );

            // Unless we are done with squeezing in this call, permute.
            if output_remaining.len() != self.parameters.rate {
                self.permute();
            }
            // Repeat with updated output slices
            output_remaining = &mut output_remaining[num_elements_squeezed..];
            rate_start_index = 0;
        }
    }
}

impl<F: PrimeField> PoseidonConfig<F> {
    /// Initialize the parameter for Poseidon Sponge.
    pub fn new(
        full_rounds: usize,
        partial_rounds: usize,
        alpha: u64,
        mds: Vec<Vec<F>>,
        ark: Vec<Vec<F>>,
        rate: usize,
        capacity: usize,
    ) -> Self {
        assert_eq!(ark.len(), full_rounds + partial_rounds);
        for item in &ark {
            assert_eq!(item.len(), rate + capacity);
        }
        assert_eq!(mds.len(), rate + capacity);
        for item in &mds {
            assert_eq!(item.len(), rate + capacity);
        }
        Self {
            full_rounds,
            partial_rounds,
            alpha,
            mds,
            ark,
            rate,
            capacity,
        }
    }
}

impl<F: PrimeField> CryptographicSponge for PoseidonSponge<F> {
    type Config = PoseidonConfig<F>;

    fn new(parameters: &Self::Config) -> Self {
        let state = vec![F::zero(); parameters.rate + parameters.capacity];
        let mode = DuplexSpongeMode::Absorbing {
            next_absorb_index: 0,
        };

        Self {
            parameters: parameters.clone(),
            state,
            mode,
        }
    }

    fn absorb(&mut self, input: &impl Absorb) {
        let elems = input.to_sponge_field_elements_as_vec::<F>();
        if elems.is_empty() {
            return;
        }

        match self.mode {
            DuplexSpongeMode::Absorbing { next_absorb_index } => {
                let mut absorb_index = next_absorb_index;
                if absorb_index == self.parameters.rate {
                    self.permute();
                    absorb_index = 0;
                }
                self.absorb_internal(absorb_index, elems.as_slice());
            }
            DuplexSpongeMode::Squeezing {
                next_squeeze_index: _,
            } => {
                self.permute();
                self.absorb_internal(0, elems.as_slice());
            }
        };
    }

    fn squeeze_bytes(&mut self, num_bytes: usize) -> Vec<u8> {
        let usable_bytes = ((F::MODULUS_BIT_SIZE - 1) / 8) as usize;

        let num_elements = (num_bytes + usable_bytes - 1) / usable_bytes;
        let src_elements = self.squeeze_native_field_elements(num_elements);

        let mut bytes: Vec<u8> = Vec::with_capacity(usable_bytes * num_elements);
        for elem in &src_elements {
            let elem_bytes = elem.into_bigint().to_bytes_le();
            bytes.extend_from_slice(&elem_bytes[..usable_bytes]);
        }

        bytes.truncate(num_bytes);
        bytes
    }

    fn squeeze_bits(&mut self, num_bits: usize) -> Vec<bool> {
        let usable_bits = (F::MODULUS_BIT_SIZE - 1) as usize;

        let num_elements = (num_bits + usable_bits - 1) / usable_bits;
        let src_elements = self.squeeze_native_field_elements(num_elements);

        let mut bits: Vec<bool> = Vec::with_capacity(usable_bits * num_elements);
        for elem in &src_elements {
            let elem_bits = elem.into_bigint().to_bits_le();
            bits.extend_from_slice(&elem_bits[..usable_bits]);
        }

        bits.truncate(num_bits);
        bits
    }

    fn squeeze_field_elements_with_sizes<F2: PrimeField>(
        &mut self,
        sizes: &[FieldElementSize],
    ) -> Vec<F2> {
        if F::characteristic() == F2::characteristic() {
            // native case
            let mut buf = Vec::with_capacity(sizes.len());
            field_cast(
                &self.squeeze_native_field_elements_with_sizes(sizes),
                &mut buf,
            )
            .unwrap();
            buf
        } else {
            squeeze_field_elements_with_sizes_default_impl(self, sizes)
        }
    }

    fn squeeze_field_elements<F2: PrimeField>(&mut self, num_elements: usize) -> Vec<F2> {
        if TypeId::of::<F>() == TypeId::of::<F2>() {
            let result = self.squeeze_native_field_elements(num_elements);
            let mut cast = Vec::with_capacity(result.len());
            field_cast(&result, &mut cast).unwrap();
            cast
        } else {
            self.squeeze_field_elements_with_sizes::<F2>(
                vec![FieldElementSize::Full; num_elements].as_slice(),
            )
        }
    }
}

impl<F: PrimeField> FieldBasedCryptographicSponge<F> for PoseidonSponge<F> {
    fn squeeze_native_field_elements(&mut self, num_elements: usize) -> Vec<F> {
        let mut squeezed_elems = vec![F::zero(); num_elements];
        match self.mode {
            DuplexSpongeMode::Absorbing {
                next_absorb_index: _,
            } => {
                self.permute();
                self.squeeze_internal(0, &mut squeezed_elems);
            }
            DuplexSpongeMode::Squeezing { next_squeeze_index } => {
                let mut squeeze_index = next_squeeze_index;
                if squeeze_index == self.parameters.rate {
                    self.permute();
                    squeeze_index = 0;
                }
                self.squeeze_internal(squeeze_index, &mut squeezed_elems);
            }
        };

        squeezed_elems
    }
}

#[derive(Clone)]
/// Stores the state of a Poseidon Sponge. Does not store any parameter.
pub struct PoseidonSpongeState<F: PrimeField> {
    state: Vec<F>,
    mode: DuplexSpongeMode,
}

impl<CF: PrimeField> SpongeExt for PoseidonSponge<CF> {
    type State = PoseidonSpongeState<CF>;

    fn from_state(state: Self::State, params: &Self::Config) -> Self {
        let mut sponge = Self::new(params);
        sponge.mode = state.mode;
        sponge.state = state.state;
        sponge
    }

    fn into_state(self) -> Self::State {
        Self::State {
            state: self.state,
            mode: self.mode,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::sponge::poseidon::PoseidonDefaultConfigField;
    use crate::sponge::test::Fr;
    use crate::sponge::{
        poseidon::PoseidonSponge, CryptographicSponge, FieldBasedCryptographicSponge,
    };
    use ark_ff::MontFp;

    #[test]
    fn test_poseidon_sponge_consistency() {
        let sponge_param = Fr::get_default_poseidon_parameters(2, false).unwrap();

        let mut sponge = PoseidonSponge::<Fr>::new(&sponge_param);
        sponge.absorb(&vec![Fr::from(0u8), Fr::from(1u8), Fr::from(2u8)]);
        let res = sponge.squeeze_native_field_elements(3);
        assert_eq!(
            res[0],
            MontFp!(
                "40442793463571304028337753002242186710310163897048962278675457993207843616876"
            )
        );
        assert_eq!(
            res[1],
            MontFp!("2664374461699898000291153145224099287711224021716202960480903840045233645301")
        );
        assert_eq!(
            res[2],
            MontFp!(
                "50191078828066923662070228256530692951801504043422844038937334196346054068797"
            )
        );
    }
}
