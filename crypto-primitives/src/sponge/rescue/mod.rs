use crate::sponge::{
    field_cast, squeeze_field_elements_with_sizes_default_impl, Absorb, CryptographicSponge,
    DuplexSpongeMode, FieldBasedCryptographicSponge, FieldElementSize, SpongeExt,
};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::any::TypeId;
#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;
use num_bigint::BigUint;
/// constraints for Rescue
#[cfg(feature = "constraints")]
pub mod constraints;

/// Config and RNG used
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct RescueConfig<F: PrimeField> {
    /// Number of rounds
    /// specified by parameter `N` in the [paper](https://eprint.iacr.org/2020/1143.pdf)
    pub rounds: usize,
    /// Exponent used in S-boxes.
    pub alpha: u64,
    /// Exponent used in inverse S-boxes.
    pub alpha_inv: BigUint,
    /// Additive Round constants.
    /// They are indexed by `ark[round_num][state_element_index]`
    /// specified by parameter `round_constants` in the [paper](https://eprint.iacr.org/2020/1143.pdf) in a flattened array.
    pub arc: Vec<Vec<F>>,
    /// Maximally Distance Separating (MDS) Matrix.
    pub mds: Vec<Vec<F>>,
    /// The rate (in terms of number of field elements). specified by parameter `r_p` in the [paper](https://eprint.iacr.org/2020/1143.pdf)
    pub rate: usize,
    /// The capacity (in terms of number of field elements). specified by parameter `c_p` in the [paper](https://eprint.iacr.org/2020/1143.pdf)
    pub capacity: usize,
}

#[derive(Clone)]
/// A duplex sponge based using the Rescue permutation.
pub struct RescueSponge<F: PrimeField> {
    /// Sponge Config
    pub parameters: RescueConfig<F>,

    // Sponge State
    /// Current sponge's state (current elements in the permutation block)
    pub state: Vec<F>,
    /// Current mode (whether its absorbing or squeezing)
    pub mode: DuplexSpongeMode,
}

impl<F: PrimeField> RescueSponge<F> {
    /// Apply the S-box to the state. the exponent can be `alpha` or `alpha_inv` depending on the position of the s-box in the permutation.
    fn apply_s_box(&self, state: &mut [F], round: usize) {
        if (round % 2) == 0 {
            for elem in state {
                *elem = elem.pow(self.parameters.alpha_inv.to_u64_digits());
            }
        } else {
            for elem in state {
                *elem = elem.pow([self.parameters.alpha]);
            }
        }
    }

    /// Apply the additive round constants to the state. Depending on the round number i, the round key is fetched from `RescueConfig.arc[i]`
    fn apply_arc(&self, state: &mut [F], round_number: usize) {
        for (i, state_elem) in state.iter_mut().enumerate() {
            state_elem.add_assign(&self.parameters.arc[round_number][i]);
        }
    }

    /// Multiply the state with the MDS matrix. The MDS matrix is stored in `RescueConfig.mds`
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

    /// The permutation function of the Rescue Sponge. It corresponds to the Algorithm 3 in the [paper](https://eprint.iacr.org/2020/1143.pdf)
    fn permute(&mut self) {
        let mut state = self.state.clone();
        assert_eq!(self.parameters.rounds * 2 + 1, self.parameters.arc.len());
        self.apply_arc(&mut state, 0);
        for (round, _round_key) in self.parameters.arc[1..].iter().enumerate() {
            self.apply_s_box(&mut state, round);
            self.apply_mds(&mut state);
            self.apply_arc(&mut state, round + 1);
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

impl<F: PrimeField> RescueConfig<F> {
    /// Initialize the parameter for Rescue Sponge.
    pub fn new(
        rounds: usize,
        alpha: u64,
        alpha_inv: BigUint,
        mds: Vec<Vec<F>>,
        arc: Vec<Vec<F>>,
        rate: usize,
        capacity: usize,
    ) -> Self {
        assert_eq!(arc.len(), 2 * rounds + 1);
        for item in &arc {
            assert_eq!(item.len(), rate + capacity);
        }
        assert_eq!(mds.len(), rate + capacity);
        for item in &mds {
            assert_eq!(item.len(), rate + capacity);
        }
        Self {
            rounds,
            alpha,
            alpha_inv,
            mds,
            arc,
            rate,
            capacity,
        }
    }
}

impl<F: PrimeField> CryptographicSponge for RescueSponge<F> {
    type Config = RescueConfig<F>;

    fn new(parameters: &Self::Config) -> Self {
        // The initial state of the sponge is all zeros
        let state = vec![F::zero(); parameters.rate + parameters.capacity];

        // The mode of the sponge is initially set to Absorbing the first element
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
        let elems: Vec<F> = input.to_sponge_field_elements_as_vec::<F>();
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

        let num_elements = num_bytes.div_ceil(usable_bytes);
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

        let num_elements = num_bits.div_ceil(usable_bits);
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

impl<F: PrimeField> FieldBasedCryptographicSponge<F> for RescueSponge<F> {
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
/// Stores the state of a Rescue Sponge. Does not store any parameter.
pub struct RescueSpongeState<F: PrimeField> {
    state: Vec<F>,
    mode: DuplexSpongeMode,
}

impl<CF: PrimeField> SpongeExt for RescueSponge<CF> {
    type State = RescueSpongeState<CF>;

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
