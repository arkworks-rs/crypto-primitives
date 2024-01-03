use crate::sponge::constraints::AbsorbGadget;
use crate::sponge::constraints::{CryptographicSpongeVar, SpongeWithGadget};
use crate::sponge::poseidon::{PoseidonConfig, PoseidonSponge};
use crate::sponge::DuplexSpongeMode;

use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::vec;
use ark_std::vec::Vec;

#[derive(Clone)]
/// the gadget for Poseidon sponge
///
/// This implementation of Poseidon is entirely from Fractal's implementation in [COS20][cos]
/// with small syntax changes.
///
/// [cos]: https://eprint.iacr.org/2019/1076
pub struct PoseidonSpongeVar<F: PrimeField> {
    /// Constraint system
    pub cs: ConstraintSystemRef<F>,

    /// Sponge Parameters
    pub parameters: PoseidonConfig<F>,

    // Sponge State
    /// The sponge's state
    pub state: Vec<FpVar<F>>,
    /// The mode
    pub mode: DuplexSpongeMode,
}

impl<F: PrimeField> SpongeWithGadget<F> for PoseidonSponge<F> {
    type Var = PoseidonSpongeVar<F>;
}

impl<F: PrimeField> PoseidonSpongeVar<F> {
    #[tracing::instrument(target = "r1cs", skip(self))]
    fn apply_s_box(
        &self,
        state: &mut [FpVar<F>],
        is_full_round: bool,
    ) -> Result<(), SynthesisError> {
        // Full rounds apply the S Box (x^alpha) to every element of state
        if is_full_round {
            for state_item in state.iter_mut() {
                *state_item = state_item.pow_by_constant(&[self.parameters.alpha])?;
            }
        }
        // Partial rounds apply the S Box (x^alpha) to just the first element of state
        else {
            state[0] = state[0].pow_by_constant(&[self.parameters.alpha])?;
        }

        Ok(())
    }

    #[tracing::instrument(target = "r1cs", skip(self))]
    fn apply_ark(&self, state: &mut [FpVar<F>], round_number: usize) -> Result<(), SynthesisError> {
        for (i, state_elem) in state.iter_mut().enumerate() {
            *state_elem += self.parameters.ark[round_number][i];
        }
        Ok(())
    }

    #[tracing::instrument(target = "r1cs", skip(self))]
    fn apply_mds(&self, state: &mut [FpVar<F>]) -> Result<(), SynthesisError> {
        let mut new_state = Vec::new();
        let zero = FpVar::<F>::zero();
        for i in 0..state.len() {
            let mut cur = zero.clone();
            for (j, state_elem) in state.iter().enumerate() {
                let term = state_elem * self.parameters.mds[i][j];
                cur += &term;
            }
            new_state.push(cur);
        }
        state.clone_from_slice(&new_state[..state.len()]);
        Ok(())
    }

    #[tracing::instrument(target = "r1cs", skip(self))]
    fn permute(&mut self) -> Result<(), SynthesisError> {
        let full_rounds_over_2 = self.parameters.full_rounds / 2;
        let mut state = self.state.clone();
        for i in 0..full_rounds_over_2 {
            self.apply_ark(&mut state, i)?;
            self.apply_s_box(&mut state, true)?;
            self.apply_mds(&mut state)?;
        }
        for i in full_rounds_over_2..(full_rounds_over_2 + self.parameters.partial_rounds) {
            self.apply_ark(&mut state, i)?;
            self.apply_s_box(&mut state, false)?;
            self.apply_mds(&mut state)?;
        }

        for i in (full_rounds_over_2 + self.parameters.partial_rounds)
            ..(self.parameters.partial_rounds + self.parameters.full_rounds)
        {
            self.apply_ark(&mut state, i)?;
            self.apply_s_box(&mut state, true)?;
            self.apply_mds(&mut state)?;
        }

        self.state = state;
        Ok(())
    }

    #[tracing::instrument(target = "r1cs", skip(self))]
    fn absorb_internal(
        &mut self,
        mut rate_start_index: usize,
        elements: &[FpVar<F>],
    ) -> Result<(), SynthesisError> {
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

                return Ok(());
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
            self.permute()?;
            // the input elements got truncated by num elements absorbed
            remaining_elements = &remaining_elements[num_elements_absorbed..];
            rate_start_index = 0;
        }
    }

    // Squeeze |output| many elements. This does not end in a squeeze
    #[tracing::instrument(target = "r1cs", skip(self))]
    fn squeeze_internal(
        &mut self,
        mut rate_start_index: usize,
        output: &mut [FpVar<F>],
    ) -> Result<(), SynthesisError> {
        let mut remaining_output = output;
        loop {
            // if we can finish in this call
            if rate_start_index + remaining_output.len() <= self.parameters.rate {
                remaining_output.clone_from_slice(
                    &self.state[self.parameters.capacity + rate_start_index
                        ..(self.parameters.capacity + remaining_output.len() + rate_start_index)],
                );
                self.mode = DuplexSpongeMode::Squeezing {
                    next_squeeze_index: rate_start_index + remaining_output.len(),
                };
                return Ok(());
            }
            // otherwise squeeze (rate - rate_start_index) elements
            let num_elements_squeezed = self.parameters.rate - rate_start_index;
            remaining_output[..num_elements_squeezed].clone_from_slice(
                &self.state[self.parameters.capacity + rate_start_index
                    ..(self.parameters.capacity + num_elements_squeezed + rate_start_index)],
            );

            // Unless we are done with squeezing in this call, permute.
            if remaining_output.len() != self.parameters.rate {
                self.permute()?;
            }
            // Repeat with updated output slices and rate start index
            remaining_output = &mut remaining_output[num_elements_squeezed..];
            rate_start_index = 0;
        }
    }
}

impl<F: PrimeField> CryptographicSpongeVar<F, PoseidonSponge<F>> for PoseidonSpongeVar<F> {
    type Parameters = PoseidonConfig<F>;

    #[tracing::instrument(target = "r1cs", skip(cs))]
    fn new(cs: ConstraintSystemRef<F>, parameters: &PoseidonConfig<F>) -> Self {
        let zero = FpVar::<F>::zero();
        let state = vec![zero; parameters.rate + parameters.capacity];
        let mode = DuplexSpongeMode::Absorbing {
            next_absorb_index: 0,
        };

        Self {
            cs,
            parameters: parameters.clone(),
            state,
            mode,
        }
    }

    #[tracing::instrument(target = "r1cs", skip(self))]
    fn cs(&self) -> ConstraintSystemRef<F> {
        self.cs.clone()
    }

    #[tracing::instrument(target = "r1cs", skip(self, input))]
    fn absorb(&mut self, input: &impl AbsorbGadget<F>) -> Result<(), SynthesisError> {
        let input = input.to_sponge_field_elements()?;
        if input.is_empty() {
            return Ok(());
        }

        match self.mode {
            DuplexSpongeMode::Absorbing { next_absorb_index } => {
                let mut absorb_index = next_absorb_index;
                if absorb_index == self.parameters.rate {
                    self.permute()?;
                    absorb_index = 0;
                }
                self.absorb_internal(absorb_index, input.as_slice())?;
            }
            DuplexSpongeMode::Squeezing {
                next_squeeze_index: _,
            } => {
                self.permute()?;
                self.absorb_internal(0, input.as_slice())?;
            }
        };

        Ok(())
    }

    #[tracing::instrument(target = "r1cs", skip(self))]
    fn squeeze_bytes(&mut self, num_bytes: usize) -> Result<Vec<UInt8<F>>, SynthesisError> {
        let usable_bytes = ((F::MODULUS_BIT_SIZE - 1) / 8) as usize;

        let num_elements = (num_bytes + usable_bytes - 1) / usable_bytes;
        let src_elements = self.squeeze_field_elements(num_elements)?;

        let mut bytes: Vec<UInt8<F>> = Vec::with_capacity(usable_bytes * num_elements);
        for elem in &src_elements {
            bytes.extend_from_slice(&elem.to_bytes()?[..usable_bytes]);
        }

        bytes.truncate(num_bytes);
        Ok(bytes)
    }

    #[tracing::instrument(target = "r1cs", skip(self))]
    fn squeeze_bits(&mut self, num_bits: usize) -> Result<Vec<Boolean<F>>, SynthesisError> {
        let usable_bits = (F::MODULUS_BIT_SIZE - 1) as usize;

        let num_elements = (num_bits + usable_bits - 1) / usable_bits;
        let src_elements = self.squeeze_field_elements(num_elements)?;

        let mut bits: Vec<Boolean<F>> = Vec::with_capacity(usable_bits * num_elements);
        for elem in &src_elements {
            bits.extend_from_slice(&elem.to_bits_le()?[..usable_bits]);
        }

        bits.truncate(num_bits);
        Ok(bits)
    }

    #[tracing::instrument(target = "r1cs", skip(self))]
    fn squeeze_field_elements(
        &mut self,
        num_elements: usize,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let zero = FpVar::zero();
        let mut squeezed_elems = vec![zero; num_elements];
        match self.mode {
            DuplexSpongeMode::Absorbing {
                next_absorb_index: _,
            } => {
                self.permute()?;
                self.squeeze_internal(0, &mut squeezed_elems)?;
            }
            DuplexSpongeMode::Squeezing { next_squeeze_index } => {
                let mut squeeze_index = next_squeeze_index;
                if squeeze_index == self.parameters.rate {
                    self.permute()?;
                    squeeze_index = 0;
                }
                self.squeeze_internal(squeeze_index, &mut squeezed_elems)?;
            }
        };

        Ok(squeezed_elems)
    }
}

#[cfg(test)]
mod tests {
    use crate::sponge::constraints::CryptographicSpongeVar;
    use crate::sponge::poseidon::constraints::PoseidonSpongeVar;
    use crate::sponge::poseidon::tests::poseidon_parameters_for_test;
    use crate::sponge::poseidon::PoseidonSponge;
    use crate::sponge::test::Fr;
    use crate::sponge::{CryptographicSponge, FieldBasedCryptographicSponge, FieldElementSize};
    use ark_ff::{Field, PrimeField, UniformRand};
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::prelude::*;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_relations::*;
    use ark_std::test_rng;

    #[test]
    fn absorb_test() {
        let mut rng = test_rng();
        let cs = ConstraintSystem::new_ref();

        let absorb1: Vec<_> = (0..256).map(|_| Fr::rand(&mut rng)).collect();
        let absorb1_var: Vec<_> = absorb1
            .iter()
            .map(|v| FpVar::new_input(ns!(cs, "absorb1"), || Ok(*v)).unwrap())
            .collect();

        let absorb2: Vec<_> = (0..8).map(|i| vec![i, i + 1, i + 2]).collect();
        let absorb2_var: Vec<_> = absorb2
            .iter()
            .map(|v| UInt8::new_input_vec(ns!(cs, "absorb2"), v).unwrap())
            .collect();

        let sponge_params = poseidon_parameters_for_test();

        let mut native_sponge = PoseidonSponge::<Fr>::new(&sponge_params);
        let mut constraint_sponge = PoseidonSpongeVar::<Fr>::new(cs.clone(), &sponge_params);

        native_sponge.absorb(&absorb1);
        constraint_sponge.absorb(&absorb1_var).unwrap();

        let squeeze1 = native_sponge.squeeze_native_field_elements(1);
        let squeeze2 = constraint_sponge.squeeze_field_elements(1).unwrap();

        assert_eq!(squeeze2.value().unwrap(), squeeze1);
        assert!(cs.is_satisfied().unwrap());

        native_sponge.absorb(&absorb2);
        constraint_sponge.absorb(&absorb2_var).unwrap();

        let squeeze1 = native_sponge.squeeze_native_field_elements(1);
        let squeeze2 = constraint_sponge.squeeze_field_elements(1).unwrap();

        assert_eq!(squeeze2.value().unwrap(), squeeze1);
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn squeeze_with_sizes() {
        let squeeze_bits = Fr::MODULUS_BIT_SIZE / 2;
        let max_squeeze = Fr::from(2).pow(<Fr as PrimeField>::BigInt::from(squeeze_bits));

        let sponge_params = poseidon_parameters_for_test();
        let mut native_sponge = PoseidonSponge::<Fr>::new(&sponge_params);

        let squeeze =
            native_sponge.squeeze_field_elements_with_sizes::<Fr>(&[FieldElementSize::Truncated(
                squeeze_bits as usize,
            )])[0];
        assert!(squeeze < max_squeeze);

        let cs = ConstraintSystem::new_ref();
        let mut constraint_sponge = PoseidonSpongeVar::<Fr>::new(cs.clone(), &sponge_params);

        let (squeeze, bits) = constraint_sponge
            .squeeze_emulated_field_elements_with_sizes::<Fr>(&[FieldElementSize::Truncated(
                squeeze_bits as usize,
            )])
            .unwrap();
        let squeeze = &squeeze[0];
        let bits = &bits[0];
        assert!(squeeze.value().unwrap() < max_squeeze);
        assert_eq!(bits.len(), squeeze_bits as usize);

        // squeeze full
        let (_, bits) = constraint_sponge
            .squeeze_emulated_field_elements_with_sizes::<Fr>(&[FieldElementSize::Full])
            .unwrap();
        let bits = &bits[0];
        assert_eq!(bits.len() as u32, Fr::MODULUS_BIT_SIZE - 1);
    }
}
