use crate::sponge::constraints::AbsorbGadget;
use crate::sponge::constraints::{CryptographicSpongeVar, SpongeWithGadget};
use crate::sponge::rescue::{RescueConfig, RescueSponge};
use crate::sponge::DuplexSpongeMode;
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};

#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;

pub const RESCUE_PREDICATE: &str = "Deg5-Mul";

#[derive(Clone)]
/// Constraints for the Rescue sponge.
pub struct RescueSpongeVar<F: PrimeField> {
    /// Constraint system
    pub cs: ConstraintSystemRef<F>,

    /// Sponge Parameters
    pub parameters: RescueConfig<F>,

    /// The sponge's state
    pub state: Vec<FpVar<F>>,
    /// The mode
    pub mode: DuplexSpongeMode,
}

impl<F: PrimeField> SpongeWithGadget<F> for RescueSponge<F> {
    type Var = RescueSpongeVar<F>;
}

impl<F: PrimeField> RescueSpongeVar<F> {
    #[tracing::instrument(target = "gr1cs", skip(self))]
    fn apply_s_box(
        &self,
        state: &mut [FpVar<F>],
        alpha: u64,
        is_forward_pass: bool,
    ) -> Result<(), SynthesisError> {
        if alpha == 5 && self.cs.has_predicate(RESCUE_PREDICATE) {
            use ark_relations::lc;

            let cs = state
                .iter()
                .fold(ConstraintSystemRef::None, |cs, item| cs.or(item.cs()));

            if is_forward_pass {
                for state_item in state {
                    if let FpVar::Var(ref fp) = state_item {
                        let new_state_item = FpVar::new_witness(cs.clone(), || {
                            state_item.value().map(|e| e.pow([self.parameters.alpha]))
                        })?;
                        let FpVar::Var(ref new_fp) = new_state_item else {
                            return Err(SynthesisError::AssignmentMissing);
                        };
                        cs.enforce_constraint_arity_2(
                            RESCUE_PREDICATE,
                            || lc![fp.variable],
                            || lc![new_fp.variable],
                        )?;
                        *state_item = new_state_item;
                    } else {
                        // If the state item is a constant, we can just raise it to the power of alpha.
                        *state_item = state_item.pow_by_constant([self.parameters.alpha])?;
                    }
                }
            } else {
                let alpha_inv = self.parameters.alpha_inv.to_u64_digits();
                for state_item in state {
                    if let FpVar::Var(ref fp) = state_item {
                        let new_state_item = FpVar::new_witness(cs.clone(), || {
                            state_item.value().map(|e| e.pow(&alpha_inv))
                        })?;
                        let FpVar::Var(ref new_fp) = new_state_item else {
                            return Err(SynthesisError::AssignmentMissing);
                        };
                        cs.enforce_constraint_arity_2(
                            RESCUE_PREDICATE,
                            || lc![new_fp.variable],
                            || lc![fp.variable],
                        )?;
                        *state_item = new_state_item;
                    } else {
                        // If the state item is a constant, we can just raise it to alpha_inv.
                        *state_item = state_item.pow_by_constant(&alpha_inv)?;
                    }
                }
            }
        } else if is_forward_pass {
            for state_item in state.iter_mut() {
                *state_item = state_item.pow_by_constant([self.parameters.alpha])?;
            }
        } else {
            for state_item in state.iter_mut() {
                let output = FpVar::new_witness(self.cs(), || {
                    state_item
                        .value()
                        .map(|e| e.pow(self.parameters.alpha_inv.to_u64_digits()))
                })?;
                let expected_input = output.pow_by_constant([alpha])?;
                expected_input.enforce_equal(state_item)?;
                *state_item = output;
            }
        }

        Ok(())
    }

    #[tracing::instrument(target = "gr1cs", skip(self))]
    fn apply_ark(&self, state: &mut [FpVar<F>], round_key: &Vec<F>) -> Result<(), SynthesisError> {
        for (i, state_elem) in state.iter_mut().enumerate() {
            *state_elem += round_key[i];
        }
        Ok(())
    }

    #[tracing::instrument(target = "gr1cs", skip(self))]
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

    #[tracing::instrument(target = "gr1cs", skip(self))]
    fn permute(&mut self) -> Result<(), SynthesisError> {
        let mut state = self.state.clone();
        self.apply_ark(&mut state, &self.parameters.arc[0])?;
        for (round, round_key) in self.parameters.arc[1..].iter().enumerate() {
            if (round % 2) == 0 {
                self.apply_s_box(&mut state, self.parameters.alpha, false)?;
            } else {
                self.apply_s_box(&mut state, self.parameters.alpha, true)?;
            }
            self.apply_mds(&mut state)?;
            self.apply_ark(&mut state, round_key)?;
        }
        self.state = state;
        Ok(())
    }

    #[tracing::instrument(target = "gr1cs", skip(self))]
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
    #[tracing::instrument(target = "gr1cs", skip(self))]
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

impl<F: PrimeField> CryptographicSpongeVar<F, RescueSponge<F>> for RescueSpongeVar<F> {
    type Parameters = RescueConfig<F>;

    fn new(cs: ConstraintSystemRef<F>, parameters: &RescueConfig<F>) -> Self {
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

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.cs.clone()
    }

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

    #[tracing::instrument(target = "gr1cs", skip(self))]
    fn squeeze_bytes(&mut self, num_bytes: usize) -> Result<Vec<UInt8<F>>, SynthesisError> {
        let usable_bytes = ((F::MODULUS_BIT_SIZE - 1) / 8) as usize;

        let num_elements = (num_bytes + usable_bytes - 1) / usable_bytes;
        let src_elements = self.squeeze_field_elements(num_elements)?;

        let mut bytes: Vec<UInt8<F>> = Vec::with_capacity(usable_bytes * num_elements);
        for elem in &src_elements {
            bytes.extend_from_slice(&elem.to_bytes_le()?[..usable_bytes]);
        }

        bytes.truncate(num_bytes);
        Ok(bytes)
    }

    #[tracing::instrument(target = "gr1cs", skip(self))]
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

    #[tracing::instrument(target = "gr1cs", skip(self))]
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
