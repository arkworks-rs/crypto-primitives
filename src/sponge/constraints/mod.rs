use crate::sponge::{Absorb, CryptographicSponge, FieldElementSize};
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::bits::boolean::Boolean;
use ark_r1cs_std::bits::uint8::UInt8;
use ark_r1cs_std::fields::fp::{AllocatedFp, FpVar};
use ark_r1cs_std::fields::nonnative::params::{get_params, OptimizationType};
use ark_r1cs_std::fields::nonnative::{AllocatedNonNativeFieldVar, NonNativeFieldVar};
use ark_r1cs_std::R1CSVar;
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSystemRef, LinearCombination, SynthesisError};
use ark_std::vec;
use ark_std::vec::Vec;

mod absorb;
pub use absorb::*;

/// Converts little-endian bits to a list of nonnative elements.
pub fn bits_le_to_nonnative<'a, F: PrimeField, CF: PrimeField>(
    cs: ConstraintSystemRef<CF>,
    all_nonnative_bits_le: impl IntoIterator<Item = &'a Vec<Boolean<CF>>>,
) -> Result<Vec<NonNativeFieldVar<F, CF>>, SynthesisError> {
    let all_nonnative_bits_le = all_nonnative_bits_le.into_iter().collect::<Vec<_>>();
    if all_nonnative_bits_le.is_empty() {
        return Ok(Vec::new());
    }

    let mut max_nonnative_bits = 0usize;
    for bits in &all_nonnative_bits_le {
        max_nonnative_bits = max_nonnative_bits.max(bits.len());
    }

    let mut lookup_table = Vec::<Vec<CF>>::new();
    let mut cur = F::one();
    for _ in 0..max_nonnative_bits {
        let repr = AllocatedNonNativeFieldVar::<F, CF>::get_limbs_representations(
            &cur,
            OptimizationType::Constraints,
        )?;
        lookup_table.push(repr);
        cur.double_in_place();
    }

    let params = get_params(
        F::MODULUS_BIT_SIZE as usize,
        CF::MODULUS_BIT_SIZE as usize,
        OptimizationType::Constraints,
    );

    let mut output = Vec::with_capacity(all_nonnative_bits_le.len());
    for nonnative_bits_le in all_nonnative_bits_le {
        let mut val = vec![CF::zero(); params.num_limbs];
        let mut lc = vec![LinearCombination::<CF>::zero(); params.num_limbs];

        for (j, bit) in nonnative_bits_le.iter().enumerate() {
            if bit.value().unwrap_or_default() {
                for (k, val) in val.iter_mut().enumerate().take(params.num_limbs) {
                    *val += &lookup_table[j][k];
                }
            }

            #[allow(clippy::needless_range_loop)]
            for k in 0..params.num_limbs {
                lc[k] = &lc[k] + bit.lc() * lookup_table[j][k];
            }
        }

        let mut limbs = Vec::new();
        for k in 0..params.num_limbs {
            let gadget =
                AllocatedFp::new_witness(ark_relations::ns!(cs, "alloc"), || Ok(val[k])).unwrap();
            lc[k] = lc[k].clone() - (CF::one(), gadget.variable);
            cs.enforce_constraint(lc!(), lc!(), lc[k].clone()).unwrap();
            limbs.push(FpVar::<CF>::from(gadget));
        }

        output.push(NonNativeFieldVar::<F, CF>::Var(
            AllocatedNonNativeFieldVar::<F, CF> {
                cs: cs.clone(),
                limbs,
                num_of_additions_over_normal_form: CF::zero(),
                is_in_the_normal_form: true,
                target_phantom: Default::default(),
            },
        ));
    }

    Ok(output)
}

/// Enables simple access to the "gadget" version of the sponge.
/// Simplifies trait bounds in downstream generic code.
pub trait SpongeWithGadget<CF: PrimeField>: CryptographicSponge {
    /// The gadget version of `Self`.
    type Var: CryptographicSpongeVar<CF, Self>;
}

/// The interface for a cryptographic sponge constraints on field `CF`.
/// A sponge can `absorb` or take in inputs and later `squeeze` or output bytes or field elements.
/// The outputs are dependent on previous `absorb` and `squeeze` calls.
pub trait CryptographicSpongeVar<CF: PrimeField, S: CryptographicSponge>: Clone {
    /// Parameters used by the sponge.
    type Parameters;

    /// Initialize a new instance of the sponge.
    fn new(cs: ConstraintSystemRef<CF>, params: &Self::Parameters) -> Self;

    /// Returns a ref to the underlying constraint system the sponge is operating in.
    fn cs(&self) -> ConstraintSystemRef<CF>;

    /// Absorb an input into the sponge.
    fn absorb(&mut self, input: &impl AbsorbGadget<CF>) -> Result<(), SynthesisError>;

    /// Squeeze `num_bytes` bytes from the sponge.
    fn squeeze_bytes(&mut self, num_bytes: usize) -> Result<Vec<UInt8<CF>>, SynthesisError>;

    /// Squeeze `num_bit` bits from the sponge.
    fn squeeze_bits(&mut self, num_bits: usize) -> Result<Vec<Boolean<CF>>, SynthesisError>;

    /// Squeeze `sizes.len()` nonnative field elements from the sponge, where the `i`-th element of
    /// the output has size `sizes[i]`.
    fn squeeze_nonnative_field_elements_with_sizes<F: PrimeField>(
        &mut self,
        sizes: &[FieldElementSize],
    ) -> Result<(Vec<NonNativeFieldVar<F, CF>>, Vec<Vec<Boolean<CF>>>), SynthesisError> {
        if sizes.len() == 0 {
            return Ok((Vec::new(), Vec::new()));
        }

        let cs = self.cs();

        let mut total_bits = 0usize;
        for size in sizes {
            total_bits += size.num_bits::<F>();
        }

        let bits = self.squeeze_bits(total_bits)?;

        let mut dest_bits = Vec::<Vec<Boolean<CF>>>::with_capacity(sizes.len());

        let mut bits_window = bits.as_slice();
        for size in sizes {
            let num_bits = size.num_bits::<F>();
            let nonnative_bits_le = bits_window[..num_bits].to_vec();
            bits_window = &bits_window[num_bits..];

            dest_bits.push(nonnative_bits_le);
        }

        let dest_gadgets = bits_le_to_nonnative(cs, dest_bits.iter())?;

        Ok((dest_gadgets, dest_bits))
    }

    /// Squeeze `num_elements` nonnative field elements from the sponge.
    fn squeeze_nonnative_field_elements<F: PrimeField>(
        &mut self,
        num_elements: usize,
    ) -> Result<(Vec<NonNativeFieldVar<F, CF>>, Vec<Vec<Boolean<CF>>>), SynthesisError> {
        self.squeeze_nonnative_field_elements_with_sizes::<F>(
            vec![FieldElementSize::Full; num_elements].as_slice(),
        )
    }

    /// Creates a new sponge with applied domain separation.
    fn fork(&self, domain: &[u8]) -> Result<Self, SynthesisError> {
        let mut new_sponge = self.clone();

        let mut input = Absorb::to_sponge_bytes_as_vec(&domain.len());
        input.extend_from_slice(domain);

        let elems: Vec<CF> = input.to_sponge_field_elements_as_vec();
        let elem_vars = elems
            .into_iter()
            .map(|elem| FpVar::Constant(elem))
            .collect::<Vec<_>>();

        new_sponge.absorb(&elem_vars)?;

        Ok(new_sponge)
    }

    /// Squeeze `num_elements` field elements from the sponge.
    fn squeeze_field_elements(
        &mut self,
        num_elements: usize,
    ) -> Result<Vec<FpVar<CF>>, SynthesisError>;
}
