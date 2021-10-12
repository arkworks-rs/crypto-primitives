use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_sponge::{
    constraints::{AbsorbGadget, CryptographicSpongeVar},
    poseidon::{constraints::PoseidonSpongeVar, PoseidonParameters},
};
use ark_std::marker::PhantomData;

use ark_ff::PrimeField;
use ark_r1cs_std::{boolean::Boolean, fields::fp::FpVar, ToBitsGadget};

use super::{CryptoHashGadget, PoWGadget};

pub struct PoseidonHashGadget<F: PrimeField, I: AbsorbGadget<F>> {
    _field: PhantomData<F>,
    _input: PhantomData<I>,
}

impl<F: PrimeField, I: AbsorbGadget<F>> CryptoHashGadget<F> for PoseidonHashGadget<F, I> {
    type Parameters = PoseidonParameters<F>;

    type InputVar = I;

    type OutputVar = FpVar<F>;

    fn digest<T: ark_std::borrow::Borrow<Self::InputVar>>(
        cs: ConstraintSystemRef<F>,
        params: &Self::Parameters,
        input: T,
    ) -> Result<Self::OutputVar, SynthesisError> {
        let input = input.borrow();
        let mut sponge = PoseidonSpongeVar::new(cs, params);
        sponge.absorb(input)?;

        let res = sponge.squeeze_field_elements(1)?;
        Ok(res[0].clone())
    }
}

impl<F: PrimeField, I: AbsorbGadget<F>> PoWGadget<F> for PoseidonHashGadget<F, I> {
    type NonceVar = FpVar<F>;

    fn verify(
        cs: ConstraintSystemRef<F>,
        params: &Self::Parameters,
        input: &Self::InputVar,
        nonce: &Self::NonceVar,
        difficulty: usize,
    ) -> Result<ark_r1cs_std::boolean::Boolean<F>, SynthesisError> {
        assert!(F::size_in_bits() >= difficulty, "difficulty is too large");

        let mut sponge = PoseidonSpongeVar::new(cs, params);
        sponge.absorb(input)?;
        sponge.absorb(nonce)?;

        let res = sponge.squeeze_field_elements(1)?[0].clone();
        // we require the least significant `difficulty` bits are zero.
        let mut result = Boolean::TRUE;

        res.to_bits_le()?
            .into_iter()
            .try_for_each(|b| -> Result<(), SynthesisError> {
                result = result.and(&b.not())?;
                Ok(())
            })?;
        Ok(result)
    }
}
