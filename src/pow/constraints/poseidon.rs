use ark_std::borrow::Borrow;

use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_sponge::{
    constraints::{AbsorbGadget, CryptographicSpongeVar},
    poseidon::constraints::PoseidonSpongeVar,
};

use ark_ff::PrimeField;
use ark_r1cs_std::{boolean::Boolean, fields::fp::FpVar, ToBitsGadget};

use crate::cryptographic_hash::constraints::poseidon::PoseidonHashGadget;

use super::PoWGadget;

impl<F: PrimeField, I: AbsorbGadget<F>> PoWGadget<F> for PoseidonHashGadget<F, I> {
    type NonceVar = FpVar<F>;

    fn verify_pow<T: Borrow<Self::InputVar>>(
        cs: ConstraintSystemRef<F>,
        params: &Self::Parameters,
        input: T,
        nonce: &Self::NonceVar,
        difficulty: usize,
    ) -> Result<ark_r1cs_std::boolean::Boolean<F>, SynthesisError> {
        assert!(F::size_in_bits() >= difficulty, "difficulty is too large");

        let mut sponge = PoseidonSpongeVar::new(cs, params);
        sponge.absorb(input.borrow())?;
        sponge.absorb(nonce)?;

        let res = sponge.squeeze_field_elements(1)?[0].clone();
        // we require the least significant `difficulty` bits are zero.
        let mut result = Boolean::TRUE;

        res.to_bits_le()?
            .into_iter()
            .take(difficulty)
            .try_for_each(|b| -> Result<(), SynthesisError> {
                result = result.and(&b.not())?;
                Ok(())
            })?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use crate::ark_std::UniformRand;
    use crate::pow::constraints::PoWGadget;
    use crate::{
        cryptographic_hash::{constraints::poseidon::PoseidonHashGadget, poseidon::PoseidonHash},
        merkle_tree::tests::test_utils::poseidon_parameters,
        pow::PoW,
    };
    use ark_ed_on_bls12_381::Fr;
    use ark_r1cs_std::R1CSVar;
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::test_rng;

    #[test]
    fn test_proof_of_work() {
        const BATCH_SIZE: usize = 64;
        const DIFFICULTY: usize = 14;
        let cs = ConstraintSystem::new_ref();
        let param = poseidon_parameters();
        let mut rng = test_rng();
        let message = (0..5).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let message_var = message
            .iter()
            .map(|x| FpVar::new_witness(cs.clone(), || Ok(x.clone())).unwrap())
            .collect::<Vec<_>>();
        let (proof, _) = PoseidonHash::<_, &[_]>::generate_pow(
            &param,
            &mut rng,
            message.as_slice(),
            DIFFICULTY,
            BATCH_SIZE,
        );

        let proof_var = FpVar::new_witness(cs.clone(), || Ok(proof)).unwrap();
        let result = PoseidonHashGadget::<_, &[_]>::verify_pow(
            cs.clone(),
            &param,
            message_var.as_slice(),
            &proof_var,
            DIFFICULTY,
        )
        .unwrap();
        assert!(result.value().unwrap());
        assert!(cs.is_satisfied().unwrap());
    }
}
