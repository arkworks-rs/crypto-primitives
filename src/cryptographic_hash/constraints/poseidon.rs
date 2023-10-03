use ark_std::{borrow::Borrow, marker::PhantomData};

use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_sponge::{
    constraints::{AbsorbGadget, CryptographicSpongeVar},
    poseidon::{constraints::PoseidonSpongeVar, PoseidonParameters},
};

use super::CryptoHashGadget;

pub struct PoseidonHashGadget<F: PrimeField, I: AbsorbGadget<F>> {
    _field: PhantomData<F>,
    _input: PhantomData<I>,
}

impl<F: PrimeField, I: AbsorbGadget<F>> CryptoHashGadget<F> for PoseidonHashGadget<F, I> {
    type Parameters = PoseidonParameters<F>;

    type InputVar = I;

    type OutputVar = FpVar<F>;

    fn digest<T: Borrow<Self::InputVar>>(
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

#[cfg(test)]
mod tests {
    use crate::{
        ark_std::UniformRand,
        cryptographic_hash::{constraints::CryptoHashGadget, poseidon::PoseidonHash, CryptoHash},
        merkle_tree::tests::test_utils::poseidon_parameters,
    };
    use ark_ed_on_bls12_381::Fr;
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::test_rng;

    use super::PoseidonHashGadget;

    #[test]
    fn test_digest() {
        let cs = ConstraintSystem::new_ref();
        let mut rng = test_rng();
        let input = (0..14).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let input_var = input
            .iter()
            .map(|x| FpVar::new_witness(cs.clone(), || Ok(*x)).unwrap())
            .collect::<Vec<_>>();

        let param = poseidon_parameters();

        let native_result = PoseidonHash::<_, &[Fr]>::digest(&param, input.as_slice());
        let var_result =
            PoseidonHashGadget::<_, &[FpVar<_>]>::digest(cs.clone(), &param, input_var.as_slice())
                .unwrap();

        assert_eq!(native_result, var_result.value().unwrap());
        assert!(cs.is_satisfied().unwrap());
    }
}
