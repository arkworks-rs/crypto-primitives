use ark_std::borrow::Borrow;

use ark_std::marker::PhantomData;

use ark_ff::PrimeField;
use ark_sponge::{
    poseidon::{PoseidonParameters, PoseidonSponge},
    Absorb, CryptographicSponge,
};

use super::CryptoHash;

/// A wrapper to poseidon cryptographic sponge.
pub struct PoseidonHash<F: PrimeField, I: Absorb + Sync> {
    _field: PhantomData<F>,
    _input: PhantomData<I>,
}

impl<F: PrimeField, I: Absorb + Sync> CryptoHash for PoseidonHash<F, I> {
    type Parameters = PoseidonParameters<F>;

    type Input = I;

    type Output = F;

    fn setup<R: ark_std::rand::Rng>(_rng: &mut R) -> &Self::Parameters {
        // automatic generation of parameters are not implemented yet
        // therefore, the developers must specify the parameters themselves
        unimplemented!()
    }

    fn digest<T: Borrow<Self::Input>>(param: &Self::Parameters, input: T) -> Self::Output {
        let input = input.borrow();

        let mut sponge = PoseidonSponge::new(param);
        sponge.absorb(input);

        let res = sponge.squeeze_field_elements::<F>(1);
        res[0]
    }
}
