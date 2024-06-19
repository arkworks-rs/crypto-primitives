use crate::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    sponge::{
        poseidon::{PoseidonConfig, PoseidonSponge},
        Absorb, CryptographicSponge,
    },
    Error,
};
use ark_ff::PrimeField;
use ark_std::{borrow::Borrow, marker::PhantomData, rand::Rng};

#[cfg(feature = "r1cs")]
pub mod constraints;

pub struct CRH<F: PrimeField + Absorb> {
    field_phantom: PhantomData<F>,
}

impl<F: PrimeField + Absorb> CRHScheme for CRH<F> {
    type Input = [F];
    type Output = F;
    type Parameters = PoseidonConfig<F>;

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        // automatic generation of parameters are not implemented yet
        // therefore, the developers must specify the parameters themselves
        unimplemented!()
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let input = input.borrow();

        let mut sponge = PoseidonSponge::new(parameters);
        sponge.absorb(&input);
        let res = sponge.squeeze_field_elements::<F>(1);
        Ok(res[0])
    }
}

pub struct TwoToOneCRH<F: PrimeField + Absorb> {
    field_phantom: PhantomData<F>,
}

impl<F: PrimeField + Absorb> TwoToOneCRHScheme for TwoToOneCRH<F> {
    type Input = F;
    type Output = F;
    type Parameters = PoseidonConfig<F>;

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        // automatic generation of parameters are not implemented yet
        // therefore, the developers must specify the parameters themselves
        unimplemented!()
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error> {
        Self::compress(parameters, left_input, right_input)
    }

    fn compress<T: Borrow<Self::Output>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error> {
        let left_input = left_input.borrow();
        let right_input = right_input.borrow();

        let mut sponge = PoseidonSponge::new(parameters);
        sponge.absorb(left_input);
        sponge.absorb(right_input);
        let res = sponge.squeeze_field_elements::<F>(1);
        Ok(res[0])
    }
}
