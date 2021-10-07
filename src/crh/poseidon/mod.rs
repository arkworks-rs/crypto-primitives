use crate::crh::TwoToOneCRHScheme;
use crate::{CRHScheme, Error};
use ark_ff::PrimeField;
use ark_sponge::poseidon::{PoseidonParameters, PoseidonSponge};
use ark_sponge::{Absorb, CryptographicSponge};
use ark_std::borrow::Borrow;
use ark_std::marker::PhantomData;
use ark_std::rand::Rng;

#[cfg(feature = "r1cs")]
pub mod constraints;

pub struct CRH<F: PrimeField + Absorb> {
    field_phantom: PhantomData<F>,
}

impl<F: PrimeField + Absorb> CRHScheme for CRH<F> {
    type Input = [F];
    type Output = F;
    type Parameters = PoseidonParameters<F>;

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
    type Parameters = PoseidonParameters<F>;

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        // automatic generation of parameters are not implemented yet
        // therefore, the developers must specify the parameters themselves
        unimplemented!()
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        left: T,
        right: T,
    ) -> Result<Self::Output, Error> {
        Self::compress(parameters, left, right)
    }

    fn compress<T: Borrow<Self::Output>>(
        parameters: &Self::Parameters,
        left: T,
        right: T,
    ) -> Result<Self::Output, Error> {
        let left = left.borrow();
        let right = right.borrow();

        let mut sponge = PoseidonSponge::new(parameters);
        sponge.absorb(left);
        sponge.absorb(right);
        let res = sponge.squeeze_field_elements::<F>(1);
        Ok(res[0])
    }
}
