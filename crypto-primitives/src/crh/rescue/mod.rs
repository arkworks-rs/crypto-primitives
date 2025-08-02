use crate::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    sponge::{
        rescue::{RescueConfig, RescueSponge},
        Absorb, CryptographicSponge,
    },
    Error,
};
use ark_ff::PrimeField;
use ark_std::vec::Vec;
use ark_std::{borrow::Borrow, marker::PhantomData, rand::Rng};

#[cfg(feature = "constraints")]
pub mod constraints;

/// The Rescue collision-resistant hash function introduced in [SAD20][sad]
/// [sad]: https://eprint.iacr.org/2020/1143.pdf
pub struct CRH<F: PrimeField + Absorb> {
    field_phantom: PhantomData<F>,
}

impl<F: PrimeField + Absorb> CRHScheme for CRH<F> {
    /// The input to Rescue is a list of field elements.
    type Input = [F];
    /// The output of Rescue is a single field element. One can change this to a list of field elements to squeeze more outputs.
    type Output = F;
    /// The parameters for the Rescue sponge, e.g. the number of rounds, mdsm, s-box specifications, etc.
    type Parameters = RescueConfig<F>;

    /// Compute the parameters for the Rescue sponge.
    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        unimplemented!("Automatic generation of parameters is not implemented yet; developers must specify the parameters manually")
    }

    /// Evaluate the Rescue sponge on the input.
    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let input = input.borrow();

        let mut sponge = RescueSponge::new(parameters);
        sponge.absorb(&input);
        let res: Vec<F> = sponge.squeeze_field_elements::<F>(1);
        Ok(res[0])
    }
}

/// The 2-to-1 version of the Rescue collision-resistant hash function introduced in [SAD20][sad] used in Merkle trees.
///
/// [sad]: https://eprint.iacr.org/2020/1143.pdf
pub struct TwoToOneCRH<F: PrimeField + Absorb> {
    field_phantom: PhantomData<F>,
}

impl<F: PrimeField + Absorb> TwoToOneCRHScheme for TwoToOneCRH<F> {
    /// Each of the inputs to the list are field elements.
    type Input = F;
    /// The output of Rescue is a single field element. One can change this to a list of field elements to squeeze more outputs.
    type Output = F;
    /// The parameters for the Rescue sponge, e.g. the number of rounds, mdsm, s-box specifications, etc.
    type Parameters = RescueConfig<F>;

    /// Compute the parameters for the Rescue sponge.
    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        unimplemented!("Automatic generation of parameters is not implemented yet; developers must specify the parameters manually")
    }

    /// Evaluate the Rescue sponge on the inputs left and right.
    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error> {
        Self::compress(parameters, left_input, right_input)
    }

    /// Compress the inputs left and right using the Rescue sponge.
    fn compress<T: Borrow<Self::Output>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error> {
        let left_input = left_input.borrow();
        let right_input = right_input.borrow();

        let mut sponge = RescueSponge::new(parameters);
        sponge.absorb(left_input);
        sponge.absorb(right_input);
        let res = sponge.squeeze_field_elements::<F>(1);
        Ok(res[0])
    }
}
