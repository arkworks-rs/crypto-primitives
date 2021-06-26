mod constraints;

use crate::{CRH, Error};
use ark_serialize::CanonicalSerialize;
use ark_std::borrow::Borrow;
use ark_std::rand::Rng;
use crate::crh::TwoToOneCRH;
use ark_std::vec::Vec;
pub struct AsBytesOutputCRH<C> {
    _marker: C
}

impl<C: CRH> CRH for AsBytesOutputCRH<C>
    where C::Output: CanonicalSerialize
{
    type Input = C::Input;
    type Output = Vec<u8>;
    type Parameters = C::Parameters;

    fn setup<R: Rng>(r: &mut R) -> Result<Self::Parameters, Error> {
        C::setup(r)
    }

    fn evaluate<T: Borrow<Self::Input>>(parameters: &Self::Parameters, input: T) -> Result<Self::Output, Error> {
        let output = C::evaluate(parameters, input)?;
        let mut output_bytes = Vec::new();
        output.serialize(&mut output_bytes)?;
        Ok(output_bytes)
    }
}

impl<C: TwoToOneCRH> TwoToOneCRH for AsBytesOutputCRH<C>
    where C::Output: CanonicalSerialize
{
    type Input = C::Input;
    type Output = Vec<u8>;
    type Parameters = C::Parameters;

    fn setup<R: Rng>(r: &mut R) -> Result<Self::Parameters, Error> {
        C::setup(r)
    }

    fn evaluate<T: Borrow<Self::Input>>(parameters: &Self::Parameters, left_input: T, right_input: T) -> Result<Self::Output, Error> {
        let output = C::evaluate(parameters, left_input, right_input)?;
        let mut output_bytes = Vec::new();
        output.serialize(&mut output_bytes)?;
        Ok(output_bytes)
    }
}