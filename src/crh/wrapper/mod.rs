mod constraints;

use crate::{CRH, Error};
use ark_serialize::CanonicalSerialize;
use ark_std::borrow::Borrow;
use ark_std::rand::Rng;
use crate::crh::TwoToOneCRH;
use ark_std::vec::Vec;
pub struct InputToBytesWrapper<C, T: CanonicalSerialize> {
    _marker: (C, T)
}

impl<C: CRH<Input=[u8]>, T: CanonicalSerialize> CRH for InputToBytesWrapper<C, T>
    where C::Input: CanonicalSerialize
{
    type Input = T;
    type Output = C::Output;
    type Parameters = C::Parameters;

    fn setup<R: Rng>(r: &mut R) -> Result<Self::Parameters, Error> {
        C::setup(r)
    }

    fn evaluate<P: Borrow<Self::Input>>(parameters: &Self::Parameters, input: P) -> Result<Self::Output, Error> {
        let mut input_bytes = Vec::new();
        input.borrow().serialize(&mut input_bytes)?;
        C::evaluate(parameters, input_bytes)
    }
}

impl<C: TwoToOneCRH<Input=[u8]>, T: CanonicalSerialize> TwoToOneCRH for InputToBytesWrapper<C, T>
    where C::Output: CanonicalSerialize
{
    type Input = T;
    type Output = C::Output;
    type Parameters = C::Parameters;


    fn setup<R: Rng>(r: &mut R) -> Result<Self::Parameters, Error> {
        C::setup(r)
    }

    fn evaluate<P: Borrow<Self::Input>>(parameters: &Self::Parameters, left_input: P, right_input: P) -> Result<Self::Output, Error> {
        let mut left_input_bytes = Vec::new();
        left_input.borrow().serialize(&mut left_input_bytes)?;

        let mut right_input_bytes = Vec::new();
        right_input.borrow().serialize(&mut right_input_bytes)?;
        C::evaluate(parameters, left_input_bytes, right_input_bytes)
    }
}