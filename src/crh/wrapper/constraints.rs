// TODO: fix this constraint (not sure what I am doing wrong here)

use ark_r1cs_std::ToBytesGadget;
use ark_ff::Field;
use crate::{CRHGadget, CRH};
use ark_r1cs_std::uint8::UInt8;
use ark_relations::r1cs::SynthesisError;
use crate::crh::{TwoToOneCRH, TwoToOneCRHGadget};

pub struct InputToBytesWrapperGadget<C, ConstraintF: Field, T: ToBytesGadget<ConstraintF>> {
    _marker: (C, ConstraintF, T)
}

impl<C, ConstraintF: Field, T: ToBytesGadget<ConstraintF>, H: CRH<Input=[u8]>> CRHGadget<H, ConstraintF>
    for InputToBytesWrapperGadget<C, ConstraintF, T>
        where C: CRHGadget<H, ConstraintF, InputVar=Vec<UInt8<ConstraintF>>>{
        type InputVar = T;
        type OutputVar = C::OutputVar;
        type ParametersVar = C::ParametersVar;

    fn evaluate(parameters: &Self::ParametersVar, input: &Self::InputVar) -> Result<Self::OutputVar, SynthesisError> {
        let input_bytes = input.to_bytes()?;
        C::evaluate(parameters, &input_bytes)
    }
}

impl<C, ConstraintF: Field, T: ToBytesGadget<ConstraintF>, H: TwoToOneCRH<Input=[u8]>> TwoToOneCRHGadget<H, ConstraintF>
for InputToBytesWrapperGadget<C, ConstraintF, T>
    where C: TwoToOneCRHGadget<H, ConstraintF, InputVar=Vec<UInt8<ConstraintF>>>{
    type InputVar = T;
    type OutputVar = C::OutputVar;
    type ParametersVar = C::ParametersVar;

    fn evaluate(parameters: &Self::ParametersVar,
                left_input: &Self::InputVar,
                right_input: &Self::InputVar) -> Result<Self::OutputVar, SynthesisError> {
        let left_input_bytes = left_input.to_bytes()?;
        let right_input_bytes = right_input.to_bytes()?;
        C::evaluate(parameters, &left_input_bytes, &right_input_bytes)
    }
}