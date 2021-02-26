use ark_relations::r1cs::{Namespace, SynthesisError};
use crate::FixedLengthCRHGadget;
use ark_r1cs_std::uint8::UInt8;
use super::{PoseidonCRH, Poseidon};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::{fields::FieldVar, alloc::AllocVar, prelude::*};
use ark_ff::PrimeField;
use super::PoseidonRoundParams;

use ark_std::{
    marker::PhantomData,
};
use core::{borrow::Borrow};


#[derive(Derivative, Clone)]
pub struct PoseidonRoundParamsVar<F: PrimeField, P: PoseidonRoundParams<F>> {
    params: Poseidon<F, P>,
}

pub struct PoseidonCRHGadget<F: PrimeField, P: PoseidonRoundParams<F>> {
    field: PhantomData<F>,
    params: PoseidonRoundParamsVar<F, P>
}

// https://github.com/arkworks-rs/r1cs-std/blob/master/src/bits/uint8.rs#L343
impl<F: PrimeField, P: PoseidonRoundParams<F>> FixedLengthCRHGadget<PoseidonCRH<F, P>, F> for PoseidonCRHGadget<F, P> {
    type OutputVar = FpVar<F>;
    type ParametersVar = PoseidonRoundParamsVar<F, P>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &[UInt8<F>],
    ) -> Result<Self::OutputVar, SynthesisError> {
        Ok(Self::OutputVar::zero())
    }
}

impl<F: PrimeField, P: PoseidonRoundParams<F>> AllocVar<Poseidon<F, P>, F> for PoseidonRoundParamsVar<F, P> {
    #[tracing::instrument(target = "r1cs", skip(_cs, f))]
    fn new_variable<T: Borrow<Poseidon<F,P>>>(
        _cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let params = f()?.borrow().clone();
        Ok(Self {
            params,
        })
    }
}