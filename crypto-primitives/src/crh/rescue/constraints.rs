use crate::crh::{
    constraints::CRHSchemeGadget as CRHGadgetTrait,
    constraints::TwoToOneCRHSchemeGadget as TwoToOneCRHGadgetTrait,
    rescue::{TwoToOneCRH, CRH},
    CRHScheme,
};
use crate::sponge::{
    constraints::CryptographicSpongeVar,
    rescue::{constraints::RescueSpongeVar, RescueConfig},
};

use crate::sponge::Absorb;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
    GR1CSVar,
};
use ark_relations::gr1cs::{Namespace, SynthesisError};
use ark_std::{borrow::Borrow, marker::PhantomData};

#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;

#[derive(Clone)]
pub struct CRHParametersVar<F: PrimeField + Absorb> {
    pub parameters: RescueConfig<F>,
}

pub struct CRHGadget<F: PrimeField + Absorb> {
    field_phantom: PhantomData<F>,
}

impl<F: PrimeField + Absorb> CRHGadgetTrait<CRH<F>, F> for CRHGadget<F> {
    type InputVar = [FpVar<F>];
    type OutputVar = FpVar<F>;
    type ParametersVar = CRHParametersVar<F>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        let cs = input.cs();

        if cs.is_none() {
            let mut constant_input = Vec::new();
            for var in input.iter() {
                constant_input.push(var.value()?);
            }
            Ok(FpVar::Constant(
                CRH::<F>::evaluate(&parameters.parameters, constant_input).unwrap(),
            ))
        } else {
            let mut sponge = RescueSpongeVar::new(cs, &parameters.parameters);
            sponge.absorb(&input)?;
            let res = sponge.squeeze_field_elements(1)?;

            Ok(res[0].clone())
        }
    }
}

pub struct TwoToOneCRHGadget<F: PrimeField + Absorb> {
    field_phantom: PhantomData<F>,
}

impl<F: PrimeField + Absorb> TwoToOneCRHGadgetTrait<TwoToOneCRH<F>, F> for TwoToOneCRHGadget<F> {
    type InputVar = FpVar<F>;
    type OutputVar = FpVar<F>;
    type ParametersVar = CRHParametersVar<F>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        left_input: &Self::InputVar,
        right_input: &Self::InputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        Self::compress(parameters, left_input, right_input)
    }

    fn compress(
        parameters: &Self::ParametersVar,
        left_input: &Self::OutputVar,
        right_input: &Self::OutputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        let cs = left_input.cs().or(right_input.cs());

        if cs.is_none() {
            Ok(FpVar::Constant(
                CRH::<F>::evaluate(
                    &parameters.parameters,
                    vec![left_input.value()?, right_input.value()?],
                )
                .unwrap(),
            ))
        } else {
            let mut sponge = RescueSpongeVar::new(cs, &parameters.parameters);
            sponge.absorb(left_input)?;
            sponge.absorb(right_input)?;
            let res = sponge.squeeze_field_elements(1)?;
            Ok(res[0].clone())
        }
    }
}

impl<F: PrimeField + Absorb> AllocVar<RescueConfig<F>, F> for CRHParametersVar<F> {
    fn new_variable<T: Borrow<RescueConfig<F>>>(
        _cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().map(|param| {
            let parameters = param.borrow().clone();
            Self { parameters }
        })
    }
}
