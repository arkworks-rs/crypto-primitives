use ark_ff::Field;
use core::fmt::Debug;

use crate::{Gadget, Vec, prf::PRF};
use ark_relations::r1cs::{Namespace, SynthesisError};

use ark_r1cs_std::prelude::*;

pub trait PRFWithGadget<ConstraintF: Field>: PRF {
    type OutputVar: EqGadget<ConstraintF>
        + ToBytesGadget<ConstraintF>
        + AllocVar<Self::Output, ConstraintF>
        + R1CSVar<ConstraintF, Value = Self::Output>
        + Clone
        + Debug;

    fn new_seed_as_witness(
        cs: impl Into<Namespace<ConstraintF>>,
        seed: &Self::Seed,
    ) -> Vec<UInt8<ConstraintF>>;

    fn evaluate_gadget(
        seed: &[UInt8<ConstraintF>],
        input: &[UInt8<ConstraintF>],
    ) -> Result<Self::OutputVar, SynthesisError>;
}

pub trait PRFGadget<ConstraintF: Field> {
    type Native: PRFWithGadget<
        ConstraintF, 
        OutputVar = Self::OutputVar,
    >;
    type OutputVar: EqGadget<ConstraintF>
        + ToBytesGadget<ConstraintF>
        + AllocVar<<Self::Native as PRF>::Output, ConstraintF>
        + Clone
        + Debug;

    fn new_seed_as_witness(
        cs: impl Into<Namespace<ConstraintF>>,
        seed: &<Self::Native as PRF>::Seed,
    ) -> Vec<UInt8<ConstraintF>> {
        Self::Native::new_seed_as_witness(cs, seed)
    }

    fn evaluate(
        seed: &[UInt8<ConstraintF>],
        input: &[UInt8<ConstraintF>],
    ) -> Result<Self::OutputVar, SynthesisError> {
        Self::Native::evaluate_gadget(seed, input)
    }
}

impl<P, ConstraintF> PRFGadget<ConstraintF> for Gadget<P> 
where
    P: PRFWithGadget<ConstraintF>,
    ConstraintF: Field,
{
    type Native = P;
    type OutputVar = P::OutputVar;

    fn evaluate(
        seed: &[UInt8<ConstraintF>],
        input: &[UInt8<ConstraintF>],
    ) -> Result<Self::OutputVar, SynthesisError> {
        P::evaluate_gadget(seed, input)
    }

}