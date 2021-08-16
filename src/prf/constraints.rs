use ark_ff::Field;
use core::fmt::Debug;

use crate::{prf::PRF, Vec};
use ark_relations::r1cs::{Namespace, SynthesisError};

use ark_r1cs_std::prelude::*;

pub trait PRFGadget<ConstraintF: Field>: PRF {
    type OutputVar: EqGadget<ConstraintF>
        + ToBytesGadget<ConstraintF>
        + AllocVar<Self::Output, ConstraintF>
        + R1CSVar<ConstraintF, Value = Self::Output>
        + Clone
        + Debug;

    fn new_seed(
        cs: impl Into<Namespace<ConstraintF>>,
        seed: &Self::Seed,
    ) -> Vec<UInt8<ConstraintF>>;

    fn evaluate(
        seed: &[UInt8<ConstraintF>],
        input: &[UInt8<ConstraintF>],
    ) -> Result<Self::OutputVar, SynthesisError>;
}
