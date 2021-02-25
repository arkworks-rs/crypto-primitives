use crate::{Error, Vec};
use ark_std::rand::Rng;
use ark_std::{
    fmt::{Debug, Formatter, Result as FmtResult},
    marker::PhantomData,
};

use ark_relations::r1cs::{Namespace, SynthesisError};

use ark_r1cs_std::bits::boolean::Boolean;

type ConstraintF<P> = <<P as ModelParameters>::BaseField as Field>::BasePrimeField;

#[derive(Derivative)]
#[derivative(Clone(bound = "P: TEModelParameters, W: Window"))]
pub struct PoseidonRoundParamsVar<P: TEModelParameters, W: Window> {
    params: Parameters<P>,
    #[doc(hidden)]
    _window: PhantomData<W>,
}

pub struct PoseidonCRHGadget<F: PrimeField, W: Window, P: PoseidonRoundParamsVar> {
    field: PhantomData<F>,
    window: PhantomData<W>,
    params: PhantomData<P>
}

// https://github.com/arkworks-rs/r1cs-std/blob/master/src/bits/uint8.rs#L343