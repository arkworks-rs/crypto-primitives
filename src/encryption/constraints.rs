use crate::{Gadget, encryption::AsymmetricEnc};

use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::SynthesisError;
use core::fmt::Debug;

use ark_ff::fields::Field;

pub trait AsymmetricEncWithGadget<ConstraintF: Field>: AsymmetricEnc {
    type CiphertextVar: AllocVar<Self::Ciphertext, ConstraintF>
        + EqGadget<ConstraintF>
        + Clone
        + Sized
        + Debug;
    type ParametersVar: AllocVar<Self::Parameters, ConstraintF> + Clone;
    type PlaintextVar: AllocVar<Self::Plaintext, ConstraintF> + Clone;
    type PublicKeyVar: AllocVar<Self::PublicKey, ConstraintF> + Clone;
    type RandomnessVar: AllocVar<Self::Randomness, ConstraintF> + Clone;

    fn encrypt_gadget(
        parameters: &Self::ParametersVar,
        message: &Self::PlaintextVar,
        randomness: &Self::RandomnessVar,
        public_key: &Self::PublicKeyVar,
    ) -> Result<Self::CiphertextVar, SynthesisError>;
}

pub trait AsymmetricEncGadget<ConstraintF: Field> {
    type Native: AsymmetricEncWithGadget<
        ConstraintF,
        CiphertextVar = Self::CiphertextVar,
        ParametersVar = Self::ParametersVar,
        PlaintextVar = Self::PlaintextVar,
        PublicKeyVar = Self::PublicKeyVar,
        RandomnessVar = Self::RandomnessVar,
    >;
    type CiphertextVar: AllocVar<<Self::Native as AsymmetricEnc>::Ciphertext, ConstraintF>
        + EqGadget<ConstraintF>
        + Clone
        + Sized
        + Debug;
    type ParametersVar: AllocVar<<Self::Native as AsymmetricEnc>::Parameters, ConstraintF> + Clone;
    type PlaintextVar: AllocVar<<Self::Native as AsymmetricEnc>::Plaintext, ConstraintF> + Clone;
    type PublicKeyVar: AllocVar<<Self::Native as AsymmetricEnc>::PublicKey, ConstraintF> + Clone;
    type RandomnessVar: AllocVar<<Self::Native as AsymmetricEnc>::Randomness, ConstraintF> + Clone;

    fn encrypt(
        parameters: &Self::ParametersVar,
        message: &Self::PlaintextVar,
        randomness: &Self::RandomnessVar,
        public_key: &Self::PublicKeyVar,
    ) -> Result<Self::CiphertextVar, SynthesisError> {
        Self::Native::encrypt_gadget(parameters, message, randomness, public_key)
    }
}

impl<Enc, ConstraintF> AsymmetricEncGadget<ConstraintF> for Gadget<Enc> 
where 
    Enc: AsymmetricEncWithGadget<ConstraintF>,
    ConstraintF: Field,
{
    type Native = Enc;
    type CiphertextVar = Enc::CiphertextVar;
    type ParametersVar = Enc::ParametersVar;
    type PlaintextVar = Enc::PlaintextVar;
    type PublicKeyVar = Enc::PublicKeyVar;
    type RandomnessVar = Enc::RandomnessVar;
}
