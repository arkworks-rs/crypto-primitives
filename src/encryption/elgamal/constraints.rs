use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{Namespace, SynthesisError};

use crate::encryption::elgamal::{
    Ciphertext, ElGamal, Parameters, Plaintext, PublicKey, Randomness,
};
use crate::encryption::AsymmetricEncWithGadget;
use ark_ec::ProjectiveCurve;
use ark_ff::{
    fields::{Field, PrimeField},
    to_bytes, Zero,
};
use ark_std::{borrow::Borrow, vec::Vec};

pub type ConstraintF<C> = <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField;

#[derive(Clone, Debug)]
pub struct RandomnessVar<F: Field>(Vec<UInt8<F>>);

impl<C, F> AllocVar<Randomness<C>, F> for RandomnessVar<F>
where
    C: CurveWithVar<ConstraintF<C>>,
    F: PrimeField,
{
    fn new_variable<T: Borrow<Randomness<C>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let r = to_bytes![&f().map(|b| b.borrow().0).unwrap_or(C::ScalarField::zero())].unwrap();
        match mode {
            AllocationMode::Constant => Ok(Self(UInt8::constant_vec(&r))),
            AllocationMode::Input => UInt8::new_input_vec(cs, &r).map(Self),
            AllocationMode::Witness => UInt8::new_witness_vec(cs, &r).map(Self),
        }
    }
}


#[derive(Derivative)]
#[derivative(Clone(bound = "C::Var: Clone"))]
pub struct ParametersVar<C: CurveWithVar<ConstraintF<C>>> {
    generator: C::Var,
}

impl<C> AllocVar<Parameters<C>, ConstraintF<C>> for ParametersVar<C>
where
    C: CurveWithVar<ConstraintF<C>>,
{
    fn new_variable<T: Borrow<Parameters<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        // Always allocate as constant
        let generator = C::Var::new_constant(cs, f().map(|g| g.borrow().generator.into()).unwrap())?;
        Ok(Self {
            generator,
        })
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = "C::Var: Clone"))]
pub struct PlaintextVar<C: CurveWithVar<ConstraintF<C>>> {
    pub plaintext: C::Var,
}

impl<C> AllocVar<Plaintext<C>, ConstraintF<C>> for PlaintextVar<C>
where
    C: CurveWithVar<ConstraintF<C>>,
{
    fn new_variable<T: Borrow<Plaintext<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let plaintext = C::Var::new_variable(cs, f, mode)?;
        Ok(Self {
            plaintext,
        })
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = "C::Var: Clone"))]
pub struct PublicKeyVar<C: CurveWithVar<ConstraintF<C>>> {
    pub pk: C::Var,
}

impl<C> AllocVar<PublicKey<C>, ConstraintF<C>> for PublicKeyVar<C>
where
    C: CurveWithVar<ConstraintF<C>>,
{
    fn new_variable<T: Borrow<PublicKey<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let pk = C::Var::new_variable(cs, f, mode)?;
        Ok(Self {
            pk,
        })
    }
}

#[derive(Derivative, Debug)]
#[derivative(Clone(bound = "C::Var: Clone"))]
pub struct CiphertextVar<C: CurveWithVar<ConstraintF<C>>> {
    pub c1: C::Var,
    pub c2: C::Var,
}

impl<C> AllocVar<Ciphertext<C>, ConstraintF<C>> for CiphertextVar<C>
where
    C: CurveWithVar<ConstraintF<C>>,
{
    fn new_variable<T: Borrow<Ciphertext<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let prep = f().map(|g| *g.borrow());
        let c1 = C::Var::new_variable(cs.clone(), || prep.map(|g| g.borrow().0), mode)?;
        let c2 = C::Var::new_variable(cs.clone(), || prep.map(|g| g.borrow().1), mode)?;
        Ok(Self {
            c1,
            c2,
        })
    }
}

impl<C> EqGadget<ConstraintF<C>> for CiphertextVar<C>
where
    C: CurveWithVar<ConstraintF<C>>,
{
    #[inline]
    fn is_eq(&self, other: &Self) -> Result<Boolean<ConstraintF<C>>, SynthesisError> {
        self.c1.is_eq(&other.c1)?.and(&self.c2.is_eq(&other.c2)?)
    }
}

impl<C> AsymmetricEncWithGadget<ConstraintF<C>> for ElGamal<C>
where
    C: CurveWithVar<ConstraintF<C>>,
    ConstraintF<C>: PrimeField,
{
    type CiphertextVar = CiphertextVar<C>;
    type ParametersVar = ParametersVar<C>;
    type PlaintextVar = PlaintextVar<C>;
    type PublicKeyVar = PublicKeyVar<C>;
    type RandomnessVar = RandomnessVar<ConstraintF<C>>;

    fn encrypt_gadget(
        parameters: &Self::ParametersVar,
        message: &Self::PlaintextVar,
        randomness: &Self::RandomnessVar,
        public_key: &Self::PublicKeyVar,
    ) -> Result<Self::CiphertextVar, SynthesisError> {
        // flatten randomness to little-endian bit vector
        let randomness = randomness
            .0
            .iter()
            .flat_map(|b| b.to_bits_le().unwrap())
            .collect::<Vec<_>>();

        // compute s = randomness*pk
        let s = public_key.pk.scalar_mul_le(randomness.iter())?;

        // compute c1 = randomness*generator
        let c1 = parameters
            .generator
            .scalar_mul_le(randomness.iter())?;

        // compute c2 = m + s
        let c2 = s + &message.plaintext;

        Ok(Self::CiphertextVar {
            c1,
            c2,
        })
    }
}

#[cfg(test)]
mod test {
    use crate::Gadget;
    use crate::encryption::constraints::AsymmetricEncGadget;
    use crate::encryption::elgamal::{ElGamal, Randomness};
    use crate::encryption::AsymmetricEnc;
    use ark_std::{test_rng, UniformRand};

    use ark_ed_on_bls12_381::{EdwardsProjective as JubJub, Fq};

    use ark_r1cs_std::prelude::*;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_elgamal_gadget() {
        let rng = &mut test_rng();

        type TestEnc = ElGamal<JubJub>;
        type TestGadget = Gadget<TestEnc>;

        // compute primitive result
        let parameters = TestEnc::setup(rng).unwrap();
        let (pk, _) = TestEnc::keygen(&parameters, rng).unwrap();
        let msg = JubJub::rand(rng).into();
        let randomness = Randomness::rand(rng);
        let primitive_result = TestEnc::encrypt(&parameters, &pk, &msg, &randomness).unwrap();

        // construct constraint system
        let cs = ConstraintSystem::<Fq>::new_ref();
        let randomness_var =
            <TestGadget as AsymmetricEncGadget<Fq>>::RandomnessVar::new_witness(
                ark_relations::ns!(cs, "gadget_randomness"),
                || Ok(&randomness),
            )
            .unwrap();
        let parameters_var =
            <TestGadget as AsymmetricEncGadget<Fq>>::ParametersVar::new_constant(
                ark_relations::ns!(cs, "gadget_parameters"),
                &parameters,
            )
            .unwrap();
        let msg_var =
            <TestGadget as AsymmetricEncGadget<Fq>>::PlaintextVar::new_witness(
                ark_relations::ns!(cs, "gadget_message"),
                || Ok(&msg),
            )
            .unwrap();
        let pk_var =
            <TestGadget as AsymmetricEncGadget<Fq>>::PublicKeyVar::new_witness(
                ark_relations::ns!(cs, "gadget_public_key"),
                || Ok(&pk),
            )
            .unwrap();

        // use gadget
        let result_var =
            TestGadget::encrypt(&parameters_var, &msg_var, &randomness_var, &pk_var).unwrap();

        // check that result equals expected ciphertext in the constraint system
        let expected_var =
            <TestGadget as AsymmetricEncGadget<Fq>>::CiphertextVar::new_input(
                ark_relations::ns!(cs, "gadget_expected"),
                || Ok(&primitive_result),
            )
            .unwrap();
        expected_var.enforce_equal(&result_var).unwrap();

        assert_eq!(primitive_result.0, result_var.c1.value().unwrap());
        assert_eq!(primitive_result.1, result_var.c2.value().unwrap());
        assert!(cs.is_satisfied().unwrap());
    }
}
