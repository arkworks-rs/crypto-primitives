use crate::Vec;
use ark_ec::ProjectiveCurve;
use ark_ff::Field;
use ark_r1cs_std::{prelude::*, fields::FieldVar};
use ark_relations::r1cs::{Namespace, SynthesisError};

use crate::crh::*;
use crate::signature::{SigVerifyGadget, SigRandomizePkGadget};

use core::{borrow::Borrow, marker::PhantomData};

use crate::signature::schnorr::{Parameters, PublicKey, Schnorr};
use digest::Digest;

type ConstraintF<C> = <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField;

#[derive(Clone)]
pub struct ParametersVar<C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    generator: GC,
    salt: [UInt8; 32],
    _curve: PhantomData<C>,
}

#[derive(Derivative)]
#[derivative(
    Debug(bound = "C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>"),
    Clone(bound = "C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>")
)]
pub struct PublicKeyVar<C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    pub_key: GC,
    #[doc(hidden)]
    _group: PhantomData<*const C>,
}

pub struct SignatureVar<F: Field, CF: Field, FVar: FieldVar<F, CF>>
{
    prover_response: FVar,
    verifier_challenge: FVar,
    #[doc(hidden)]
    _field: PhantomData<*const F>,
    #[doc(hidden)]
    _constraint_field: PhantomData<*const CF>,
}

pub struct SchnorrSignatureVerifyGadget<
    H: CRH, 
    C: ProjectiveCurve, 
    H2F: CRHGadget<H, ConstraintF<C>>, 
    GC: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    #[doc(hidden)]
    _group: PhantomData<*const C>,
    #[doc(hidden)]
    _group_gadget: PhantomData<*const GC>,
}

impl<C, GC, D, H, H2F> SigVerifyGadget<Schnorr<C, D>> 
    for SchnorrSignatureVerifyGadget<H, C, H2F, GC>
where
    H: CRH,
    C: ProjectiveCurve,
    H2F: CRHGadget<H, ConstraintF<C>>,
    GC: CurveVar<C, ConstraintF<C>>,
    D: Digest + Send + Sync,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    type ParametersVar = ParametersVar<C, GC>;
    type PublicKeyVar = PublicKeyVar<C, GC>;
    type SignatureVar = SignatureVar<ConstraintF<C>, ConstraintF<C>, ConstraintF<C>>;


    fn verify(
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        message: UInt8<ConstraintF>,
        signature: &Self::SignatureVar,
    ) -> Result<Boolean<ConstraintF>, SynthesisError>
    {
        let prover_response = signature.prover_response;
        let verifier_challenge = signature.verifier_challenge;
        let mut claimed_prover_commitment = parameters.generator.mul(*prover_response);
        let public_key_times_verifier_challenge = public_key.mul(*verifier_challenge);
        claimed_prover_commitment += &public_key_times_verifier_challenge;
        let claimed_prover_commitment = claimed_prover_commitment.into_affine();

        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&parameters.salt);
        hash_input.extend_from_slice(&claimed_prover_commitment.to_bytes()?);
        hash_input.extend_from_slice(&message);

        // TODO: Change to H2F
        let obtained_verifier_challenge = if let Some(obtained_verifier_challenge) =
            C::ScalarField::from_random_bytes(&D::digest(&hash_input))
        {
            obtained_verifier_challenge
        } else {
            return Ok(false);
        };
        
        Ok(verifier_challenge.equals(obtained_verifier_challenge))
    }
}

pub struct SchnorrRandomizePkGadget<C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    #[doc(hidden)]
    _group: PhantomData<*const C>,
    #[doc(hidden)]
    _group_gadget: PhantomData<*const GC>,
}

impl<C, GC, D> SigRandomizePkGadget<Schnorr<C, D>, ConstraintF<C>>
    for SchnorrRandomizePkGadget<C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C, ConstraintF<C>>,
    D: Digest + Send + Sync,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    type ParametersVar = ParametersVar<C, GC>;
    type PublicKeyVar = PublicKeyVar<C, GC>;

    #[tracing::instrument(target = "r1cs", skip(parameters, public_key, randomness))]
    fn randomize(
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        randomness: &[UInt8<ConstraintF<C>>],
    ) -> Result<Self::PublicKeyVar, SynthesisError> {
        let base = parameters.generator.clone();
        let randomness = randomness
            .iter()
            .flat_map(|b| b.to_bits_le().unwrap())
            .collect::<Vec<_>>();
        let rand_pk = &public_key.pub_key + &base.scalar_mul_le(randomness.iter())?;
        Ok(PublicKeyVar {
            pub_key: rand_pk,
            _group: PhantomData,
        })
    }
}

impl<C, GC, D> AllocVar<Parameters<C, D>, ConstraintF<C>> for ParametersVar<C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C, ConstraintF<C>>,
    D: Digest,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    fn new_variable<T: Borrow<Parameters<C, D>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let generator = GC::new_variable(cs, || f().map(|g| g.borrow().generator), mode)?;
        let salt = f().map(|b| b.borrow().salt);
        Ok(Self {
            generator,
            salt,
            _curve: PhantomData,
        })
    }
}

impl<C, GC> AllocVar<PublicKey<C>, ConstraintF<C>> for PublicKeyVar<C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    fn new_variable<T: Borrow<PublicKey<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let pub_key = GC::new_variable(cs, f, mode)?;
        Ok(Self {
            pub_key,
            _group: PhantomData,
        })
    }
}

impl<ConstraintF> AllocVar<ConstraintF> for SignatureVar<ConstraintF>
where
    ConstraintF: ProjectiveCurve,
{
    fn new_variable<T: Borrow<Signature<ConstraintF>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let pub_key = GC::new_variable(cs, f, mode)?;
        Ok(Self {
            pub_key,
            _group: PhantomData,
        })
    }
}

impl<C, GC> EqGadget<ConstraintF<C>> for PublicKeyVar<C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    #[inline]
    fn is_eq(&self, other: &Self) -> Result<Boolean<ConstraintF<C>>, SynthesisError> {
        self.pub_key.is_eq(&other.pub_key)
    }

    #[inline]
    fn conditional_enforce_equal(
        &self,
        other: &Self,
        condition: &Boolean<ConstraintF<C>>,
    ) -> Result<(), SynthesisError> {
        self.pub_key
            .conditional_enforce_equal(&other.pub_key, condition)
    }

    #[inline]
    fn conditional_enforce_not_equal(
        &self,
        other: &Self,
        condition: &Boolean<ConstraintF<C>>,
    ) -> Result<(), SynthesisError> {
        self.pub_key
            .conditional_enforce_not_equal(&other.pub_key, condition)
    }
}

impl<C, GC> ToBytesGadget<ConstraintF<C>> for PublicKeyVar<C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    fn to_bytes(&self) -> Result<Vec<UInt8<ConstraintF<C>>>, SynthesisError> {
        self.pub_key.to_bytes()
    }
}
