use crate::{signature::SignatureScheme, Error};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{
    fields::{Field, PrimeField},
    AdditiveGroup, One, ToConstraintField, UniformRand, Zero,
};
use ark_serialize::CanonicalSerialize;
#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;
use ark_std::{hash::Hash, marker::PhantomData, ops::Mul, rand::Rng};
use digest::Digest;

#[cfg(feature = "r1cs")]
pub mod constraints;

pub struct Schnorr<C: CurveGroup, D: Digest> {
    _group: PhantomData<C>,
    _hash: PhantomData<D>,
}

#[derive(Derivative)]
#[derivative(Clone(bound = "C: CurveGroup, H: Digest"), Debug)]
pub struct Parameters<C: CurveGroup, H: Digest> {
    _hash: PhantomData<H>,
    pub generator: C::Affine,
    pub salt: [u8; 32],
}

pub type PublicKey<C> = <C as CurveGroup>::Affine;

#[derive(Clone, Default, Debug, CanonicalSerialize)]
pub struct SecretKey<C: CurveGroup>(pub C::ScalarField);

#[derive(Clone, Default, Debug)]
pub struct Signature<C: CurveGroup> {
    pub prover_response: C::ScalarField,
    pub verifier_challenge: C::ScalarField,
}

impl<C: CurveGroup + Hash, D: Digest + Send + Sync> SignatureScheme for Schnorr<C, D>
where
    C::ScalarField: PrimeField,
{
    type Parameters = Parameters<C, D>;
    type PublicKey = PublicKey<C>;
    type SecretKey = SecretKey<C>;
    type Signature = Signature<C>;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error> {
        let setup_time = start_timer!(|| "SchnorrSig::Setup");

        let mut salt = [0u8; 32];
        rng.fill_bytes(&mut salt);
        let generator = C::rand(rng).into();

        end_timer!(setup_time);
        Ok(Parameters {
            _hash: PhantomData,
            generator,
            salt,
        })
    }

    fn keygen<R: Rng>(
        parameters: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), Error> {
        let keygen_time = start_timer!(|| "SchnorrSig::KeyGen");

        let secret_key = C::ScalarField::rand(rng);
        let public_key = parameters.generator.mul(secret_key).into();

        end_timer!(keygen_time);
        Ok((public_key, SecretKey(secret_key)))
    }

    fn sign<R: Rng>(
        parameters: &Self::Parameters,
        sk: &Self::SecretKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self::Signature, Error> {
        let sign_time = start_timer!(|| "SchnorrSig::Sign");
        // (k, e);
        let (random_scalar, verifier_challenge) = loop {
            // Sample a random scalar `k` from the prime scalar field.
            let random_scalar: C::ScalarField = C::ScalarField::rand(rng);
            // Commit to the random scalar via r := k · G.
            // This is the prover's first msg in the Sigma protocol.
            let prover_commitment = parameters.generator.mul(random_scalar).into_affine();

            // Hash everything to get verifier challenge.
            let mut hash_input = Vec::new();
            parameters.salt.serialize_compressed(&mut hash_input)?;
            prover_commitment.serialize_compressed(&mut hash_input)?;
            message.serialize_compressed(&mut hash_input)?;

            // Compute the supposed verifier response: e := H(salt || r || msg);
            if let Some(verifier_challenge) =
                C::ScalarField::from_random_bytes(&D::digest(&hash_input))
            {
                break (random_scalar, verifier_challenge);
            };
        };

        // k - xe;
        let prover_response = random_scalar - (verifier_challenge * sk.0);
        let signature = Signature {
            prover_response,
            verifier_challenge,
        };

        end_timer!(sign_time);
        Ok(signature)
    }

    fn verify(
        parameters: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool, Error> {
        let verify_time = start_timer!(|| "SchnorrSig::Verify");

        let Signature {
            prover_response,
            verifier_challenge,
        } = signature;
        let mut claimed_prover_commitment = parameters.generator.mul(*prover_response);
        let public_key_times_verifier_challenge = pk.mul(*verifier_challenge);
        claimed_prover_commitment += &public_key_times_verifier_challenge;
        let claimed_prover_commitment = claimed_prover_commitment.into_affine();

        let mut hash_input = Vec::new();
        parameters.salt.serialize_compressed(&mut hash_input)?;
        claimed_prover_commitment.serialize_compressed(&mut hash_input)?;
        message.serialize_compressed(&mut hash_input)?;

        let obtained_verifier_challenge = if let Some(obtained_verifier_challenge) =
            C::ScalarField::from_random_bytes(&D::digest(&hash_input))
        {
            obtained_verifier_challenge
        } else {
            return Ok(false);
        };
        end_timer!(verify_time);
        Ok(verifier_challenge == &obtained_verifier_challenge)
    }

    fn randomize_public_key(
        parameters: &Self::Parameters,
        public_key: &Self::PublicKey,
        randomness: &[u8],
    ) -> Result<Self::PublicKey, Error> {
        let rand_pk_time = start_timer!(|| "SchnorrSig::RandomizePubKey");

        let randomized_pk = *public_key;
        let base = parameters.generator;
        let mut encoded = C::zero();
        for bit in bytes_to_bits(randomness)
            .into_iter()
            .rev()
            .skip_while(|b| !b)
        {
            encoded.double_in_place();
            if bit {
                encoded.add_assign(&base)
            }
        }
        encoded.add_assign(&randomized_pk);

        end_timer!(rand_pk_time);

        Ok(encoded.into())
    }

    fn randomize_signature(
        _parameter: &Self::Parameters,
        signature: &Self::Signature,
        randomness: &[u8],
    ) -> Result<Self::Signature, Error> {
        let rand_signature_time = start_timer!(|| "SchnorrSig::RandomizeSig");
        let Signature {
            prover_response,
            verifier_challenge,
        } = signature;
        let mut base = C::ScalarField::one();
        let mut multiplier = C::ScalarField::zero();
        for bit in bytes_to_bits(randomness) {
            if bit {
                multiplier += &base;
            }
            base.double_in_place();
        }

        let new_sig = Signature {
            prover_response: *prover_response - (*verifier_challenge * multiplier),
            verifier_challenge: *verifier_challenge,
        };
        end_timer!(rand_signature_time);
        Ok(new_sig)
    }
}

pub fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for i in 0..8 {
            let bit = (*byte >> (8 - i - 1)) & 1;
            bits.push(bit == 1);
        }
    }
    bits
}

impl<ConstraintF: Field, C: CurveGroup + ToConstraintField<ConstraintF>, D: Digest>
    ToConstraintField<ConstraintF> for Parameters<C, D>
{
    #[inline]
    fn to_field_elements(&self) -> Option<Vec<ConstraintF>> {
        self.generator.into_group().to_field_elements()
    }
}
