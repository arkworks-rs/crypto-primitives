use crate::{encryption::AsymmetricEncryptionScheme, Error};
use ark_ec::{AdditiveGroup, CurveGroup};
use ark_ff::{fields::PrimeField, UniformRand};
use ark_std::{marker::PhantomData, ops::Mul, rand::Rng};

#[cfg(feature = "r1cs")]
pub mod constraints;

pub struct ElGamal<C: CurveGroup> {
    _group: PhantomData<C>,
}

pub struct Parameters<C: CurveGroup> {
    pub generator: C::Affine,
}

pub type PublicKey<C> = <C as CurveGroup>::Affine;

pub struct SecretKey<C: CurveGroup>(pub C::ScalarField);

pub struct Randomness<C: CurveGroup>(pub C::ScalarField);

impl<C: CurveGroup> UniformRand for Randomness<C> {
    #[inline]
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        Randomness(<C as AdditiveGroup>::Scalar::rand(rng))
    }
}

pub type Plaintext<C> = <C as CurveGroup>::Affine;

pub type Ciphertext<C> = (<C as CurveGroup>::Affine, <C as CurveGroup>::Affine);

impl<C: CurveGroup> AsymmetricEncryptionScheme for ElGamal<C>
where
    C::ScalarField: PrimeField,
{
    type Parameters = Parameters<C>;
    type PublicKey = PublicKey<C>;
    type SecretKey = SecretKey<C>;
    type Randomness = Randomness<C>;
    type Plaintext = Plaintext<C>;
    type Ciphertext = Ciphertext<C>;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error> {
        // get a random generator
        let generator = C::rand(rng).into();

        Ok(Parameters { generator })
    }

    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), Error> {
        // get a random element from the scalar field
        let secret_key: <C as AdditiveGroup>::Scalar = C::ScalarField::rand(rng);

        // compute secret_key*generator to derive the public key
        let public_key = pp.generator.mul(secret_key).into();

        Ok((public_key, SecretKey(secret_key)))
    }

    fn encrypt(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &Self::Plaintext,
        r: &Self::Randomness,
    ) -> Result<Self::Ciphertext, Error> {
        // compute s = r*pk
        let s = pk.mul(r.0).into();

        // compute c1 = r*generator
        let c1 = pp.generator.mul(r.0).into();

        // compute c2 = m + s
        let c2 = *message + s;

        Ok((c1, c2.into_affine()))
    }

    fn decrypt(
        _pp: &Self::Parameters,
        sk: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::Plaintext, Error> {
        let c1: <C as CurveGroup>::Affine = ciphertext.0;
        let c2: <C as CurveGroup>::Affine = ciphertext.1;

        // compute s = secret_key * c1
        let s = c1.mul(sk.0);
        let s_inv = -s;

        // compute message = c2 - s
        let m = c2 + s_inv;

        Ok(m.into_affine())
    }
}

#[cfg(test)]
mod test {
    use ark_std::{test_rng, UniformRand};

    use ark_ed_on_bls12_381::EdwardsProjective as JubJub;

    use crate::encryption::elgamal::{ElGamal, Randomness};
    use crate::encryption::AsymmetricEncryptionScheme;

    #[test]
    fn test_elgamal_encryption() {
        let rng = &mut test_rng();

        // setup and key generation
        let parameters = ElGamal::<JubJub>::setup(rng).unwrap();
        let (pk, sk) = ElGamal::<JubJub>::keygen(&parameters, rng).unwrap();

        // get a random msg and encryption randomness
        let msg = JubJub::rand(rng).into();
        let r = Randomness::rand(rng);

        // encrypt and decrypt the message
        let cipher = ElGamal::<JubJub>::encrypt(&parameters, &pk, &msg, &r).unwrap();
        let check_msg = ElGamal::<JubJub>::decrypt(&parameters, &sk, &cipher).unwrap();

        assert_eq!(msg, check_msg);
    }
}
