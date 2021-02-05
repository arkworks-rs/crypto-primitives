use super::CommitmentScheme;
use crate::Error;
use ark_std::rand::Rng;
use blake2::Blake2s as b2s;
use digest::Digest;

pub struct Commitment;

#[cfg(feature = "r1cs")]
pub mod constraints;

impl CommitmentScheme for Commitment {
    type Parameters = ();
    type Randomness = [u8; 32];
    type Output = [u8; 32];

    fn setup<R: Rng>(_: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    fn commit(
        _: &Self::Parameters,
        input: &[u8],
        r: &Self::Randomness,
    ) -> Result<Self::Output, Error> {
        let mut h = b2s::new();
        h.update(input);
        h.update(r.as_ref());
        let mut result = [0u8; 32];
        result.copy_from_slice(&h.finalize());
        Ok(result)
    }
}
