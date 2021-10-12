use ark_std::borrow::Borrow;

use ark_sponge::{
    poseidon::{PoseidonParameters, PoseidonSponge},
    Absorb, CryptographicSponge,
};
use ark_std::marker::PhantomData;

use ark_ff::{BitIteratorLE, PrimeField};

use ark_std::vec::Vec;

use super::{CryptoHash, PoW};

/// A wrapper to poseidon cryptographic sponge.
pub struct PoseidonHash<F: PrimeField, I: Absorb + Sync> {
    _field: PhantomData<F>,
    _input: PhantomData<I>,
}

impl<F: PrimeField, I: Absorb + Sync> CryptoHash for PoseidonHash<F, I> {
    type Parameters = PoseidonParameters<F>;

    type Input = I;

    type Output = F;

    fn setup<R: ark_std::rand::Rng>(_rng: &mut R) -> &Self::Parameters {
        // automatic generation of parameters are not implemented yet
        // therefore, the developers must specify the parameters themselves
        unimplemented!()
    }

    fn digest<T: Borrow<Self::Input>>(param: &Self::Parameters, input: T) -> Self::Output {
        let input = input.borrow();

        let mut sponge = PoseidonSponge::new(param);
        sponge.absorb(input);

        let res = sponge.squeeze_field_elements::<F>(1);
        res[0]
    }
}

impl<F: PrimeField + Absorb, I: Absorb + Sync> PoW for PoseidonHash<F, I> {
    type Nonce = F;

    fn verify(
        param: &Self::Parameters,
        input: &Self::Input,
        nonce: &Self::Nonce,
        difficulty: usize,
    ) -> bool {
        assert!(F::size_in_bits() >= difficulty, "difficulty is too large");
        let input = input.borrow();

        let mut sponge = PoseidonSponge::new(param);
        sponge.absorb(input);
        sponge.absorb(nonce);

        let res = sponge.squeeze_field_elements::<F>(1)[0];
        // we requires the least significant `difficulty` bits are zero
        let res = BitIteratorLE::new(res.into_repr())
            .take(difficulty)
            .collect::<Vec<_>>();
        res.into_iter().all(|x| !x)
    }

    fn initial_nonce<R: ark_std::rand::Rng>(_param: &Self::Parameters, rng: &mut R) -> Self::Nonce {
        // Start with a random position.
        F::rand(rng)
    }

    fn next_nonce(_param: &Self::Parameters, nonce: &Self::Nonce) -> Self::Nonce {
        *nonce + F::one()
    }
}

#[cfg(test)]
mod tests {
    use ark_std::test_rng;

    use crate::{merkle_tree::tests::test_utils::poseidon_parameters, pow::PoW};

    use super::PoseidonHash;
    #[test]
    fn test_pow() {
        const BATCH_SIZE: usize = 64;
        const DIFFICULTY: usize = 15;
        let param = poseidon_parameters();
        let message = vec![0x11, 0x12, 0x13, 0x14, 0x15];
        let mut rng = test_rng();
        let (proof, num_batches_iterated) =
            PoseidonHash::generate_pow(&param, &mut rng, &&message[..], DIFFICULTY, BATCH_SIZE);
        println!(
            "total number of iterations: {}x{} = {}",
            num_batches_iterated,
            BATCH_SIZE,
            num_batches_iterated * BATCH_SIZE
        );
        let result = PoseidonHash::verify(&param, &&message[..], &proof, DIFFICULTY);
        assert!(result);
    }
}
