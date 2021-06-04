use crate::{CryptoError, Error, Vec, CRH as CRHTrait};
use ark_ff::fields::PrimeField;
use ark_ff::BigInteger;
use ark_ff::ToConstraintField;
use ark_std::marker::PhantomData;
use ark_std::rand::Rng;

#[cfg(feature = "r1cs")]
pub mod constraints;

pub struct CRH<F: PrimeField> {
    field: PhantomData<F>,
}

impl<F: PrimeField> CRHTrait for CRH<F> {
    const INPUT_SIZE_BITS: usize = F::BigInt::NUM_LIMBS * 64;
    type Output = F;
    type Parameters = ();

    fn setup<R: Rng>(_: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    fn evaluate(_: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error> {
        let f_inputs: Vec<F> = input
            .to_field_elements()
            .ok_or(CryptoError::IncorrectInputLength(input.len()))?;

        Ok(f_inputs
            .get(0)
            .cloned()
            .ok_or(CryptoError::IncorrectInputLength(input.len()))?)
    }
}

#[cfg(test)]
mod test {
    use super::CRH;
    use crate::crh::CRH as CRHTrait;
    use ark_ed_on_bn254::Fq;
    use ark_ff::FpParameters;
    use ark_ff::{to_bytes, PrimeField};

    type IdentityCRH = CRH<Fq>;

    pub fn safe_to_bytes<F: PrimeField>(fs: &[F]) -> Vec<u8> {
        let mut bytes = Vec::new();
        let max_size = (F::Params::CAPACITY / 8) as usize;
        fs.iter().for_each(|x| {
            let f_bytes = to_bytes![x].unwrap();
            bytes.extend(f_bytes[..max_size].to_vec());
        });
        bytes
    }
    #[test]
    fn should_return_same_data() {
        let val = Fq::from(4u64);

        let bytes = safe_to_bytes(&[val]);
        let res = IdentityCRH::evaluate(&(), &bytes).unwrap();

        assert_eq!(res, val);
    }
}
