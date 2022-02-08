use ark_ff::PrimeField;
use ark_r1cs_std::bits::{boolean::Boolean, uint32::UInt32, uint8::UInt8, ToBitsGadget};
use core::iter;

/// Extra traits not automatically implemented by UInt32
pub(crate) trait UInt32Ext<ConstraintF: PrimeField> {
    /// Right shift
    fn shr(&self, by: usize) -> Self;

    /// Bitwise NOT
    fn not(&self) -> Self;

    /// Bitwise AND
    fn bitand(&self, rhs: &Self) -> Self;

    /// Converts from big-endian bytes
    fn from_be_bytes(bytes: &[UInt8<ConstraintF>]) -> Self;

    /// Converts to big-endian bytes
    fn to_be_bytes(&self) -> Vec<UInt8<ConstraintF>>;
}

impl<ConstraintF: PrimeField> UInt32Ext<ConstraintF> for UInt32<ConstraintF> {
    fn shr(&self, by: usize) -> Self {
        assert!(by < 32);

        let zeros = iter::repeat(Boolean::constant(false)).take(by);
        let new_bits: Vec<_> = self
            .to_bits_le()
            .into_iter()
            .skip(by)
            .chain(zeros)
            .collect();
        UInt32::from_bits_le(&new_bits)
    }

    fn not(&self) -> Self {
        let new_bits: Vec<_> = self.to_bits_le().iter().map(Boolean::not).collect();
        UInt32::from_bits_le(&new_bits)
    }

    fn bitand(&self, rhs: &Self) -> Self {
        let new_bits: Vec<_> = self
            .to_bits_le()
            .into_iter()
            .zip(rhs.to_bits_le().into_iter())
            .map(|(a, b)| a.and(&b).unwrap())
            .collect();
        UInt32::from_bits_le(&new_bits)
    }

    fn from_be_bytes(bytes: &[UInt8<ConstraintF>]) -> Self {
        assert_eq!(bytes.len(), 4);

        let bits: Vec<_> = bytes
            .iter()
            .rev()
            .flat_map(|b| b.to_bits_le().unwrap())
            .collect();
        UInt32::from_bits_le(&bits)
    }

    fn to_be_bytes(&self) -> Vec<UInt8<ConstraintF>> {
        self.to_bits_le()
            .chunks(8)
            .rev()
            .map(UInt8::from_bits_le)
            .collect()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use ark_bls12_377::Fr;
    use ark_r1cs_std::{bits::uint32::UInt32, R1CSVar};
    use ark_std::rand::Rng;

    const NUM_TESTS: usize = 10_000;

    #[test]
    fn test_shr() {
        let mut rng = ark_std::test_rng();
        for _ in 0..NUM_TESTS {
            let x = rng.gen::<u32>();
            let by = rng.gen::<usize>() % 32;
            assert_eq!(UInt32::<Fr>::constant(x).shr(by).value().unwrap(), x >> by);
        }
    }

    #[test]
    fn test_bitand() {
        let mut rng = ark_std::test_rng();
        for _ in 0..NUM_TESTS {
            let x = rng.gen::<u32>();
            let y = rng.gen::<u32>();
            assert_eq!(
                UInt32::<Fr>::constant(x)
                    .bitand(&UInt32::constant(y))
                    .value()
                    .unwrap(),
                x & y
            );
        }
    }

    #[test]
    fn test_to_from_be_bytes() {
        let mut rng = ark_std::test_rng();
        for _ in 0..NUM_TESTS {
            let x = UInt32::<Fr>::constant(rng.gen::<u32>());
            let bytes = x.to_be_bytes();
            let y = UInt32::from_be_bytes(&bytes);
            assert_eq!(x.value(), y.value());
        }
    }
}
