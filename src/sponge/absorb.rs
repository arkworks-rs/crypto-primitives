use ark_ec::short_weierstrass::Affine as SWAffine;
use ark_ec::twisted_edwards::Affine as TEAffine;
use ark_ec::{
    short_weierstrass::SWCurveConfig as SWModelParameters,
    twisted_edwards::TECurveConfig as TEModelParameters,
};
use ark_ff::models::{Fp, FpConfig};
use ark_ff::{BigInteger, PrimeField, ToConstraintField};
use ark_serialize::CanonicalSerialize;
use ark_std::vec::Vec;

/// An interface for objects that can be absorbed by a `CryptographicSponge`.
pub trait Absorb {
    /// Converts the object into a list of bytes that can be absorbed by a `CryptographicSponge`.
    /// Append the list to `dest`.
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>);

    /// Converts the object into a list of bytes that can be absorbed by a `CryptographicSponge`.
    /// Return the list as `Vec`.
    fn to_sponge_bytes_as_vec(&self) -> Vec<u8> {
        let mut result = Vec::new();
        self.to_sponge_bytes(&mut result);
        result
    }

    /// Converts the object into field elements that can be absorbed by a `CryptographicSponge`.
    /// Append the list to `dest`
    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>);

    /// Converts the object into field elements that can be absorbed by a `CryptographicSponge`.
    /// Return the list as `Vec`
    fn to_sponge_field_elements_as_vec<F: PrimeField>(&self) -> Vec<F> {
        let mut result = Vec::new();
        self.to_sponge_field_elements(&mut result);
        result
    }

    /// Specifies the conversion into a list of bytes for a batch. Append the list to `dest`.
    fn batch_to_sponge_bytes(batch: &[Self], dest: &mut Vec<u8>)
    where
        Self: Sized,
    {
        for absorbable in batch {
            absorbable.to_sponge_bytes(dest)
        }
    }

    /// Specifies the conversion into a list of bytes for a batch. Return the list as `Vec`.
    fn batch_to_sponge_bytes_as_vec(batch: &[Self]) -> Vec<u8>
    where
        Self: Sized,
    {
        let mut result = Vec::new();
        Self::batch_to_sponge_bytes(batch, &mut result);
        result
    }

    /// Specifies the conversion into a list of field elements for a batch. Append the list to `dest`.
    fn batch_to_sponge_field_elements<F: PrimeField>(batch: &[Self], dest: &mut Vec<F>)
    where
        Self: Sized,
    {
        for absorbable in batch {
            absorbable.to_sponge_field_elements(dest)
        }
    }

    /// Specifies the conversion into a list of field elements for a batch. Append the list to `dest`.
    fn batch_to_sponge_field_elements_as_vec<F: PrimeField>(batch: &[Self]) -> Vec<F>
    where
        Self: Sized,
    {
        let mut result = Vec::new();
        for absorbable in batch {
            absorbable.to_sponge_field_elements(&mut result)
        }
        result
    }
}

/// An extension to `Absorb` that is specific to items with variable length, such as a list.
pub trait AbsorbWithLength: Absorb {
    /// The length of the `self` being absorbed.
    fn absorb_length(&self) -> usize;

    /// Converts the object into a list of bytes along with its length information
    /// that can be absorbed by a `CryptographicSponge`.
    /// Append the list to `dest`.
    fn to_sponge_bytes_with_length(&self, dest: &mut Vec<u8>) {
        self.absorb_length().to_sponge_bytes(dest);
        self.to_sponge_bytes(dest)
    }

    /// Converts the object into field elements along with its length information
    /// that can be absorbed by a `CryptographicSponge`.
    /// Append the list to `dest`
    fn to_sponge_field_elements_with_length<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.absorb_length().to_sponge_field_elements(dest);
        <Self as Absorb>::to_sponge_field_elements(&self, dest)
    }
}

/// If `F1` equals to `F2`, add all elements of `x` as `F2` to `dest` and returns `dest` pointer.
///
/// This function will return None and no-op if `F1` is not equal to `F2`.
pub(crate) fn field_cast<'a, F1: PrimeField, F2: PrimeField>(
    x: &[F1],
    dest: &'a mut Vec<F2>,
) -> Option<&'a mut Vec<F2>> {
    if F1::characteristic() != F2::characteristic() {
        // "Trying to absorb non-native field elements."
        None
    } else {
        x.iter().for_each(|item| {
            let bytes = item.into_bigint().to_bytes_le();
            dest.push(F2::from_le_bytes_mod_order(&bytes))
        });
        Some(dest)
    }
}

impl Absorb for u8 {
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        dest.push(*self)
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        dest.push(F::from(*self))
    }

    fn batch_to_sponge_bytes(batch: &[Self], dest: &mut Vec<u8>) {
        dest.extend_from_slice(batch)
    }

    fn batch_to_sponge_field_elements<F: PrimeField>(batch: &[Self], dest: &mut Vec<F>) {
        let mut bytes = (batch.len() as u64).to_le_bytes().to_vec();
        bytes.extend_from_slice(batch);
        dest.extend_from_slice(&bytes.to_field_elements().unwrap()[..])
    }
}

impl Absorb for bool {
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        dest.push(*self as u8)
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        dest.push(F::from(*self))
    }
}

impl<P: FpConfig<N>, const N: usize> Absorb for Fp<P, N> {
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        self.serialize_compressed(dest).unwrap()
    }
    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        let _ = field_cast(&[*self], dest);
    }
    fn batch_to_sponge_field_elements<F: PrimeField>(batch: &[Self], dest: &mut Vec<F>)
    where
        Self: Sized,
    {
        field_cast(batch, dest).unwrap();
    }
}

macro_rules! impl_absorbable_unsigned {
    ($t:ident) => {
        impl Absorb for $t {
            fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
                dest.extend_from_slice(&self.to_le_bytes()[..])
            }

            fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
                dest.push(F::from(*self))
            }
        }
    };
}
//
impl_absorbable_unsigned!(u16);
impl_absorbable_unsigned!(u32);
impl_absorbable_unsigned!(u64);
impl_absorbable_unsigned!(u128);

macro_rules! impl_absorbable_signed {
    ($signed:ident, $unsigned:ident) => {
        impl Absorb for $signed {
            fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
                dest.extend_from_slice(&self.to_le_bytes()[..])
            }

            fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
                let mut elem = F::from(self.abs() as $unsigned);
                if *self < 0 {
                    elem = -elem;
                }
                dest.push(elem)
            }
        }
    };
}

impl_absorbable_signed!(i8, u8);
impl_absorbable_signed!(i16, u16);
impl_absorbable_signed!(i32, u32);
impl_absorbable_signed!(i64, u64);
impl_absorbable_signed!(i128, u128);

impl Absorb for usize {
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        dest.extend_from_slice(&((*self as u64).to_le_bytes())[..])
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        (*self as u64).to_sponge_field_elements(dest)
    }
}

impl Absorb for isize {
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        dest.extend_from_slice(&self.to_le_bytes()[..])
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        (*self as i64).to_sponge_field_elements(dest)
    }
}

impl<CF: PrimeField, P: TEModelParameters<BaseField = CF>> Absorb for TEAffine<P> {
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        self.to_field_elements()
            .unwrap()
            .serialize_compressed(dest)
            .unwrap()
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        field_cast::<P::BaseField, _>(&self.to_field_elements().unwrap(), dest).unwrap();
    }
}

impl<CF: PrimeField, P: SWModelParameters<BaseField = CF>> Absorb for SWAffine<P> {
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        self.to_field_elements()
            .unwrap()
            .serialize_compressed(dest)
            .unwrap()
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        field_cast::<P::BaseField, _>(&self.to_field_elements().unwrap(), dest).unwrap();
    }
}

impl<A: Absorb> Absorb for &[A] {
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        A::batch_to_sponge_bytes(self, dest)
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        A::batch_to_sponge_field_elements(self, dest)
    }
}

impl<A: Absorb> AbsorbWithLength for &[A] {
    fn absorb_length(&self) -> usize {
        self.len()
    }
}

impl<A: Absorb> Absorb for Vec<A> {
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        self.as_slice().to_sponge_bytes(dest)
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.as_slice().to_sponge_field_elements(dest)
    }
}

impl<A: Absorb> AbsorbWithLength for Vec<A> {
    fn absorb_length(&self) -> usize {
        self.as_slice().len()
    }
}

impl<A: Absorb> Absorb for Option<A> {
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        self.is_some().to_sponge_bytes(dest);
        if let Some(item) = self {
            item.to_sponge_bytes(dest)
        }
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.is_some().to_sponge_field_elements(dest);
        if let Some(item) = self {
            item.to_sponge_field_elements(dest)
        }
    }
}

// TODO: add more for common data structures, treemap?

impl<A: Absorb> Absorb for &A {
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        (*self).to_sponge_bytes(dest)
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        (*self).to_sponge_field_elements(dest)
    }
}

/// Individually absorbs each element in a comma-separated list of absorbables into a sponge.
/// Format is `absorb!(s, a_0, a_1, ..., a_n)`, where `s` is a mutable reference to a sponge
/// and each `a_i` implements `Absorb`.
#[macro_export]
macro_rules! absorb {
    ($sponge:expr, $($absorbable:expr),+ ) => {
        $(
            CryptographicSponge::absorb($sponge, &$absorbable);
        )+
    };
}

/// Quickly convert a list of different [`Absorb`]s into sponge bytes.
#[macro_export]
macro_rules! collect_sponge_bytes {
    ($head:expr $(, $tail:expr)* ) => {
        {
            let mut output = Absorb::to_sponge_bytes_as_vec(&$head);
            $(
                Absorb::to_sponge_bytes(&$tail, &mut output);
            )*
            output
        }
    };
}

/// Quickly convert a list of different [`Absorb`]s into sponge field elements.
#[macro_export]
macro_rules! collect_sponge_field_elements {
    ($head:expr $(, $tail:expr)* ) => {
        {
            let mut output = Absorb::to_sponge_field_elements_as_vec(&$head);
            $(
               Absorb::to_sponge_field_elements(&$tail, &mut output);
            )*
            output
        }
    };
}

#[cfg(test)]
mod tests {
    use crate::sponge::field_cast;
    use crate::sponge::test::Fr;
    use ark_std::{test_rng, vec::Vec, UniformRand};

    #[test]
    fn test_cast() {
        let mut rng = test_rng();
        let expected: Vec<_> = (0..10).map(|_| Fr::rand(&mut rng)).collect();
        let mut actual = Vec::new();
        field_cast::<_, Fr>(&expected, &mut actual).unwrap();
        assert_eq!(actual, expected);
    }
}
