use ark_ec::{
    short_weierstrass::SWCurveConfig as SWModelParameters,
    twisted_edwards::TECurveConfig as TEModelParameters, CurveConfig as ModelParameters,
};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::bits::boolean::Boolean;
use ark_r1cs_std::bits::uint8::UInt8;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::{FieldOpsBounds, FieldVar};
use ark_r1cs_std::groups::curves::short_weierstrass::{
    AffineVar as SWAffineVar, ProjectiveVar as SWProjectiveVar,
};
use ark_r1cs_std::groups::curves::twisted_edwards::AffineVar as TEAffineVar;
use ark_r1cs_std::{ToBytesGadget, ToConstraintFieldGadget};
use ark_relations::r1cs::SynthesisError;
use ark_std::vec;
use ark_std::vec::Vec;
/// An interface for objects that can be absorbed by a `CryptographicSpongeVar` whose constraint field
/// is `CF`.
pub trait AbsorbGadget<F: PrimeField> {
    /// Converts the object into a list of bytes that can be absorbed by a `CryptographicSpongeVar`.
    /// return the list.
    fn to_sponge_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError>;

    /// Specifies the conversion into a list of bytes for a batch.
    fn batch_to_sponge_bytes(batch: &[Self]) -> Result<Vec<UInt8<F>>, SynthesisError>
    where
        Self: Sized,
    {
        let mut result = Vec::new();
        for item in batch {
            result.append(&mut (item.to_sponge_bytes()?))
        }
        Ok(result)
    }

    /// Converts the object into field elements that can be absorbed by a `CryptographicSpongeVar`.
    fn to_sponge_field_elements(&self) -> Result<Vec<FpVar<F>>, SynthesisError>;

    /// Specifies the conversion into a list of field elements for a batch.
    fn batch_to_sponge_field_elements(batch: &[Self]) -> Result<Vec<FpVar<F>>, SynthesisError>
    where
        Self: Sized,
    {
        let mut output = Vec::new();
        for absorbable in batch {
            output.append(&mut absorbable.to_sponge_field_elements()?);
        }

        Ok(output)
    }
}

impl<F: PrimeField> AbsorbGadget<F> for UInt8<F> {
    fn to_sponge_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        Ok(vec![self.clone()])
    }

    fn to_sponge_field_elements(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        vec![self.clone()].to_constraint_field()
    }

    fn batch_to_sponge_field_elements(batch: &[Self]) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // It's okay to allocate as constant because at circuit-generation time,
        // the length must be statically known (it cannot vary with the variable assignments).
        let mut bytes = UInt8::constant_vec((batch.len() as u64).to_le_bytes().as_ref());
        bytes.extend_from_slice(batch);
        bytes.to_constraint_field()
    }
}

impl<F: PrimeField> AbsorbGadget<F> for Boolean<F> {
    fn to_sponge_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        self.to_bytes()
    }

    fn to_sponge_field_elements(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        Ok(vec![FpVar::from(self.clone())])
    }
}

impl<F: PrimeField> AbsorbGadget<F> for FpVar<F> {
    fn to_sponge_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        self.to_bytes()
    }

    fn to_sponge_field_elements(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        Ok(vec![self.clone()])
    }

    fn batch_to_sponge_field_elements(batch: &[Self]) -> Result<Vec<FpVar<F>>, SynthesisError> {
        Ok(batch.to_vec())
    }
}

macro_rules! impl_absorbable_group {
    ($group:ident, $params:ident) => {
        impl<P, F> AbsorbGadget<<P::BaseField as Field>::BasePrimeField> for $group<P, F>
        where
            P: $params,
            F: FieldVar<P::BaseField, <P::BaseField as Field>::BasePrimeField>,
            for<'a> &'a F: FieldOpsBounds<'a, P::BaseField, F>,
            F: ToConstraintFieldGadget<<P::BaseField as Field>::BasePrimeField>,
        {
            fn to_sponge_bytes(
                &self,
            ) -> Result<Vec<UInt8<<P::BaseField as Field>::BasePrimeField>>, SynthesisError> {
                self.to_constraint_field()?.to_sponge_bytes()
            }

            fn to_sponge_field_elements(
                &self,
            ) -> Result<Vec<FpVar<<P::BaseField as Field>::BasePrimeField>>, SynthesisError> {
                self.to_constraint_field()
            }
        }
    };
}

impl_absorbable_group!(TEAffineVar, TEModelParameters);
impl_absorbable_group!(SWAffineVar, SWModelParameters);

impl<P, F> AbsorbGadget<<P::BaseField as Field>::BasePrimeField> for SWProjectiveVar<P, F>
where
    P: SWModelParameters,
    F: FieldVar<P::BaseField, <P::BaseField as Field>::BasePrimeField>,
    for<'a> &'a F: FieldOpsBounds<'a, P::BaseField, F>,
    F: ToConstraintFieldGadget<<P::BaseField as Field>::BasePrimeField>,
{
    fn to_sponge_bytes(
        &self,
    ) -> Result<
        Vec<UInt8<<<P as ModelParameters>::BaseField as Field>::BasePrimeField>>,
        SynthesisError,
    > {
        self.to_bytes()
    }

    fn to_sponge_field_elements(
        &self,
    ) -> Result<
        Vec<FpVar<<<P as ModelParameters>::BaseField as Field>::BasePrimeField>>,
        SynthesisError,
    > {
        self.to_affine()?.to_sponge_field_elements()
    }
}

impl<F: PrimeField, A: AbsorbGadget<F>> AbsorbGadget<F> for &[A] {
    fn to_sponge_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        A::batch_to_sponge_bytes(self)
    }

    fn to_sponge_field_elements(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        A::batch_to_sponge_field_elements(self)
    }
}

impl<F: PrimeField, A: AbsorbGadget<F>> AbsorbGadget<F> for Vec<A> {
    fn to_sponge_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        self.as_slice().to_sponge_bytes()
    }

    fn to_sponge_field_elements(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        self.as_slice().to_sponge_field_elements()
    }
}

impl<F: PrimeField, A: AbsorbGadget<F>> AbsorbGadget<F> for Option<A> {
    fn to_sponge_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        let mut output = Vec::new();
        output.append(&mut (Boolean::Constant(self.is_some()).to_sponge_bytes()?));
        if let Some(item) = self {
            output.append(&mut (item.to_sponge_bytes()?))
        }
        Ok(output)
    }

    fn to_sponge_field_elements(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let mut output = vec![FpVar::from(Boolean::constant(self.is_some()))];
        if let Some(absorbable) = self.as_ref() {
            output.append(&mut absorbable.to_sponge_field_elements()?);
        }
        Ok(output)
    }
}

impl<F: PrimeField, A: AbsorbGadget<F>> AbsorbGadget<F> for &A {
    fn to_sponge_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        (*self).to_sponge_bytes()
    }

    fn to_sponge_field_elements(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        (*self).to_sponge_field_elements()
    }
}

/// Individually absorbs each element in a comma-separated list of [`Absorbable`]s into a sponge.
/// Format is `absorb!(s, a_0, a_1, ..., a_n)`, where `s` is a mutable reference to a sponge
/// and each `a_i` implements `AbsorbableVar`.
#[macro_export]
macro_rules! absorb_gadget {
    ($sponge:expr, $($absorbable:expr),+ ) => {
        $(
            CryptographicSpongeVar::absorb($sponge, &$absorbable)?;
        )+
    };
}

/// Quickly convert a list of different [`Absorbable`]s into sponge field elements.
#[macro_export]
macro_rules! collect_sponge_field_elements_gadget {
    ($head:expr $(, $tail:expr)* ) => {
        {
            let mut output = AbsorbGadget::to_sponge_field_elements(&$head)?;
            $(
                output.append(&mut AbsorbGadget::to_sponge_field_elements(&$tail)?);
            )*

            Ok(output)
        }
    };
}

#[cfg(test)]
mod tests {
    use crate::sponge::constraints::AbsorbGadget;
    use crate::sponge::test::Fr;
    use crate::sponge::Absorb;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::uint8::UInt8;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_relations::*;
    use ark_std::{test_rng, UniformRand};

    #[test]
    fn consistency_check() {
        // test constraint is consistent with native
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut rng = test_rng();
        // uint8
        let data = vec![0u8, 1u8, 2u8, 3u8, 4u8, 5u8];
        let data_var = UInt8::new_input_vec(ns!(cs, "u8data"), &data).unwrap();

        let native_bytes = data.to_sponge_bytes_as_vec();
        let constraint_bytes = data_var.to_sponge_bytes().unwrap();

        assert_eq!(constraint_bytes.value().unwrap(), native_bytes);

        // field

        let data: Vec<_> = (0..10).map(|_| Fr::rand(&mut rng)).collect();
        let data_var: Vec<_> = data
            .iter()
            .map(|item| FpVar::new_input(ns!(cs, "fpdata"), || Ok(*item)).unwrap())
            .collect();

        let native_bytes = data.to_sponge_bytes_as_vec();
        let constraint_bytes = data_var.to_sponge_bytes().unwrap();
        assert_eq!(constraint_bytes.value().unwrap(), native_bytes);

        assert!(cs.is_satisfied().unwrap())
    }
}
