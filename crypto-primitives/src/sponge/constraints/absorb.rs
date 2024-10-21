use ark_ec::{
    short_weierstrass::SWCurveConfig as SWModelParameters,
    twisted_edwards::TECurveConfig as TEModelParameters, CurveConfig as ModelParameters,
};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    boolean::Boolean,
    convert::{ToBytesGadget, ToConstraintFieldGadget},
    fields::{fp::FpVar, FieldOpsBounds, FieldVar},
    groups::curves::{
        short_weierstrass::{AffineVar as SWAffineVar, ProjectiveVar as SWProjectiveVar},
        twisted_edwards::AffineVar as TEAffineVar,
    },
    uint8::UInt8,
};
use ark_relations::r1cs::SynthesisError;
#[cfg(not(feature = "std"))]
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
        self.to_bytes_le()
    }

    fn to_sponge_field_elements(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        Ok(vec![FpVar::from(self.clone())])
    }
}

impl<F: PrimeField> AbsorbGadget<F> for FpVar<F> {
    fn to_sponge_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        self.to_bytes_le()
    }

    fn to_sponge_field_elements(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        Ok(vec![self.clone()])
    }

    fn batch_to_sponge_field_elements(batch: &[Self]) -> Result<Vec<FpVar<F>>, SynthesisError> {
        Ok(batch.to_vec())
    }
}

impl<P, F> AbsorbGadget<<P::BaseField as Field>::BasePrimeField> for TEAffineVar<P, F>
where
    P: TEModelParameters,
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

impl<P, F> AbsorbGadget<<P::BaseField as Field>::BasePrimeField> for SWAffineVar<P, F>
where
    P: SWModelParameters,
    F: FieldVar<P::BaseField, <P::BaseField as Field>::BasePrimeField>,
    for<'a> &'a F: FieldOpsBounds<'a, P::BaseField, F>,
    F: ToConstraintFieldGadget<<P::BaseField as Field>::BasePrimeField>,
{
    fn to_sponge_bytes(
        &self,
    ) -> Result<Vec<UInt8<<P::BaseField as Field>::BasePrimeField>>, SynthesisError> {
        let mut bytes = self.x.to_constraint_field()?.to_sponge_bytes()?;
        bytes.append(&mut self.y.to_constraint_field()?.to_sponge_bytes()?);
        bytes.append(&mut self.infinity.to_bytes_le()?.to_sponge_bytes()?);

        Ok(bytes)
    }

    fn to_sponge_field_elements(
        &self,
    ) -> Result<Vec<FpVar<<P::BaseField as Field>::BasePrimeField>>, SynthesisError> {
        self.to_constraint_field()
    }
}

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
        self.to_bytes_le()
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

/// Individually absorbs each element in a comma-separated list of [`AbsorbGadget`]s into a sponge.
/// Format is `absorb!(s, a_0, a_1, ..., a_n)`, where `s` is a mutable reference to a sponge
/// and each `a_i` implements [`AbsorbGadget`].
#[macro_export]
macro_rules! absorb_gadget {
    ($sponge:expr, $($absorbable:expr),+ ) => {
        $(
            CryptographicSpongeVar::absorb($sponge, &$absorbable)?;
        )+
    };
}

/// Quickly convert a list of different [`AbsorbGadget`]s into sponge field elements.
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
    use crate::sponge::Absorb;
    use ark_bls12_377::{Fq, G1Projective as G};
    use ark_ec::CurveGroup;
    use ark_ec::{
        short_weierstrass::{Projective as SWProjective, SWCurveConfig},
        twisted_edwards::{Projective as TEProjective, TECurveConfig},
    };
    use ark_ed_on_bls12_377::EdwardsProjective;
    use ark_ff::PrimeField;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::uint8::UInt8;
    use ark_r1cs_std::R1CSVar;
    use ark_r1cs_std::{
        alloc::AllocVar,
        groups::curves::{
            short_weierstrass::ProjectiveVar as SWProjectiveVar,
            twisted_edwards::AffineVar as TEAffineVar,
        },
    };
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
    use ark_relations::*;
    use ark_std::{test_rng, UniformRand, Zero};

    fn sw_curve_consistency_check<C>(
        cs: ConstraintSystemRef<C::BaseField>,
        g: SWProjective<C>,
    ) -> r1cs::Result<()>
    where
        C: SWCurveConfig,
        C::BaseField: PrimeField,
    {
        let g_affine = g.into_affine();
        let native_point_bytes = g_affine.to_sponge_bytes_as_vec();
        let native_point_field = g_affine.to_sponge_field_elements_as_vec::<C::BaseField>();

        let cs_point =
            SWProjectiveVar::<C, FpVar<C::BaseField>>::new_input(ns!(cs, "sw_projective"), || {
                Ok(g)
            })?;
        let cs_point_bytes = cs_point.to_sponge_bytes()?;
        let cs_point_field = cs_point.to_sponge_field_elements()?;

        let cs_affine_point = cs_point.to_affine()?;
        let cs_affine_bytes = cs_affine_point.to_sponge_bytes()?;
        let cs_affine_field = cs_affine_point.to_sponge_field_elements()?;

        assert_eq!(native_point_bytes, cs_point_bytes.value()?);
        assert_eq!(native_point_field, cs_point_field.value()?);

        assert_eq!(native_point_bytes, cs_affine_bytes.value()?);
        assert_eq!(native_point_field, cs_affine_field.value()?);

        Ok(())
    }

    fn te_curve_consistency_check<C>(g: TEProjective<C>) -> r1cs::Result<()>
    where
        C: TECurveConfig,
        C::BaseField: PrimeField,
    {
        let cs = ConstraintSystem::<C::BaseField>::new_ref();

        let g_affine = g.into_affine();
        let native_point_bytes = g_affine.to_sponge_bytes_as_vec();
        let native_point_field = g_affine.to_sponge_field_elements_as_vec::<C::BaseField>();

        let cs_point =
            TEAffineVar::<C, FpVar<C::BaseField>>::new_input(ns!(cs, "te_affine"), || Ok(g))?;
        let cs_point_bytes = cs_point.to_sponge_bytes()?;
        let cs_point_field = cs_point.to_sponge_field_elements()?;

        assert_eq!(native_point_bytes, cs_point_bytes.value()?);
        assert_eq!(native_point_field, cs_point_field.value()?);

        assert!(cs.is_satisfied()?);

        Ok(())
    }

    #[test]
    fn consistency_check() {
        // test constraint is consistent with native
        let cs = ConstraintSystem::<Fq>::new_ref();
        let mut rng = test_rng();
        // uint8
        let data = vec![0u8, 1u8, 2u8, 3u8, 4u8, 5u8];
        let data_var = UInt8::new_input_vec(ns!(cs, "u8data"), &data).unwrap();

        let native_bytes = data.to_sponge_bytes_as_vec();
        let constraint_bytes = data_var.to_sponge_bytes().unwrap();

        assert_eq!(constraint_bytes.value().unwrap(), native_bytes);

        // field

        let data: Vec<_> = (0..10).map(|_| Fq::rand(&mut rng)).collect();
        let data_var: Vec<_> = data
            .iter()
            .map(|item| FpVar::new_input(ns!(cs, "fpdata"), || Ok(*item)).unwrap())
            .collect();

        let native_bytes = data.to_sponge_bytes_as_vec();
        let constraint_bytes = data_var.to_sponge_bytes().unwrap();
        assert_eq!(constraint_bytes.value().unwrap(), native_bytes);

        // sw curve
        sw_curve_consistency_check(cs.clone(), G::zero()).unwrap();
        sw_curve_consistency_check(cs.clone(), G::rand(&mut rng)).unwrap();

        // twisted edwards curve
        te_curve_consistency_check(EdwardsProjective::zero()).unwrap();
        te_curve_consistency_check(EdwardsProjective::rand(&mut rng)).unwrap();

        assert!(cs.is_satisfied().unwrap())
    }
}
