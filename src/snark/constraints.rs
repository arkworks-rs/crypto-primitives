use ark_ff::{BigInteger, FpParameters, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar, bits::boolean::Boolean, fields::fp::FpVar, ToBitsGadget, ToBytesGadget,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Namespace, SynthesisError},
};
use core::{borrow::Borrow, marker::PhantomData};

use ark_r1cs_std::alloc::AllocationMode;
use ark_snark::{CircuitSpecificSetupSNARK, UniversalSetupSNARK, SNARK};

pub trait SNARKGadgets<F: PrimeField, ConstraintF: PrimeField, T: SNARK<F>> {
    type ProcessedVerifyingKeyVar: AllocVar<T::ProcessedVerifyingKey, ConstraintF> + Clone;
    type VerifyingKeyVar: AllocVar<T::VerifyingKey, ConstraintF>
        + ToBytesGadget<ConstraintF>
        + Clone;
    type InputVar: AllocVar<Vec<F>, ConstraintF> + FromFieldElementsGadget<F, ConstraintF> + Clone;
    type ProofVar: AllocVar<T::Proof, ConstraintF> + Clone;

    fn verify_with_processed_vk(
        cs: ConstraintSystemRef<ConstraintF>,
        circuit_pvk: &Self::ProcessedVerifyingKeyVar,
        x: &Self::InputVar,
        proof: &Self::ProofVar,
    ) -> Result<Boolean<ConstraintF>, SynthesisError>;

    fn verify(
        cs: ConstraintSystemRef<ConstraintF>,
        circuit_vk: &Self::VerifyingKeyVar,
        x: &Self::InputVar,
        proof: &Self::ProofVar,
    ) -> Result<Boolean<ConstraintF>, SynthesisError>;
}

pub trait CircuitSpecificSetupSNARKGadgets<
    F: PrimeField,
    ConstraintF: PrimeField,
    T: CircuitSpecificSetupSNARK<F>,
>: SNARKGadgets<F, ConstraintF, T>
{
}

pub trait UniversalSetupSNARKGadgets<
    F: PrimeField,
    ConstraintF: PrimeField,
    T: UniversalSetupSNARK<F>,
>: SNARKGadgets<F, ConstraintF, T>
{
    type BoundCircuit: From<T::ComputationBound> + ConstraintSynthesizer<F> + Clone;
}

pub trait FromFieldElementsGadget<F: PrimeField, ConstraintF: PrimeField>: Sized {
    fn get_converted_input(src: &Vec<F>) -> Vec<ConstraintF>;
    fn from_field_elements(
        cs: ConstraintSystemRef<ConstraintF>,
        src: &Vec<FpVar<ConstraintF>>,
    ) -> Result<Self, SynthesisError>;
}

pub struct BooleanInputVar<F: PrimeField, CF: PrimeField> {
    pub val: Vec<Vec<Boolean<CF>>>,
    pub field_phantom: PhantomData<F>,
    pub constraint_field_phantom: PhantomData<CF>,
}

impl<F: PrimeField, CF: PrimeField> Clone for BooleanInputVar<F, CF> {
    fn clone(&self) -> Self {
        Self {
            val: self.val.clone(),
            field_phantom: PhantomData,
            constraint_field_phantom: PhantomData,
        }
    }
}

impl<F: PrimeField, CF: PrimeField> AllocVar<Vec<F>, CF> for BooleanInputVar<F, CF> {
    fn new_variable<T: Borrow<Vec<F>>>(
        cs: impl Into<Namespace<CF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        if mode == AllocationMode::Input {
            Self::new_input(cs, f)
        } else {
            let ns = cs.into();
            let cs = ns.cs();

            let t = f()?;
            let obj = t.borrow();

            let mut res = Vec::<Vec<Boolean<CF>>>::new();
            for elem in obj.iter() {
                let mut bits = elem.into_repr().to_bits(); // big endian
                bits.reverse();
                bits.truncate(F::size_in_bits());

                let mut booleans = Vec::<Boolean<CF>>::new();
                for bit in bits.iter() {
                    booleans.push(Boolean::new_variable(ns!(cs, "bit"), || Ok(*bit), mode)?);
                }

                res.push(booleans);
            }

            Ok(Self {
                val: res,
                field_phantom: PhantomData,
                constraint_field_phantom: PhantomData,
            })
        }
    }

    fn new_input<T: Borrow<Vec<F>>>(
        cs: impl Into<Namespace<CF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let obj = f()?;

        // first obtain the bits
        let mut src_bits = Vec::<bool>::new();
        for elem in obj.borrow().iter() {
            let mut bits = elem.into_repr().to_bits(); // big endian
            bits.reverse();
            bits.truncate(F::size_in_bits());
            for _ in bits.len()..F::size_in_bits() {
                bits.push(false);
            }
            bits.reverse();

            src_bits.append(&mut bits);
        }

        // then pack them as CF field elements
        let capacity = if CF::size_in_bits() == F::size_in_bits() {
            let fq = <<CF as PrimeField>::Params as FpParameters>::MODULUS;
            let fr = <<F as PrimeField>::Params as FpParameters>::MODULUS;

            let fq_u64: &[u64] = fq.as_ref();
            let fr_u64: &[u64] = fr.as_ref();

            let mut fq_not_smaller_than_fr = true;
            for (left, right) in fq_u64.iter().zip(fr_u64.iter()).rev() {
                if left < right {
                    fq_not_smaller_than_fr = false;
                    break;
                }

                if left > right {
                    break;
                }
            }

            if fq_not_smaller_than_fr {
                CF::size_in_bits()
            } else {
                CF::size_in_bits() - 1
            }
        } else {
            CF::size_in_bits() - 1
        };

        let mut src_booleans = Vec::<Boolean<CF>>::new();

        for chunk in src_bits.chunks(capacity) {
            let elem = CF::from_repr(<CF as PrimeField>::BigInt::from_bits(chunk)).unwrap(); // big endian

            let elem_gadget = FpVar::<CF>::new_input(ns!(cs, "input"), || Ok(elem))?;

            let mut booleans = elem_gadget.to_bits_le()?;
            booleans.truncate(chunk.len());
            booleans.reverse();

            src_booleans.append(&mut booleans);
        }

        // then unpack them
        let res = src_booleans
            .chunks(F::size_in_bits())
            .map(|f| {
                let mut res = f.to_vec();
                res.reverse();
                res
            })
            .collect::<Vec<Vec<Boolean<CF>>>>();

        Ok(Self {
            val: res,
            field_phantom: PhantomData,
            constraint_field_phantom: PhantomData,
        })
    }
}

impl<F: PrimeField, CF: PrimeField> FromFieldElementsGadget<F, CF> for BooleanInputVar<F, CF> {
    fn get_converted_input(src: &Vec<F>) -> Vec<CF> {
        // first obtain the bits
        let mut src_bits = Vec::<bool>::new();
        for (_, elem) in src.iter().enumerate() {
            let mut bits = elem.into_repr().to_bits(); // big endian
            bits.reverse();
            bits.truncate(F::size_in_bits());
            for _ in bits.len()..F::size_in_bits() {
                bits.push(false);
            }
            bits.reverse();

            src_bits.append(&mut bits);
        }

        // then pack them as CF field elements
        let capacity = if CF::size_in_bits() == F::size_in_bits() {
            let fq = <<CF as PrimeField>::Params as FpParameters>::MODULUS;
            let fr = <<F as PrimeField>::Params as FpParameters>::MODULUS;

            let fq_u64: &[u64] = fq.as_ref();
            let fr_u64: &[u64] = fr.as_ref();

            let mut fq_not_smaller_than_fr = true;
            for (left, right) in fq_u64.iter().zip(fr_u64.iter()).rev() {
                if left < right {
                    fq_not_smaller_than_fr = false;
                    break;
                }

                if left > right {
                    break;
                }
            }

            if fq_not_smaller_than_fr {
                CF::size_in_bits()
            } else {
                CF::size_in_bits() - 1
            }
        } else {
            CF::size_in_bits() - 1
        };

        let mut dest = Vec::<CF>::new();
        for chunk in src_bits.chunks(capacity) {
            let elem = CF::from_repr(<CF as PrimeField>::BigInt::from_bits(chunk)).unwrap(); // big endian
            dest.push(elem);
        }

        dest
    }

    fn from_field_elements(
        _cs: ConstraintSystemRef<CF>,
        src: &Vec<FpVar<CF>>,
    ) -> Result<Self, SynthesisError> {
        // first obtain the bits
        let mut src_booleans = Vec::<Boolean<CF>>::new();
        for elem in src.iter() {
            let mut bits = elem.to_bits_le()?;
            bits.reverse();
            src_booleans.extend_from_slice(&bits);
        }

        // then pack them as F field elements
        let capacity = if CF::size_in_bits() == F::size_in_bits() {
            let fq = <<CF as PrimeField>::Params as FpParameters>::MODULUS;
            let fr = <<F as PrimeField>::Params as FpParameters>::MODULUS;

            let fq_u64: &[u64] = fq.as_ref();
            let fr_u64: &[u64] = fr.as_ref();

            let mut fr_not_smaller_than_fq = true;
            for (left, right) in fr_u64.iter().zip(fq_u64.iter()).rev() {
                if left < right {
                    fr_not_smaller_than_fq = false;
                    break;
                }

                if left > right {
                    break;
                }
            }

            if fr_not_smaller_than_fq {
                F::size_in_bits()
            } else {
                F::size_in_bits() - 1
            }
        } else {
            F::size_in_bits() - 1
        };

        let res = src_booleans
            .chunks(capacity)
            .map(|x| {
                let mut res = x.to_vec();
                res.reverse();
                res
            })
            .collect::<Vec<Vec<Boolean<CF>>>>();
        Ok(Self {
            val: res,
            field_phantom: PhantomData,
            constraint_field_phantom: PhantomData,
        })
    }
}
