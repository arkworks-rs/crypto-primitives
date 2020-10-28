use ark_ff::{BigInteger, FpParameters, PrimeField};
use ark_nonnative_field::params::get_params;
use ark_nonnative_field::{AllocatedNonNativeFieldVar, NonNativeFieldVar};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    bits::boolean::Boolean,
    fields::fp::{AllocatedFp, FpVar},
    R1CSVar, ToBitsGadget, ToBytesGadget,
};
use ark_relations::{
    lc, ns,
    r1cs::{ConstraintSynthesizer, LinearCombination, Namespace, SynthesisError},
};
use ark_snark::{CircuitSpecificSetupSNARK, UniversalSetupSNARK, SNARK};
use core::{borrow::Borrow, marker::PhantomData};
use ark_r1cs_std::fields::fp::FpVar::Constant;
use ark_relations::r1cs::ConstraintSystemRef;

/// The SNARK verifier gadgets
pub trait SNARKGadget<F: PrimeField, ConstraintF: PrimeField, S: SNARK<F>> {
    type ProcessedVerifyingKeyVar: AllocVar<S::ProcessedVerifyingKey, ConstraintF> + Clone;
    type VerifyingKeyVar: AllocVar<S::VerifyingKey, ConstraintF>
        + ToBytesGadget<ConstraintF>
        + Clone;
    type InputVar: AllocVar<Vec<F>, ConstraintF> + FromFieldElementsGadget<F, ConstraintF> + Clone;
    type ProofVar: AllocVar<S::Proof, ConstraintF> + Clone;

    fn verify_with_processed_vk(
        circuit_pvk: &Self::ProcessedVerifyingKeyVar,
        x: &Self::InputVar,
        proof: &Self::ProofVar,
    ) -> Result<Boolean<ConstraintF>, SynthesisError>;

    fn verify(
        circuit_vk: &Self::VerifyingKeyVar,
        x: &Self::InputVar,
        proof: &Self::ProofVar,
    ) -> Result<Boolean<ConstraintF>, SynthesisError>;
}

pub trait CircuitSpecificSetupSNARKGadgets<
    F: PrimeField,
    ConstraintF: PrimeField,
    S: CircuitSpecificSetupSNARK<F>,
>: SNARKGadget<F, ConstraintF, S>
{
}

pub trait UniversalSetupSNARKGadgets<
    F: PrimeField,
    ConstraintF: PrimeField,
    S: UniversalSetupSNARK<F>,
>: SNARKGadget<F, ConstraintF, S>
{
    type BoundCircuit: From<S::ComputationBound> + ConstraintSynthesizer<F> + Clone;
}

/// Gadgets to convert elements between different fields for recursive proofs
pub trait FromFieldElementsGadget<F: PrimeField, ConstraintF: PrimeField>: Sized {
    fn repack_input(src: &Vec<F>) -> Vec<ConstraintF>;
    fn from_field_elements(src: &Vec<FpVar<ConstraintF>>) -> Result<Self, SynthesisError>;
}

/// Conversion of field elements by converting them to boolean sequences
/// Used by Groth16 and Gm17
pub struct BooleanInputVar<F: PrimeField, CF: PrimeField> {
    val: Vec<Vec<Boolean<CF>>>,
    _snark_field_: PhantomData<F>,
}

impl<F: PrimeField, CF: PrimeField> BooleanInputVar<F, CF> {
    pub fn new(val: Vec<Vec<Boolean<CF>>>) -> Self {
        Self {
            val,
            _snark_field_: PhantomData,
        }
    }
}

impl<F: PrimeField, CF: PrimeField> Clone for BooleanInputVar<F, CF> {
    fn clone(&self) -> Self {
        Self {
            val: self.val.clone(),
            _snark_field_: PhantomData,
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

            // convert the elements into booleans (little-endian)
            let mut res = Vec::<Vec<Boolean<CF>>>::new();
            for elem in obj.iter() {
                let mut bits = elem.into_repr().to_bits();
                // the result of to_bits() is big-endian

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
                _snark_field_: PhantomData,
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

        // Step 1: obtain the bits of the F field elements (little-endian)
        let mut src_bits = Vec::<bool>::new();
        for elem in obj.borrow().iter() {
            let mut bits = elem.into_repr().to_bits();
            // to_bits()'s result is big-endian

            bits.reverse();
            bits.truncate(F::size_in_bits());
            for _ in bits.len()..F::size_in_bits() {
                bits.push(false);
            }
            bits.reverse();

            src_bits.append(&mut bits);
        }

        // Step 2: repack the bits as CF field elements
        // Deciding how many bits can be embedded,
        //  if CF has the same number of bits as F, but is larger,
        //  then it is okay to put the entire field element in.
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

        // Step 3: allocate the CF field elements as input
        let mut src_booleans = Vec::<Boolean<CF>>::new();
        for chunk in src_bits.chunks(capacity) {
            let elem = CF::from_repr(<CF as PrimeField>::BigInt::from_bits(chunk)).unwrap(); // big endian

            let elem_gadget = FpVar::<CF>::new_input(ns!(cs, "input"), || Ok(elem))?;

            let mut booleans = elem_gadget.to_bits_le()?;
            booleans.truncate(chunk.len());
            booleans.reverse();

            src_booleans.append(&mut booleans);
        }

        // Step 4: unpack them back to bits
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
            _snark_field_: PhantomData,
        })
    }
}

impl<F: PrimeField, CF: PrimeField> FromFieldElementsGadget<F, CF> for BooleanInputVar<F, CF> {
    fn repack_input(src: &Vec<F>) -> Vec<CF> {
        // Step 1: obtain the bits of the F field elements
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

        // Step 2: repack the bits as CF field elements
        // Deciding how many bits can be embedded.
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

        // Step 3: directly pack the bits
        let mut dest = Vec::<CF>::new();
        for chunk in src_bits.chunks(capacity) {
            let elem = CF::from_repr(<CF as PrimeField>::BigInt::from_bits(chunk)).unwrap(); // big endian
            dest.push(elem);
        }

        dest
    }

    fn from_field_elements(src: &Vec<FpVar<CF>>) -> Result<Self, SynthesisError> {
        // Step 1: obtain the booleans of the CF field variables
        let mut src_booleans = Vec::<Boolean<CF>>::new();
        for elem in src.iter() {
            let mut bits = elem.to_bits_le()?;
            bits.reverse();
            src_booleans.extend_from_slice(&bits);
        }

        // Step 2: repack the bits as F field elements
        // Deciding how many bits can be embedded.
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

        // Step 3: group them based on the used capacity of F
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
            _snark_field_: PhantomData,
        })
    }
}

/// Conversion of field elements by allocating them as nonnative field elements
/// Used by Marlin
pub struct NonNativeFieldInputVar<F, CF>
where
    F: PrimeField,
    CF: PrimeField,
{
    val: Vec<NonNativeFieldVar<F, CF>>,
}

impl<F, CF> NonNativeFieldInputVar<F, CF>
where
    F: PrimeField,
    CF: PrimeField,
{
    pub fn new(val: Vec<NonNativeFieldVar<F, CF>>) -> Self {
        Self { val }
    }
}

impl<F, CF> Clone for NonNativeFieldInputVar<F, CF>
where
    F: PrimeField,
    CF: PrimeField,
{
    fn clone(&self) -> Self {
        Self {
            val: self.val.clone(),
        }
    }
}

impl<F, CF> AllocVar<Vec<F>, CF> for NonNativeFieldInputVar<F, CF>
where
    F: PrimeField,
    CF: PrimeField,
{
    fn new_variable<T: Borrow<Vec<F>>>(
        cs: impl Into<Namespace<CF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        if mode == AllocationMode::Input {
            Self::new_input(cs, f)
        } else {
            // directly allocate them as nonnative field elements

            let ns = cs.into();
            let cs = ns.cs();

            let t = f()?;
            let obj = t.borrow();
            let mut allocated = Vec::<NonNativeFieldVar<F, CF>>::new();

            for elem in obj.iter() {
                let elem_allocated = NonNativeFieldVar::<F, CF>::new_variable(
                    ns!(cs, "allocating element"),
                    || Ok(elem),
                    mode,
                )?;
                allocated.push(elem_allocated);
            }

            Ok(Self { val: allocated })
        }
    }

    fn new_input<T: Borrow<Vec<F>>>(
        cs: impl Into<Namespace<CF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
    ) -> Result<Self, SynthesisError> {
        // allocate the nonnative field elements by squeezing the bits like in BooleanInputVar

        let ns = cs.into();
        let cs = ns.cs();

        let params = get_params::<F, CF>(&cs);

        let obj = f()?;

        // Step 1: use BooleanInputVar to allocate the values as bits
        // This is to make sure that we are using as few elements as possible
        let boolean_allocation =
            BooleanInputVar::new_input(ns!(cs, "boolean"), || Ok(obj.borrow()))?;

        // Step 2: allocating the nonnative field elements as witnesses
        let mut field_allocation = Vec::<AllocatedNonNativeFieldVar<F, CF>>::new();

        for elem in obj.borrow().iter() {
            let mut elem_allocated = AllocatedNonNativeFieldVar::<F, CF>::new_witness(
                ns!(cs, "allocating element"),
                || Ok(elem),
            )?;

            // due to the consistency check below
            elem_allocated.is_in_the_normal_form = true;
            elem_allocated.num_of_additions_over_normal_form = CF::zero();

            field_allocation.push(elem_allocated);
        }

        // Step 3: check consistency
        for (field_bits, field_elem) in boolean_allocation.val.iter().zip(field_allocation.iter()) {
            let mut field_bits = field_bits.clone();
            field_bits.reverse();

            // must use lc to save computation
            for (j, limb) in field_elem.limbs.iter().enumerate() {
                let bits_slice = if j == 0 {
                    field_bits[0..params.bits_per_top_limb].to_vec()
                } else {
                    field_bits[params.bits_per_top_limb + (j - 1) * params.bits_per_non_top_limb
                        ..params.bits_per_top_limb + j * params.bits_per_non_top_limb]
                        .to_vec()
                };

                let mut lc = LinearCombination::<CF>::zero();
                let mut cur = CF::one();

                for bit in bits_slice.iter().rev() {
                    lc = lc + &bit.lc() * cur;
                    cur.double_in_place();
                }

                lc = lc - limb.variable;
                cs.enforce_constraint(lc!(), lc!(), lc).unwrap();
            }
        }

        let mut wrapped_field_allocation = Vec::<NonNativeFieldVar<F, CF>>::new();
        for field_gadget in field_allocation.iter() {
            wrapped_field_allocation.push(NonNativeFieldVar::Var(field_gadget.clone()));
        }
        Ok(Self {
            val: wrapped_field_allocation,
        })
    }
}

impl<F, CF> FromFieldElementsGadget<F, CF> for NonNativeFieldInputVar<F, CF>
where
    F: PrimeField,
    CF: PrimeField,
{
    fn repack_input(src: &Vec<F>) -> Vec<CF> {
        BooleanInputVar::repack_input(src)
    }

    fn from_field_elements(src: &Vec<FpVar<CF>>) -> Result<Self, SynthesisError> {
        let cs = src.cs();

        if cs == ConstraintSystemRef::None {
            // Step 1: use BooleanInputVar to convert them into booleans
            let boolean_allocation = BooleanInputVar::<F, CF>::from_field_elements(src)?;

            // Step 2: construct the nonnative field gadgets from bits
            let mut field_allocation = Vec::<NonNativeFieldVar<F, CF>>::new();

            // reconstruct the field elements and check consistency
            for field_bits in boolean_allocation.val.iter() {
                let mut field_bits = field_bits.clone();
                field_bits.resize(F::size_in_bits(), Boolean::<CF>::Constant(false));

                let mut cur = CF::one();

                let mut value = CF::zero();
                for bit in field_bits.iter().rev() {
                    if bit.value().unwrap_or_default() {
                        value += &cur;
                    }
                    cur.double_in_place();
                }

                field_allocation.push(NonNativeFieldVar::Constant(value));
            }

            Ok(Self {
                val: field_allocation,
            })
        }else {
            let params = get_params::<F, CF>(&cs);

            // Step 1: use BooleanInputVar to convert them into booleans
            let boolean_allocation = BooleanInputVar::<F, CF>::from_field_elements(src)?;

            // Step 2: construct the nonnative field gadgets from bits
            let mut field_allocation = Vec::<NonNativeFieldVar<F, CF>>::new();

            // reconstruct the field elements and check consistency
            for field_bits in boolean_allocation.val.iter() {
                let mut field_bits = field_bits.clone();
                field_bits.resize(F::size_in_bits(), Boolean::<CF>::Constant(false));
                field_bits.reverse();

                let mut limbs = Vec::<AllocatedFp<CF>>::new();

                // must use lc to save computation
                for j in 0..params.num_limbs {
                    let bits_slice = if j == 0 {
                        field_bits[0..params.bits_per_top_limb].to_vec()
                    } else {
                        field_bits[(params.bits_per_top_limb + (j - 1) * params.bits_per_non_top_limb)
                            ..(params.bits_per_top_limb + j * params.bits_per_non_top_limb)]
                            .to_vec()
                    };

                    let mut lc = LinearCombination::<CF>::zero();
                    let mut cur = CF::one();

                    let mut limb_value = CF::zero();
                    for bit in bits_slice.iter().rev() {
                        lc = &lc + bit.lc() * cur;
                        if bit.value().unwrap_or_default() {
                            limb_value += &cur;
                        }
                        cur.double_in_place();
                    }

                    let limb = AllocatedFp::<CF>::new_witness(ns!(cs, "limb"), || Ok(limb_value))?;
                    lc = lc - limb.variable;
                    cs.enforce_constraint(lc!(), lc!(), lc).unwrap();

                    limbs.push(limb);
                }

                field_allocation.push(NonNativeFieldVar::<F, CF>::Var(
                    AllocatedNonNativeFieldVar::<F, CF> {
                        cs: cs.clone(),
                        limbs: limbs,
                        num_of_additions_over_normal_form: CF::zero(),
                        is_in_the_normal_form: true,
                        target_phantom: PhantomData,
                    },
                ))
            }

            Ok(Self {
                val: field_allocation,
            })
        }
    }
}