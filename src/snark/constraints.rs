use ark_ff::{BigInteger, FpParameters, PrimeField};
use ark_nonnative_field::params::{get_params, OptimizationType};
use ark_nonnative_field::{AllocatedNonNativeFieldVar, NonNativeFieldVar};
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::{
    bits::boolean::Boolean,
    fields::fp::{AllocatedFp, FpVar},
    R1CSVar,
};
use ark_relations::r1cs::OptimizationGoal;
use ark_relations::{
    lc, ns,
    r1cs::{
        ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, Namespace, SynthesisError,
    },
};
use ark_snark::{CircuitSpecificSetupSNARK, UniversalSetupSNARK, SNARK};
use ark_std::{
    borrow::Borrow,
    fmt,
    marker::PhantomData,
    vec::{IntoIter, Vec},
};

/// This implements constraints for SNARK verifiers.
pub trait SNARKGadget<F: PrimeField, ConstraintF: PrimeField, S: SNARK<F>> {
    type ProcessedVerifyingKeyVar: AllocVar<S::ProcessedVerifyingKey, ConstraintF> + Clone;
    type VerifyingKeyVar: AllocVar<S::VerifyingKey, ConstraintF>
        + ToBytesGadget<ConstraintF>
        + Clone;
    type InputVar: AllocVar<Vec<F>, ConstraintF> + FromFieldElementsGadget<F, ConstraintF> + Clone;
    type ProofVar: AllocVar<S::Proof, ConstraintF> + Clone;

    /// Information about the R1CS constraints required to check proofs relative
    /// a given verification key. In the context of a LPCP-based pairing-based SNARK
    /// like that of [[Groth16]](https://eprint.iacr.org/2016/260),
    /// this is independent of the R1CS matrices,
    /// whereas for more "complex" SNARKs like [[Marlin]](https://eprint.iacr.org/2019/1047),
    /// this can encode information about the highest degree of polynomials
    /// required to verify proofs.
    type VerifierSize: PartialOrd + Clone + fmt::Debug;

    /// Returns information about the R1CS constraints required to check proofs relative
    /// to the verification key `circuit_vk`.
    fn verifier_size(circuit_vk: &S::VerifyingKey) -> Self::VerifierSize;

    /// Optionally allocates `S::Proof` in `cs` without performing
    /// additional checks, such as subgroup membership checks. Use this *only*
    /// if you know it is safe to do so. Such "safe" scenarios can include
    /// the case where `proof` is a public input (`mode == AllocationMode::Input`),
    /// and the corresponding checks are performed by the SNARK verifier outside
    /// the circuit.  Another example is the when `mode == AllocationMode::Constant`.
    ///
    /// The default implementation does not omit such checks, and just invokes
    /// `Self::ProofVar::new_variable`.
    #[tracing::instrument(target = "r1cs", skip(cs, f))]
    fn new_proof_unchecked<T: Borrow<S::Proof>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self::ProofVar, SynthesisError> {
        Self::ProofVar::new_variable(cs, f, mode)
    }

    /// Optionally allocates `S::VerifyingKey` in `cs` without performing
    /// additional checks, such as subgroup membership checks. Use this *only*
    /// if you know it is safe to do so. Such "safe" scenarios can include
    /// the case where `vk` is a public input (`mode == AllocationMode::Input`),
    /// and the corresponding checks are performed by the SNARK verifier outside
    /// the circuit. Another example is the when `mode == AllocationMode::Constant`.
    ///
    /// The default implementation does not omit such checks, and just invokes
    /// `Self::VerifyingKeyVar::new_variable`.
    #[tracing::instrument(target = "r1cs", skip(cs, f))]
    fn new_verification_key_unchecked<T: Borrow<S::VerifyingKey>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self::VerifyingKeyVar, SynthesisError> {
        Self::VerifyingKeyVar::new_variable(cs, f, mode)
    }

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

pub trait CircuitSpecificSetupSNARKGadget<
    F: PrimeField,
    ConstraintF: PrimeField,
    S: CircuitSpecificSetupSNARK<F>,
>: SNARKGadget<F, ConstraintF, S>
{
}

pub trait UniversalSetupSNARKGadget<
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
#[derive(Clone)]
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

impl<F: PrimeField, CF: PrimeField> IntoIterator for BooleanInputVar<F, CF> {
    type Item = Vec<Boolean<CF>>;
    type IntoIter = IntoIter<Vec<Boolean<CF>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.val.into_iter()
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
                let mut bits = elem.into_repr().to_bits_le();
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
            let mut bits = elem.into_repr().to_bits_le();
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
            let elem = CF::from_repr(<CF as PrimeField>::BigInt::from_bits_be(chunk)).unwrap(); // big endian

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
            let mut bits = elem.into_repr().to_bits_le();
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
            let elem = CF::from_repr(<CF as PrimeField>::BigInt::from_bits_be(chunk)).unwrap(); // big endian
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
    pub val: Vec<NonNativeFieldVar<F, CF>>,
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

impl<F, CF> IntoIterator for NonNativeFieldInputVar<F, CF>
where
    F: PrimeField,
    CF: PrimeField,
{
    type Item = NonNativeFieldVar<F, CF>;
    type IntoIter = IntoIter<NonNativeFieldVar<F, CF>>;

    fn into_iter(self) -> Self::IntoIter {
        self.val.into_iter()
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

        let optimization_type = match cs.optimization_goal() {
            OptimizationGoal::None => OptimizationType::Constraints,
            OptimizationGoal::Constraints => OptimizationType::Constraints,
            OptimizationGoal::Weight => OptimizationType::Weight,
        };

        let params = get_params(F::size_in_bits(), CF::size_in_bits(), optimization_type);

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

            let bit_per_top_limb =
                F::size_in_bits() - (params.num_limbs - 1) * params.bits_per_limb;
            let bit_per_non_top_limb = params.bits_per_limb;

            // must use lc to save computation
            for (j, limb) in field_elem.limbs.iter().enumerate() {
                let bits_slice = if j == 0 {
                    field_bits[0..bit_per_top_limb].to_vec()
                } else {
                    field_bits[bit_per_top_limb + (j - 1) * bit_per_non_top_limb
                        ..bit_per_top_limb + j * bit_per_non_top_limb]
                        .to_vec()
                };

                let mut bit_sum = FpVar::<CF>::zero();
                let mut cur = CF::one();

                for bit in bits_slice.iter().rev() {
                    bit_sum += <FpVar<CF> as From<Boolean<CF>>>::from((*bit).clone()) * cur;
                    cur.double_in_place();
                }

                limb.enforce_equal(&bit_sum)?;
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

                let mut cur = F::one();

                let mut value = F::zero();
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
        } else {
            let optimization_type = match cs.optimization_goal() {
                OptimizationGoal::None => OptimizationType::Constraints,
                OptimizationGoal::Constraints => OptimizationType::Constraints,
                OptimizationGoal::Weight => OptimizationType::Weight,
            };

            let params = get_params(F::size_in_bits(), CF::size_in_bits(), optimization_type);

            // Step 1: use BooleanInputVar to convert them into booleans
            let boolean_allocation = BooleanInputVar::<F, CF>::from_field_elements(src)?;

            // Step 2: construct the nonnative field gadgets from bits
            let mut field_allocation = Vec::<NonNativeFieldVar<F, CF>>::new();

            // reconstruct the field elements and check consistency
            for field_bits in boolean_allocation.val.iter() {
                let mut field_bits = field_bits.clone();
                field_bits.resize(F::size_in_bits(), Boolean::<CF>::Constant(false));
                field_bits.reverse();

                let mut limbs = Vec::<FpVar<CF>>::new();

                let bit_per_top_limb =
                    F::size_in_bits() - (params.num_limbs - 1) * params.bits_per_limb;
                let bit_per_non_top_limb = params.bits_per_limb;

                // must use lc to save computation
                for j in 0..params.num_limbs {
                    let bits_slice = if j == 0 {
                        field_bits[0..bit_per_top_limb].to_vec()
                    } else {
                        field_bits[bit_per_top_limb + (j - 1) * bit_per_non_top_limb
                            ..bit_per_top_limb + j * bit_per_non_top_limb]
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

                    limbs.push(FpVar::from(limb));
                }

                field_allocation.push(NonNativeFieldVar::<F, CF>::Var(
                    AllocatedNonNativeFieldVar::<F, CF> {
                        cs: cs.clone(),
                        limbs,
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
