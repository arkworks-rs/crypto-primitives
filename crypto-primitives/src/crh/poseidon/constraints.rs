use crate::crh::poseidon::{TwoToOneCRH, CRH};
use crate::crh::CRHScheme;
use crate::crh::{
    CRHSchemeGadget as CRHGadgetTrait, TwoToOneCRHSchemeGadget as TwoToOneCRHGadgetTrait,
};
use crate::sponge::constraints::CryptographicSpongeVar;
use crate::sponge::poseidon::constraints::PoseidonSpongeVar;
use crate::sponge::poseidon::PoseidonConfig;

use crate::sponge::Absorb;
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::borrow::Borrow;
use ark_std::marker::PhantomData;
#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;

#[derive(Clone)]
pub struct CRHParametersVar<F: PrimeField + Absorb> {
    pub parameters: PoseidonConfig<F>,
}

pub struct CRHGadget<F: PrimeField + Absorb> {
    field_phantom: PhantomData<F>,
}

impl<F: PrimeField + Absorb> CRHGadgetTrait<CRH<F>, F> for CRHGadget<F> {
    type InputVar = [FpVar<F>];
    type OutputVar = FpVar<F>;
    type ParametersVar = CRHParametersVar<F>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        let cs = input.cs();

        if cs.is_none() {
            let mut constant_input = Vec::new();
            for var in input.iter() {
                constant_input.push(var.value()?);
            }
            Ok(FpVar::Constant(
                CRH::<F>::evaluate(&parameters.parameters, constant_input).unwrap(),
            ))
        } else {
            let mut sponge = PoseidonSpongeVar::new(cs, &parameters.parameters);
            sponge.absorb(&input)?;
            let res = sponge.squeeze_field_elements(1)?;
            Ok(res[0].clone())
        }
    }
}

pub struct TwoToOneCRHGadget<F: PrimeField + Absorb> {
    field_phantom: PhantomData<F>,
}

impl<F: PrimeField + Absorb> TwoToOneCRHGadgetTrait<TwoToOneCRH<F>, F> for TwoToOneCRHGadget<F> {
    type InputVar = FpVar<F>;
    type OutputVar = FpVar<F>;
    type ParametersVar = CRHParametersVar<F>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        left_input: &Self::InputVar,
        right_input: &Self::InputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        Self::compress(parameters, left_input, right_input)
    }

    fn compress(
        parameters: &Self::ParametersVar,
        left_input: &Self::OutputVar,
        right_input: &Self::OutputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        let cs = left_input.cs().or(right_input.cs());

        if cs.is_none() {
            Ok(FpVar::Constant(
                CRH::<F>::evaluate(
                    &parameters.parameters,
                    vec![left_input.value()?, right_input.value()?],
                )
                .unwrap(),
            ))
        } else {
            let mut sponge = PoseidonSpongeVar::new(cs, &parameters.parameters);
            sponge.absorb(left_input)?;
            sponge.absorb(right_input)?;
            let res = sponge.squeeze_field_elements(1)?;
            Ok(res[0].clone())
        }
    }
}

impl<F: PrimeField + Absorb> AllocVar<PoseidonConfig<F>, F> for CRHParametersVar<F> {
    fn new_variable<T: Borrow<PoseidonConfig<F>>>(
        _cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|param| {
            let parameters = param.borrow().clone();

            Ok(Self { parameters })
        })
    }
}

#[cfg(test)]
mod test {
    use crate::crh::poseidon::constraints::{CRHGadget, CRHParametersVar, TwoToOneCRHGadget};
    use crate::crh::poseidon::{TwoToOneCRH, CRH};
    use crate::crh::{CRHScheme, CRHSchemeGadget};
    use crate::crh::{TwoToOneCRHScheme, TwoToOneCRHSchemeGadget};
    use crate::sponge::poseidon::PoseidonConfig;
    use ark_bls12_377::Fr;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::{
        fields::fp::{AllocatedFp, FpVar},
        R1CSVar,
    };
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::UniformRand;

    #[test]
    fn test_consistency() {
        let mut test_rng = ark_std::test_rng();

        // The following way of generating the MDS matrix is incorrect
        // and is only for test purposes.

        let mut mds = vec![vec![]; 3];
        for i in 0..3 {
            for _ in 0..3 {
                mds[i].push(Fr::rand(&mut test_rng));
            }
        }

        let mut ark = vec![vec![]; 8 + 24];
        for i in 0..8 + 24 {
            for _ in 0..3 {
                ark[i].push(Fr::rand(&mut test_rng));
            }
        }

        let mut test_a = Vec::new();
        let mut test_b = Vec::new();
        for _ in 0..3 {
            test_a.push(Fr::rand(&mut test_rng));
            test_b.push(Fr::rand(&mut test_rng));
        }

        let params = PoseidonConfig::<Fr>::new(8, 24, 31, mds, ark, 2, 1);
        let crh_a = CRH::<Fr>::evaluate(&params, test_a.clone()).unwrap();
        let crh_b = CRH::<Fr>::evaluate(&params, test_b.clone()).unwrap();
        let crh = TwoToOneCRH::<Fr>::compress(&params, crh_a, crh_b).unwrap();

        let cs = ConstraintSystem::<Fr>::new_ref();

        let mut test_a_g = Vec::new();
        let mut test_b_g = Vec::new();

        for elem in test_a.iter() {
            test_a_g.push(FpVar::Var(
                AllocatedFp::<Fr>::new_witness(cs.clone(), || Ok(elem)).unwrap(),
            ));
        }
        for elem in test_b.iter() {
            test_b_g.push(FpVar::Var(
                AllocatedFp::<Fr>::new_witness(cs.clone(), || Ok(elem)).unwrap(),
            ));
        }

        let params_g = CRHParametersVar::<Fr>::new_witness(cs, || Ok(params)).unwrap();
        let crh_a_g = CRHGadget::<Fr>::evaluate(&params_g, &test_a_g).unwrap();
        let crh_b_g = CRHGadget::<Fr>::evaluate(&params_g, &test_b_g).unwrap();
        let crh_g = TwoToOneCRHGadget::<Fr>::compress(&params_g, &crh_a_g, &crh_b_g).unwrap();

        assert_eq!(crh_a, crh_a_g.value().unwrap());
        assert_eq!(crh_b, crh_b_g.value().unwrap());
        assert_eq!(crh, crh_g.value().unwrap());
    }
}
