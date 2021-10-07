use crate::{
    commitment::{
        injective_map::PedersenCommCompressor,
        pedersen::{
            constraints::{ParametersVar, RandomnessVar},
            Commitment, Window,
        },
        CommitmentGadget,
    },
    Gadget,
};

pub use crate::crh::injective_map::constraints::InjectiveMapGadget;
use ark_ec::ProjectiveCurve;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    groups::{CurveWithVar, GroupOpsBounds},
    uint8::UInt8,
};
use ark_relations::r1cs::SynthesisError;

type ConstraintF<C> = <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField;

impl<C, I, W> crate::commitment::CommitmentWithGadget<ConstraintF<C>>
    for PedersenCommCompressor<C, I, W>
where
    C: CurveWithVar<ConstraintF<C>>,
    I: InjectiveMapGadget<C>,
    ConstraintF<C>: PrimeField,
    W: Window,
    for<'a> &'a C::Var: GroupOpsBounds<'a, C, C::Var>,
{
    type OutputVar = I::OutputVar;
    type ParametersVar = ParametersVar<C>;
    type RandomnessVar = RandomnessVar<ConstraintF<C>>;

    fn commit_gadget(
        parameters: &Self::ParametersVar,
        input: &[UInt8<ConstraintF<C>>],
        r: &Self::RandomnessVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        let result = Gadget::<Commitment<C, W>>::commit(parameters, input, r)?;
        I::evaluate(&result)
    }
}
