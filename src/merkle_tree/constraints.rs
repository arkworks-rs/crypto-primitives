use crate::crh::TwoToOneFixedLengthCRHGadget;
use crate::merkle_tree::Config;
use crate::FixedLengthCRHGadget;
use ark_ff::Field;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::ToBytesGadget;
use ark_relations::r1cs::SynthesisError;

/// Represents a merkle tree path gadget.
pub struct PathVar<P, LeafH, NodeH, ConstraintF>
where
    P: Config,
    LeafH: FixedLengthCRHGadget<P::LeafHash, ConstraintF>,
    NodeH: TwoToOneFixedLengthCRHGadget<P::TwoToOneHash, ConstraintF>,
    ConstraintF: Field,
{
    /// `path[i]` is 0 (false) iff ith non-leaf node from top to bottom is left.
    path: Vec<Boolean<ConstraintF>>,
    /// `auth_path[i]` is the entry of sibling of ith non-leaf node from top to bottom.
    auth_path: Vec<NodeH::OutputVar>,
    /// Leaf of sibling.
    leaf_sibling: LeafH::OutputVar,
}

impl<P, LeafH, NodeH, ConstraintF> PathVar<P, LeafH, NodeH, ConstraintF>
where
    P: Config,
    LeafH: FixedLengthCRHGadget<P::LeafHash, ConstraintF>,
    NodeH: TwoToOneFixedLengthCRHGadget<P::TwoToOneHash, ConstraintF>,
    ConstraintF: Field,
{
    /// Given a leaf, calculate the hash of the merkle tree
    /// along the path and check if the given root is correct.
    ///
    /// Constraints will not be satisfied if root is incorrect.
    pub fn check_membership(
        &self,
        root: &NodeH::OutputVar,
        leaf: impl ToBytesGadget<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        self.conditionally_check_membership(root, leaf, &Boolean::constant(true))
    }

    /// Check membership if `should_enforce` is True.
    pub fn conditionally_check_membership(
        &self,
        root: &NodeH::OutputVar,
        leaf: &impl ToBytesGadget<ConstraintF>,
        should_enforce: &Boolean<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        todo!()
    }

    /// update the `old_leaf` to `new_leaf` and returned the updated MT root.
    ///
    /// If the `old_leaf` does not lead to `old_root`, constraints will not be satisfied.
    pub fn update_leaf(
        &self,
        old_root: &NodeH::OutputVar, // todo: do we check the root here?
        old_leaf: &impl ToBytesGadget<ConstraintF>,
        new_leaf: &impl ToBytesGadget<ConstraintF>,
    ) -> Result<NodeH::OutputVar, SynthesisError> {
        todo!()
    }

    /// update the `old_leaf` to `new_leaf` and returned the updated MT root.
    ///
    /// If the `old_leaf` does not lead to `old_root`, or `new_leaf` does not lead to `new_root`,
    /// then constraints will not be satisfied.
    pub fn check_and_update(
        &self,
        old_root: &NodeH::OutputVar,
        new_root: &NodeH::OutputVar,
        old_leaf: &impl ToBytesGadget<ConstraintF>,
        new_leaf: &impl ToBytesGadget<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        todo!()
    }
}
