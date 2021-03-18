use crate::crh::TwoToOneCRHGadget;
use crate::merkle_tree::Config;
use crate::CRHGadget;
use ark_ff::Field;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::ToBytesGadget;
use ark_relations::r1cs::SynthesisError;

/// Represents a merkle tree path gadget.
pub struct PathVar<P, LeafH, NodeH, ConstraintF>
where
    P: Config,
    LeafH: CRHGadget<P::LeafHash, ConstraintF>,
    NodeH: TwoToOneCRHGadget<P::TwoToOneHash, ConstraintF>,
    ConstraintF: Field,
{
    /// `path[i]` is 0 (false) iff ith non-leaf node from top to bottom is left.
    path: Vec<Boolean<ConstraintF>>,
    /// `auth_path[i]` is the entry of sibling of ith non-leaf node from top to bottom.
    auth_path: Vec<NodeH::OutputVar>,
    /// THe sibling of leaf.
    leaf_sibling: LeafH::OutputVar,
    /// position of leaf. Should be 0 (false) iff leaf is on the left.
    leaf_position_bit: Boolean<ConstraintF>,
}

impl<P, LeafH, TwoToOneH, ConstraintF> PathVar<P, LeafH, TwoToOneH, ConstraintF>
where
    P: Config,
    LeafH: CRHGadget<P::LeafHash, ConstraintF>,
    TwoToOneH: TwoToOneCRHGadget<P::TwoToOneHash, ConstraintF>,
    ConstraintF: Field,
{
    /// Given a leaf, calculate the hash of the merkle tree
    /// along the path and check if the given root is correct.
    ///
    /// Constraints will not be satisfied if root is incorrect.
    pub fn check_membership(
        &self,
        leaf_hash_parameter: &LeafH::ParametersVar,
        two_to_one_hash_parameter: &TwoToOneH::ParametersVar,
        root: &TwoToOneH::OutputVar,
        leaf: &impl ToBytesGadget<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        self.conditionally_check_membership(
            leaf_hash_parameter,
            two_to_one_hash_parameter,
            root,
            leaf,
            &Boolean::constant(true),
        )
    }

    /// Check membership if `should_enforce` is True.
    pub fn conditionally_check_membership(
        &self,
        leaf_hash_parameter: &LeafH::ParametersVar,
        two_to_one_hash_parameter: &TwoToOneH::ParametersVar,
        root: &TwoToOneH::OutputVar,
        leaf: &impl ToBytesGadget<ConstraintF>,
        should_enforce: &Boolean<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        // calculate leaf hash
        let leaf_bytes = leaf.to_bytes()?;
        let claimed_leaf_hash = LeafH::evaluate(leaf_hash_parameter, &leaf_bytes)?;
        let leaf_sibling_hash = &self.leaf_sibling;

        // calculate hash for the bottom non_leaf_layer

        // At any given bit, the bit being 0 indicates our currently hashed value is the left,
        // and the bit being 1 indicates our currently hashed value is on the right.
        // Thus `left_hash` is sibling if leaf_position_bit is 1, and leaf if bit is 0

        let left_hash = self
            .leaf_position_bit
            .select(leaf_sibling_hash, &claimed_leaf_hash)?
            .to_bytes()?;
        let right_hash = self
            .leaf_position_bit
            .select(&claimed_leaf_hash, leaf_sibling_hash)?
            .to_bytes()?;

        let mut curr_hash =
            TwoToOneH::evaluate_both(two_to_one_hash_parameter, &left_hash, &right_hash)?;

        // To traverse up a MT, we iterate over the path from bottom to top (in reverse)
        let path_rev = {
            let mut p = self.path.to_vec();
            p.reverse();
            p
        };
        let auth_path_rev = {
            let mut p = self.auth_path.to_vec();
            p.reverse();
            p
        };

        for level in 0..auth_path_rev.len() {
            // At any given bit, the bit being 0 indicates our currently hashed value is the left,
            // and the bit being 1 indicates our currently hashed value is on the right.
            // Thus `left_hash` is sibling if bit is 1, and leaf if bit is 0
            let bit = &path_rev[level];

            let sibling = &auth_path_rev[level];

            let left_hash = bit.select(sibling, &curr_hash)?;
            let right_hash = bit.select(&curr_hash, sibling)?;

            curr_hash = TwoToOneH::evaluate_both(
                two_to_one_hash_parameter,
                &left_hash.to_bytes()?,
                &right_hash.to_bytes()?,
            )?
        }

        // enforce `curr_hash` is root
        curr_hash.conditional_enforce_equal(root, should_enforce);
        Ok(())
    }

    /// update the `old_leaf` to `new_leaf` and returned the updated MT root.
    ///
    /// If the `old_leaf` does not lead to `old_root`, constraints will not be satisfied.
    pub fn update_leaf(
        &self,
        old_root: &TwoToOneH::OutputVar, // todo: do we check the root here?
        old_leaf: &impl ToBytesGadget<ConstraintF>,
        new_leaf: &impl ToBytesGadget<ConstraintF>,
    ) -> Result<TwoToOneH::OutputVar, SynthesisError> {
        todo!()
    }

    /// update the `old_leaf` to `new_leaf` and returned the updated MT root.
    ///
    /// If the `old_leaf` does not lead to `old_root`, or `new_leaf` does not lead to `new_root`,
    /// then constraints will not be satisfied.
    pub fn check_and_update(
        &self,
        old_root: &TwoToOneH::OutputVar,
        new_root: &TwoToOneH::OutputVar,
        old_leaf: &impl ToBytesGadget<ConstraintF>,
        new_leaf: &impl ToBytesGadget<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        todo!()
    }
}
