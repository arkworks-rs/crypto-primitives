use crate::crh::TwoToOneCRHGadget;
use crate::merkle_tree::Config;
use crate::{CRHGadget, Path};
use ark_ff::Field;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
#[allow(unused)]
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::ToBytesGadget;
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::borrow::Borrow;

/// Represents a merkle tree path gadget.
pub struct PathVar<P, LeafHG, TwoToOneHG, ConstraintF>
where
    P: Config,
    LeafHG: CRHGadget<P::LeafHash, ConstraintF>,
    TwoToOneHG: TwoToOneCRHGadget<P::TwoToOneHash, ConstraintF>,
    ConstraintF: Field,
{
    /// `path[i]` is 0 (false) iff ith non-leaf node from top to bottom is left.
    path: Vec<Boolean<ConstraintF>>,
    /// `auth_path[i]` is the entry of sibling of ith non-leaf node from top to bottom.
    auth_path: Vec<TwoToOneHG::OutputVar>,
    /// THe sibling of leaf.
    leaf_sibling: LeafHG::OutputVar,
    /// position of leaf. Should be 0 (false) iff leaf is on the left.
    leaf_position_bit: Boolean<ConstraintF>,
}

impl<P, LeafHG, TwoToOneHG, ConstraintF> AllocVar<Path<P>, ConstraintF>
    for PathVar<P, LeafHG, TwoToOneHG, ConstraintF>
where
    P: Config,
    LeafHG: CRHGadget<P::LeafHash, ConstraintF>,
    TwoToOneHG: TwoToOneCRHGadget<P::TwoToOneHash, ConstraintF>,
    ConstraintF: Field,
{
    fn new_variable<T: Borrow<Path<P>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        f().and_then(|val| {
            let leaf_sibling = LeafHG::OutputVar::new_variable(
                ark_relations::ns!(cs, "leaf_sibling"),
                || Ok(val.borrow().leaf_sibling_hash.clone()),
                mode,
            )?;
            let leaf_position_bit = Boolean::new_variable(
                ark_relations::ns!(cs, "leaf_position_bit"),
                || Ok(val.borrow().leaf_index & 1 == 1),
                mode,
            )?;
            let mut path = Vec::with_capacity(val.borrow().position_list().len());
            let pos_list = val.borrow().position_list();
            for &bit in &pos_list[..pos_list.len() - 1] {
                // we do not include leaf bit here, so ignore last element returned by pos_list
                path.push(Boolean::new_variable(
                    ark_relations::ns!(cs, "path_bit"),
                    || Ok(bit),
                    mode,
                )?)
            }

            let mut auth_path = Vec::with_capacity(val.borrow().auth_path.len());
            for v in val.borrow().auth_path.iter() {
                auth_path.push(TwoToOneHG::OutputVar::new_variable(
                    ark_relations::ns!(cs, "auth_path_node"),
                    || Ok(v.clone()),
                    mode,
                )?)
            }
            Ok(PathVar {
                path,
                auth_path,
                leaf_sibling,
                leaf_position_bit,
            })
        })
    }
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
            )?;
        }

        // enforce `curr_hash` is root
        curr_hash.conditional_enforce_equal(root, should_enforce);
        assert!(root.cs().is_satisfied()?);
        Ok(())
    }

    /// update the `old_leaf` to `new_leaf` and returned the updated MT root.
    ///
    /// If the `old_leaf` does not lead to `old_root`, constraints will not be satisfied.
    pub fn update_leaf(
        &self,
        _old_root: &TwoToOneH::OutputVar, // todo: do we check the root here?
        _old_leaf: &impl ToBytesGadget<ConstraintF>,
        _new_leaf: &impl ToBytesGadget<ConstraintF>,
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

#[cfg(test)]
mod tests {
    use crate::crh::pedersen::constraints::PedersenGadget;
    use crate::crh::{pedersen, TwoToOneCRH, TwoToOneCRHGadget};

    use crate::merkle_tree::Config;
    use crate::{CRHGadget, MerkleTree, PathVar, CRH};
    use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective as JubJub, Fq};
    #[allow(unused)]
    use ark_r1cs_std::prelude::*;
    #[allow(unused)]
    use ark_relations::r1cs::ConstraintSystem;

    #[derive(Clone)]
    pub(super) struct Window4x256;
    impl pedersen::Window for Window4x256 {
        const WINDOW_SIZE: usize = 4;
        const NUM_WINDOWS: usize = 256;
    }

    type H = pedersen::PedersenCRH<JubJub, Window4x256>;
    type HG = PedersenGadget<JubJub, EdwardsVar, Window4x256>;

    struct JubJubMerkleTreeParams;

    impl Config for JubJubMerkleTreeParams {
        type LeafHash = H;
        type TwoToOneHash = H;

        fn leaf_hash_output_size_upper_bound() -> usize {
            32
        }

        fn two_to_one_hash_output_size_upper_bound() -> usize {
            32
        }
    }

    type JubJubMerkleTree = MerkleTree<JubJubMerkleTreeParams>;

    /// Generate a merkle tree, its constraints, and test its constraints
    fn merkle_tree_test(leaves: &[[u8; 30]], use_bad_root: bool) -> () {
        let mut rng = ark_std::test_rng();

        let leaf_crh_parameters = H::setup_crh(&mut rng).unwrap();
        let two_to_one_crh_parameters = H::setup_two_to_one_crh(&mut rng).unwrap();
        let tree = JubJubMerkleTree::new(&leaf_crh_parameters, &two_to_one_crh_parameters, leaves)
            .unwrap();
        let root = tree.root();
        let cs = ConstraintSystem::<Fq>::new_ref();
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof
                .verify(
                    &leaf_crh_parameters,
                    &two_to_one_crh_parameters,
                    &root,
                    &leaf
                )
                .unwrap());

            // Allocate Merkle Tree Root
            let root = <HG as CRHGadget<H, _>>::OutputVar::new_witness(
                ark_relations::ns!(cs, "new_digest"),
                || {
                    if use_bad_root {
                        Ok(<H as CRH>::Output::default())
                    } else {
                        Ok(root)
                    }
                },
            )
            .unwrap();

            // let constraints_from_digest = cs.num_constraints();
            // println!("constraints from digest: {}", constraints_from_digest);

            // Allocate Parameters for CRH
            let leaf_crh_parameters_var = <HG as CRHGadget<H, _>>::ParametersVar::new_constant(
                ark_relations::ns!(cs, "leaf_crh_parameter"),
                &leaf_crh_parameters,
            )
            .unwrap();
            let two_to_one_crh_parameters_var =
                <HG as TwoToOneCRHGadget<H, _>>::ParametersVar::new_constant(
                    ark_relations::ns!(cs, "two_to_one_crh_parameter"),
                    &two_to_one_crh_parameters,
                )
                .unwrap();

            // let constraints_from_parameters = cs.num_constraints() - constraints_from_digest;
            // println!(
            //     "constraints from parameters: {}",
            //     constraints_from_parameters
            // );

            // Allocate Leaf
            let leaf_g = UInt8::constant_vec(leaf);

            // let constraints_from_leaf =
            //     cs.num_constraints() - constraints_from_parameters - constraints_from_digest;
            // println!("constraints from leaf: {}", constraints_from_leaf);

            // Allocate Merkle Tree Path
            let cw: PathVar<_, HG, HG, Fq> =
                PathVar::new_witness(ark_relations::ns!(cs, "new_witness"), || Ok(&proof)).unwrap();
            // check pathvar correctness
            assert_eq!(cw.leaf_sibling.value().unwrap(), proof.leaf_sibling_hash);
            assert_eq!(
                cw.leaf_position_bit.value().unwrap(),
                proof.leaf_index & 1 == 1
            );
            let position_list = proof.position_list();
            for (i, path_node) in cw.path.iter().enumerate() {
                assert_eq!(path_node.value().unwrap(), position_list[i]);
            }
            for (i, auth_path_node) in cw.auth_path.iter().enumerate() {
                assert_eq!(auth_path_node.value().unwrap(), proof.auth_path[i])
            }

            // let constraints_from_path = cs.num_constraints()
            //     - constraints_from_parameters
            //     - constraints_from_digest
            //     - constraints_from_leaf;
            // println!("constraints from path: {}", constraints_from_path);
            let leaf_g: &[_] = leaf_g.as_slice();
            assert!(cs.is_satisfied().unwrap());
            cw.check_membership(
                &leaf_crh_parameters_var,
                &two_to_one_crh_parameters_var,
                &root,
                &leaf_g,
            )
            .unwrap();
            // let setup_constraints = constraints_from_leaf
            //     + constraints_from_digest
            //     + constraints_from_parameters
            //     + constraints_from_path;
            // println!(
            //     "number of constraints: {}",
            //     cs.num_constraints() - setup_constraints
            // );
        }

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn good_root_test() {
        let mut leaves = Vec::new();
        for i in 0..4u8 {
            let input = [i; 30];
            leaves.push(input);
        }
        merkle_tree_test(&leaves, false);
    }
}
