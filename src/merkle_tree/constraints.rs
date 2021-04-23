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
use ark_std::vec::Vec;
/// Represents a merkle tree path gadget.
pub struct PathVar<P, LeafH, TwoToOneH, ConstraintF>
where
    P: Config,
    LeafH: CRHGadget<P::LeafHash, ConstraintF>,
    TwoToOneH: TwoToOneCRHGadget<P::TwoToOneHash, ConstraintF>,
    ConstraintF: Field,
{
    /// `path[i]` is 0 (false) iff ith non-leaf node from top to bottom is left.
    path: Vec<Boolean<ConstraintF>>,
    /// `auth_path[i]` is the entry of sibling of ith non-leaf node from top to bottom.
    auth_path: Vec<TwoToOneH::OutputVar>,
    /// The sibling of leaf.
    leaf_sibling: LeafH::OutputVar,
    /// Is this leaf the right child?
    leaf_is_right_child: Boolean<ConstraintF>,
}

impl<P, LeafH, TwoToOneH, ConstraintF> AllocVar<Path<P>, ConstraintF>
    for PathVar<P, LeafH, TwoToOneH, ConstraintF>
where
    P: Config,
    LeafH: CRHGadget<P::LeafHash, ConstraintF>,
    TwoToOneH: TwoToOneCRHGadget<P::TwoToOneHash, ConstraintF>,
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
            let leaf_sibling = LeafH::OutputVar::new_variable(
                ark_relations::ns!(cs, "leaf_sibling"),
                || Ok(val.borrow().leaf_sibling_hash.clone()),
                mode,
            )?;
            let leaf_position_bit = Boolean::new_variable(
                ark_relations::ns!(cs, "leaf_position_bit"),
                || Ok(val.borrow().leaf_index & 1 == 1),
                mode,
            )?;
            let pos_list: Vec<_> = val.borrow().position_list().collect();
            let path = Vec::new_variable(
                ark_relations::ns!(cs, "path_bits"),
                || Ok(&pos_list[..(pos_list.len() - 1)]),
                mode,
            )?;

            let auth_path = Vec::new_variable(
                ark_relations::ns!(cs, "auth_path_nodes"),
                || Ok(&val.borrow().auth_path[..]),
                mode,
            )?;
            Ok(PathVar {
                path,
                auth_path,
                leaf_sibling,
                leaf_is_right_child: leaf_position_bit,
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
    /// Calculate the root of the Merkle tree assuming that `leaf` is the leaf on the path defined by `self`.
    fn calculate_root(
        &self,
        leaf_hash_params: &LeafH::ParametersVar,
        two_to_one_hash_params: &TwoToOneH::ParametersVar,
        leaf: &impl ToBytesGadget<ConstraintF>,
    ) -> Result<TwoToOneH::OutputVar, SynthesisError> {
        let leaf_bytes = leaf.to_bytes()?;
        let claimed_leaf_hash = LeafH::evaluate(leaf_hash_params, &leaf_bytes)?;
        let leaf_sibling_hash = &self.leaf_sibling;

        // calculate hash for the bottom non_leaf_layer

        // We assume that when a bit is 0, it indicates that the currently hashed value H is the left child,
        // and when bit is 1, it indicates our H is the right child.
        // Thus `left_hash` is sibling if the bit `leaf_is_right_child` is 1, and is leaf otherwise.

        let left_hash = self
            .leaf_is_right_child
            .select(leaf_sibling_hash, &claimed_leaf_hash)?
            .to_bytes()?;
        let right_hash = self
            .leaf_is_right_child
            .select(&claimed_leaf_hash, leaf_sibling_hash)?
            .to_bytes()?;

        let mut curr_hash = TwoToOneH::evaluate(two_to_one_hash_params, &left_hash, &right_hash)?;
        // To traverse up a MT, we iterate over the path from bottom to top (i.e. in reverse)

        // At any given bit, the bit being 0 indicates our currently hashed value is the left,
        // and the bit being 1 indicates our currently hashed value is on the right.
        // Thus `left_hash` is the sibling if bit is 1, and it's the computed hash if bit is 0
        for (bit, sibling) in self.path.iter().rev().zip(self.auth_path.iter().rev()) {
            let left_hash = bit.select(sibling, &curr_hash)?;
            let right_hash = bit.select(&curr_hash, sibling)?;

            curr_hash = TwoToOneH::evaluate(
                two_to_one_hash_params,
                &left_hash.to_bytes()?,
                &right_hash.to_bytes()?,
            )?;
        }

        Ok(curr_hash)
    }

    /// Check that hashing a Merkle tree path according to `self`, and
    /// with `leaf` as the leaf, leads to a Merkle tree root equalling `root`.
    pub fn verify_membership(
        &self,
        leaf_hash_params: &LeafH::ParametersVar,
        two_to_one_hash_params: &TwoToOneH::ParametersVar,
        root: &TwoToOneH::OutputVar,
        leaf: &impl ToBytesGadget<ConstraintF>,
    ) -> Result<Boolean<ConstraintF>, SynthesisError> {
        let expected_root = self.calculate_root(leaf_hash_params, two_to_one_hash_params, leaf)?;
        Ok(expected_root.is_eq(root)?)
    }

    /// Check that `old_leaf` is the leaf of the Merkle tree on the path defined by
    /// `self`, and then compute the new root when replacing `old_leaf` by `new_leaf`.
    pub fn update_leaf(
        &self,
        leaf_hash_params: &LeafH::ParametersVar,
        two_to_one_hash_params: &TwoToOneH::ParametersVar,
        old_root: &TwoToOneH::OutputVar,
        old_leaf: &impl ToBytesGadget<ConstraintF>,
        new_leaf: &impl ToBytesGadget<ConstraintF>,
    ) -> Result<TwoToOneH::OutputVar, SynthesisError> {
        self.verify_membership(leaf_hash_params, two_to_one_hash_params, old_root, old_leaf)?
            .enforce_equal(&Boolean::TRUE);
        Ok(self.calculate_root(leaf_hash_params, two_to_one_hash_params, new_leaf)?)
    }

    /// Check that `old_leaf` is the leaf of the Merkle tree on the path defined by
    /// `self`, and then compute the expected new root when replacing `old_leaf` by `new_leaf`.
    /// Return a boolean indicating whether expected new root equals `new_root`.
    pub fn update_and_check(
        &self,
        leaf_hash_params: &LeafH::ParametersVar,
        two_to_one_hash_params: &TwoToOneH::ParametersVar,
        old_root: &TwoToOneH::OutputVar,
        new_root: &TwoToOneH::OutputVar,
        old_leaf: &impl ToBytesGadget<ConstraintF>,
        new_leaf: &impl ToBytesGadget<ConstraintF>,
    ) -> Result<Boolean<ConstraintF>, SynthesisError> {
        let actual_new_root = self.update_leaf(
            leaf_hash_params,
            two_to_one_hash_params,
            old_root,
            old_leaf,
            new_leaf,
        )?;
        Ok(actual_new_root.is_eq(&new_root)?)
    }
}

#[cfg(test)]
mod tests {
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

    type H = pedersen::CRH<JubJub, Window4x256>;
    type HG = pedersen::constraints::CRHGadget<JubJub, EdwardsVar, Window4x256>;

    struct JubJubMerkleTreeParams;

    impl Config for JubJubMerkleTreeParams {
        type LeafHash = H;
        type TwoToOneHash = H;
    }

    type JubJubMerkleTree = MerkleTree<JubJubMerkleTreeParams>;

    /// Generate a merkle tree, its constraints, and test its constraints
    fn merkle_tree_test(
        leaves: &[[u8; 30]],
        use_bad_root: bool,
        update_query: Option<(usize, [u8; 30])>,
    ) -> () {
        let mut rng = ark_std::test_rng();

        let leaf_crh_params = <H as CRH>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <H as TwoToOneCRH>::setup(&mut rng).unwrap();
        let mut tree =
            JubJubMerkleTree::new(&leaf_crh_params, &two_to_one_crh_params, leaves).unwrap();
        let root = tree.root();
        let cs = ConstraintSystem::<Fq>::new_ref();
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof
                .verify(&leaf_crh_params, &two_to_one_crh_params, &root, &leaf)
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

            let constraints_from_digest = cs.num_constraints();
            println!("constraints from digest: {}", constraints_from_digest);

            // Allocate Parameters for CRH
            let leaf_crh_params_var = <HG as CRHGadget<H, _>>::ParametersVar::new_constant(
                ark_relations::ns!(cs, "leaf_crh_parameter"),
                &leaf_crh_params,
            )
            .unwrap();
            let two_to_one_crh_params_var =
                <HG as TwoToOneCRHGadget<H, _>>::ParametersVar::new_constant(
                    ark_relations::ns!(cs, "two_to_one_crh_parameter"),
                    &two_to_one_crh_params,
                )
                .unwrap();

            let constraints_from_params = cs.num_constraints() - constraints_from_digest;
            println!("constraints from parameters: {}", constraints_from_params);

            // Allocate Leaf
            let leaf_g = UInt8::constant_vec(leaf);

            let constraints_from_leaf =
                cs.num_constraints() - constraints_from_params - constraints_from_digest;
            println!("constraints from leaf: {}", constraints_from_leaf);

            // Allocate Merkle Tree Path
            let cw: PathVar<_, HG, HG, Fq> =
                PathVar::new_witness(ark_relations::ns!(cs, "new_witness"), || Ok(&proof)).unwrap();
            // check pathvar correctness
            assert_eq!(cw.leaf_sibling.value().unwrap(), proof.leaf_sibling_hash);
            assert_eq!(
                cw.leaf_is_right_child.value().unwrap(),
                proof.leaf_index & 1 == 1
            );
            let position_list: Vec<_> = proof.position_list().collect();
            for (i, path_node) in cw.path.iter().enumerate() {
                assert_eq!(path_node.value().unwrap(), position_list[i]);
            }
            for (i, auth_path_node) in cw.auth_path.iter().enumerate() {
                assert_eq!(auth_path_node.value().unwrap(), proof.auth_path[i])
            }

            let constraints_from_path = cs.num_constraints()
                - constraints_from_params
                - constraints_from_digest
                - constraints_from_leaf;
            println!("constraints from path: {}", constraints_from_path);
            let leaf_g: &[_] = leaf_g.as_slice();
            assert!(cs.is_satisfied().unwrap());
            assert!(cw
                .verify_membership(
                    &leaf_crh_params_var,
                    &two_to_one_crh_params_var,
                    &root,
                    &leaf_g,
                )
                .unwrap()
                .value()
                .unwrap());
            let setup_constraints = constraints_from_leaf
                + constraints_from_digest
                + constraints_from_params
                + constraints_from_path;
            println!(
                "number of constraints: {}",
                cs.num_constraints() - setup_constraints
            );
        }

        assert!(
            cs.is_satisfied().unwrap(),
            "verification constraints not satisfied"
        );

        // check update
        if let Some(update_query) = update_query {
            let cs = ConstraintSystem::<Fq>::new_ref();
            // allocate parameters for CRH
            let leaf_crh_params_var = <HG as CRHGadget<H, _>>::ParametersVar::new_constant(
                ark_relations::ns!(cs, "leaf_crh_parameter"),
                &leaf_crh_params,
            )
            .unwrap();
            let two_to_one_crh_params_var =
                <HG as TwoToOneCRHGadget<H, _>>::ParametersVar::new_constant(
                    ark_relations::ns!(cs, "two_to_one_crh_parameter"),
                    &two_to_one_crh_params,
                )
                .unwrap();

            // allocate old leaf and new leaf
            let old_leaf_var =
                UInt8::new_input_vec(ark_relations::ns!(cs, "old_leaf"), &leaves[update_query.0])
                    .unwrap();
            let new_leaf_var =
                UInt8::new_input_vec(ark_relations::ns!(cs, "new_leaf"), &update_query.1).unwrap();
            //
            // suppose the verifier already knows old root, new root, old leaf, new leaf, and the original path (so they are public)
            let old_root = tree.root();
            let old_root_var = <HG as CRHGadget<H, _>>::OutputVar::new_input(
                ark_relations::ns!(cs, "old_root"),
                || Ok(old_root),
            )
            .unwrap();
            let old_path = tree.generate_proof(update_query.0).unwrap();
            let old_path_var: PathVar<_, HG, HG, Fq> =
                PathVar::new_input(ark_relations::ns!(cs, "old_path"), || Ok(old_path)).unwrap();
            let new_root = {
                tree.update(update_query.0, &update_query.1).unwrap();
                tree.root()
            };
            let new_root_var = <HG as CRHGadget<H, _>>::OutputVar::new_input(
                ark_relations::ns!(cs, "old_root"),
                || Ok(new_root),
            )
            .unwrap();
            // verifier need to get a proof (the witness) to show the known new root is correct
            assert!(old_path_var
                .update_and_check(
                    &leaf_crh_params_var,
                    &two_to_one_crh_params_var,
                    &old_root_var,
                    &new_root_var,
                    &old_leaf_var.as_slice(),
                    &new_leaf_var.as_slice(),
                )
                .unwrap()
                .value()
                .unwrap());
            assert!(cs.is_satisfied().unwrap())
        }
    }

    #[test]
    fn good_root_test() {
        let mut leaves = Vec::new();
        for i in 0..4u8 {
            let input = [i; 30];
            leaves.push(input);
        }
        merkle_tree_test(&leaves, false, Some((3usize, [7u8; 30])));
    }

    #[test]
    #[should_panic]
    fn bad_root_test() {
        let mut leaves = Vec::new();
        for i in 0..4u8 {
            let input = [i; 30];
            leaves.push(input);
        }
        merkle_tree_test(&leaves, true, None);
    }
}
