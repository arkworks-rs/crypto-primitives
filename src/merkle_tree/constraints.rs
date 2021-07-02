use crate::crh::TwoToOneCRHGadget;
use crate::merkle_tree::{Config, IdentityDigestConverter};
use crate::{CRHGadget, Path};
use ark_ff::Field;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
#[allow(unused)]
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::ToBytesGadget;
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::borrow::Borrow;
use ark_std::fmt::Debug;
use ark_std::vec::Vec;

pub trait DigestVarConverter<From, To> {
    fn convert(from: From) -> Result<To, SynthesisError>;
}

impl<T> DigestVarConverter<T, T> for IdentityDigestConverter<T> {
    fn convert(from: T) -> Result<T, SynthesisError> {
        Ok(from)
    }
}

pub struct BytesVarDigestConverter<T: ToBytesGadget<ConstraintF>, ConstraintF: Field> {
    _prev_layer_digest: T,
    _constraint_field: ConstraintF,
}

impl<T: ToBytesGadget<ConstraintF>, ConstraintF: Field>
    DigestVarConverter<T, Vec<UInt8<ConstraintF>>> for BytesVarDigestConverter<T, ConstraintF>
{
    fn convert(from: T) -> Result<Vec<UInt8<ConstraintF>>, SynthesisError> {
        from.to_non_unique_bytes()
    }
}

pub trait ConfigGadget<P: Config, ConstraintF: Field> {
    type Leaf: Debug;
    type LeafDigest: AllocVar<P::LeafDigest, ConstraintF>
        + EqGadget<ConstraintF>
        + ToBytesGadget<ConstraintF>
        + CondSelectGadget<ConstraintF>
        + R1CSVar<ConstraintF>
        + Debug
        + Clone
        + Sized;
    type LeafInnerConverter: DigestVarConverter<
        Self::LeafDigest,
        <Self::TwoToOneHash as TwoToOneCRHGadget<P::TwoToOneHash, ConstraintF>>::InputVar,
    >;
    type InnerDigest: AllocVar<P::InnerDigest, ConstraintF>
        + EqGadget<ConstraintF>
        + ToBytesGadget<ConstraintF>
        + CondSelectGadget<ConstraintF>
        + R1CSVar<ConstraintF>
        + Debug
        + Clone
        + Sized;

    type LeafHash: CRHGadget<
        P::LeafHash,
        ConstraintF,
        InputVar = Self::Leaf,
        OutputVar = Self::LeafDigest,
    >;
    type TwoToOneHash: TwoToOneCRHGadget<
        P::TwoToOneHash,
        ConstraintF,
        OutputVar = Self::InnerDigest,
    >;
}

type LeafParam<PG, P, ConstraintF> =
    <<PG as ConfigGadget<P, ConstraintF>>::LeafHash as CRHGadget<
        <P as Config>::LeafHash,
        ConstraintF,
    >>::ParametersVar;
type TwoToOneParam<PG, P, ConstraintF> =
    <<PG as ConfigGadget<P, ConstraintF>>::TwoToOneHash as TwoToOneCRHGadget<
        <P as Config>::TwoToOneHash,
        ConstraintF,
    >>::ParametersVar;

/// Represents a merkle tree path gadget.
#[derive(Debug)]
pub struct PathVar<P: Config, ConstraintF: Field, PG: ConfigGadget<P, ConstraintF>> {
    /// `path[i]` is 0 (false) iff ith non-leaf node from top to bottom is left.
    path: Vec<Boolean<ConstraintF>>,
    /// `auth_path[i]` is the entry of sibling of ith non-leaf node from top to bottom.
    auth_path: Vec<PG::InnerDigest>,
    /// The sibling of leaf.
    leaf_sibling: PG::LeafDigest,
    /// Is this leaf the right child?
    leaf_is_right_child: Boolean<ConstraintF>,
}

impl<P: Config, ConstraintF: Field, PG: ConfigGadget<P, ConstraintF>> AllocVar<Path<P>, ConstraintF>
    for PathVar<P, ConstraintF, PG>
where
    P: Config,
    ConstraintF: Field,
{
    #[tracing::instrument(target = "r1cs", skip(cs, f))]
    fn new_variable<T: Borrow<Path<P>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        f().and_then(|val| {
            let leaf_sibling = PG::LeafDigest::new_variable(
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

impl<P: Config, ConstraintF: Field, PG: ConfigGadget<P, ConstraintF>> PathVar<P, ConstraintF, PG> {
    /// Calculate the root of the Merkle tree assuming that `leaf` is the leaf on the path defined by `self`.
    #[tracing::instrument(target = "r1cs", skip(self, leaf_params, two_to_one_params))]
    pub fn calculate_root(
        &self,
        leaf_params: &LeafParam<PG, P, ConstraintF>,
        two_to_one_params: &TwoToOneParam<PG, P, ConstraintF>,
        leaf: &PG::Leaf,
    ) -> Result<PG::InnerDigest, SynthesisError> {
        let claimed_leaf_hash = PG::LeafHash::evaluate(leaf_params, leaf)?;
        let leaf_sibling_hash = &self.leaf_sibling;

        // calculate hash for the bottom non_leaf_layer

        // We assume that when a bit is 0, it indicates that the currently hashed value H is the left child,
        // and when bit is 1, it indicates our H is the right child.
        // Thus `left_hash` is sibling if the bit `leaf_is_right_child` is 1, and is leaf otherwise.

        let left_hash = self
            .leaf_is_right_child
            .select(leaf_sibling_hash, &claimed_leaf_hash)?;
        let right_hash = self
            .leaf_is_right_child
            .select(&claimed_leaf_hash, leaf_sibling_hash)?;

        // convert leaf digest to inner digest
        let left_hash = PG::LeafInnerConverter::convert(left_hash)?;
        let right_hash = PG::LeafInnerConverter::convert(right_hash)?;

        let mut curr_hash = PG::TwoToOneHash::evaluate(two_to_one_params, &left_hash, &right_hash)?;
        // To traverse up a MT, we iterate over the path from bottom to top (i.e. in reverse)

        // At any given bit, the bit being 0 indicates our currently hashed value is the left,
        // and the bit being 1 indicates our currently hashed value is on the right.
        // Thus `left_hash` is the sibling if bit is 1, and it's the computed hash if bit is 0
        for (bit, sibling) in self.path.iter().rev().zip(self.auth_path.iter().rev()) {
            let left_hash = bit.select(sibling, &curr_hash)?;
            let right_hash = bit.select(&curr_hash, sibling)?;

            curr_hash = PG::TwoToOneHash::compress(two_to_one_params, &left_hash, &right_hash)?;
        }

        Ok(curr_hash)
    }

    /// Check that hashing a Merkle tree path according to `self`, and
    /// with `leaf` as the leaf, leads to a Merkle tree root equalling `root`.
    #[tracing::instrument(target = "r1cs", skip(self, leaf_params, two_to_one_params))]
    pub fn verify_membership(
        &self,
        leaf_params: &LeafParam<PG, P, ConstraintF>,
        two_to_one_params: &TwoToOneParam<PG, P, ConstraintF>,
        root: &PG::InnerDigest,
        leaf: &PG::Leaf,
    ) -> Result<Boolean<ConstraintF>, SynthesisError> {
        let expected_root = self.calculate_root(leaf_params, two_to_one_params, leaf)?;
        Ok(expected_root.is_eq(root)?)
    }

    /// Check that `old_leaf` is the leaf of the Merkle tree on the path defined by
    /// `self`, and then compute the new root when replacing `old_leaf` by `new_leaf`.
    #[tracing::instrument(target = "r1cs", skip(self, leaf_params, two_to_one_params))]
    pub fn update_leaf(
        &self,
        leaf_params: &LeafParam<PG, P, ConstraintF>,
        two_to_one_params: &TwoToOneParam<PG, P, ConstraintF>,
        old_root: &PG::InnerDigest,
        old_leaf: &PG::Leaf,
        new_leaf: &PG::Leaf,
    ) -> Result<PG::InnerDigest, SynthesisError> {
        self.verify_membership(leaf_params, two_to_one_params, old_root, old_leaf)?
            .enforce_equal(&Boolean::TRUE)?;
        Ok(self.calculate_root(leaf_params, two_to_one_params, new_leaf)?)
    }

    /// Check that `old_leaf` is the leaf of the Merkle tree on the path defined by
    /// `self`, and then compute the expected new root when replacing `old_leaf` by `new_leaf`.
    /// Return a boolean indicating whether expected new root equals `new_root`.
    #[tracing::instrument(target = "r1cs", skip(self, leaf_params, two_to_one_params))]
    pub fn update_and_check(
        &self,
        leaf_params: &LeafParam<PG, P, ConstraintF>,
        two_to_one_params: &TwoToOneParam<PG, P, ConstraintF>,
        old_root: &PG::InnerDigest,
        new_root: &PG::InnerDigest,
        old_leaf: &PG::Leaf,
        new_leaf: &PG::Leaf,
    ) -> Result<Boolean<ConstraintF>, SynthesisError> {
        let actual_new_root =
            self.update_leaf(leaf_params, two_to_one_params, old_root, old_leaf, new_leaf)?;
        Ok(actual_new_root.is_eq(&new_root)?)
    }
}

#[cfg(test)]
mod tests {
    use crate::crh::{pedersen, TwoToOneCRH, TwoToOneCRHGadget};

    use crate::merkle_tree::constraints::{BytesVarDigestConverter, ConfigGadget};
    use crate::merkle_tree::{ByteDigestConverter, Config};
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
    type LeafVar<ConstraintF> = Vec<UInt8<ConstraintF>>;

    struct JubJubMerkleTreeParams;

    impl Config for JubJubMerkleTreeParams {
        type Leaf = [u8];
        type LeafDigest = <H as CRH>::Output;
        type LeafInnerDigestConverter = ByteDigestConverter<Self::LeafDigest>;

        type InnerDigest = <H as CRH>::Output;
        type LeafHash = H;
        type TwoToOneHash = H;
    }

    type ConstraintF = Fq;
    struct JubJubMerkleTreeParamsVar;
    impl ConfigGadget<JubJubMerkleTreeParams, ConstraintF> for JubJubMerkleTreeParamsVar {
        type Leaf = LeafVar<ConstraintF>;
        type LeafDigest = <HG as CRHGadget<H, ConstraintF>>::OutputVar;
        type LeafInnerConverter = BytesVarDigestConverter<Self::LeafDigest, ConstraintF>;
        type InnerDigest = <HG as TwoToOneCRHGadget<H, ConstraintF>>::OutputVar;
        type LeafHash = HG;
        type TwoToOneHash = HG;
    }

    type JubJubMerkleTree = MerkleTree<JubJubMerkleTreeParams>;

    /// Generate a merkle tree, its constraints, and test its constraints
    fn merkle_tree_test(
        leaves: &[Vec<u8>],
        use_bad_root: bool,
        update_query: Option<(usize, Vec<u8>)>,
    ) -> () {
        let mut rng = ark_std::test_rng();

        let leaf_crh_params = <H as CRH>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <H as TwoToOneCRH>::setup(&mut rng).unwrap();
        let mut tree = JubJubMerkleTree::new(
            &leaf_crh_params,
            &two_to_one_crh_params,
            leaves.iter().map(|v| v.as_slice()),
        )
        .unwrap();
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
            let cw: PathVar<JubJubMerkleTreeParams, Fq, JubJubMerkleTreeParamsVar> =
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
            let old_path_var: PathVar<JubJubMerkleTreeParams, Fq, JubJubMerkleTreeParamsVar> =
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
                    &old_leaf_var,
                    &new_leaf_var,
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
            let input = vec![i; 30];
            leaves.push(input);
        }
        merkle_tree_test(&leaves, false, Some((3usize, vec![7u8; 30])));
    }

    #[test]
    #[should_panic]
    fn bad_root_test() {
        let mut leaves = Vec::new();
        for i in 0..4u8 {
            let input = vec![i; 30];
            leaves.push(input);
        }
        merkle_tree_test(&leaves, true, None);
    }
}
