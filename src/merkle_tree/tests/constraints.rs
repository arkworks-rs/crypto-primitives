mod byte_mt_tests {
    use crate::crh::{pedersen, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget};

    use crate::merkle_tree::constraints::{BytesVarDigestConverter, ConfigGadget};
    use crate::merkle_tree::{ByteDigestConverter, Config};
    use crate::{CRHScheme, CRHSchemeGadget, MerkleTree, PathVar};
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

    type LeafH = pedersen::CRH<JubJub, Window4x256>;
    type LeafHG = pedersen::constraints::CRHGadget<JubJub, EdwardsVar, Window4x256>;

    type CompressH = pedersen::TwoToOneCRH<JubJub, Window4x256>;
    type CompressHG = pedersen::constraints::TwoToOneCRHGadget<JubJub, EdwardsVar, Window4x256>;

    type LeafVar<ConstraintF> = [UInt8<ConstraintF>];

    struct JubJubMerkleTreeParams;

    impl Config for JubJubMerkleTreeParams {
        type Leaf = [u8];
        type LeafDigest = <LeafH as CRHScheme>::Output;
        type LeafInnerDigestConverter = ByteDigestConverter<Self::LeafDigest>;

        type InnerDigest = <CompressH as TwoToOneCRHScheme>::Output;
        type LeafHash = LeafH;
        type TwoToOneHash = CompressH;
    }

    type ConstraintF = Fq;
    struct JubJubMerkleTreeParamsVar;
    impl ConfigGadget<JubJubMerkleTreeParams, ConstraintF> for JubJubMerkleTreeParamsVar {
        type Leaf = LeafVar<ConstraintF>;
        type LeafDigest = <LeafHG as CRHSchemeGadget<LeafH, ConstraintF>>::OutputVar;
        type LeafInnerConverter = BytesVarDigestConverter<Self::LeafDigest, ConstraintF>;
        type InnerDigest =
            <CompressHG as TwoToOneCRHSchemeGadget<CompressH, ConstraintF>>::OutputVar;
        type LeafHash = LeafHG;
        type TwoToOneHash = CompressHG;
    }

    type JubJubMerkleTree = MerkleTree<JubJubMerkleTreeParams>;

    /// Generate a merkle tree, its constraints, and test its constraints
    fn merkle_tree_test(
        leaves: &[Vec<u8>],
        use_bad_root: bool,
        update_query: Option<(usize, Vec<u8>)>,
    ) -> () {
        let mut rng = ark_std::test_rng();

        let leaf_crh_params = <LeafH as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <CompressH as TwoToOneCRHScheme>::setup(&mut rng).unwrap();
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
                .verify(
                    &leaf_crh_params,
                    &two_to_one_crh_params,
                    &root,
                    leaf.as_slice()
                )
                .unwrap());

            // Allocate Merkle Tree Root
            let root = <LeafHG as CRHSchemeGadget<LeafH, _>>::OutputVar::new_witness(
                ark_relations::ns!(cs, "new_digest"),
                || {
                    if use_bad_root {
                        Ok(<LeafH as CRHScheme>::Output::default())
                    } else {
                        Ok(root)
                    }
                },
            )
            .unwrap();

            let constraints_from_digest = cs.num_constraints();
            println!("constraints from digest: {}", constraints_from_digest);

            // Allocate Parameters for CRH
            let leaf_crh_params_var =
                <LeafHG as CRHSchemeGadget<LeafH, _>>::ParametersVar::new_constant(
                    ark_relations::ns!(cs, "leaf_crh_parameter"),
                    &leaf_crh_params,
                )
                .unwrap();
            let two_to_one_crh_params_var =
                <CompressHG as TwoToOneCRHSchemeGadget<CompressH, _>>::ParametersVar::new_constant(
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
            let leaf_crh_params_var =
                <LeafHG as CRHSchemeGadget<LeafH, _>>::ParametersVar::new_constant(
                    ark_relations::ns!(cs, "leaf_crh_parameter"),
                    &leaf_crh_params,
                )
                .unwrap();
            let two_to_one_crh_params_var =
                <CompressHG as TwoToOneCRHSchemeGadget<CompressH, _>>::ParametersVar::new_constant(
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
            let old_root_var = <LeafHG as CRHSchemeGadget<LeafH, _>>::OutputVar::new_input(
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
            let new_root_var = <LeafHG as CRHSchemeGadget<LeafH, _>>::OutputVar::new_input(
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

mod field_mt_tests {
    // TODO
}
