#[cfg(feature = "r1cs")]
mod constraints;
mod test_utils;

mod bytes_mt_tests {

    use crate::{crh::*, merkle_tree::*};
    use ark_ed_on_bls12_381::EdwardsProjective as JubJub;
    use ark_ff::BigInteger256;
    use ark_std::{iter::zip, test_rng, UniformRand};
    use crate::merkle_tree::LeafOrderingMode;

    #[derive(Clone)]
    pub(super) struct Window4x256;
    impl pedersen::Window for Window4x256 {
        const WINDOW_SIZE: usize = 4;
        const NUM_WINDOWS: usize = 256;
    }

    type LeafH = pedersen::CRH<JubJub, Window4x256>;
    type CompressH = pedersen::TwoToOneCRH<JubJub, Window4x256>;

    struct JubJubMerkleTreeParams;

    impl Config for JubJubMerkleTreeParams {
        type Leaf = [u8];

        type LeafDigest = <LeafH as CRHScheme>::Output;
        type LeafInnerDigestConverter = ByteDigestConverter<Self::LeafDigest>;
        type InnerDigest = <CompressH as TwoToOneCRHScheme>::Output;

        type LeafHash = LeafH;
        type TwoToOneHash = CompressH;
    }
    type JubJubMerkleTree = MerkleTree<JubJubMerkleTreeParams>;

    /// Pedersen only takes bytes as leaf, so we use `ToBytes` trait.
    fn merkle_tree_test<L: CanonicalSerialize>(leaves: &[L], update_query: &[(usize, L)]) -> () {
        let mut rng = ark_std::test_rng();

        let mut leaves: Vec<_> = leaves
            .iter()
            .map(|leaf| crate::to_uncompressed_bytes!(leaf).unwrap())
            .collect();

        let leaf_crh_params = <LeafH as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_params = <CompressH as TwoToOneCRHScheme>::setup(&mut rng).unwrap();

        let mut tree =
            JubJubMerkleTree::new(&leaf_crh_params, &two_to_one_params, &leaves, LeafOrderingMode::NATURAL).unwrap();

        let mut root = tree.root();
        // test merkle tree functionality without update
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof
                .verify(&leaf_crh_params, &two_to_one_params, &root, leaf.as_slice())
                .unwrap());
        }

        // test the merkle tree multi-proof functionality
        let mut multi_proof = tree
            .generate_multi_proof((0..leaves.len()).collect::<Vec<_>>())
            .unwrap();

        assert!(multi_proof
            .verify(&leaf_crh_params, &two_to_one_params, &root, leaves.clone())
            .unwrap());

        // test merkle tree update functionality
        for (i, v) in update_query {
            let v = crate::to_uncompressed_bytes!(v).unwrap();
            tree.update(*i, &v).unwrap();
            leaves[*i] = v.clone();
        }
        // update the root
        root = tree.root();
        // verify again
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof
                .verify(&leaf_crh_params, &two_to_one_params, &root, leaf.as_slice())
                .unwrap());
        }

        // test the merkle tree multi-proof functionality again
        multi_proof = tree
            .generate_multi_proof((0..leaves.len()).collect::<Vec<_>>())
            .unwrap();

        assert!(multi_proof
            .verify(&leaf_crh_params, &two_to_one_params, &root, leaves.clone())
            .unwrap());
    }

    #[test]
    fn good_root_test() {
        let mut rng = test_rng();

        let mut leaves = Vec::new();
        for _ in 0..2u8 {
            leaves.push(BigInteger256::rand(&mut rng));
        }
        merkle_tree_test(
            &leaves,
            &vec![
                (0, BigInteger256::rand(&mut rng)),
                (1, BigInteger256::rand(&mut rng)),
            ],
        );

        let mut leaves = Vec::new();
        for _ in 0..4u8 {
            leaves.push(BigInteger256::rand(&mut rng));
        }
        merkle_tree_test(&leaves, &vec![(3, BigInteger256::rand(&mut rng))]);

        let mut leaves = Vec::new();
        for _ in 0..128u8 {
            leaves.push(BigInteger256::rand(&mut rng));
        }
        merkle_tree_test(
            &leaves,
            &vec![
                (2, BigInteger256::rand(&mut rng)),
                (3, BigInteger256::rand(&mut rng)),
                (5, BigInteger256::rand(&mut rng)),
                (111, BigInteger256::rand(&mut rng)),
                (127, BigInteger256::rand(&mut rng)),
            ],
        );
    }

    #[test]
    fn multi_proof_dissection_test() {
        let mut rng = test_rng();

        let mut leaves = Vec::new();
        for _ in 0..8u8 {
            leaves.push(BigInteger256::rand(&mut rng));
        }
        assert_eq!(leaves.len(), 8);

        let serialized_leaves: Vec<_> = leaves
            .iter()
            .map(|leaf| crate::to_uncompressed_bytes!(leaf).unwrap())
            .collect();

        let leaf_crh_params = <LeafH as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_params = <CompressH as TwoToOneCRHScheme>::setup(&mut rng).unwrap();

        let tree = JubJubMerkleTree::new(&leaf_crh_params, &two_to_one_params, &serialized_leaves, LeafOrderingMode::NATURAL)
            .unwrap();

        let mut proofs = Vec::with_capacity(leaves.len());

        for (i, _) in leaves.iter().enumerate() {
            proofs.push(tree.generate_proof(i).unwrap());
        }

        let multi_proof = tree
            .generate_multi_proof((0..leaves.len()).collect::<Vec<_>>())
            .unwrap();

        // test compression theretical prefix lengths for size 8 Tree:
        // we should send 6 hashes instead of 2*8 = 16
        let theoretical_prefix_lengths = vec![0, 2, 1, 2, 0, 2, 1, 2];

        for (comp_len, exp_len) in zip(
            &multi_proof.auth_paths_prefix_lenghts,
            &theoretical_prefix_lengths,
        ) {
            assert_eq!(comp_len, exp_len);
        }

        // test that the compressed paths can expand to expected len
        for (prefix_len, suffix) in zip(
            &multi_proof.auth_paths_prefix_lenghts,
            &multi_proof.auth_paths_suffixes,
        ) {
            assert_eq!(prefix_len + suffix.len(), proofs[0].auth_path.len());
        }
    }

    #[test]
    fn bit_reversed_ordering_test() {
        use ark_serialize::CanonicalSerialize;
        let mut rng = test_rng();

        // Create test leaves with distinct values
        let mut leaves = Vec::new();
        for i in 0..8u8 {
            leaves.push(BigInteger256::from(i as u64));
        }

        let serialized_leaves: Vec<_> = leaves
            .iter()
            .map(|leaf| crate::to_uncompressed_bytes!(leaf).unwrap())
            .collect();

        let leaf_crh_params = <LeafH as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_params = <CompressH as TwoToOneCRHScheme>::setup(&mut rng).unwrap();

        // Create two trees: one with natural ordering, one with bit-reversed ordering
        let tree_natural = JubJubMerkleTree::new(
            &leaf_crh_params,
            &two_to_one_params,
            &serialized_leaves,
            LeafOrderingMode::NATURAL,
        )
        .unwrap();

        let tree_bit_reversed = JubJubMerkleTree::new(
            &leaf_crh_params,
            &two_to_one_params,
            &serialized_leaves,
            LeafOrderingMode::BIT_REVERSED,
        )
        .unwrap();

        // NOTE: The roots will be DIFFERENT because the physical leaf arrangement is different
        // This is expected and correct behavior
        assert_ne!(tree_natural.root(), tree_bit_reversed.root());

        // Test that proofs work correctly for both ordering modes
        for (i, leaf) in serialized_leaves.iter().enumerate() {
            // Natural ordering proof
            let proof_natural = tree_natural.generate_proof(i).unwrap();
            assert!(proof_natural
                .verify(&leaf_crh_params, &two_to_one_params, &tree_natural.root(), leaf.as_slice())
                .unwrap());

            // Bit-reversed ordering proof
            let proof_bit_reversed = tree_bit_reversed.generate_proof(i).unwrap();
            let actual_leaf = serialized_leaves[bit_reverse_index(i, (tree_bit_reversed.height() - 1) as u32)].clone();
            assert!(proof_bit_reversed
                .verify(&leaf_crh_params, &two_to_one_params, &tree_bit_reversed.root(), actual_leaf.as_slice())
                .unwrap());
        }

        // Test multi-proofs work with bit-reversed ordering
        let multi_proof_natural = tree_natural
            .generate_multi_proof((0..serialized_leaves.len()).collect::<Vec<_>>())
            .unwrap();
        assert!(multi_proof_natural
            .verify(&leaf_crh_params, &two_to_one_params, &tree_natural.root(), serialized_leaves.clone())
            .unwrap());

        let multi_proof_bit_reversed = tree_bit_reversed
            .generate_multi_proof((0..serialized_leaves.len()).collect::<Vec<_>>())
            .unwrap();
        assert!(multi_proof_bit_reversed
            .verify(&leaf_crh_params, &two_to_one_params, &tree_bit_reversed.root(), serialized_leaves.clone())
            .unwrap());

        // Verify the ordering mode is stored correctly in multi-proofs
        assert_eq!(multi_proof_natural.leaf_ordering_mode, LeafOrderingMode::NATURAL);
        assert_eq!(multi_proof_bit_reversed.leaf_ordering_mode, LeafOrderingMode::BIT_REVERSED);
    }

    #[test]
    fn bit_reverse_index_test() {
        // Test the bit_reverse_index function directly
        // For height=3 (8 leaves), indices should be:
        // 0 (000) -> 0 (000)
        // 1 (001) -> 4 (100)
        // 2 (010) -> 2 (010)
        // 3 (011) -> 6 (110)
        // 4 (100) -> 1 (001)
        // 5 (101) -> 5 (101)
        // 6 (110) -> 3 (011)
        // 7 (111) -> 7 (111)
        
        use crate::merkle_tree::bit_reverse_index;
        
        let height = 3u32;
        assert_eq!(bit_reverse_index(0, height), 0);
        assert_eq!(bit_reverse_index(1, height), 4);
        assert_eq!(bit_reverse_index(2, height), 2);
        assert_eq!(bit_reverse_index(3, height), 6);
        assert_eq!(bit_reverse_index(4, height), 1);
        assert_eq!(bit_reverse_index(5, height), 5);
        assert_eq!(bit_reverse_index(6, height), 3);
        assert_eq!(bit_reverse_index(7, height), 7);

        // Test with height=2 (4 leaves)
        let height = 2u32;
        assert_eq!(bit_reverse_index(0, height), 0);
        assert_eq!(bit_reverse_index(1, height), 2);
        assert_eq!(bit_reverse_index(2, height), 1);
        assert_eq!(bit_reverse_index(3, height), 3);

        // Test edge case: height=0 should return the same index
        assert_eq!(bit_reverse_index(5, 0), 5);
    }
}

mod field_mt_tests {
    use crate::{
        crh::poseidon,
        merkle_tree::{
            tests::test_utils::poseidon_parameters, Config, IdentityDigestConverter, MerkleTree, LeafOrderingMode
        },
    };
    use ark_std::{test_rng, One, UniformRand};

    type F = ark_ed_on_bls12_381::Fr;
    type H = poseidon::CRH<F>;
    type TwoToOneH = poseidon::TwoToOneCRH<F>;

    struct FieldMTConfig;
    impl Config for FieldMTConfig {
        type Leaf = [F];
        type LeafDigest = F;
        type LeafInnerDigestConverter = IdentityDigestConverter<F>;
        type InnerDigest = F;
        type LeafHash = H;
        type TwoToOneHash = TwoToOneH;
    }

    type FieldMT = MerkleTree<FieldMTConfig>;

    fn merkle_tree_test(leaves: &[Vec<F>], update_query: &[(usize, Vec<F>)]) -> () {
        let mut leaves = leaves.to_vec();
        let leaf_crh_params = poseidon_parameters();
        let two_to_one_params = leaf_crh_params.clone();

        let mut tree = FieldMT::new(&leaf_crh_params, &two_to_one_params, &leaves, LeafOrderingMode::NATURAL).unwrap();

        let mut root = tree.root();

        // test merkle tree functionality without update
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof
                .verify(&leaf_crh_params, &two_to_one_params, &root, leaf.as_slice())
                .unwrap());
        }

        // test the merkle tree multi-proof functionality
        let mut multi_proof = tree
            .generate_multi_proof((0..leaves.len()).collect::<Vec<_>>())
            .unwrap();

        assert!(multi_proof
            .verify(&leaf_crh_params, &two_to_one_params, &root, leaves.clone())
            .unwrap());

        {
            // wrong root should lead to error but do not panic
            let wrong_root = root + F::one();
            let proof = tree.generate_proof(0).unwrap();
            assert!(!proof
                .verify(
                    &leaf_crh_params,
                    &two_to_one_params,
                    &wrong_root,
                    leaves[0].as_slice()
                )
                .unwrap());

            // test the merkle tree multi-proof functionality
            let multi_proof = tree
                .generate_multi_proof((0..leaves.len()).collect::<Vec<_>>())
                .unwrap();

            assert!(!multi_proof
                .verify(
                    &leaf_crh_params,
                    &two_to_one_params,
                    &wrong_root,
                    leaves.clone()
                )
                .unwrap());
        }

        // test merkle tree update functionality
        for (i, v) in update_query {
            tree.update(*i, v).unwrap();
            leaves[*i] = v.to_vec();
        }

        // update the root
        root = tree.root();

        // verify again
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof
                .verify(&leaf_crh_params, &two_to_one_params, &root, leaf.as_slice())
                .unwrap());
        }

        multi_proof = tree
            .generate_multi_proof((0..leaves.len()).collect::<Vec<_>>())
            .unwrap();

        assert!(multi_proof
            .verify(&leaf_crh_params, &two_to_one_params, &root, leaves.clone())
            .unwrap());
    }

    #[test]
    fn good_root_test() {
        let mut rng = test_rng();
        let mut rand_leaves = || (0..3).map(|_| F::rand(&mut rng)).collect();

        let mut leaves: Vec<Vec<_>> = Vec::new();
        for _ in 0..128u8 {
            leaves.push(rand_leaves())
        }
        merkle_tree_test(
            &leaves,
            &vec![
                (2, rand_leaves()),
                (3, rand_leaves()),
                (5, rand_leaves()),
                (111, rand_leaves()),
                (127, rand_leaves()),
            ],
        )
    }
}
