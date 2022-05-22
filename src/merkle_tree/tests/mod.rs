#[cfg(feature = "r1cs")]
mod constraints;
mod test_utils;

mod bytes_mt_tests {

    use crate::{
        crh::{pedersen, *},
        merkle_tree::{incremental_merkle_tree::*, *},
    };
    use ark_ed_on_bls12_381::EdwardsProjective as JubJub;
    use ark_ff::BigInteger256;
    use ark_std::{test_rng, UniformRand};

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
    type JubJubIncrementalMerkleTree = IncrementalMerkleTree<JubJubMerkleTreeParams>;

    /// Pedersen only takes bytes as leaf, so we use `ToBytes` trait.
    fn merkle_tree_test<L: CanonicalSerialize>(leaves: &[L], update_query: &[(usize, L)]) -> () {
        let mut rng = ark_std::test_rng();
        let mut leaves: Vec<_> = leaves
            .iter()
            .map(|leaf| crate::to_unchecked_bytes!(leaf).unwrap())
            .collect();
        let leaf_crh_params = <LeafH as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_params = <CompressH as TwoToOneCRHScheme>::setup(&mut rng)
            .unwrap()
            .clone();
        let mut tree = JubJubMerkleTree::new(
            &leaf_crh_params.clone(),
            &two_to_one_params.clone(),
            leaves.iter().map(|x| x.as_slice()),
        )
        .unwrap();
        let mut root = tree.root();
        // test merkle tree functionality without update
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof
                .verify(&leaf_crh_params, &two_to_one_params, &root, leaf.as_slice())
                .unwrap());
        }

        // test merkle tree update functionality
        for (i, v) in update_query {
            let v = crate::to_unchecked_bytes!(v).unwrap();
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
    }

    /// Pedersen only takes bytes as leaf, so we use `ToBytes` trait.
    fn incremental_merkle_tree_test<L: CanonicalSerialize>(
        tree_height: usize,
        update_query: &[L],
    ) -> () {
        let mut rng = ark_std::test_rng();
        let leaf_crh_params = <LeafH as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_params = <CompressH as TwoToOneCRHScheme>::setup(&mut rng)
            .unwrap()
            .clone();
        let mut tree = JubJubIncrementalMerkleTree::blank(
            &leaf_crh_params.clone(),
            &two_to_one_params.clone(),
            tree_height,
        )
        .unwrap();

        // test merkle tree update functionality
        for v in update_query {
            let v = crate::to_unchecked_bytes!(v).unwrap();
            tree.append(v.clone()).unwrap();
            println!("{:?}", tree.next_available());
            println!("{:?}", tree.is_empty());
            let proof = tree.current_proof();
            assert!(proof
                .verify(&leaf_crh_params, &two_to_one_params, &tree.root(), v)
                .unwrap());
        }
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
    fn test_emptyness_for_imt() {
        let mut rng = test_rng();
        let leaf_crh_params = <LeafH as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_params = <CompressH as TwoToOneCRHScheme>::setup(&mut rng)
            .unwrap()
            .clone();
        let mut tree = JubJubIncrementalMerkleTree::blank(
            &leaf_crh_params.clone(),
            &two_to_one_params.clone(),
            5,
        )
        .unwrap();
        assert!(tree.is_empty());
        let v = BigInteger256::rand(&mut rng);
        tree.append(crate::to_unchecked_bytes!(v).unwrap()).unwrap();
        assert!(!tree.is_empty());
    }

    #[test]
    fn good_root_test_for_imt() {
        let mut rng = test_rng();

        // test various sized IMTs
        let mut updates = Vec::new();
        for _ in 0..2u8 {
            updates.push(BigInteger256::rand(&mut rng));
        }
        incremental_merkle_tree_test(2, &updates);

        let mut updates = Vec::new();
        for _ in 0..7u8 {
            updates.push(BigInteger256::rand(&mut rng));
        }
        incremental_merkle_tree_test(4, &updates);

        let mut updates = Vec::new();
        for _ in 0..128u8 {
            updates.push(BigInteger256::rand(&mut rng));
        }
        incremental_merkle_tree_test(8, &updates);
    }

    #[test]
    #[should_panic]
    fn out_of_capacity_test_for_imt() {
        let mut rng = test_rng();

        // test various sized IMTs
        let mut updates = Vec::new();
        for _ in 0..3u8 {
            updates.push(BigInteger256::rand(&mut rng));
        }
        incremental_merkle_tree_test(2, &updates);
    }
}

mod field_mt_tests {
    use crate::crh::poseidon;
    use crate::merkle_tree::incremental_merkle_tree::IncrementalMerkleTree;
    use crate::merkle_tree::tests::test_utils::poseidon_parameters;
    use crate::merkle_tree::{Config, IdentityDigestConverter};
    use crate::MerkleTree;
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
    type FieldIMT = IncrementalMerkleTree<FieldMTConfig>;

    fn merkle_tree_test(leaves: &[Vec<F>], update_query: &[(usize, Vec<F>)]) -> () {
        let mut leaves = leaves.to_vec();
        let leaf_crh_params = poseidon_parameters();
        let two_to_one_params = leaf_crh_params.clone();

        let mut tree = FieldMT::new(
            &leaf_crh_params,
            &two_to_one_params,
            leaves.iter().map(|x| x.as_slice()),
        )
        .unwrap();

        let mut root = tree.root();

        // test merkle tree functionality without update
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof
                .verify(&leaf_crh_params, &two_to_one_params, &root, leaf.as_slice())
                .unwrap());
        }

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
                .unwrap())
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
    }

    fn incremental_merkle_tree_test(tree_height: usize, update_query: &[Vec<F>]) -> () {
        let leaf_crh_params = poseidon_parameters();
        let two_to_one_params = leaf_crh_params.clone();

        let mut tree = FieldIMT::blank(&leaf_crh_params, &two_to_one_params, tree_height).unwrap();

        // test incremental merkle tree append
        for v in update_query {
            tree.append(v.as_slice()).unwrap();
            let proof = tree.current_proof();
            assert!(proof
                .verify(
                    &leaf_crh_params,
                    &two_to_one_params,
                    &tree.root(),
                    v.as_slice()
                )
                .unwrap());
        }

        {
            // wrong root should lead to error but do not panic
            let wrong_root = tree.root() + F::one();
            let proof = tree.current_proof();
            assert!(!proof
                .verify(
                    &leaf_crh_params,
                    &two_to_one_params,
                    &wrong_root,
                    update_query.last().unwrap().as_slice()
                )
                .unwrap())
        }
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

    #[test]
    fn good_root_test_for_imt() {
        let mut rng = test_rng();
        let mut rand_leaves = || (0..3).map(|_| F::rand(&mut rng)).collect();

        let mut updates: Vec<Vec<_>> = Vec::new();
        for _ in 0..128u8 {
            updates.push(rand_leaves())
        }
        incremental_merkle_tree_test(8, &updates)
    }
}
