#[macro_use]
extern crate criterion;

static NUM_LEAVES: i32 = 1 << 20;

mod bytes_mt_benches {
    use ark_crypto_primitives::crh::*;
    use ark_crypto_primitives::merkle_tree::*;
    use ark_crypto_primitives::to_uncompressed_bytes;
    use ark_ff::BigInteger256;
    use ark_serialize::CanonicalSerialize;
    use ark_std::{test_rng, UniformRand};
    use criterion::Criterion;
    use std::borrow::Borrow;
    use std::iter::zip;

    use crate::NUM_LEAVES;

    type LeafH = sha2::Sha256;
    type CompressH = sha2::Sha256;

    struct Sha256MerkleTreeParams;

    impl Config for Sha256MerkleTreeParams {
        type Leaf = [u8];

        type LeafDigest = <LeafH as CRHScheme>::Output;
        type LeafInnerDigestConverter = ByteDigestConverter<Self::LeafDigest>;
        type InnerDigest = <CompressH as TwoToOneCRHScheme>::Output;

        type LeafHash = LeafH;
        type TwoToOneHash = CompressH;
    }
    type Sha256MerkleTree = MerkleTree<Sha256MerkleTreeParams>;

    pub fn merkle_tree_create(c: &mut Criterion) {
        let mut rng = test_rng();
        let leaves: Vec<_> = (0..NUM_LEAVES)
            .map(|_| {
                let rnd = BigInteger256::rand(&mut rng);
                to_uncompressed_bytes!(rnd).unwrap()
            })
            .collect();
        let leaf_crh_params = <LeafH as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_params = <CompressH as TwoToOneCRHScheme>::setup(&mut rng)
            .unwrap()
            .clone();
        c.bench_function("Merkle Tree Create (Leaves as [u8])", move |b| {
            b.iter(|| {
                Sha256MerkleTree::new(
                    &leaf_crh_params.clone(),
                    &two_to_one_params.clone(),
                    &leaves,
                )
                .unwrap();
            })
        });
    }

    pub fn merkle_tree_generate_proof(c: &mut Criterion) {
        let mut rng = test_rng();
        let leaves: Vec<_> = (0..NUM_LEAVES)
            .map(|_| {
                let rnd = BigInteger256::rand(&mut rng);
                to_uncompressed_bytes!(rnd).unwrap()
            })
            .collect();
        let leaf_crh_params = <LeafH as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_params = <CompressH as TwoToOneCRHScheme>::setup(&mut rng)
            .unwrap()
            .clone();

        let tree = Sha256MerkleTree::new(
            &leaf_crh_params.clone(),
            &two_to_one_params.clone(),
            &leaves,
        )
        .unwrap();
        c.bench_function("Merkle Tree Generate Proof (Leaves as [u8])", move |b| {
            b.iter(|| {
                for (i, _) in leaves.iter().enumerate() {
                    tree.generate_proof(i).unwrap();
                }
            })
        });
    }

    pub fn merkle_tree_verify_proof(c: &mut Criterion) {
        let mut rng = test_rng();
        let leaves: Vec<_> = (0..NUM_LEAVES)
            .map(|_| {
                let rnd = BigInteger256::rand(&mut rng);
                to_uncompressed_bytes!(rnd).unwrap()
            })
            .collect();
        let leaf_crh_params = <LeafH as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_params = <CompressH as TwoToOneCRHScheme>::setup(&mut rng)
            .unwrap()
            .clone();

        let tree = Sha256MerkleTree::new(
            &leaf_crh_params.clone(),
            &two_to_one_params.clone(),
            &leaves,
        )
        .unwrap();

        let root = tree.root();

        let proofs: Vec<_> = leaves
            .iter()
            .enumerate()
            .map(|(i, _)| tree.generate_proof(i).unwrap())
            .collect();

        c.bench_function("Merkle Tree Verify Proof (Leaves as [u8])", move |b| {
            b.iter(|| {
                for (proof, leaf) in zip(proofs.clone(), leaves.clone()) {
                    proof
                        .verify(&leaf_crh_params, &two_to_one_params, &root, leaf.as_slice())
                        .unwrap();
                }
            })
        });
    }

    pub fn merkle_tree_generate_multi_proof(c: &mut Criterion) {
        let mut rng = test_rng();
        let leaves: Vec<_> = (0..NUM_LEAVES)
            .map(|_| {
                let rnd = BigInteger256::rand(&mut rng);
                to_uncompressed_bytes!(rnd).unwrap()
            })
            .collect();
        let leaf_crh_params = <LeafH as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_params = <CompressH as TwoToOneCRHScheme>::setup(&mut rng)
            .unwrap()
            .clone();

        let tree = Sha256MerkleTree::new(
            &leaf_crh_params.clone(),
            &two_to_one_params.clone(),
            &leaves,
        )
        .unwrap();
        c.bench_function(
            "Merkle Tree Generate Multi Proof (Leaves as [u8])",
            move |b| {
                b.iter(|| {
                    tree.generate_multi_proof((0..leaves.len()).collect::<Vec<_>>())
                        .unwrap();
                })
            },
        );
    }

    pub fn merkle_tree_verify_multi_proof(c: &mut Criterion) {
        let mut rng = test_rng();
        let leaves: Vec<_> = (0..NUM_LEAVES)
            .map(|_| {
                let rnd = BigInteger256::rand(&mut rng);
                to_uncompressed_bytes!(rnd).unwrap()
            })
            .collect();
        let leaf_crh_params = <LeafH as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_params = <CompressH as TwoToOneCRHScheme>::setup(&mut rng)
            .unwrap()
            .clone();

        let tree = Sha256MerkleTree::new(
            &leaf_crh_params.clone(),
            &two_to_one_params.clone(),
            &leaves,
        )
        .unwrap();

        let root = tree.root();

        let multi_proof = tree
            .generate_multi_proof((0..leaves.len()).collect::<Vec<_>>())
            .unwrap();

        c.bench_function(
            "Merkle Tree Verify Multi Proof (Leaves as [u8])",
            move |b| {
                b.iter(|| {
                    multi_proof.verify(&leaf_crh_params, &two_to_one_params, &root, leaves.clone())
                })
            },
        );
    }

    criterion_group! {
        name = mt_create;
        config = Criterion::default().sample_size(100);
        targets = merkle_tree_create
    }

    criterion_group! {
        name = mt_proof;
        config = Criterion::default().sample_size(100);
        targets = merkle_tree_generate_proof, merkle_tree_generate_multi_proof
    }

    criterion_group! {
        name = mt_verify;
        config = Criterion::default().sample_size(10);
        targets = merkle_tree_verify_proof, merkle_tree_verify_multi_proof
    }
}

criterion_main!(
    bytes_mt_benches::mt_create,
    bytes_mt_benches::mt_proof,
    bytes_mt_benches::mt_verify
);
