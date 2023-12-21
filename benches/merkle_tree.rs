#[macro_use]
extern crate criterion;

mod utils;

static NUM_LEAVES: i32 = i32::pow(2, 8);

mod bytes_mt_benches {
    use ark_crypto_primitives::crh::*;
    use ark_crypto_primitives::merkle_tree::*;
    use ark_crypto_primitives::to_uncompressed_bytes;
    use ark_ed_on_bls12_381::EdwardsProjective as JubJub;
    use ark_ff::BigInteger256;
    use ark_serialize::CanonicalSerialize;
    use ark_std::{test_rng, UniformRand};
    use criterion::Criterion;
    use std::borrow::Borrow;

    #[cfg(feature = "parallel")]
    use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

    use crate::NUM_LEAVES;

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
                #[cfg(not(feature = "parallel"))]
                {
                    _ = JubJubMerkleTree::new(
                        &leaf_crh_params.clone(),
                        &two_to_one_params.clone(),
                        leaves.iter().map(|x| x.as_slice()),
                    )
                    .unwrap();
                }
                #[cfg(feature = "parallel")]
                {
                    _ = JubJubMerkleTree::new(
                        &leaf_crh_params.clone(),
                        &two_to_one_params.clone(),
                        leaves.par_iter().map(|x| x.as_slice()),
                    )
                    .unwrap();
                }
            })
        });
    }

    criterion_group! {
        name = mt_create;
        config = Criterion::default().sample_size(10);
        targets = merkle_tree_create
    }
}
mod field_mt_benches {
    use crate::utils::merkle_tree_utils;
    use ark_crypto_primitives::crh::poseidon;
    use ark_crypto_primitives::merkle_tree::*;
    use ark_std::{test_rng, vec::Vec, UniformRand};
    use criterion::Criterion;

    #[cfg(feature = "parallel")]
    use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

    use crate::NUM_LEAVES;

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

    type FieldMerkleTree = MerkleTree<FieldMTConfig>;

    pub fn merkle_tree_create(c: &mut Criterion) {
        let mut rng = test_rng();
        let field_elems_in_leaf = 3;
        let mut rand_leaves = || {
            (0..field_elems_in_leaf)
                .map(|_| F::rand(&mut rng))
                .collect()
        };
        let leaves: Vec<Vec<_>> = (0..NUM_LEAVES).map(|_| rand_leaves()).collect();
        let leaf_crh_params = merkle_tree_utils::poseidon_parameters();
        let two_to_one_params = leaf_crh_params.clone();
        c.bench_function("Merkle Tree Create (Leaves as [F.E])", move |b| {
            b.iter(|| {
                #[cfg(not(feature = "parallel"))]
                {
                    _ = FieldMerkleTree::new(
                        &leaf_crh_params.clone(),
                        &two_to_one_params.clone(),
                        leaves.iter().map(|x| x.as_slice()),
                    )
                    .unwrap();
                }
                #[cfg(feature = "parallel")]
                {
                    _ = FieldMerkleTree::new(
                        &leaf_crh_params.clone(),
                        &two_to_one_params.clone(),
                        leaves.par_iter().map(|x| x.as_slice()),
                    )
                    .unwrap();
                }
            })
        });
    }

    criterion_group! {
        name = mt_create;
        config = Criterion::default().sample_size(10);
        targets = merkle_tree_create
    }
}
criterion_main!(
    crate::bytes_mt_benches::mt_create,
    crate::field_mt_benches::mt_create
);
