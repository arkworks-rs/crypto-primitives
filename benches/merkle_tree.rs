#[macro_use]
extern crate criterion;

static NUM_LEAVES: i32 = 1 << 20;

mod bytes_mt_benches {
    use ark_crypto_primitives::crh::*;
    use ark_crypto_primitives::merkle_tree::*;
    use ark_crypto_primitives::to_uncompressed_bytes;
    use ark_ff::BigInteger256;
    use ark_serialize::CanonicalSerialize;
    use ark_std::cfg_iter;
    use ark_std::{test_rng, UniformRand};
    use criterion::Criterion;
    use std::borrow::Borrow;

    #[cfg(feature = "parallel")]
    use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

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
                    leaves.iter().map(|x| x.as_slice()),
                )
                .unwrap();
            })
        });
    }

    criterion_group! {
        name = mt_create;
        config = Criterion::default().sample_size(10);
        targets = merkle_tree_create
    }
}

criterion_main!(crate::bytes_mt_benches::mt_create,);
