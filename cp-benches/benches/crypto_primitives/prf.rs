#[macro_use]
extern crate criterion;

use ark_crypto_primitives::prf::*;
use ark_std::rand::Rng;
use criterion::Criterion;

fn blake2s_prf_eval(c: &mut Criterion) {
    let rng = &mut ark_std::test_rng();
    let input: [u8; 32] = rng.gen();
    let seed: [u8; 32] = rng.gen();
    c.bench_function("Blake2s PRF Eval", move |b| {
        b.iter(|| Blake2s::evaluate(&seed, &input).unwrap())
    });
}

criterion_group! {
    name = prf_eval;
    config = Criterion::default().sample_size(50);
    targets = blake2s_prf_eval
}

criterion_main!(prf_eval);
