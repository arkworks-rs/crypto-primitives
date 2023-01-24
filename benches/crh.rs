#[macro_use]
extern crate criterion;

use ark_crypto_primitives::crh::{
    pedersen::{Window, CRH as PedersenCRH},
    CRHScheme,
};
use ark_ed_on_bls12_377::EdwardsProjective as Edwards;
use criterion::Criterion;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct HashWindow;

impl Window for HashWindow {
    const WINDOW_SIZE: usize = 250;
    const NUM_WINDOWS: usize = 8;
}

fn pedersen_crh_setup(c: &mut Criterion) {
    c.bench_function("Pedersen CRH Setup", move |b| {
        b.iter(|| {
            let mut rng = &mut ark_std::test_rng();
            PedersenCRH::<Edwards, HashWindow>::setup(&mut rng).unwrap()
        })
    });
}

fn pedersen_crh_eval(c: &mut Criterion) {
    let mut rng = &mut ark_std::test_rng();
    let parameters = PedersenCRH::<Edwards, HashWindow>::setup(&mut rng).unwrap();
    let input = vec![5u8; 128];
    c.bench_function("Pedersen CRH Eval", move |b| {
        b.iter(|| PedersenCRH::<Edwards, HashWindow>::evaluate(&parameters, input.clone()).unwrap())
    });
}

criterion_group! {
    name = crh_setup;
    config = Criterion::default().sample_size(10);
    targets = pedersen_crh_setup
}

criterion_group! {
    name = crh_eval;
    config = Criterion::default().sample_size(10);
    targets = pedersen_crh_eval
}

criterion_main!(crh_setup, crh_eval);
