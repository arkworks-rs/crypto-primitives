#[macro_use]
extern crate criterion;

use ark_crypto_primitives::commitment::{pedersen::*, CommitmentScheme};
use ark_ed_on_bls12_377::EdwardsProjective as Edwards;
use ark_std::UniformRand;
use criterion::Criterion;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CommWindow;

impl Window for CommWindow {
    const WINDOW_SIZE: usize = 250;
    const NUM_WINDOWS: usize = 8;
}

fn pedersen_comm_setup(c: &mut Criterion) {
    c.bench_function("Pedersen Commitment Setup", move |b| {
        b.iter(|| {
            let mut rng = &mut ark_std::test_rng();
            Commitment::<Edwards, CommWindow>::setup(&mut rng).unwrap()
        })
    });
}

fn pedersen_comm_eval(c: &mut Criterion) {
    let mut rng = &mut ark_std::test_rng();
    let parameters = Commitment::<Edwards, CommWindow>::setup(&mut rng).unwrap();
    let input = vec![5u8; 128];
    c.bench_function("Pedersen Commitment Eval", move |b| {
        b.iter(|| {
            let rng = &mut ark_std::test_rng();
            let commitment_randomness = Randomness::rand(rng);
            Commitment::<Edwards, CommWindow>::commit(&parameters, &input, &commitment_randomness)
                .unwrap()
        })
    });
}

criterion_group! {
    name = comm_setup;
    config = Criterion::default().sample_size(10);
    targets = pedersen_comm_setup
}

criterion_group! {
    name = comm_eval;
    config = Criterion::default().sample_size(10);
    targets = pedersen_comm_eval
}

criterion_main!(comm_setup, comm_eval);
