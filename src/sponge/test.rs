use crate::sponge::poseidon::{PoseidonDefaultConfig, PoseidonDefaultConfigEntry};
use ark_ff::fields::Fp256;
use ark_ff::{MontBackend, MontConfig};

#[derive(MontConfig)]
#[modulus = "52435875175126190479447740508185965837690552500527637822603658699938581184513"]
#[generator = "7"]
pub struct FrBackend;

type FrConfig = MontBackend<FrBackend, 4>;
pub type Fr = Fp256<FrConfig>;

impl PoseidonDefaultConfig<4> for FrConfig {
    const PARAMS_OPT_FOR_CONSTRAINTS: [PoseidonDefaultConfigEntry; 7] = [
        PoseidonDefaultConfigEntry::new(2, 17, 8, 31, 0),
        PoseidonDefaultConfigEntry::new(3, 5, 8, 56, 0),
        PoseidonDefaultConfigEntry::new(4, 5, 8, 56, 0),
        PoseidonDefaultConfigEntry::new(5, 5, 8, 57, 0),
        PoseidonDefaultConfigEntry::new(6, 5, 8, 57, 0),
        PoseidonDefaultConfigEntry::new(7, 5, 8, 57, 0),
        PoseidonDefaultConfigEntry::new(8, 5, 8, 57, 0),
    ];
    const PARAMS_OPT_FOR_WEIGHTS: [PoseidonDefaultConfigEntry; 7] = [
        PoseidonDefaultConfigEntry::new(2, 257, 8, 13, 0),
        PoseidonDefaultConfigEntry::new(3, 257, 8, 13, 0),
        PoseidonDefaultConfigEntry::new(4, 257, 8, 13, 0),
        PoseidonDefaultConfigEntry::new(5, 257, 8, 13, 0),
        PoseidonDefaultConfigEntry::new(6, 257, 8, 13, 0),
        PoseidonDefaultConfigEntry::new(7, 257, 8, 13, 0),
        PoseidonDefaultConfigEntry::new(8, 257, 8, 13, 0),
    ];
}
