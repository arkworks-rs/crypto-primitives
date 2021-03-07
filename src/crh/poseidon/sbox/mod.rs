use ark_ff::PrimeField;

#[cfg(feature = "r1cs")]
pub mod constraints;

/// An S-Box that can be used with Poseidon.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PoseidonSbox {
    Exponentiation(usize),
    Inverse,
}

impl PoseidonSbox {
    pub fn apply_sbox<F: PrimeField>(&self, elem: F) -> F {
        match self {
            PoseidonSbox::Exponentiation(val) => {
                match val {
                    2 => elem.clone() * elem.clone(),
                    3 => elem.clone() * elem.clone() * elem.clone(),
                    4 => {
                        let sqr = elem.clone() * elem.clone();
                        sqr.clone() * sqr.clone()
                    }
                    5 => {
                        let sqr = elem.clone() * elem.clone();
                        sqr.clone() * sqr.clone() * elem.clone()
                    }
                    6 => {
                        let sqr = elem.clone() * elem.clone();
                        let quad = sqr * sqr;
                        sqr.clone() * quad
                    }
                    7 => {
                        let sqr = elem.clone() * elem.clone();
                        let quad = sqr * sqr;
                        sqr.clone() * quad * elem.clone()
                    }
                    17 => {
                        let sqr = elem.clone() * elem.clone();
                        let quad = sqr * sqr;
                        let eighth = quad * quad;
                        let sixteenth = eighth * eighth;
                        sixteenth * elem.clone()
                    }
                    // default to cubed
                    _ => elem.clone() * elem.clone() * elem.clone(),
                }
            }
            PoseidonSbox::Inverse => elem.inverse().unwrap_or(F::zero()),
        }
    }
}
