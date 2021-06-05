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
                    2 => elem * &elem,
                    3 => elem * &elem * &elem,
                    4 => {
                        let sqr = elem.square();
                        sqr * &sqr.clone()
                    }
                    5 => {
                        let sqr = elem.square();
                        sqr * &sqr.clone() * &elem
                    }
                    6 => {
                        let sqr = elem.square();
                        let quad = sqr * &sqr;
                        sqr * &quad
                    }
                    7 => {
                        let sqr = elem.square();
                        let quad = sqr * &sqr;
                        sqr * &quad * &elem
                    }
                    17 => {
                        let sqr = elem.square();
                        let quad = sqr * &sqr;
                        let eighth = quad * &quad;
                        let sixteenth = eighth * &eighth;
                        sixteenth * &elem
                    }
                    // default to cubed
                    _ => elem * &elem * &elem,
                }
            }
            PoseidonSbox::Inverse => elem.inverse().unwrap_or(F::zero()),
        }
    }
}
