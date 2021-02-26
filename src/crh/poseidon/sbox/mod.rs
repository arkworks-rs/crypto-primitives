use ark_ff::PrimeField;

#[cfg(feature = "r1cs")]
pub mod constraints;

/// An S-Box that can be used with Poseidon.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PoseidonSbox {
    Exponentiation3,
    Exponentiation5,
    Inverse,
}

impl PoseidonSbox {
    pub fn apply_sbox<F: PrimeField>(&self, elem: F) -> F {
        match self {
            PoseidonSbox::Exponentiation3 => (elem * elem) * elem,
            PoseidonSbox::Exponentiation5 => {
                let sqr = elem * elem;
                (sqr * sqr) * elem
            },
            PoseidonSbox::Inverse => elem.inverse().unwrap_or(F::zero()),
        }
    }
}
