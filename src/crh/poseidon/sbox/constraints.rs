use super::PoseidonSbox;
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::r1cs::SynthesisError;

pub trait SboxConstraints {
    fn synthesize_sbox<F: PrimeField>(
        &self,
        input: FpVar<F>,
        round_key: F,
    ) -> Result<FpVar<F>, SynthesisError>;
}

impl SboxConstraints for PoseidonSbox {
    fn synthesize_sbox<F: PrimeField>(
        &self,
        input_var: FpVar<F>,
        round_key: F,
    ) -> Result<FpVar<F>, SynthesisError> {
        match self {
            PoseidonSbox::Exponentiation(val) => match val {
                3 => synthesize_exp3_sbox::<F>(input_var, round_key),
                5 => synthesize_exp5_sbox::<F>(input_var, round_key),
                _ => synthesize_exp3_sbox::<F>(input_var, round_key),
            },
            PoseidonSbox::Inverse => synthesize_inverse_sbox::<F>(input_var, round_key),
        }
    }
}

// Allocate variables in circuit and enforce constraints when Sbox as cube
fn synthesize_exp3_sbox<F: PrimeField>(
    input_var: FpVar<F>,
    round_key: F,
) -> Result<FpVar<F>, SynthesisError> {
    let inp_plus_const: FpVar<F> = input_var + round_key;
    let sqr = inp_plus_const.clone() * inp_plus_const.clone();
    let cube = inp_plus_const.clone() * sqr;
    Ok(cube)
}

// Allocate variables in circuit and enforce constraints when Sbox as cube
fn synthesize_exp5_sbox<F: PrimeField>(
    input_var: FpVar<F>,
    round_key: F,
) -> Result<FpVar<F>, SynthesisError> {
    let inp_plus_const: FpVar<F> = input_var + round_key;
    let sqr = inp_plus_const.clone() * inp_plus_const.clone();
    let fourth = sqr.clone() * sqr.clone();
    let fifth = inp_plus_const.clone() * fourth;
    Ok(fifth)
}

// Allocate variables in circuit and enforce constraints when Sbox as
// inverse
fn synthesize_inverse_sbox<F: PrimeField>(
    input_var: FpVar<F>,
    round_key: F,
) -> Result<FpVar<F>, SynthesisError> {
    let inp_plus_const: FpVar<F> = input_var + round_key;
    let input_inv = inp_plus_const.inverse().unwrap();
    Ok(input_inv)
}
