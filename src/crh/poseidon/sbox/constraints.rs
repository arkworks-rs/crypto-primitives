use super::PoseidonSbox;
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::r1cs::SynthesisError;

pub trait SboxConstraints {
    fn synthesize_sbox<F: PrimeField>(&self, input: &FpVar<F>) -> Result<FpVar<F>, SynthesisError>;
}

impl SboxConstraints for PoseidonSbox {
    fn synthesize_sbox<F: PrimeField>(
        &self,
        input_var: &FpVar<F>,
    ) -> Result<FpVar<F>, SynthesisError> {
        match self {
            PoseidonSbox::Exponentiation(val) => match val {
                3 => synthesize_exp3_sbox::<F>(input_var),
                5 => synthesize_exp5_sbox::<F>(input_var),
                _ => synthesize_exp3_sbox::<F>(input_var),
            },
            PoseidonSbox::Inverse => synthesize_inverse_sbox::<F>(input_var),
        }
    }
}

// Allocate variables in circuit and enforce constraints when Sbox as cube
fn synthesize_exp3_sbox<F: PrimeField>(input_var: &FpVar<F>) -> Result<FpVar<F>, SynthesisError> {
    let sqr = input_var * input_var;
    let cube = input_var * sqr;
    Ok(cube)
}

// Allocate variables in circuit and enforce constraints when Sbox as cube
fn synthesize_exp5_sbox<F: PrimeField>(input_var: &FpVar<F>) -> Result<FpVar<F>, SynthesisError> {
    let sqr = input_var * input_var;
    let fourth = &sqr * &sqr;
    let fifth = input_var * fourth;
    Ok(fifth)
}

// Allocate variables in circuit and enforce constraints when Sbox as
// inverse
fn synthesize_inverse_sbox<F: PrimeField>(
    input_var: &FpVar<F>,
) -> Result<FpVar<F>, SynthesisError> {
    input_var.inverse()
}
