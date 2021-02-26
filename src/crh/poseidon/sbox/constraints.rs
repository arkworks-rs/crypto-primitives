use ark_relations::r1cs::SynthesisError;
use ark_r1cs_std::fields::fp::FpVar;
use ark_ff::PrimeField;
use ark_r1cs_std::{R1CSVar, fields::FieldVar};

pub enum PoseidonSboxGadget {
    Exponentiation3,
    Exponentiation5,
    Inverse,
}

impl PoseidonSboxGadget {
    pub fn synthesize_sbox<F: PrimeField>(
        &self,
        input_var: FpVar<F>,
        round_key: F,
    ) -> Result<FpVar<F>, SynthesisError> {
        match self {
            PoseidonSboxGadget::Exponentiation3 => {
                Self::synthesize_exp3_sbox(input_var, round_key)
            },
            PoseidonSboxGadget::Exponentiation5 => {
                Self::synthesize_exp5_sbox(input_var, round_key)
            },
            PoseidonSboxGadget::Inverse => {
                Self::synthesize_inverse_sbox(input_var, round_key)
            },
        }
    }

    // Allocate variables in circuit and enforce constraints when Sbox as cube
    fn synthesize_exp3_sbox<F: PrimeField>(
        input_var: FpVar<F>,
        round_key: F,
    ) -> Result<FpVar<F>, SynthesisError> {
        let cs = input_var.cs();
        let inp_plus_const: FpVar<F> = input_var + round_key;
        let sqr = inp_plus_const * inp_plus_const;
        let cube = inp_plus_const * sqr;
        Ok(cube)
    }

    // Allocate variables in circuit and enforce constraints when Sbox as cube
    fn synthesize_exp5_sbox<F: PrimeField>(
        input_var: FpVar<F>,
        round_key: F,
    ) -> Result<FpVar<F>, SynthesisError> {
        let cs = input_var.cs();
        let inp_plus_const: FpVar<F> = input_var + round_key;
        let sqr = inp_plus_const * inp_plus_const;
        let fourth = sqr * sqr;
        let fifth = inp_plus_const * fourth;
        Ok(fifth)
    }

    // Allocate variables in circuit and enforce constraints when Sbox as
    // inverse
    fn synthesize_inverse_sbox<F: PrimeField>(
        input_var: FpVar<F>,
        round_key: F,
    ) -> Result<FpVar<F>, SynthesisError> {
        let cs = input_var.cs();
        let inp_plus_const: FpVar<F> = input_var + round_key;

        inp_plus_const.is_zero()?;
        let input_inv = inp_plus_const.inverse().unwrap();
        Ok(input_inv)
    }
}