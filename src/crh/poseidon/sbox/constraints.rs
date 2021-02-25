use ark_relations::r1cs::SynthesisError;
use ark_relations::r1cs::LinearCombination;
use ark_relations::r1cs::Variable;
use ark_ff::PrimeField;

pub enum PoseidonSboxGadget<F> {
    Exponentiation3,
    Exponentiation5,
    Inverse,
}

impl<F: PrimeField> PoseidonSboxGadget<F> {
    pub fn synthesize_sbox(
        &self,
        input_var: LinearCombination<F>,
        round_key: F,
    ) -> Result<Variable, SynthesisError> {
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
    fn synthesize_exp3_sbox(
        input_var: LinearCombination<F>,
        round_key: F,
    ) -> Result<Variable, SynthesisError> {
        let cs = input_var.cs();
        let inp_plus_const: LinearCombination = input_var + round_key;
        let sqr = inp_plus_const * inp_plus_const;
        let cube = inp_plus_const * sqr;
        Ok(cube)
    }

    // Allocate variables in circuit and enforce constraints when Sbox as cube
    fn synthesize_exp5_sbox(
        input_var: LinearCombination<F>,
        round_key: F,
    ) -> Result<Variable, SynthesisError> {
        let cs = input_var.cs();
        let inp_plus_const: LinearCombination = input_var + round_key;
        let (i, _, sqr) = cs.multiply(inp_plus_const.clone(), inp_plus_const);
        let (_, _, fourth) = cs.multiply(sqr.into(), sqr.into());
        let (_, _, fifth) = cs.multiply(fourth.into(), i.into());
        Ok(fifth)
    }

    // Allocate variables in circuit and enforce constraints when Sbox as
    // inverse
    fn synthesize_inverse_sbox(
        input_var: LinearCombination<F>,
        round_key: F,
    ) -> Result<Variable, SynthesisError> {
        let cs = input_var.cs();
        let inp_plus_const: FpVar =
            (input_var + round_key).compactify();

        inp_plus_const.is_zero();
        // let val_l = cs.eval_lc(&inp_plus_const);
        // let val_r = val_l.map(|l| l.invert());

        // let (var_l, _) = cs.allocate_single(val_l)?;
        // let (var_r, var_o) = cs.allocate_single(val_r)?;

        // // Ensure `inp_plus_const` is not zero. As a side effect,
        // // `is_nonzero_gadget` also ensures that arguments passes are inverse of
        // // each other
        // let l_scalar =  {
        //     variable: var_l,
        //     assignment: val_l,
        // };
        // let r_scalar = AllocatedFp {
        //     variable: var_r,
        //     assignment: val_r,
        // };
        // is_nonzero_gadget(cs, l_scalar, r_scalar)?;

        // Constrain product of `inp_plus_const` and its inverse to be 1.
        constrain_lc_with_scalar::<CS>(
            cs,
            var_o.unwrap().into(),
            &Scalar::one(),
        );

        Ok(var_r)
    }
}