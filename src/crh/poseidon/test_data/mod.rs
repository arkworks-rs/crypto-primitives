pub mod result_x5_254_3;
pub mod result_x5_254_5;
pub mod x5_254_3;
pub mod x5_254_5;
use ark_ff::fields::PrimeField;

pub fn decode_hex(s: &str) -> Vec<u8> {
    let s = &s[2..];
    let vec: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect();

    vec
}

pub fn get_bytes_array_from_hex(hex_str: &str) -> [u8; 32] {
    let bytes = decode_hex(hex_str);
    let mut result: [u8; 32] = [0; 32];
    result.copy_from_slice(&bytes);
    result
}

pub fn get_results_5<F: PrimeField>() -> Vec<F> {
    let mut res = vec![];
    for r in result_x5_254_5::RESULT.iter() {
        let c = F::from_be_bytes_mod_order(&get_bytes_array_from_hex(r));
        res.push(c);
    }
    res
}

pub fn get_results_3<F: PrimeField>() -> Vec<F> {
    let mut res = vec![];
    for r in result_x5_254_3::RESULT.iter() {
        let c = F::from_be_bytes_mod_order(&get_bytes_array_from_hex(r));
        res.push(c);
    }
    res
}

pub fn get_rounds_3<F: PrimeField>() -> Vec<F> {
    let mut rc = vec![];
    for r in x5_254_3::ROUND_CONSTS.iter() {
        let c = F::from_be_bytes_mod_order(&get_bytes_array_from_hex(r));
        rc.push(c);
    }
    rc
}

pub fn get_mds_3<F: PrimeField>() -> Vec<Vec<F>> {
    let mds_entries = x5_254_3::MDS_ENTRIES;
    let width = mds_entries.len();
    let mut mds: Vec<Vec<F>> = vec![vec![F::zero(); width]; width];
    for i in 0..width {
        for j in 0..width {
            // TODO: Remove unwrap, handle error
            mds[i][j] = F::from_be_bytes_mod_order(&get_bytes_array_from_hex(mds_entries[i][j]));
        }
    }
    mds
}

pub fn get_rounds_5<F: PrimeField>() -> Vec<F> {
    let mut rc = vec![];
    for r in x5_254_5::ROUND_CONSTS.iter() {
        let c = F::from_be_bytes_mod_order(&get_bytes_array_from_hex(r));
        rc.push(c);
    }
    rc
}

pub fn get_mds_5<F: PrimeField>() -> Vec<Vec<F>> {
    let mds_entries = x5_254_5::MDS_ENTRIES;
    let width = mds_entries.len();
    let mut mds: Vec<Vec<F>> = vec![vec![F::zero(); width]; width];
    for i in 0..width {
        for j in 0..width {
            // TODO: Remove unwrap, handle error
            mds[i][j] = F::from_be_bytes_mod_order(&get_bytes_array_from_hex(mds_entries[i][j]));
        }
    }
    mds
}
