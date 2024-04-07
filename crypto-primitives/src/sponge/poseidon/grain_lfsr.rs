#![allow(dead_code)]

use ark_ff::{BigInteger, PrimeField};
#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;

pub struct PoseidonGrainLFSR {
    pub prime_num_bits: u64,

    pub state: [bool; 80],
    pub head: usize,
}

#[allow(unused_variables)]
impl PoseidonGrainLFSR {
    pub fn new(
        is_sbox_an_inverse: bool,
        prime_num_bits: u64,
        state_len: u64,
        num_full_rounds: u64,
        num_partial_rounds: u64,
    ) -> Self {
        let mut state = [false; 80];

        // b0, b1 describes the field
        state[1] = true;

        // b2, ..., b5 describes the S-BOX
        if is_sbox_an_inverse {
            state[5] = true;
        } else {
            state[5] = false;
        }

        // b6, ..., b17 are the binary representation of n (prime_num_bits)
        {
            let mut cur = prime_num_bits;
            for i in (6..=17).rev() {
                state[i] = cur & 1 == 1;
                cur >>= 1;
            }
        }

        // b18, ..., b29 are the binary representation of t (state_len, rate + capacity)
        {
            let mut cur = state_len;
            for i in (18..=29).rev() {
                state[i] = cur & 1 == 1;
                cur >>= 1;
            }
        }

        // b30, ..., b39 are the binary representation of R_F (the number of full rounds)
        {
            let mut cur = num_full_rounds;
            for i in (30..=39).rev() {
                state[i] = cur & 1 == 1;
                cur >>= 1;
            }
        }

        // b40, ..., b49 are the binary representation of R_P (the number of partial rounds)
        {
            let mut cur = num_partial_rounds;
            for i in (40..=49).rev() {
                state[i] = cur & 1 == 1;
                cur >>= 1;
            }
        }

        // b50, ..., b79 are set to 1
        for i in 50..=79 {
            state[i] = true;
        }

        let head = 0;

        let mut res = Self {
            prime_num_bits,
            state,
            head,
        };
        res.init();
        res
    }

    pub fn get_bits(&mut self, num_bits: usize) -> Vec<bool> {
        let mut res = Vec::new();

        for _ in 0..num_bits {
            // Obtain the first bit
            let mut new_bit = self.update();

            // Loop until the first bit is true
            while new_bit == false {
                // Discard the second bit
                let _ = self.update();
                // Obtain another first bit
                new_bit = self.update();
            }

            // Obtain the second bit
            res.push(self.update());
        }

        res
    }

    pub fn get_field_elements_rejection_sampling<F: PrimeField>(
        &mut self,
        num_elems: usize,
    ) -> Vec<F> {
        assert_eq!(F::MODULUS_BIT_SIZE as u64, self.prime_num_bits);

        let mut res = Vec::new();
        for _ in 0..num_elems {
            // Perform rejection sampling
            loop {
                // Obtain n bits and make it most-significant-bit first
                let mut bits = self.get_bits(self.prime_num_bits as usize);
                bits.reverse();

                // Construct the number
                let bigint = F::BigInt::from_bits_le(&bits);

                if let Some(f) = F::from_bigint(bigint) {
                    res.push(f);
                    break;
                }
            }
        }

        res
    }

    pub fn get_field_elements_mod_p<F: PrimeField>(&mut self, num_elems: usize) -> Vec<F> {
        assert_eq!(F::MODULUS_BIT_SIZE as u64, self.prime_num_bits);

        let mut res = Vec::new();
        for _ in 0..num_elems {
            // Obtain n bits and make it most-significant-bit first
            let mut bits = self.get_bits(self.prime_num_bits as usize);
            bits.reverse();

            let bytes = bits
                .chunks(8)
                .map(|chunk| {
                    let mut result = 0u8;
                    for (i, bit) in chunk.iter().enumerate() {
                        result |= u8::from(*bit) << i
                    }
                    result
                })
                .collect::<Vec<u8>>();

            res.push(F::from_le_bytes_mod_order(&bytes));
        }

        res
    }

    #[inline]
    fn update(&mut self) -> bool {
        let new_bit = self.state[(self.head + 62) % 80]
            ^ self.state[(self.head + 51) % 80]
            ^ self.state[(self.head + 38) % 80]
            ^ self.state[(self.head + 23) % 80]
            ^ self.state[(self.head + 13) % 80]
            ^ self.state[self.head];
        self.state[self.head] = new_bit;
        self.head += 1;
        self.head %= 80;

        new_bit
    }

    fn init(&mut self) {
        for _ in 0..160 {
            let _ = self.update();
        }
    }
}

#[cfg(test)]
mod test {
    use crate::sponge::poseidon::grain_lfsr::PoseidonGrainLFSR;
    use crate::sponge::test::Fr;
    use ark_ff::MontFp;

    #[test]
    fn test_grain_lfsr_consistency() {
        let mut lfsr = PoseidonGrainLFSR::new(false, 255, 3, 8, 31);

        assert_eq!(
            lfsr.get_field_elements_rejection_sampling::<Fr>(1)[0],
            MontFp!(
                "27117311055620256798560880810000042840428971800021819916023577129547249660720"
            )
        );
        assert_eq!(
            lfsr.get_field_elements_rejection_sampling::<Fr>(1)[0],
            MontFp!(
                "51641662388546346858987925410984003801092143452466182801674685248597955169158"
            )
        );
        assert_eq!(
            lfsr.get_field_elements_mod_p::<Fr>(1)[0],
            MontFp!(
                "30468495022634911716522728179277518871747767531215914044579216845399211650580"
            )
        );
        assert_eq!(
            lfsr.get_field_elements_mod_p::<Fr>(1)[0],
            MontFp!(
                "17250718238509906485015112994867732544602358855445377986727968022920517907825"
            )
        );
    }
}
