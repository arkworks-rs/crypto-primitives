use crate::sponge::{Absorb, CryptographicSponge};
use merlin::Transcript;

impl CryptographicSponge for Transcript {
    type Config = &'static [u8];

    fn new(params: &Self::Config) -> Self {
        Transcript::new(*params)
    }

    fn absorb(&mut self, input: &impl Absorb) {
        self.append_message(b"", &input.to_sponge_bytes_as_vec());
    }

    fn squeeze_bytes(&mut self, num_bytes: usize) -> Vec<u8> {
        let mut dest = vec![0; num_bytes];
        self.challenge_bytes(b"", &mut dest);
        dest
    }

    fn squeeze_bits(&mut self, num_bits: usize) -> Vec<bool> {
        let num_bytes = (num_bits + 7) / 8;
        let mut tmp = vec![0; num_bytes];
        self.challenge_bytes(b"", &mut tmp);
        let dest = tmp
            .iter()
            .flat_map(|byte| (0..8u32).rev().map(move |i| (byte >> i) & 1 == 1))
            .collect::<Vec<_>>();
        dest[..num_bits].to_vec()
    }
}
