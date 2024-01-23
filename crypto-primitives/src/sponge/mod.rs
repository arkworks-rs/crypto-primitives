use ark_ff::PrimeField;
use ark_std::vec;
use ark_std::vec::Vec;

/// Infrastructure for the constraints counterparts.
#[cfg(feature = "r1cs")]
pub mod constraints;

mod absorb;
pub use absorb::*;

/// The sponge for Poseidon
///
/// This implementation of Poseidon is entirely from Fractal's implementation in [COS20][cos]
/// with small syntax changes.
///
/// [cos]: https://eprint.iacr.org/2019/1076
pub mod poseidon;

/// The sponge for Merlin
///
///
pub mod merlin;

#[cfg(test)]
mod test;

/// An enum for specifying the output field element size.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum FieldElementSize {
    /// Sample field elements from the entire field.
    Full,

    /// Sample field elements from a subset of the field, specified by the maximum number of bits.
    Truncated(usize),
}

impl FieldElementSize {
    pub(crate) fn num_bits<F: PrimeField>(&self) -> usize {
        if let FieldElementSize::Truncated(num_bits) = self {
            if *num_bits > (F::MODULUS_BIT_SIZE as usize) {
                panic!("num_bits is greater than the capacity of the field.")
            }
            *num_bits
        } else {
            (F::MODULUS_BIT_SIZE - 1) as usize
        }
    }

    /// Calculate the sum of field element sizes in `elements`.
    pub fn sum<F: PrimeField>(elements: &[Self]) -> usize {
        elements.iter().map(|item| item.num_bits::<F>()).sum()
    }
}

/// Default implementation of `CryptographicSponge::squeeze_field_elements_with_sizes`
pub(crate) fn squeeze_field_elements_with_sizes_default_impl<F: PrimeField>(
    sponge: &mut impl CryptographicSponge,
    sizes: &[FieldElementSize],
) -> Vec<F> {
    if sizes.len() == 0 {
        return Vec::new();
    }

    let mut total_bits = 0usize;
    for size in sizes {
        total_bits += size.num_bits::<F>();
    }

    let bits = sponge.squeeze_bits(total_bits);
    let mut bits_window = bits.as_slice();

    let mut output = Vec::with_capacity(sizes.len());
    for size in sizes {
        let num_bits = size.num_bits::<F>();
        let emulated_bits_le: Vec<bool> = bits_window[..num_bits].to_vec();
        bits_window = &bits_window[num_bits..];

        let emulated_bytes = emulated_bits_le
            .chunks(8)
            .map(|bits| {
                let mut byte = 0u8;
                for (i, &bit) in bits.into_iter().enumerate() {
                    if bit {
                        byte += 1 << i;
                    }
                }
                byte
            })
            .collect::<Vec<_>>();

        output.push(F::from_le_bytes_mod_order(emulated_bytes.as_slice()));
    }

    output
}

/// The interface for a cryptographic sponge.
/// A sponge can `absorb` or take in inputs and later `squeeze` or output bytes or field elements.
/// The outputs are dependent on previous `absorb` and `squeeze` calls.
pub trait CryptographicSponge: Clone {
    /// The configuration of the sponge.
    type Config;

    /// Initialize a new instance of the sponge.
    fn new(params: &Self::Config) -> Self;

    /// Absorb an input into the sponge.
    fn absorb(&mut self, input: &impl Absorb);

    /// Squeeze `num_bytes` bytes from the sponge.
    fn squeeze_bytes(&mut self, num_bytes: usize) -> Vec<u8>;

    /// Squeeze `num_bits` bits from the sponge.
    fn squeeze_bits(&mut self, num_bits: usize) -> Vec<bool>;

    /// Squeeze `sizes.len()` field elements from the sponge, where the `i`-th element of
    /// the output has size `sizes[i]`.
    ///
    /// If the implementation is field-based, to squeeze native field elements,
    /// call `self.squeeze_native_field_elements` instead.
    ///
    /// TODO: Support general Field.
    ///
    /// Note that when `FieldElementSize` is `FULL`, the output is not strictly uniform. Output
    /// space is uniform in \[0, 2^{F::MODULUS_BITS - 1}\]
    fn squeeze_field_elements_with_sizes<F: PrimeField>(
        &mut self,
        sizes: &[FieldElementSize],
    ) -> Vec<F> {
        squeeze_field_elements_with_sizes_default_impl(self, sizes)
    }

    /// Squeeze `num_elements` emulated field elements from the sponge.
    ///
    /// Because of rust limitation, for field-based implementation, using this method to squeeze
    /// native field elements will have runtime casting cost. For better efficiency, use `squeeze_native_field_elements`.
    fn squeeze_field_elements<F: PrimeField>(&mut self, num_elements: usize) -> Vec<F> {
        self.squeeze_field_elements_with_sizes::<F>(
            vec![FieldElementSize::Full; num_elements].as_slice(),
        )
    }

    /// Creates a new sponge with applied domain separation.
    fn fork(&self, domain: &[u8]) -> Self {
        let mut new_sponge = self.clone();

        let mut input = Absorb::to_sponge_bytes_as_vec(&domain.len());
        input.extend_from_slice(domain);
        new_sponge.absorb(&input);

        new_sponge
    }
}

/// The interface for field-based cryptographic sponge.
/// `CF` is the native field used by the cryptographic sponge implementation.
pub trait FieldBasedCryptographicSponge<CF: PrimeField>: CryptographicSponge {
    /// Squeeze `num_elements` field elements from the sponge.
    fn squeeze_native_field_elements(&mut self, num_elements: usize) -> Vec<CF>;

    /// Squeeze `sizes.len()` field elements from the sponge, where the `i`-th element of
    /// the output has size `sizes[i]`.
    fn squeeze_native_field_elements_with_sizes(&mut self, sizes: &[FieldElementSize]) -> Vec<CF> {
        let mut all_full_sizes = true;
        for size in sizes {
            if *size != FieldElementSize::Full {
                all_full_sizes = false;
                break;
            }
        }

        if all_full_sizes {
            self.squeeze_native_field_elements(sizes.len())
        } else {
            squeeze_field_elements_with_sizes_default_impl(self, sizes)
        }
    }
}

/// An extension for the interface of a cryptographic sponge.
/// In addition to operations defined in `CryptographicSponge`, `SpongeExt` can convert itself to
/// a state, and instantiate itself from state.
pub trait SpongeExt: CryptographicSponge {
    /// The full state of the cryptographic sponge.
    type State: Clone;
    /// Returns a sponge that uses `state`.
    fn from_state(state: Self::State, params: &Self::Config) -> Self;
    /// Consumes `self` and returns the state.
    fn into_state(self) -> Self::State;
}

/// The mode structure for duplex sponges
#[derive(Clone, Debug)]
pub enum DuplexSpongeMode {
    /// The sponge is currently absorbing data.
    Absorbing {
        /// next position of the state to be XOR-ed when absorbing.
        next_absorb_index: usize,
    },
    /// The sponge is currently squeezing data out.
    Squeezing {
        /// next position of the state to be outputted when squeezing.
        next_squeeze_index: usize,
    },
}
