use crate::Error;
use ark_std::rand::Rng;
use ark_std::{
    fmt::{Debug, Formatter, Result as FmtResult},
    marker::PhantomData,
};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::crh::{CRHScheme, TwoToOneCRHScheme};
use ark_ec::CurveGroup;
use ark_ff::{Field, ToConstraintField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::borrow::Borrow;
use ark_std::cfg_chunks;
#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;

#[cfg(feature = "r1cs")]
pub mod constraints;

pub trait Window: Clone {
    const WINDOW_SIZE: usize;
    const NUM_WINDOWS: usize;
}

#[derive(Clone, Default, CanonicalSerialize, CanonicalDeserialize)]
pub struct Parameters<C: CurveGroup> {
    pub generators: Vec<Vec<C>>,
}

pub struct CRH<C: CurveGroup, W: Window> {
    group: PhantomData<C>,
    window: PhantomData<W>,
}

impl<C: CurveGroup, W: Window> CRH<C, W> {
    pub(crate) const INPUT_SIZE_BITS: usize = W::WINDOW_SIZE * W::NUM_WINDOWS;
    pub fn create_generators<R: Rng>(rng: &mut R) -> Vec<Vec<C>> {
        let mut generators_powers = Vec::new();
        for _ in 0..W::NUM_WINDOWS {
            generators_powers.push(Self::generator_powers(W::WINDOW_SIZE, rng));
        }
        generators_powers
    }

    pub fn generator_powers<R: Rng>(num_powers: usize, rng: &mut R) -> Vec<C> {
        let mut cur_gen_powers = Vec::with_capacity(num_powers);
        let mut base = C::rand(rng);
        for _ in 0..num_powers {
            cur_gen_powers.push(base);
            base.double_in_place();
        }
        cur_gen_powers
    }
}

impl<C: CurveGroup, W: Window> CRHScheme for CRH<C, W> {
    type Input = [u8];
    type Output = C::Affine;
    type Parameters = Parameters<C>;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error> {
        let time = start_timer!(|| format!(
            "PedersenCRH::Setup: {} {}-bit windows; {{0,1}}^{{{}}} -> C",
            W::NUM_WINDOWS,
            W::WINDOW_SIZE,
            W::NUM_WINDOWS * W::WINDOW_SIZE
        ));
        let generators = Self::create_generators(rng);
        end_timer!(time);
        Ok(Self::Parameters { generators })
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let eval_time = start_timer!(|| "PedersenCRH::Eval");
        let input = input.borrow();
        if (input.len() * 8) > W::WINDOW_SIZE * W::NUM_WINDOWS {
            panic!(
                "incorrect input length {:?} for window params {:?}✕{:?}",
                input.len(),
                W::WINDOW_SIZE,
                W::NUM_WINDOWS
            );
        }

        let mut padded_input = Vec::with_capacity(input.len());
        let mut input = input;
        // Pad the input if it is not the current length.
        if (input.len() * 8) < W::WINDOW_SIZE * W::NUM_WINDOWS {
            padded_input.extend_from_slice(input);
            let padded_length = (W::WINDOW_SIZE * W::NUM_WINDOWS) / 8;
            padded_input.resize(padded_length, 0u8);
            input = padded_input.as_slice();
        }

        assert_eq!(
            parameters.generators.len(),
            W::NUM_WINDOWS,
            "Incorrect pp of size {:?}✕{:?} for window params {:?}✕{:?}",
            parameters.generators[0].len(),
            parameters.generators.len(),
            W::WINDOW_SIZE,
            W::NUM_WINDOWS
        );

        // Compute sum of h_i^{m_i} for all i.
        let bits = bytes_to_bits(input);
        let result = cfg_chunks!(bits, W::WINDOW_SIZE)
            .zip(&parameters.generators)
            .map(|(bits, generator_powers)| {
                let mut encoded = C::zero();
                for (bit, base) in bits.iter().zip(generator_powers.iter()) {
                    if *bit {
                        encoded += base;
                    }
                }
                encoded
            })
            .sum::<C>();

        end_timer!(eval_time);

        Ok(result.into())
    }
}

pub struct TwoToOneCRH<C: CurveGroup, W: Window> {
    group: PhantomData<C>,
    window: PhantomData<W>,
}

impl<C: CurveGroup, W: Window> TwoToOneCRH<C, W> {
    pub(crate) const INPUT_SIZE_BITS: usize = W::WINDOW_SIZE * W::NUM_WINDOWS;
    const HALF_INPUT_SIZE_BITS: usize = Self::INPUT_SIZE_BITS / 2;
    pub fn create_generators<R: Rng>(rng: &mut R) -> Vec<Vec<C>> {
        CRH::<C, W>::create_generators(rng)
    }

    pub fn generator_powers<R: Rng>(num_powers: usize, rng: &mut R) -> Vec<C> {
        CRH::<C, W>::generator_powers(num_powers, rng)
    }
}

impl<C: CurveGroup, W: Window> TwoToOneCRHScheme for TwoToOneCRH<C, W> {
    type Input = [u8];
    type Output = C::Affine;
    type Parameters = Parameters<C>;

    fn setup<R: Rng>(r: &mut R) -> Result<Self::Parameters, Error> {
        CRH::<C, W>::setup(r)
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error> {
        let left_input = left_input.borrow();
        let right_input = right_input.borrow();
        assert_eq!(
            left_input.len(),
            right_input.len(),
            "left and right input should be of equal length"
        );
        // check overflow

        debug_assert!(left_input.len() * 8 <= Self::HALF_INPUT_SIZE_BITS);

        let mut buffer = vec![0u8; (Self::HALF_INPUT_SIZE_BITS + Self::HALF_INPUT_SIZE_BITS) / 8];

        buffer
            .iter_mut()
            .zip(left_input.iter().chain(right_input.iter()))
            .for_each(|(b, l_b)| *b = *l_b);

        CRH::<C, W>::evaluate(parameters, buffer.as_slice())
    }

    /// A simple implementation method: just concat the left input and right input together
    ///
    /// `evaluate` requires that `left_input` and `right_input` are of equal length.
    fn compress<T: Borrow<Self::Output>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error> {
        Self::evaluate(
            parameters,
            crate::to_uncompressed_bytes!(left_input)?,
            crate::to_uncompressed_bytes!(right_input)?,
        )
    }
}

pub fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for i in 0..8 {
            let bit = (*byte >> i) & 1;
            bits.push(bit == 1)
        }
    }
    bits
}

impl<C: CurveGroup> Debug for Parameters<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        writeln!(f, "Pedersen Hash Parameters {{")?;
        for (i, g) in self.generators.iter().enumerate() {
            writeln!(f, "\t  Generator {}: {:?}", i, g)?;
        }
        writeln!(f, "}}")
    }
}

impl<ConstraintF: Field, C: CurveGroup + ToConstraintField<ConstraintF>>
    ToConstraintField<ConstraintF> for Parameters<C>
{
    #[inline]
    fn to_field_elements(&self) -> Option<Vec<ConstraintF>> {
        Some(Vec::new())
    }
}
