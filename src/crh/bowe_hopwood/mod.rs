//! The [Bowe-Hopwood-Pedersen] hash is a optimized variant of the Pedersen CRH for
//! specific Twisted Edwards (TE) curves. See [Section 5.4.17 of the Zcash protocol specification](https://raw.githubusercontent.com/zcash/zips/master/protocol/protocol.pdf#concretepedersenhash) for a formal description of this hash function, specialized for the Jubjub curve.
//! The implementation in this repository is generic across choice of TE curves.

use crate::{Error, Vec};
use ark_std::rand::Rng;
use ark_std::{
    fmt::{Debug, Formatter, Result as FmtResult},
    marker::PhantomData,
};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use super::pedersen;
use crate::crh::{TwoToOneCRH, CRH as CRHTrait};
use ark_ec::{
    twisted_edwards_extended::GroupProjective as TEProjective, ProjectiveCurve, TEModelParameters,
};
use ark_ff::{biginteger::BigInteger, fields::PrimeField};
use ark_std::cfg_chunks;
use ark_std::UniformRand;

#[cfg(feature = "r1cs")]
pub mod constraints;

pub const CHUNK_SIZE: usize = 3;

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Default(bound = ""))]
pub struct Parameters<P: TEModelParameters> {
    pub generators: Vec<Vec<TEProjective<P>>>,
}

pub struct CRH<P: TEModelParameters, W: pedersen::Window> {
    group: PhantomData<P>,
    window: PhantomData<W>,
}

impl<P: TEModelParameters, W: pedersen::Window> CRH<P, W> {
    pub fn create_generators<R: Rng>(rng: &mut R) -> Vec<Vec<TEProjective<P>>> {
        let mut generators = Vec::new();
        for _ in 0..W::NUM_WINDOWS {
            let mut generators_for_segment = Vec::new();
            let mut base = TEProjective::rand(rng);
            for _ in 0..W::WINDOW_SIZE {
                generators_for_segment.push(base);
                for _ in 0..4 {
                    base.double_in_place();
                }
            }
            generators.push(generators_for_segment);
        }
        generators
    }
}

impl<P: TEModelParameters, W: pedersen::Window> CRHTrait for CRH<P, W> {
    const INPUT_SIZE_BITS: usize = pedersen::CRH::<TEProjective<P>, W>::INPUT_SIZE_BITS;
    type Output = P::BaseField;
    type Parameters = Parameters<P>;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error> {
        fn calculate_num_chunks_in_segment<F: PrimeField>() -> usize {
            let upper_limit = F::modulus_minus_one_div_two();
            let mut c = 0;
            let mut range = F::BigInt::from(2_u64);
            while range < upper_limit {
                range.muln(4);
                c += 1;
            }

            c
        }

        let maximum_num_chunks_in_segment = calculate_num_chunks_in_segment::<P::ScalarField>();
        if W::WINDOW_SIZE > maximum_num_chunks_in_segment {
            panic!(
                "Bowe-Hopwood-PedersenCRH hash must have a window size resulting in scalars < (p-1)/2, \
                 maximum segment size is {}",
                maximum_num_chunks_in_segment
            );
        }

        let time = start_timer!(|| format!(
            "Bowe-Hopwood-PedersenCRH::Setup: {} segments of {} 3-bit chunks; {{0,1}}^{{{}}} -> P",
            W::NUM_WINDOWS,
            W::WINDOW_SIZE,
            W::WINDOW_SIZE * W::NUM_WINDOWS * CHUNK_SIZE
        ));
        let generators = Self::create_generators(rng);
        end_timer!(time);
        Ok(Self::Parameters { generators })
    }

    fn evaluate(parameters: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error> {
        let eval_time = start_timer!(|| "BoweHopwoodPedersenCRH::Eval");

        if (input.len() * 8) > W::WINDOW_SIZE * W::NUM_WINDOWS * CHUNK_SIZE {
            panic!(
                "incorrect input length {:?} for window params {:?}x{:?}x{}",
                input.len(),
                W::WINDOW_SIZE,
                W::NUM_WINDOWS,
                CHUNK_SIZE,
            );
        }

        let mut padded_input = Vec::with_capacity(input.len());
        let input = pedersen::bytes_to_bits(input);
        // Pad the input if it is not the current length.
        padded_input.extend_from_slice(&input);
        if input.len() % CHUNK_SIZE != 0 {
            let remaining = CHUNK_SIZE - input.len() % CHUNK_SIZE;
            padded_input.extend_from_slice(&vec![false; remaining]);
        }

        assert_eq!(padded_input.len() % CHUNK_SIZE, 0);

        assert_eq!(
            parameters.generators.len(),
            W::NUM_WINDOWS,
            "Incorrect pp of size {:?} for window params {:?}x{:?}x{}",
            parameters.generators.len(),
            W::WINDOW_SIZE,
            W::NUM_WINDOWS,
            CHUNK_SIZE,
        );
        for generators in parameters.generators.iter() {
            assert_eq!(generators.len(), W::WINDOW_SIZE);
        }
        assert_eq!(CHUNK_SIZE, 3);

        // Compute sum of h_i^{sum of
        // (1-2*c_{i,j,2})*(1+c_{i,j,0}+2*c_{i,j,1})*2^{4*(j-1)} for all j in segment}
        // for all i. Described in section 5.4.1.7 in the Zcash protocol
        // specification.

        let result = cfg_chunks!(padded_input, W::WINDOW_SIZE * CHUNK_SIZE)
            .zip(&parameters.generators)
            .map(|(segment_bits, segment_generators)| {
                cfg_chunks!(segment_bits, CHUNK_SIZE)
                    .zip(segment_generators)
                    .map(|(chunk_bits, generator)| {
                        let mut encoded = *generator;
                        if chunk_bits[0] {
                            encoded += generator;
                        }
                        if chunk_bits[1] {
                            encoded += &generator.double();
                        }
                        if chunk_bits[2] {
                            encoded = -encoded;
                        }
                        encoded
                    })
                    .sum::<TEProjective<P>>()
            })
            .sum::<TEProjective<P>>();

        end_timer!(eval_time);

        Ok(result.into_affine().x)
    }
}

impl<P: TEModelParameters, W: pedersen::Window> TwoToOneCRH for CRH<P, W> {
    const LEFT_INPUT_SIZE_BITS: usize = <Self as CRHTrait>::INPUT_SIZE_BITS / 2;
    const RIGHT_INPUT_SIZE_BITS: usize = Self::LEFT_INPUT_SIZE_BITS;

    type Output = P::BaseField;
    type Parameters = Parameters<P>;

    fn setup<R: Rng>(r: &mut R) -> Result<Self::Parameters, Error> {
        <Self as CRHTrait>::setup(r)
    }

    /// A simple implementation method: just concat the left input and right input together
    ///
    /// `evaluate` requires that `left_input` and `right_input` are of equal length.
    fn evaluate(
        parameters: &Self::Parameters,
        left_input: &[u8],
        right_input: &[u8],
    ) -> Result<Self::Output, Error> {
        assert_eq!(
            left_input.len(),
            right_input.len(),
            "left and right input should be of equal length"
        );
        // check overflow

        debug_assert!(left_input.len() * 8 <= Self::LEFT_INPUT_SIZE_BITS);

        let mut buffer = vec![0u8; (Self::LEFT_INPUT_SIZE_BITS + Self::RIGHT_INPUT_SIZE_BITS) / 8];

        buffer
            .iter_mut()
            .zip(left_input.iter().chain(right_input.iter()))
            .for_each(|(b, l_b)| *b = *l_b);

        <Self as CRHTrait>::evaluate(parameters, &buffer)
    }
}

impl<P: TEModelParameters> Debug for Parameters<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        writeln!(f, "Bowe-Hopwood-Pedersen Hash Parameters {{")?;
        for (i, g) in self.generators.iter().enumerate() {
            writeln!(f, "\t  Generator {}: {:?}", i, g)?;
        }
        writeln!(f, "}}")
    }
}

#[cfg(test)]
mod test {
    use crate::{
        crh::{bowe_hopwood, pedersen::Window},
        CRH,
    };
    use ark_ed_on_bls12_381::EdwardsParameters;
    use ark_std::test_rng;

    #[test]
    fn test_simple_bh() {
        #[derive(Clone)]
        struct TestWindow {}
        impl Window for TestWindow {
            const WINDOW_SIZE: usize = 63;
            const NUM_WINDOWS: usize = 8;
        }

        let rng = &mut test_rng();
        let params = <bowe_hopwood::CRH<EdwardsParameters, TestWindow> as CRH>::setup(rng).unwrap();
        let _ = <bowe_hopwood::CRH<EdwardsParameters, TestWindow> as CRH>::evaluate(
            &params,
            &[1, 2, 3],
        )
        .unwrap();
    }
}
