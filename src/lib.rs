#![cfg_attr(not(feature = "std"), no_std)]
#![deny(
    unused,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    // missing_docs
)]
#![forbid(unsafe_code)]

#[macro_use]
extern crate ark_std;

#[macro_use]
extern crate derivative;

pub(crate) use ark_std::{borrow::ToOwned, boxed::Box, vec::Vec};

pub mod commitment;
pub mod crh;
pub mod merkle_tree;

pub mod encryption;
pub mod prf;
pub mod signature;
pub mod snark;

pub use self::{
    commitment::CommitmentScheme,
    crh::CRH,
    merkle_tree::{MerkleTree, Path},
    prf::PRF,
    signature::SignatureScheme,
    snark::{CircuitSpecificSetupSNARK, UniversalSetupSNARK, SNARK},
};

#[cfg(feature = "r1cs")]
pub use self::{
    commitment::CommitmentGadget, crh::CRHGadget, merkle_tree::constraints::PathVar,
    prf::PRFGadget, signature::SigRandomizePkGadget, snark::SNARKGadget,
};

pub type Error = Box<dyn ark_std::error::Error>;

#[derive(Debug)]
pub enum CryptoError {
    IncorrectInputLength(usize),
    NotPrimeOrder,
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            CryptoError::IncorrectInputLength(len) => format!("input length is wrong: {}", len),
            CryptoError::NotPrimeOrder => "element is not prime order".to_owned(),
        };
        write!(f, "{}", msg)
    }
}

impl ark_std::error::Error for CryptoError {}
