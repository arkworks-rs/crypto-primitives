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

#[allow(unused_imports)]
#[macro_use]
extern crate derivative;

#[allow(unused_imports)]
pub(crate) use ark_std::{borrow::ToOwned, boxed::Box, vec::Vec};
mod macros;

#[cfg(feature = "commitment")]
pub mod commitment;

#[cfg(feature = "crh")]
pub mod crh;

#[cfg(feature = "merkle_tree")]
pub mod merkle_tree;

#[cfg(feature = "encryption")]
pub mod encryption;

#[cfg(feature = "prf")]
pub mod prf;

#[cfg(feature = "signature")]
pub mod signature;

#[cfg(feature = "snark")]
pub mod snark;

#[cfg(feature = "sponge")]
pub mod sponge;

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
