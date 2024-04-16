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

#[derive(Debug)]
pub enum Error {
    IncorrectInputLength(usize),
    NotPrimeOrder,
    GenericError(Box<dyn ark_std::error::Error + Send>),
    SerializationError(ark_serialize::SerializationError),
}

impl ark_std::fmt::Display for Error {
    fn fmt(&self, f: &mut ark_std::fmt::Formatter<'_>) -> ark_std::fmt::Result {
        match self {
            Self::IncorrectInputLength(len) => write!(f, "incorrect input length: {len}"),
            Self::NotPrimeOrder => write!(f, "element is not prime order"),
            Self::GenericError(e) => write!(f, "{e}"),
            Self::SerializationError(e) => write!(f, "{e}"),
        }
    }
}

impl ark_std::error::Error for Error {}

impl From<ark_serialize::SerializationError> for Error {
    fn from(e: ark_serialize::SerializationError) -> Self {
        Self::SerializationError(e)
    }
}
