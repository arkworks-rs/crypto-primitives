use crate::FixedLengthCRH;
use crate::crh::FixedLengthTwoToOneCRH;

#[cfg(feature = "r1cs")]
pub mod constraints;

pub trait Config {
    const HEIGHT: usize;
    type LeafHash: FixedLengthCRH;
    type TwoToOneHash: FixedLengthTwoToOneCRH;
}

pub type TwoToOneDigest<P: Config> = P::TwoToOneHash::Output;
pub type LeafDigest<P: Config> = P::LeafHash::Output;

/// Stores the hashes of a particular path (in order) from leaf to root.
/// Our path `is_left_child()` if the boolean in `path` is true.
pub struct Path<P: Config> {
    pub(crate) leaf_and_sibling_hash: (LeafDigest<P>, LeafDigest<P>),
    pub(crate) non_leaf_and_sibling_hash_path: Vec<(TwoToOneDigest<P>, TwoToOneDigest<P>)>
}