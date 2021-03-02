#![allow(unused)] // temporary

use crate::crh::FixedLengthTwoToOneCRH;
use crate::FixedLengthCRH;
use ark_ff::ToBytes;

#[cfg(feature = "r1cs")]
pub mod constraints;

pub trait Config {
    const HEIGHT: usize;
    type LeafHash: FixedLengthCRH;
    type TwoToOneHash: FixedLengthTwoToOneCRH;
}

pub type TwoToOneDigest<P> = <<P as Config>::TwoToOneHash as FixedLengthTwoToOneCRH>::Output;
pub type LeafDigest<P> = <<P as Config>::LeafHash as FixedLengthCRH>::Output;
pub type TwoToOneParam<P> = <<P as Config>::TwoToOneHash as FixedLengthTwoToOneCRH>::Parameters;
pub type LeafParam<P> = <<P as Config>::LeafHash as FixedLengthCRH>::Parameters;
/// Stores the hashes of a particular path (in order) from leaf to root.
/// Our path `is_left_child()` if the boolean in `path` is true.
///

pub struct Path<P: Config> {
    pub(crate) leaf_and_sibling_hash: (LeafDigest<P>, LeafDigest<P>),
    /// The hash path from lower layer to higher layer.
    pub(crate) non_leaf_and_sibling_hash_path: Vec<(TwoToOneDigest<P>, TwoToOneDigest<P>)>,
}

impl<P: Config> Path<P> {
    pub fn verify<L: ToBytes>(
        &self,
        leaf_hash_parameters: LeafParam<P>,
        two_to_one_hash_parameters: TwoToOneParam<P>,
        root_hash: TwoToOneDigest<P>,
        leaf: &L,
    ) -> Result<bool, crate::Error> {
        todo!()
    }
}

/// Defines a merkle tree data structure.
/// This merkle tree has fixed height, and uses padding trees.
///
/// For example, if HEIGHT is 4, and number of non-empty leaves is 2,
/// then the tree represented by `non_leaf_nodes` and `leaf_nodes` is
///  H(H(A), H(B)) -> using 2-to-1 hash
///     /  \
///   /     \
/// H(A)   H(B) -> using leaf hash
///
/// The actual tree should be
///          H(H(H(H(A), H(B)), H(pad1)),H(pad2))  -> using 2-to-1 hash
///               /                 \
///       H(H(H(A), H(B)), H(pad1))    H(pad2)  -> using 2-to-1 hash
///         /         \
/// H(H(A), H(B))    H(pad1)   -> using 2-to-1 hash
///     /  \
///   /     \
/// H(A)   H(B)   -> using leaf hash
pub struct MerkleTree<P: Config> {
    /// stores the non-leaf nodes in level order.
    non_leaf_nodes: Vec<TwoToOneDigest<P>>,
    /// store the hash of leaf nodes from left to right
    leaf_nodes: Vec<LeafDigest<P>>,
    /// Stores path of the padding tree from lower layer to upper layer.
    /// In this example, `padding_tree_path` stores [(H(H(A), H(B)), H(pad1)),((H(H(A), H(B)), H(pad1)), H(pad2))]
    padding_trees_path: Vec<(TwoToOneDigest<P>, TwoToOneDigest<P>)>,
    /// Store the two-to-one hash parameters
    two_to_one_param: TwoToOneParam<P>,
    /// Store the leaf hash parameters
    leaf_hash_param: LeafParam<P>,
    /// Stores the hash of root node
    root: TwoToOneDigest<P>,
}

impl<P: Config> MerkleTree<P> {
    pub fn blank(leaf_hash_param: &LeafParam<P>, two_to_one_hash_param: &TwoToOneParam<P>) -> Self {
        todo!()
    }

    pub fn new<L: ToBytes>(
        leaf_hash_param: &LeafParam<P>,
        two_to_one_hash_param: &TwoToOneParam<P>,
        leaves: &[L],
    ) -> Result<Self, crate::Error> {
        todo!()
    }

    /// returns the root fo the merkle tree
    pub fn root(&self) -> TwoToOneDigest<P> {
        todo!()
    }

    /// Returns the authentication path from leaf to root
    pub fn generate_proof<L: ToBytes>(
        &self,
        index: usize,
        leaf: &L,
    ) -> Result<Path<P>, crate::Error> {
        todo!()
    }

    /// Update the leaf at `index` to updated leaf.
    pub fn update<L: ToBytes>(&mut self, index: usize, new_leaf: &L) -> Result<(), crate::Error> {
        todo!()
    }

    /// Update the leaf and check if the updated root is equal to `asserted_new_root`.
    ///
    /// Tree will not be modified if check failed.
    pub fn check_update<L: ToBytes>(
        &mut self,
        index: usize,
        new_leaf: &L,
        asserted_new_root: &TwoToOneDigest<P>,
    ) -> Result<(), crate::Error> {
        todo!()
    }
}
