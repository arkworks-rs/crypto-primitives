#![allow(unused)] // temporary

use crate::crh::TwoToOneCRH;
use crate::CRH;
use ark_ff::ToBytes;

#[cfg(feature = "r1cs")]
pub mod constraints;

pub trait Config {
    type LeafHash: CRH;
    type TwoToOneHash: TwoToOneCRH;
    /// Determine the upper bound of output size of leaf hash.
    fn leaf_hash_output_size_upper_bound() -> usize;
    /// Determine the upper bound of output size of two-to-one hash.
    fn two_to_one_hash_output_size_upper_bound() -> usize;
}

pub type TwoToOneDigest<P> = <<P as Config>::TwoToOneHash as TwoToOneCRH>::Output;
pub type LeafDigest<P> = <<P as Config>::LeafHash as CRH>::Output;
pub type TwoToOneParam<P> = <<P as Config>::TwoToOneHash as TwoToOneCRH>::Parameters;
pub type LeafParam<P> = <<P as Config>::LeafHash as CRH>::Parameters;
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
/// This merkle tree has runtime fixed height, and assumes number of leaves is 2^height.
///
/// TODO: add RFC-6962 compatible merkle tree in the future.
/// For this release, padding will not be supported because of security concerns: if the leaf hash and two to one hash uses same underlying
/// CRH, a malicious prover can prove a leaf while the actual node is an inner node. In the future, we can prefix leaf hashes in different layers to
/// solve the problem.
pub struct MerkleTree<P: Config> {
    /// stores the non-leaf nodes in level order. The first element is the root node.
    non_leaf_nodes: Vec<TwoToOneDigest<P>>,
    /// store the hash of leaf nodes from left to right
    leaf_nodes: Vec<LeafDigest<P>>,
    /// Store the two-to-one hash parameters
    two_to_one_hash_param: TwoToOneParam<P>,
    /// Store the leaf hash parameters
    leaf_hash_param: LeafParam<P>,
    /// Stores the height of the MerkleTree
    height: usize,
}

impl<P: Config> MerkleTree<P> {
    pub fn blank(
        leaf_hash_param: &LeafParam<P>,
        two_to_one_hash_param: &TwoToOneParam<P>,
        height: usize,
    ) -> Self {
        todo!()
    }

    /// Returns a new merkle tree. `leaves.len()` should be power of two.
    pub fn new<L: ToBytes>(
        leaf_hash_param: &LeafParam<P>,
        two_to_one_hash_param: &TwoToOneParam<P>,
        leaves: &[L],
    ) -> Result<Self, crate::Error> {
        let leaf_nodes_size = leaves.len(); // size of the leaf layer
        assert!(
            leaf_nodes_size.is_power_of_two(),
            "`leaves.len() should be power of two"
        );
        let non_leaf_nodes_size = leaf_nodes_size - 1;

        let tree_height = tree_height(non_leaf_nodes_size + leaf_nodes_size);

        let hash_of_empty: TwoToOneDigest<P> = P::TwoToOneHash::evaluate(
            two_to_one_hash_param,
            &vec![0u8; P::TwoToOneHash::INPUT_SIZE_BITS],
            &vec![0u8; P::TwoToOneHash::INPUT_SIZE_BITS],
        )?;

        // initialize the merkle tree as array of nodes in level order
        let mut non_leaf_nodes: Vec<TwoToOneDigest<P>> = (0..non_leaf_nodes_size)
            .map(|_| hash_of_empty.clone())
            .collect();
        let mut leaf_nodes: Vec<LeafDigest<P>> = Vec::with_capacity(leaf_nodes_size);

        // Compute the starting indices for each non-leaf level of the tree
        let mut index = 0;
        let mut level_indices = Vec::with_capacity(tree_height - 1);
        for _ in 0..tree_height {
            level_indices.push(index);
            index = left_child(index);
        }

        // compute and store hash values for each leaf
        let mut buffer = vec![0u8; P::leaf_hash_output_size_upper_bound()]; // assume output length <= 128
        for leaf in leaves.iter() {
            read_to_buffer(leaf, &mut buffer);
            leaf_nodes.push(P::LeafHash::evaluate(leaf_hash_param, &buffer)?)
        }

        // compute the hash values for the non-leaf bottom layer
        {
            let mut buffer_left = vec![0u8; P::two_to_one_hash_output_size_upper_bound()];
            let mut buffer_right = vec![0u8; P::two_to_one_hash_output_size_upper_bound()];
            let start_index = level_indices.pop().unwrap();
            let upper_bound = left_child(start_index);
            for current_index in start_index..upper_bound {
                let left_leaf_index = left_child(current_index) - upper_bound;
                let right_leaf_index = right_child(current_index) - upper_bound;
                // compute hash
                read_to_buffer(&leaf_nodes[left_leaf_index], &mut buffer_left)?;
                read_to_buffer(&leaf_nodes[right_leaf_index], &mut buffer_right)?;
                non_leaf_nodes[current_index] =
                    P::TwoToOneHash::evaluate(&two_to_one_hash_param, &buffer_left, &buffer_right)?
            }
        }

        // compute the hash values for nodes in every other layer in the tree
        let mut buffer_left = vec![0u8; P::two_to_one_hash_output_size_upper_bound()];
        let mut buffer_right = vec![0u8; P::two_to_one_hash_output_size_upper_bound()];
        level_indices.reverse();
        for &start_index in &level_indices {
            let upper_bound = left_child(start_index); // The exclusive index upper bound for this layer
            for current_index in start_index..upper_bound {
                let left_index = left_child(current_index);
                let right_index = right_child(current_index);
                non_leaf_nodes[current_index] =
                    P::TwoToOneHash::evaluate(&two_to_one_hash_param, &buffer_left, &buffer_right)?
            }
        }

        Ok(MerkleTree {
            leaf_nodes,
            non_leaf_nodes,
            height: tree_height,
            two_to_one_hash_param: two_to_one_hash_param.clone(),
            leaf_hash_param: leaf_hash_param.clone(),
        })
    }

    /// returns the root fo the merkle tree
    pub fn root(&self) -> TwoToOneDigest<P> {
        self.non_leaf_nodes[0].clone()
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

/// read `data` to `buf`
fn read_to_buffer(data: &impl ToBytes, buf: &mut [u8]) -> Result<(), crate::Error> {
    buf.iter_mut()
        .zip(&ark_ff::to_bytes![&data]?)
        .for_each(|(b, l_b)| *b = *l_b);
    Ok(())
}

/// Returns the height of the tree, given the size of the tree.
#[inline]
fn tree_height(tree_size: usize) -> usize {
    if tree_size == 1 {
        return 1;
    }

    ark_std::log2(tree_size) as usize
}
/// Returns true iff the index represents the root.
#[inline]
fn is_root(index: usize) -> bool {
    index == 0
}

/// Returns the index of the left child, given an index.
#[inline]
fn left_child(index: usize) -> usize {
    2 * index + 1
}

/// Returns the index of the right child, given an index.
#[inline]
fn right_child(index: usize) -> usize {
    2 * index + 2
}

/// Returns the index of the sibling, given an index.
#[inline]
fn sibling(index: usize) -> Option<usize> {
    if index == 0 {
        None
    } else if is_left_child(index) {
        Some(index + 1)
    } else {
        Some(index - 1)
    }
}

/// Returns true iff the given index represents a left child.
#[inline]
fn is_left_child(index: usize) -> bool {
    index % 2 == 1
}

/// Returns the index of the parent, given an index.
#[inline]
fn parent(index: usize) -> Option<usize> {
    if index > 0 {
        Some((index - 1) >> 1)
    } else {
        None
    }
}
