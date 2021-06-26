#![allow(unused)] // temporary
#![allow(clippy::needless_range_loop)]

use crate::crh::TwoToOneCRH;
use crate::CRH;
use ark_ff::ToBytes;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_std::vec::Vec;

#[cfg(feature = "r1cs")]
pub mod constraints;

pub trait Config {
    type LeafHash: CRH;
    type TwoToOneHash: TwoToOneCRH;
}

pub type TwoToOneDigest<P> = <<P as Config>::TwoToOneHash as TwoToOneCRH>::Output;
pub type LeafDigest<P> = <<P as Config>::LeafHash as CRH>::Output;
pub type TwoToOneParam<P> = <<P as Config>::TwoToOneHash as TwoToOneCRH>::Parameters;
pub type LeafParam<P> = <<P as Config>::LeafHash as CRH>::Parameters;

/// Stores the hashes of a particular path (in order) from root to leaf.
/// For example:
/// ```tree_diagram
///         [A]
///        /   \
///      [B]    C
///     / \   /  \
///    D [E] F    H
///   .. / \ ....
///    [I] J
/// ```
///  Suppose we want to prove I, then `leaf_sibling_hash` is J, `auth_path` is `[C,D]`
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Path<P: Config> {
    pub leaf_sibling_hash: LeafDigest<P>,
    /// The sibling of path node ordered from higher layer to lower layer (does not include root node).
    pub auth_path: Vec<TwoToOneDigest<P>>,
    /// stores the leaf index of the node
    pub leaf_index: usize,
}

impl<P: Config> Path<P> {
    /// The position of on_path node in `leaf_and_sibling_hash` and `non_leaf_and_sibling_hash_path`.
    /// `position[i]` is 0 (false) iff `i`th on-path node from top to bottom is on the left.
    ///
    /// This function simply converts `self.leaf_index` to boolean array in big endian form.
    fn position_list(&'_ self) -> impl '_ + Iterator<Item = bool> {
        (0..self.auth_path.len() + 1)
            .map(move |i| ((self.leaf_index >> i) & 1) != 0)
            .rev()
    }
}

/// Convert `computed_hash` and `sibling_hash` to bytes. `index` is the first `path.len()` bits of
/// the position of tree.
///
/// If the least significant bit of `index` is 0, then `input_1` will be left and `input_2` will be right.
/// Otherwise, `input_1` will be right and `input_2` will be left.
///
/// Returns: (left, right)
fn select_left_right_bytes<B: ToBytes>(
    index: usize,
    computed_hash: &B,
    sibling_hash: &B,
) -> Result<(Vec<u8>, Vec<u8>), crate::Error> {
    let is_left = index & 1 == 0;
    let mut left_bytes = ark_ff::to_bytes!(computed_hash)?;
    let mut right_bytes = ark_ff::to_bytes!(sibling_hash)?;
    if !is_left {
        core::mem::swap(&mut left_bytes, &mut right_bytes);
    }
    Ok((left_bytes, right_bytes))
}

impl<P: Config> Path<P> {
    /// Verify that a leaf is at `self.index` of the merkle tree.
    /// * `leaf_size`: leaf size in number of bytes
    ///
    /// `verify` infers the tree height by setting `tree_height = self.auth_path.len() + 2`
    pub fn verify<L: ToBytes>(
        &self,
        leaf_hash_params: &LeafParam<P>,
        two_to_one_hash_params: &TwoToOneParam<P>,
        root_hash: &TwoToOneDigest<P>,
        leaf: &L,
    ) -> Result<bool, crate::Error> {
        // calculate leaf hash
        let claimed_leaf_hash =
            P::LeafHash::evaluate(&leaf_hash_params, &ark_ff::to_bytes!(&leaf)?)?;
        // check hash along the path from bottom to root
        let (left_bytes, right_bytes) =
            select_left_right_bytes(self.leaf_index, &claimed_leaf_hash, &self.leaf_sibling_hash)?;

        let mut curr_path_node =
            P::TwoToOneHash::evaluate(&two_to_one_hash_params, &left_bytes, &right_bytes)?;

        // we will use `index` variable to track the position of path
        let mut index = self.leaf_index;
        index >>= 1;

        // Check levels between leaf level and root
        for level in (0..self.auth_path.len()).rev() {
            // check if path node at this level is left or right
            let (left_bytes, right_bytes) =
                select_left_right_bytes(index, &curr_path_node, &self.auth_path[level])?;
            // update curr_path_node
            curr_path_node =
                P::TwoToOneHash::evaluate(&two_to_one_hash_params, &left_bytes, &right_bytes)?;
            index >>= 1;
        }

        // check if final hash is root
        if &curr_path_node != root_hash {
            return Ok(false);
        }

        Ok(true)
    }
}

/// Defines a merkle tree data structure.
/// This merkle tree has runtime fixed height, and assumes number of leaves is 2^height.
///
/// TODO: add RFC-6962 compatible merkle tree in the future.
/// For this release, padding will not be supported because of security concerns: if the leaf hash and two to one hash uses same underlying
/// CRH, a malicious prover can prove a leaf while the actual node is an inner node. In the future, we can prefix leaf hashes in different layers to
/// solve the problem.
#[derive(Clone)]
pub struct MerkleTree<P: Config> {
    /// stores the non-leaf nodes in level order. The first element is the root node.
    /// The ith nodes (starting at 1st) children are at indices `2*i`, `2*i+1`
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
    /// Create an empty merkle tree such that all leaves are zero-filled.
    /// Consider using a sparse merkle tree if you need the tree to be low memory
    pub fn blank(
        leaf_hash_param: &LeafParam<P>,
        two_to_one_hash_param: &TwoToOneParam<P>,
        height: usize,
    ) -> Result<Self, crate::Error> {
        let leaf = vec![0u8; P::LeafHash::INPUT_SIZE_BITS / 8];
        let leaves = vec![leaf; 1 << (height - 1)];
        Self::new(leaf_hash_param, two_to_one_hash_param, &leaves)
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

        let tree_height = tree_height(leaf_nodes_size);

        let hash_of_empty: TwoToOneDigest<P> = P::TwoToOneHash::evaluate(
            two_to_one_hash_param,
            &vec![0u8; P::TwoToOneHash::LEFT_INPUT_SIZE_BITS / 8],
            &vec![0u8; P::TwoToOneHash::RIGHT_INPUT_SIZE_BITS / 8],
        )?;

        // initialize the merkle tree as array of nodes in level order
        let mut non_leaf_nodes: Vec<TwoToOneDigest<P>> = (0..non_leaf_nodes_size)
            .map(|_| hash_of_empty.clone())
            .collect();
        let mut leaf_nodes: Vec<LeafDigest<P>> = Vec::with_capacity(leaf_nodes_size);

        // Compute the starting indices for each non-leaf level of the tree
        let mut index = 0;
        let mut level_indices = Vec::with_capacity(tree_height - 1);
        for _ in 0..(tree_height - 1) {
            level_indices.push(index);
            index = left_child(index);
        }

        // compute and store hash values for each leaf
        for leaf in leaves.iter() {
            leaf_nodes.push(P::LeafHash::evaluate(
                leaf_hash_param,
                &ark_ff::to_bytes!(leaf)?,
            )?)
        }

        // compute the hash values for the non-leaf bottom layer
        {
            let start_index = level_indices.pop().unwrap();
            let upper_bound = left_child(start_index);
            for current_index in start_index..upper_bound {
                // `left_child(current_index)` and `right_child(current_index) returns the position of
                // leaf in the whole tree (represented as a list in level order). We need to shift it
                // by `-upper_bound` to get the index in `leaf_nodes` list.
                let left_leaf_index = left_child(current_index) - upper_bound;
                let right_leaf_index = right_child(current_index) - upper_bound;
                // compute hash
                let left_bytes = ark_ff::to_bytes!(&leaf_nodes[left_leaf_index])?;
                let right_bytes = ark_ff::to_bytes!(&leaf_nodes[right_leaf_index])?;
                non_leaf_nodes[current_index] =
                    P::TwoToOneHash::evaluate(&two_to_one_hash_param, &left_bytes, &right_bytes)?
            }
        }

        // compute the hash values for nodes in every other layer in the tree
        level_indices.reverse();
        for &start_index in &level_indices {
            // The layer beginning `start_index` ends at `upper_bound` (exclusive).
            let upper_bound = left_child(start_index);
            for current_index in start_index..upper_bound {
                let left_index = left_child(current_index);
                let right_index = right_child(current_index);
                let left_bytes = ark_ff::to_bytes!(&non_leaf_nodes[left_index])?;
                let right_bytes = ark_ff::to_bytes!(&non_leaf_nodes[right_index])?;
                non_leaf_nodes[current_index] =
                    P::TwoToOneHash::evaluate(&two_to_one_hash_param, &left_bytes, &right_bytes)?
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

    /// Returns the root of the Merkle tree.
    pub fn root(&self) -> TwoToOneDigest<P> {
        self.non_leaf_nodes[0].clone()
    }

    /// Returns the height of the Merkle tree.
    pub fn height(&self) -> usize {
        self.height
    }

    /// Returns the authentication path from leaf at `index` to root.
    pub fn generate_proof(&self, index: usize) -> Result<Path<P>, crate::Error> {
        // gather basic tree information
        let tree_height = tree_height(self.leaf_nodes.len());

        // Get Leaf hash, and leaf sibling hash,
        let leaf_index_in_tree = convert_index_to_last_level(index, tree_height);
        let leaf_sibling_hash = if index & 1 == 0 {
            // leaf is left child
            self.leaf_nodes[index + 1].clone()
        } else {
            // leaf is right child
            self.leaf_nodes[index - 1].clone()
        };

        // path.len() = `tree height - 2`, the two missing elements being the leaf sibling hash and the root
        let mut path = Vec::with_capacity(tree_height - 2);
        // Iterate from the bottom layer after the leaves, to the top, storing all sibling node's hash values.
        let mut current_node = parent(leaf_index_in_tree).unwrap();
        while !is_root(current_node) {
            let sibling_node = sibling(current_node).unwrap();
            path.push(self.non_leaf_nodes[sibling_node].clone());
            current_node = parent(current_node).unwrap();
        }

        debug_assert_eq!(path.len(), tree_height - 2);

        // we want to make path from root to bottom
        path.reverse();

        Ok(Path {
            leaf_index: index,
            auth_path: path,
            leaf_sibling_hash,
        })
    }

    /// Given the index and new leaf, return the hash of leaf and an updated path in order from root to bottom non-leaf level.
    /// This does not mutate the underlying tree.
    fn updated_path<L: ToBytes>(
        &self,
        index: usize,
        new_leaf: &L,
    ) -> Result<(LeafDigest<P>, Vec<TwoToOneDigest<P>>), crate::Error> {
        // calculate the hash of leaf
        let new_leaf_hash =
            P::LeafHash::evaluate(&self.leaf_hash_param, &ark_ff::to_bytes!(&new_leaf)?)?;

        // calculate leaf sibling hash and locate its position (left or right)
        let (leaf_left, leaf_right) = if index & 1 == 0 {
            // leaf on left
            (&new_leaf_hash, &self.leaf_nodes[index + 1])
        } else {
            (&self.leaf_nodes[index - 1], &new_leaf_hash)
        };

        // calculate the updated hash at bottom non-leaf-level
        let mut path_bottom_to_top = Vec::with_capacity(self.height - 1);
        {
            path_bottom_to_top.push(P::TwoToOneHash::evaluate(
                &self.two_to_one_hash_param,
                &ark_ff::to_bytes!(&leaf_left)?,
                &ark_ff::to_bytes!(&leaf_right)?,
            )?);
        }

        // then calculate the updated hash from bottom to root
        let leaf_index_in_tree = convert_index_to_last_level(index, self.height);
        let mut prev_index = parent(leaf_index_in_tree).unwrap();
        while !is_root(prev_index) {
            let (left_hash_bytes, right_hash_bytes) = if is_left_child(prev_index) {
                (
                    ark_ff::to_bytes!(path_bottom_to_top.last().unwrap())?,
                    ark_ff::to_bytes!(&self.non_leaf_nodes[sibling(prev_index).unwrap()])?,
                )
            } else {
                (
                    ark_ff::to_bytes!(&self.non_leaf_nodes[sibling(prev_index).unwrap()])?,
                    ark_ff::to_bytes!(path_bottom_to_top.last().unwrap())?,
                )
            };
            path_bottom_to_top.push(P::TwoToOneHash::evaluate(
                &self.two_to_one_hash_param,
                &left_hash_bytes,
                &right_hash_bytes,
            )?);
            prev_index = parent(prev_index).unwrap();
        }

        debug_assert_eq!(path_bottom_to_top.len(), self.height - 1);
        let path_top_to_bottom: Vec<_> = path_bottom_to_top.into_iter().rev().collect();
        Ok((new_leaf_hash, path_top_to_bottom))
    }

    /// Update the leaf at `index` to updated leaf.
    /// ```tree_diagram
    ///         [A]
    ///        /   \
    ///      [B]    C
    ///     / \   /  \
    ///    D [E] F    H
    ///   .. / \ ....
    ///    [I] J
    /// ```
    /// update(3, {new leaf}) would swap the leaf value at `[I]` and cause a recomputation of `[A]`, `[B]`, and `[E]`.
    pub fn update<L: ToBytes>(&mut self, index: usize, new_leaf: &L) -> Result<(), crate::Error> {
        assert!(index < self.leaf_nodes.len(), "index out of range");
        let (updated_leaf_hash, mut updated_path) = self.updated_path(index, new_leaf)?;
        self.leaf_nodes[index] = updated_leaf_hash;
        let mut curr_index = convert_index_to_last_level(index, self.height);
        for _ in 0..self.height - 1 {
            curr_index = parent(curr_index).unwrap();
            self.non_leaf_nodes[curr_index] = updated_path.pop().unwrap();
        }
        Ok(())
    }

    /// Update the leaf and check if the updated root is equal to `asserted_new_root`.
    ///
    /// Tree will not be modified if the check fails.
    pub fn check_update<L: ToBytes>(
        &mut self,
        index: usize,
        new_leaf: &L,
        asserted_new_root: &TwoToOneDigest<P>,
    ) -> Result<bool, crate::Error> {
        assert!(index < self.leaf_nodes.len(), "index out of range");
        let (updated_leaf_hash, mut updated_path) = self.updated_path(index, new_leaf)?;
        if &updated_path[0] != asserted_new_root {
            return Ok(false);
        }
        self.leaf_nodes[index] = updated_leaf_hash;
        let mut curr_index = convert_index_to_last_level(index, self.height);
        for _ in 0..self.height - 1 {
            curr_index = parent(curr_index).unwrap();
            self.non_leaf_nodes[curr_index] = updated_path.pop().unwrap();
        }
        Ok(true)
    }
}

/// Returns the height of the tree, given the number of leaves.
#[inline]
fn tree_height(num_leaves: usize) -> usize {
    if num_leaves == 1 {
        return 1;
    }

    (ark_std::log2(num_leaves) as usize) + 1
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

#[inline]
fn convert_index_to_last_level(index: usize, tree_height: usize) -> usize {
    index + (1 << (tree_height - 1)) - 1
}

#[cfg(test)]
mod tests {
    use crate::{
        crh::{pedersen, *},
        merkle_tree::*,
    };
    use ark_ed_on_bls12_381::EdwardsProjective as JubJub;
    use ark_ff::{BigInteger256, ToBytes};
    use ark_std::{test_rng, UniformRand};

    #[derive(Clone)]
    pub(super) struct Window4x256;
    impl pedersen::Window for Window4x256 {
        const WINDOW_SIZE: usize = 4;
        const NUM_WINDOWS: usize = 256;
    }

    type H = pedersen::CRH<JubJub, Window4x256>;

    struct JubJubMerkleTreeParams;

    impl Config for JubJubMerkleTreeParams {
        type LeafHash = H;
        type TwoToOneHash = H;
    }
    type JubJubMerkleTree = MerkleTree<JubJubMerkleTreeParams>;

    fn merkle_tree_test<L: ToBytes + Clone + Eq>(leaves: &[L], update_query: &[(usize, L)]) -> () {
        let mut rng = ark_std::test_rng();
        let mut leaves = leaves.to_vec();
        let leaf_crh_params = <H as CRH>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <H as TwoToOneCRH>::setup(&mut rng).unwrap();
        let mut tree = JubJubMerkleTree::new(
            &leaf_crh_params.clone(),
            &two_to_one_crh_params.clone(),
            &leaves,
        )
        .unwrap();
        let mut root = tree.root();
        // test merkle tree functionality without update
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof
                .verify(&leaf_crh_params, &two_to_one_crh_params, &root, &leaf)
                .unwrap());
        }

        // test merkle tree update functionality
        for (i, v) in update_query {
            tree.update(*i, v);
            leaves[*i] = v.clone();
        }
        // update the root
        root = tree.root();
        // verify again
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof
                .verify(&leaf_crh_params, &two_to_one_crh_params, &root, &leaf)
                .unwrap());
        }
    }

    #[test]
    fn good_root_test() {
        let mut rng = test_rng();

        let mut leaves = Vec::new();
        for _ in 0..2u8 {
            leaves.push(BigInteger256::rand(&mut rng));
        }
        merkle_tree_test(
            &leaves,
            &vec![
                (0, BigInteger256::rand(&mut rng)),
                (1, BigInteger256::rand(&mut rng)),
            ],
        );

        let mut leaves = Vec::new();
        for _ in 0..4u8 {
            leaves.push(BigInteger256::rand(&mut rng));
        }
        merkle_tree_test(&leaves, &vec![(3, BigInteger256::rand(&mut rng))]);

        let mut leaves = Vec::new();
        for _ in 0..128u8 {
            leaves.push(BigInteger256::rand(&mut rng));
        }
        merkle_tree_test(
            &leaves,
            &vec![
                (2, BigInteger256::rand(&mut rng)),
                (3, BigInteger256::rand(&mut rng)),
                (5, BigInteger256::rand(&mut rng)),
                (111, BigInteger256::rand(&mut rng)),
                (127, BigInteger256::rand(&mut rng)),
            ],
        );
    }
}
