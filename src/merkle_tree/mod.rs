#![allow(unused)] // temporary

use crate::crh::TwoToOneCRH;
use crate::CRH;
use ark_ff::ToBytes;
use ark_std::vec::Vec;
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

/// Stores the hashes of a particular path (in order) from root to leaf.
/// For example:
/// ```tree_diagram
///          A
///        /  \
///       B   C
///     / \  / \
///    D  E F  H
///   .. / \ ....
///     I  J
/// ```
///  Suppose we want to prove I, then `leaf_and_sibling_hash` is (I, J), `non_leaf_and_sibling_hash` is
///  [(B,C),(D,E)]
pub struct Path<P: Config> {
    pub(crate) leaf_and_sibling_hash: (LeafDigest<P>, LeafDigest<P>),
    /// The hash path from higher layer to lower layer.
    pub(crate) non_leaf_and_sibling_hash_path: Vec<(TwoToOneDigest<P>, TwoToOneDigest<P>)>,
    /// stores the leaf index of the node
    pub(crate) leaf_index: usize,
}

impl<P: Config> Path<P> {
    /// The position of on_path node in `leaf_and_sibling_hash` and `non_leaf_and_sibling_hash_path`.
    /// `position[i]` is 0 (false) iff `i`th on-path node from top to bottom is on the left.
    ///
    /// This function simply converts `self.leaf_index` to boolean array in big endian form.
    fn position_list(&self) -> Vec<bool> {
        let position: Vec<_> = (0..self.non_leaf_and_sibling_hash_path.len() + 1)
            .map(|i| ((self.leaf_index >> i) & 1) != 0)
            .rev()
            .collect();
        position
    }
}

impl<P: Config> Path<P> {
    /// Verify that a leaf is at `self.index` of the merkle tree.
    /// * `leaf_size`: leaf size in number of bytes
    pub fn verify<L: ToBytes>(
        &self,
        leaf_hash_parameters: &LeafParam<P>,
        two_to_one_hash_parameters: &TwoToOneParam<P>,
        root_hash: &TwoToOneDigest<P>,
        tree_height: usize,
        leaf: &L,
        leaf_size: usize,
    ) -> Result<bool, crate::Error> {
        // verify path length
        if self.non_leaf_and_sibling_hash_path.len() != tree_height - 2 {
            return Ok(false); // invalid length path
        }

        // calculate leaf hash
        let mut buffer = vec![0u8; leaf_size];
        read_to_buffer(leaf, &mut buffer)?;
        let claimed_leaf_hash = P::LeafHash::evaluate(&leaf_hash_parameters, &buffer)?;

        // check if leaf corresponds to leaf hash `path`
        if self.leaf_index & 1 == 0 && claimed_leaf_hash != self.leaf_and_sibling_hash.0 {
            // left
            return Ok(false);
        } else if self.leaf_index & 1 == 1 && claimed_leaf_hash != self.leaf_and_sibling_hash.1 {
            // right
            return Ok(false);
        }

        // check hash along the path from bottom to root
        let mut left_buffer = vec![0u8; P::leaf_hash_output_size_upper_bound()];
        let mut right_buffer = vec![0u8; P::leaf_hash_output_size_upper_bound()];
        read_to_buffer(&self.leaf_and_sibling_hash.0, &mut left_buffer);
        read_to_buffer(&self.leaf_and_sibling_hash.1, &mut right_buffer);

        let mut curr_hash =
            P::TwoToOneHash::evaluate(&two_to_one_hash_parameters, &left_buffer, &right_buffer)?;

        // we will use `index` variable to track the position of path
        let mut index = self.leaf_index;
        index >>= 1;

        // Check levels between leaf level and root
        for level in (0..self.non_leaf_and_sibling_hash_path.len()).rev() {
            // check if path node at this level is left or right
            let path_node = if index & 1 == 0 {
                &self.non_leaf_and_sibling_hash_path[level].0
            } else {
                &self.non_leaf_and_sibling_hash_path[level].1
            };
            // if the hash calculated from last level is different from path_node, then reject
            if &curr_hash != path_node {
                return Ok(false);
            }
            // update `currHash`
            set_zero(&mut left_buffer);
            set_zero(&mut right_buffer);
            read_to_buffer(
                &self.non_leaf_and_sibling_hash_path[level].0,
                &mut left_buffer,
            );
            read_to_buffer(
                &self.non_leaf_and_sibling_hash_path[level].1,
                &mut right_buffer,
            );
            curr_hash = P::TwoToOneHash::evaluate(
                &two_to_one_hash_parameters,
                &left_buffer,
                &right_buffer,
            )?;
            index >>= 1;
        }

        // check if final hash is root
        if &curr_hash != root_hash {
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
        let mut buffer = vec![0u8; P::leaf_hash_output_size_upper_bound()]; // assume output length <= 128
        for leaf in leaves.iter() {
            set_zero(&mut buffer);
            read_to_buffer(leaf, &mut buffer);
            leaf_nodes.push(P::LeafHash::evaluate(leaf_hash_param, &buffer)?)
        }

        // compute the hash values for the non-leaf bottom layer
        {
            let mut buffer_left = vec![0u8; P::leaf_hash_output_size_upper_bound()];
            let mut buffer_right = vec![0u8; P::leaf_hash_output_size_upper_bound()];
            let start_index = level_indices.pop().unwrap();
            let upper_bound = left_child(start_index);
            for current_index in start_index..upper_bound {
                let left_leaf_index = left_child(current_index) - upper_bound;
                let right_leaf_index = right_child(current_index) - upper_bound;
                // compute hash
                set_zero(&mut buffer_left);
                set_zero(&mut buffer_right);
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
                set_zero(&mut buffer_left);
                set_zero(&mut buffer_right);
                read_to_buffer(&non_leaf_nodes[left_index], &mut buffer_left)?;
                read_to_buffer(&non_leaf_nodes[right_index], &mut buffer_right)?;
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

    /// returns height of the merkle tree
    pub fn height(&self) -> usize {
        self.height
    }

    /// Returns the authentication path from leaf at `index` to root
    pub fn generate_proof(&self, index: usize) -> Result<Path<P>, crate::Error> {
        // gather basic tree information
        let tree_height = tree_height(self.non_leaf_nodes.len() + self.leaf_nodes.len());

        // Get Leaf hash, and leaf sibling hash,
        let leaf_index_in_tree = convert_index_to_last_level(index, tree_height);
        let (leaf_left_hash, leaf_right_hash) = if index & 1 == 0 {
            // leaf is left child
            (
                self.leaf_nodes[index].clone(),
                self.leaf_nodes[index + 1].clone(),
            )
        } else {
            // leaf is right child
            (
                self.leaf_nodes[index - 1].clone(),
                self.leaf_nodes[index].clone(),
            )
        };

        let mut path = Vec::with_capacity(tree_height - 2); // tree height - one for leaf node - one for root
                                                            // Iterate from the bottom inner node to top, storing all intermediate hash values
        let mut current_node = parent(leaf_index_in_tree).unwrap();
        while !is_root(current_node) {
            let sibling_node = sibling(current_node).unwrap();
            let (curr_hash, sibling_hash) = (
                self.non_leaf_nodes[current_node].clone(),
                self.non_leaf_nodes[sibling_node].clone(),
            );
            if is_left_child(current_node) {
                path.push((curr_hash, sibling_hash));
            } else {
                path.push((sibling_hash, curr_hash));
            }
            current_node = parent(current_node).unwrap();
        }

        debug_assert_eq!(path.len(), tree_height - 2);

        // we want to make path from root to bottom
        path.reverse();

        Ok(Path {
            leaf_index: index,
            non_leaf_and_sibling_hash_path: path,
            leaf_and_sibling_hash: (leaf_left_hash, leaf_right_hash),
        })
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

// set a byte sequence to zero
fn set_zero(buf: &mut [u8]) {
    buf.iter_mut().for_each(|v| *v = 0)
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
    use ark_ff::{ToBytes, Zero};

    #[derive(Clone)]
    pub(super) struct Window4x256;
    impl pedersen::Window for Window4x256 {
        const WINDOW_SIZE: usize = 4;
        const NUM_WINDOWS: usize = 256;
    }

    type H = pedersen::PedersenCRH<JubJub, Window4x256>;

    struct JubJubMerkleTreeParams;

    impl Config for JubJubMerkleTreeParams {
        type LeafHash = H;
        type TwoToOneHash = H;

        fn leaf_hash_output_size_upper_bound() -> usize {
            32
        }

        fn two_to_one_hash_output_size_upper_bound() -> usize {
            32
        }
    }
    type JubJubMerkleTree = MerkleTree<JubJubMerkleTreeParams>;

    fn generate_merkle_tree_test<L: ToBytes + Clone + Eq>(leaves: &[L], leaf_size: usize) -> () {
        let mut rng = ark_std::test_rng();

        let leaf_crh_parameters = <H as CRH>::setup(&mut rng).unwrap();
        let two_to_one_crh_parameters = <H as TwoToOneCRH>::setup(&mut rng).unwrap();
        let tree = JubJubMerkleTree::new(
            &leaf_crh_parameters.clone(),
            &two_to_one_crh_parameters.clone(),
            &leaves,
        )
        .unwrap();
        let root = tree.root();
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof
                .verify(
                    &leaf_crh_parameters,
                    &two_to_one_crh_parameters,
                    &root,
                    tree.height,
                    &leaf,
                    leaf_size
                )
                .unwrap());
        }
    }

    #[test]
    fn good_root_test() {
        // let mut leaves = Vec::new();
        // for i in 0..4u8 {
        //     leaves.push([i, i, i, i, i, i, i, i]);
        // }
        // generate_merkle_tree_test(&leaves, 8);
        let mut leaves = Vec::new();
        for i in 0..128u8 {
            leaves.push([i, i, i, i, i, i, i, i]);
        }
        generate_merkle_tree_test(&leaves, 8);
    }
}
