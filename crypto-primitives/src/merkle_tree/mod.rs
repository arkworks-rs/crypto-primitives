#![allow(clippy::needless_range_loop)]

/// Defines a trait to chain two types of CRHs.
use crate::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    sponge::Absorb,
    Error,
};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize,
};
#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;
use ark_std::{
    borrow::Borrow,
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    hash::Hash,
};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[cfg(feature = "constraints")]
pub mod constraints;

#[cfg(test)]
mod tests;

/// Convert a hash digest from one layer to the next by transforming the previous layer's output
/// into `TargetType`, which borrows into the next layer's input.
pub trait DigestConverter<From, To: ?Sized> {
    type TargetType: Borrow<To>;
    fn convert(item: From) -> Result<Self::TargetType, Error>;
}

/// A trivial converter where the previous layer's digest is identical to the next layer's input.
pub struct IdentityDigestConverter<T> {
    _prev_layer_digest: T,
}

impl<T> DigestConverter<T, T> for IdentityDigestConverter<T> {
    type TargetType = T;
    fn convert(item: T) -> Result<T, Error> {
        Ok(item)
    }
}

/// Convert previous layer's digest to bytes and use bytes as input for next layer's digest.
/// TODO: `ToBytes` trait will be deprecated in future versions.
pub struct ByteDigestConverter<T: CanonicalSerialize> {
    _prev_layer_digest: T,
}

impl<T: CanonicalSerialize> DigestConverter<T, [u8]> for ByteDigestConverter<T> {
    type TargetType = Vec<u8>;

    fn convert(item: T) -> Result<Self::TargetType, Error> {
        // TODO: In some tests, `serialize` is not consistent with constraints. Try fix those.
        Ok(crate::to_uncompressed_bytes!(item)?)
    }
}

/// Merkle tree has two types of hashes.
/// * `LeafHash`: Convert leaf to leaf digest
/// * `TwoToOneHash`: Compress two inner digests to one inner digest
pub trait Config {
    type Leaf: ?Sized + Send; // merkle tree does not store the leaf
                              // leaf layer
    type LeafDigest: Clone
        + Eq
        + Debug
        + Hash
        + Default
        + CanonicalSerialize
        + CanonicalDeserialize
        + Send
        + Sync;

    // transition between leaf layer to inner layer
    type LeafInnerDigestConverter: DigestConverter<
        Self::LeafDigest,
        <Self::TwoToOneHash as TwoToOneCRHScheme>::Input,
    >;
    // inner layer
    type InnerDigest: Clone
        + Eq
        + Debug
        + Hash
        + Default
        + CanonicalSerialize
        + CanonicalDeserialize
        + Send
        + Sync
        + Absorb;

    // Tom's Note: in the future, if we want different hash function, we can simply add more
    // types of digest here and specify a digest converter. Same for constraints.

    /// leaf -> leaf digest
    /// If leaf hash digest and inner hash digest are different, we can create a new
    /// leaf hash which wraps the original leaf hash and convert its output to `Digest`.
    type LeafHash: CRHScheme<Input = Self::Leaf, Output = Self::LeafDigest>;
    /// 2 inner digest -> inner digest
    type TwoToOneHash: TwoToOneCRHScheme<Output = Self::InnerDigest>;
}

pub type TwoToOneParam<P> = <<P as Config>::TwoToOneHash as TwoToOneCRHScheme>::Parameters;
pub type LeafParam<P> = <<P as Config>::LeafHash as CRHScheme>::Parameters;

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
#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(
    PartialEq(bound = "P: Config"),
    Clone(bound = "P: Config"),
    Debug(bound = "P: Config"),
    Default(bound = "P: Config")
)]
pub struct Path<P: Config> {
    pub leaf_sibling_hash: P::LeafDigest,
    /// Sibling hashes from root to leaf layer (does not include the root).
    pub auth_path: Vec<P::InnerDigest>,
    /// stores the leaf index of the node
    pub leaf_index: usize,
}

impl<P: Config> Path<P> {
    /// The position of on_path node in `leaf_and_sibling_hash` and `non_leaf_and_sibling_hash_path`.
    /// `position[i]` is 0 (false) iff `i`th on-path node from top to bottom is on the left.
    ///
    /// Converts `self.leaf_index` to a boolean array in big-endian form.
    #[allow(unused)] // this function is actually used when r1cs feature is on
    fn position_list(&'_ self) -> impl '_ + Iterator<Item = bool> {
        (0..self.auth_path.len() + 1)
            .map(move |i| ((self.leaf_index >> i) & 1) != 0)
            .rev()
    }
}

impl<P: Config> Path<P> {
    /// Verify that a leaf is at `self.index` of the merkle tree.
    /// * `leaf_size`: leaf size in number of bytes
    ///
    /// `verify` infers the tree height by setting `tree_height = self.auth_path.len() + 2`
    pub fn verify<L: Borrow<P::Leaf>>(
        &self,
        leaf_hash_params: &LeafParam<P>,
        two_to_one_params: &TwoToOneParam<P>,
        root_hash: &P::InnerDigest,
        leaf: L,
    ) -> bool {
        // calculate leaf hash
        let claimed_leaf_hash = P::LeafHash::evaluate(&leaf_hash_params, leaf).unwrap();
        // check hash along the path from bottom to root
        let (left_child, right_child) =
            select_left_right_child(self.leaf_index, &claimed_leaf_hash, &self.leaf_sibling_hash);

        // leaf layer to inner layer conversion
        let left_child = P::LeafInnerDigestConverter::convert(left_child).unwrap();
        let right_child = P::LeafInnerDigestConverter::convert(right_child).unwrap();

        let mut curr_path_node =
            P::TwoToOneHash::evaluate(&two_to_one_params, left_child, right_child).unwrap();

        // we will use `index` variable to track the position of path
        let mut index = self.leaf_index;
        index >>= 1;

        // Check levels between leaf level and root
        for level in (0..self.auth_path.len()).rev() {
            // check if path node at this level is left or right
            let (left, right) =
                select_left_right_child(index, &curr_path_node, &self.auth_path[level]);
            // update curr_path_node
            curr_path_node = P::TwoToOneHash::compress(&two_to_one_params, &left, &right).unwrap();
            index >>= 1;
        }

        // check if final hash is root
        &curr_path_node == root_hash
    }
}

/// Batch Merkle membership proof.
///
/// For example:
/// ```tree_diagram
///         [A]             d = 0
///        /   \
///      [B]    C           d = 1
///     / \    /  \
///    D [E]  F    H        d = 2
///  ... / \ / \ ....
///    [I] J L  M           d = 3
/// ```
///  Suppose we want to prove I and J (leaf indexes 2 and 3), then:
///  - `tree_height`: `4`
///  - `leaf_copath`: `[]` (I and J are siblings, so no leaf copath is needed)
///  - `inner_copath`: `[D, C]`  (depths 1..3, ascending index within each depth)
///  - `leaf_indexes`: `[2, 3]`
///
///  Both prover and verifier independently derive the positions of all required copath nodes
///  from `leaf_indexes` and `tree_height` via [`compute_on_path`]. The proof transmits only
///  digests in canonical depth-then-index order.
///
///  At verification time:
///  1. Reconstruct the on-path sets A_j from `leaf_indexes` via [`compute_on_path`].
///  2. For each depth 1..leaf_depth (ascending index within each depth), consume one digest from
///     `inner_copath` for each on-path node whose sibling is NOT on-path.
///  3. Recompute all parent hashes bottom-up and compare the root against `root_hash`.
///
///  The proof contains only the siblings needed to reconstruct all parents on the union of paths.
#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(
    Clone(bound = "P: Config"),
    Debug(bound = "P: Config"),
    Default(bound = "P: Config")
)]
pub struct CoPath<P: Config> {
    /// Height of the tree this proof was generated from (>= 2).
    pub(crate) tree_height: usize,
    /// Leaf-layer copath digests (`B*_{d-1}`), ascending sibling index order.
    pub leaf_copath: Vec<P::LeafDigest>,
    /// Inner copath digests in canonical order: depth 1 ascending, depth 2 ascending, …
    /// The verifier derives positions from `leaf_indexes` and `tree_height`.
    pub inner_copath: Vec<P::InnerDigest>,
    /// Leaf indexes that were opened, in ascending order.
    pub leaf_indexes: Vec<usize>,
}


impl<P: Config> CoPath<P> {
    /// Hashes provided leaves (ordered by `leaf_indexes`) and returns a map from leaf index to digest.
    fn ingest_leaves<L, I>(
        leaf_indexes: &[usize],
        leaves: &mut I,
        leaf_hash_params: &LeafParam<P>,
    ) -> Option<BTreeMap<usize, P::LeafDigest>>
    where
        L: Borrow<P::Leaf>,
        I: Iterator<Item = L>,
    {
        let mut leaf_level: BTreeMap<usize, P::LeafDigest> = BTreeMap::new();
        for &idx in leaf_indexes {
            let leaf = leaves.next()?;
            let leaf_hash = P::LeafHash::evaluate(leaf_hash_params, leaf.borrow()).unwrap();
            leaf_level.insert(idx, leaf_hash);
        }
        if leaves.next().is_some() {
            return None;
        }
        Some(leaf_level)
    }

    /// Compute which leaf siblings are needed to verify the proof (those not already on-path).
    fn compute_needed_leaf_siblings(leaf_depth: usize, on_path: &[Vec<usize>]) -> Vec<usize> {
        let mut expected_leaf_coset: Vec<usize> = Vec::new();
        for &path_idx in on_path[leaf_depth].iter() {
            let sibling_idx = path_idx ^ 1;
            if on_path[leaf_depth].binary_search(&sibling_idx).is_err() {
                expected_leaf_coset.push(sibling_idx);
            }
        }
        expected_leaf_coset.sort_unstable();
        expected_leaf_coset
    }

    /// Absorb the leaf copath digests into `leaf_level`, verifying counts and detecting conflicts.
    fn absorb_leaf_copath(
        expected_leaf_coset: &[usize],
        provided_leaf_copath: &[P::LeafDigest],
        leaf_level: &mut BTreeMap<usize, P::LeafDigest>,
    ) -> bool {
        if expected_leaf_coset.len() != provided_leaf_copath.len() {
            return false;
        }

        for (sibling_idx, sibling_digest) in expected_leaf_coset.iter().zip(provided_leaf_copath) {
            match leaf_level.get(sibling_idx) {
                Some(existing) if existing != sibling_digest => return false,
                _ => {
                    leaf_level.insert(*sibling_idx, sibling_digest.clone());
                }
            }
        }
        true
    }

    /// Verify and hash the transition from leaf digests to the first inner layer.
    fn verify_and_hash_bottom_layer(
        leaf_depth: usize,
        on_path: &[Vec<usize>],
        leaf_level: &BTreeMap<usize, P::LeafDigest>,
        two_to_one_params: &TwoToOneParam<P>,
        inner_levels: &mut [BTreeMap<usize, P::InnerDigest>],
    ) -> bool {
        for &parent_index in on_path[leaf_depth - 1].iter() {
            let left = leaf_level.get(&(parent_index * 2)).cloned();
            let right = leaf_level.get(&(parent_index * 2 + 1)).cloned();
            let (left, right) = match (left, right) {
                (Some(left), Some(right)) => (left, right),
                _ => return false,
            };
            let parent = P::TwoToOneHash::evaluate(
                two_to_one_params,
                P::LeafInnerDigestConverter::convert(left).unwrap(),
                P::LeafInnerDigestConverter::convert(right).unwrap(),
            )
            .unwrap();
            inner_levels[leaf_depth - 1].insert(parent_index, parent);
        }
        true
    }

    /// Verify and hash the inner layers from leaf depth up to the root.
    fn verify_and_hash_inner_chain(
        leaf_depth: usize,
        on_path: &[Vec<usize>],
        two_to_one_params: &TwoToOneParam<P>,
        inner_levels: &mut [BTreeMap<usize, P::InnerDigest>],
    ) -> bool {
        for depth in (1..=leaf_depth - 1).rev() {
            let parent_depth = depth - 1;
            for &parent_index in on_path[parent_depth].iter() {
                let left = inner_levels[depth].get(&(parent_index * 2)).cloned();
                let right = inner_levels[depth].get(&(parent_index * 2 + 1)).cloned();
                let (left, right) = match (left, right) {
                    (Some(left), Some(right)) => (left, right),
                    _ => return false,
                };
                let parent =
                    P::TwoToOneHash::compress(two_to_one_params, &left, &right).unwrap();
                inner_levels[parent_depth].insert(parent_index, parent);
            }
        }
        true
    }

    /// Verify that leaves are at `self.leaf_indexes` of the merkle tree.
    ///
    /// The verifier reconstructs the canonical copath order from `leaf_indexes` and `tree_height`,
    /// then consumes digests from `inner_copath`. If the count doesn't match, verification fails.
    ///
    /// Leaves must be supplied in `leaf_indexes` order:
    /// ```text
    /// let ordered_leaves: Vec<_> = proof.leaf_indexes.iter().map(|&i| leaves[i].clone()).collect();
    /// ```
    ///
    /// `expected_tree_height` must equal the height of the tree the proof was generated from.
    /// The verifier supplies this value rather than taking it from the (prover-controlled) proof.
    pub fn verify<L: Borrow<P::Leaf> + Clone>(
        &self,
        leaf_hash_params: &LeafParam<P>,
        two_to_one_params: &TwoToOneParam<P>,
        root_hash: &P::InnerDigest,
        expected_tree_height: usize,
        leaves: impl IntoIterator<Item = L>,
    ) -> bool {
        assert!(
            !self.leaf_indexes.is_empty(),
            "batch proof must contain at least one leaf index"
        );
        assert!(self.tree_height >= 2, "tree_height must be >= 2");

        if self.tree_height != expected_tree_height {
            return false;
        }

        let d = self.tree_height;
        let leaf_depth = d - 1;

        // Hash opened leaves and build map containing all leaf digests needed at the bottom layer.
        let mut leaves_iter = leaves.into_iter();
        let mut leaf_level =
            match Self::ingest_leaves(&self.leaf_indexes, &mut leaves_iter, leaf_hash_params) {
                Some(m) => m,
                None => return false,
            };

        // Compute on-path sets A_j and the expected leaf coset B*_{d-1} = siblings(A_{d-1}) \ A_{d-1}.
        let index_set: BTreeSet<usize> = self.leaf_indexes.iter().copied().collect();
        let on_path = compute_on_path(leaf_depth, &index_set);

        let expected_leaf_coset = Self::compute_needed_leaf_siblings(leaf_depth, &on_path);
        if !Self::absorb_leaf_copath(&expected_leaf_coset, &self.leaf_copath, &mut leaf_level) {
            return false;
        }

        // Prepare inner-level maps for copath siblings and computed parents.
        let mut inner_levels: Vec<BTreeMap<usize, P::InnerDigest>> =
            (0..d).map(|_| BTreeMap::new()).collect();

        // Consume inner_copath in canonical order: depths 1..leaf_depth, ascending index.
        let mut copath_iter = self.inner_copath.iter();
        for depth in 1..leaf_depth {
            for &path_idx in on_path[depth].iter() {
                let sibling_idx = path_idx ^ 1;
                if on_path[depth].binary_search(&sibling_idx).is_err() {
                    let digest = match copath_iter.next() {
                        Some(d) => d,
                        None => return false, // prover sent fewer digests than expected
                    };
                    inner_levels[depth].insert(sibling_idx, digest.clone());
                }
            }
        }

        // Reject if prover sent more digests than expected.
        if copath_iter.next().is_some() {
            return false;
        }

        if !Self::verify_and_hash_bottom_layer(
            leaf_depth,
            &on_path,
            &leaf_level,
            two_to_one_params,
            &mut inner_levels,
        ) {
            return false;
        }

        if !Self::verify_and_hash_inner_chain(
            leaf_depth,
            &on_path,
            two_to_one_params,
            &mut inner_levels,
        ) {
            return false;
        }

        // Check root.
        match inner_levels[0].get(&0) {
            Some(h) => h == root_hash,
            None => false,
        }
    }

    // The position of on_path node in `leaf_and_sibling_hash` and `non_leaf_and_sibling_hash_path`.
    // `position[i]` is 0 (false) iff `i`th on-path node from top to bottom is on the left.
    //
    // Converts each index in `self.leaf_indexes` to a boolean array in big-endian form.
    #[allow(unused)] // this function is actually used when r1cs feature is on
    fn position_list(&'_ self) -> impl '_ + Iterator<Item = Vec<bool>> {
        let path_len = self.tree_height.saturating_sub(2);

        cfg_into_iter!(self.leaf_indexes.clone())
            .map(move |i| {
                (0..path_len + 1)
                    .map(move |j| ((i >> j) & 1) != 0)
                    .rev()
                    .collect()
            })
            .collect::<Vec<_>>()
            .into_iter()
    }
}

/// `index` is the first `path.len()` bits of
/// the position of tree.
///
/// If the least significant bit of `index` is 0, then `sibling` will be left and `computed` will be right.
/// Otherwise, `sibling` will be right and `computed` will be left.
///
/// Returns: (left, right)
fn select_left_right_child<L: Clone>(
    index: usize,
    computed_hash: &L,
    sibling_hash: &L,
) -> (L, L) {
    let is_left = index & 1 == 0;
    let mut left_child = computed_hash;
    let mut right_child = sibling_hash;
    if !is_left {
        core::mem::swap(&mut left_child, &mut right_child);
    }
    (left_child.clone(), right_child.clone())
}

/// A merkle tree with fixed height and a leaf count of 2^height.
///
/// TODO: add RFC-6962 compatible merkle tree in the future.
/// For this release, padding is not supported due to security: if leaf and inner hashes use
/// the same CRH, a malicious prover could prove a leaf that is actually an inner node. Future
/// versions can prefix hashes by layer to prevent this.
#[derive(Derivative)]
#[derivative(Clone(bound = "P: Config"))]
pub struct MerkleTree<P: Config> {
    /// Non-leaf nodes in level order, with the root at index 0. For node i, children are at `2*i + 1` and `2*i + 2`.
    non_leaf_nodes: Vec<P::InnerDigest>,
    /// store the hash of leaf nodes from left to right
    leaf_nodes: Vec<P::LeafDigest>,
    /// Store the inner hash parameters
    two_to_one_hash_param: TwoToOneParam<P>,
    /// Store the leaf hash parameters
    leaf_hash_param: LeafParam<P>,
    /// Stores the height of the MerkleTree
    height: usize,
}

impl<P: Config> MerkleTree<P> {
    /// Create a merkle tree with zero-filled leaves. Use a sparse tree for memory efficiency.
    pub fn blank(
        leaf_hash_param: &LeafParam<P>,
        two_to_one_hash_param: &TwoToOneParam<P>,
        height: usize,
    ) -> Result<Self, crate::Error> {
        // use empty leaf digest
        let leaf_digests = vec![P::LeafDigest::default(); 1 << (height - 1)];
        Self::new_with_leaf_digest(leaf_hash_param, two_to_one_hash_param, leaf_digests)
    }

    /// Create a merkle tree from leaves. The leaf count must be a power of two.
    pub fn new<L: AsRef<P::Leaf> + Send>(
        leaf_hash_param: &LeafParam<P>,
        two_to_one_hash_param: &TwoToOneParam<P>,
        #[cfg(not(feature = "parallel"))] leaves: impl IntoIterator<Item = L>,
        #[cfg(feature = "parallel")] leaves: impl IntoParallelIterator<Item = L>,
    ) -> Result<Self, crate::Error> {
        let leaf_digests: Vec<_> = cfg_into_iter!(leaves)
            .map(|input| P::LeafHash::evaluate(leaf_hash_param, input.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;

        Self::new_with_leaf_digest(leaf_hash_param, two_to_one_hash_param, leaf_digests)
    }

    pub fn new_with_leaf_digest(
        leaf_hash_param: &LeafParam<P>,
        two_to_one_hash_param: &TwoToOneParam<P>,
        leaf_digests: Vec<P::LeafDigest>,
    ) -> Result<Self, crate::Error> {
        let leaf_nodes_size = leaf_digests.len();
        assert!(
            leaf_nodes_size.is_power_of_two() && leaf_nodes_size > 1,
            "`leaves.len() should be power of two and greater than one"
        );
        let non_leaf_nodes_size = leaf_nodes_size - 1;

        let tree_height = tree_height(leaf_nodes_size);

        let hash_of_empty: P::InnerDigest = P::InnerDigest::default();

        // initialize the merkle tree as array of nodes in level order
        let mut non_leaf_nodes: Vec<P::InnerDigest> = cfg_into_iter!(0..non_leaf_nodes_size)
            .map(|_| hash_of_empty.clone())
            .collect();

        // Compute the starting indices for each non-leaf level of the tree
        let mut index = 0;
        let mut level_indices = Vec::with_capacity(tree_height - 1);
        for _ in 0..(tree_height - 1) {
            level_indices.push(index);
            index = left_child(index);
        }

        // compute the hash values for the non-leaf bottom layer
        {
            let start_index = level_indices.pop().unwrap();
            let upper_bound = left_child(start_index);

            cfg_iter_mut!(non_leaf_nodes[start_index..upper_bound])
                .enumerate()
                .try_for_each(|(i, n)| {
                    // `left_child(current_index)` and `right_child(current_index) returns the position of
                    // leaf in the whole tree (represented as a list in level order). We need to shift it
                    // by `-upper_bound` to get the index in `leaf_nodes` list.

                    // similarly, we need to rescale i by start_index
                    // to get the index outside the slice and in the level-ordered list of nodes

                    let current_index = i + start_index;
                    let left_leaf_index = left_child(current_index) - upper_bound;
                    let right_leaf_index = right_child(current_index) - upper_bound;

                    *n = P::TwoToOneHash::evaluate(
                        two_to_one_hash_param,
                        P::LeafInnerDigestConverter::convert(
                            leaf_digests[left_leaf_index].clone(),
                        )?,
                        P::LeafInnerDigestConverter::convert(
                            leaf_digests[right_leaf_index].clone(),
                        )?,
                    )?;
                    Ok::<(), crate::Error>(())
                })?;
        }

        // compute the hash values for nodes in every other layer in the tree
        level_indices.reverse();
        for &start_index in &level_indices {
            // The layer beginning `start_index` ends at `upper_bound` (exclusive).
            let upper_bound = left_child(start_index);

            let (nodes_at_level, nodes_at_prev_level) =
                non_leaf_nodes[..].split_at_mut(upper_bound);
            // Iterate over the nodes at the current level, and compute the hash of each node
            cfg_iter_mut!(nodes_at_level[start_index..])
                .enumerate()
                .try_for_each(|(i, n)| {
                    // `left_child(current_index)` and `right_child(current_index) returns the position of
                    // leaf in the whole tree (represented as a list in level order). We need to shift it
                    // by `-upper_bound` to get the index in `leaf_nodes` list.

                    // similarly, we need to rescale i by start_index
                    // to get the index outside the slice and in the level-ordered list of nodes
                    let current_index = i + start_index;
                    let left_leaf_index = left_child(current_index) - upper_bound;
                    let right_leaf_index = right_child(current_index) - upper_bound;

                    // need for unwrap as Box<Error> does not implement trait Send
                    *n = P::TwoToOneHash::compress(
                        two_to_one_hash_param,
                        nodes_at_prev_level[left_leaf_index].clone(),
                        nodes_at_prev_level[right_leaf_index].clone(),
                    )?;
                    Ok::<_, crate::Error>(())
                })?;
        }
        Ok(MerkleTree {
            leaf_nodes: leaf_digests,
            non_leaf_nodes,
            height: tree_height,
            leaf_hash_param: leaf_hash_param.clone(),
            two_to_one_hash_param: two_to_one_hash_param.clone(),
        })
    }

    /// Returns the root of the Merkle tree.
    pub fn root(&self) -> P::InnerDigest {
        self.non_leaf_nodes[0].clone()
    }

    /// Returns the height of the Merkle tree.
    pub fn height(&self) -> usize {
        self.height
    }

    /// Given the `index` of a leaf, returns the digest of its leaf sibling
    pub fn get_leaf_sibling_hash(&self, index: usize) -> P::LeafDigest {
        if index & 1 == 0 {
            // leaf is left child
            self.leaf_nodes[index + 1].clone()
        } else {
            // leaf is right child
            self.leaf_nodes[index - 1].clone()
        }
    }

    /// Returns the authentication path from leaf at `index` to root, as a Vec of digests
    fn compute_auth_path(&self, index: usize) -> Vec<P::InnerDigest> {
        // gather basic tree information
        let tree_height = tree_height(self.leaf_nodes.len());

        // Get Leaf hash, and leaf sibling hash,
        let leaf_index_in_tree = convert_index_to_last_level(index, tree_height);

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
        path
    }

    /// Returns the authentication path from leaf at `index` to root.
    pub fn generate_proof(&self, index: usize) -> Result<Path<P>, crate::Error> {
        let path = self.compute_auth_path(index);
        Ok(Path {
            leaf_index: index,
            auth_path: path,
            leaf_sibling_hash: self.get_leaf_sibling_hash(index),
        })
    }

    /// Returns a [`CoPath`] (batch membership proof) for the given leaf indexes,
    /// sufficient to verify each leaf up to the root.
    /// Indexes are internally deduplicated and sorted; the proof emits digests in that order.
    ///
    /// With the CoSet encoding we do not store full per-leaf authentication paths.
    /// Instead, for each tree level, only the siblings of on-path nodes that are not themselves
    /// on-path are transmitted in canonical depth-then-index order.  The verifier reconstructs
    /// the ordering independently from `leaf_indexes` and `tree_height`, so no coordinate
    /// metadata is included.
    ///
    /// When verifying the proof, leaves must be supplied in `leaf_indexes` order:
    /// ```text
    /// let ordered_leaves: Vec<_> = proof.leaf_indexes.iter().map(|&i| leaves[i].clone()).collect();
    /// ```
    ///
    /// An empty query produces a structurally valid empty proof; calling `verify` on it is a
    /// caller error (`leaf_indexes.is_empty()` → panic) per the security invariant.
    pub fn generate_multi_proof(
        &self,
        indexes: impl IntoIterator<Item = usize>,
    ) -> Result<CoPath<P>, crate::Error> {
        // Deduplicate and sort for canonical ordering.
        let indexes: BTreeSet<usize> = indexes.into_iter().collect();
        let d = self.height();

        if indexes.is_empty() {
            return Ok(CoPath {
                tree_height: d,
                leaf_copath: Vec::new(),
                inner_copath: Vec::new(),
                leaf_indexes: Vec::new(),
            });
        }

        let leaf_depth = d - 1;
        // Compute on-path sets A_j and then minimal co-path B*_j = siblings(A_j) \ A_j.
        let on_path = compute_on_path(leaf_depth, &indexes);

        // Leaf layer (depth = d-1): collect sibling indices not already on-path.
        let mut leaf_coset_ids: Vec<usize> = Vec::new();
        for &path_idx in on_path[leaf_depth].iter() {
            let sibling_idx = path_idx ^ 1;
            if on_path[leaf_depth].binary_search(&sibling_idx).is_err() {
                leaf_coset_ids.push(sibling_idx);
            }
        }
        leaf_coset_ids.sort_unstable();

        let mut leaf_copath = Vec::with_capacity(leaf_coset_ids.len());
        for sibling_idx in leaf_coset_ids.iter().copied() {
            let sibling_digest = self
                .leaf_nodes
                .get(sibling_idx)
                .ok_or_else(|| crate::Error::IncorrectInputLength(self.leaf_nodes.len()))?;
            leaf_copath.push(sibling_digest.clone());
        }

        // Inner layers: canonical order = depths 1..leaf_depth, ascending index within each depth.
        let mut inner_copath: Vec<P::InnerDigest> = Vec::new();
        for depth in 1..leaf_depth {
            for &path_idx in on_path[depth].iter() {
                let sibling_idx = path_idx ^ 1;
                if on_path[depth].binary_search(&sibling_idx).is_err() {
                    let heap_idx = level_index(depth, sibling_idx);
                    let digest = self.non_leaf_nodes.get(heap_idx).ok_or_else(|| {
                        crate::Error::IncorrectInputLength(self.non_leaf_nodes.len())
                    })?;
                    inner_copath.push(digest.clone());
                }
            }
        }

        Ok(CoPath {
            tree_height: d,
            leaf_copath,
            inner_copath,
            leaf_indexes: Vec::from_iter(indexes),
        })
    }

    /// Compute the hash of a new leaf and the updated path from root to leaf, without modifying the tree.
    fn updated_path<T: Borrow<P::Leaf>>(
        &self,
        index: usize,
        new_leaf: T,
    ) -> Result<(P::LeafDigest, Vec<P::InnerDigest>), crate::Error> {
        // calculate the hash of leaf
        let new_leaf_hash: P::LeafDigest = P::LeafHash::evaluate(&self.leaf_hash_param, new_leaf)?;

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
                P::LeafInnerDigestConverter::convert(leaf_left.clone())?,
                P::LeafInnerDigestConverter::convert(leaf_right.clone())?,
            )?);
        }

        // then calculate the updated hash from bottom to root
        let leaf_index_in_tree = convert_index_to_last_level(index, self.height);
        let mut prev_index = parent(leaf_index_in_tree).unwrap();
        while !is_root(prev_index) {
            let (left_child, right_child) = if is_left_child(prev_index) {
                (
                    path_bottom_to_top.last().unwrap(),
                    &self.non_leaf_nodes[sibling(prev_index).unwrap()],
                )
            } else {
                (
                    &self.non_leaf_nodes[sibling(prev_index).unwrap()],
                    path_bottom_to_top.last().unwrap(),
                )
            };
            let evaluated =
                P::TwoToOneHash::compress(&self.two_to_one_hash_param, left_child, right_child)?;
            path_bottom_to_top.push(evaluated);
            prev_index = parent(prev_index).unwrap();
        }

        debug_assert_eq!(path_bottom_to_top.len(), self.height - 1);
        let path_top_to_bottom: Vec<_> = path_bottom_to_top.into_iter().rev().collect();
        Ok((new_leaf_hash, path_top_to_bottom))
    }

    /// Update the leaf at `index`.
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
    pub fn update(&mut self, index: usize, new_leaf: &P::Leaf) -> Result<(), crate::Error> {
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

    /// Update the leaf and verify the root matches `asserted_new_root`. Does not modify the tree if verification fails.
    pub fn check_update<T: Borrow<P::Leaf>>(
        &mut self,
        index: usize,
        new_leaf: &P::Leaf,
        asserted_new_root: &P::InnerDigest,
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

/// Convert depth and position to a heap index. Node at depth d and position p maps to index (1<<d) - 1 + p.
#[inline]
pub(super) fn level_index(depth: usize, pos: usize) -> usize {
    ((1usize << depth) - 1) + pos
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

/// Compute the on-path sets A_j for a batch of leaf indexes.
/// A_j contains all indices at depth j that lie on at least one path from the leaves to the root.
///
/// Implementation detail:
/// * Uses sorted `Vec<usize>` per level to keep the hot loops linear and cache-friendly.
/// * Each leaf contributes one index per depth. As we walk up, we divide by 2 then sort and dedup.
pub(super) fn compute_on_path(
    depth_leaves: usize,
    indexes: &ark_std::collections::BTreeSet<usize>,
) -> Vec<Vec<usize>> {
    // collect raw indices per depth
    let mut path_sets: Vec<Vec<usize>> = vec![Vec::new(); depth_leaves + 1];
    for &leaf_index in indexes {
        let mut idx = leaf_index;
        let mut depth = depth_leaves;
        loop {
            path_sets[depth].push(idx);
            if depth == 0 {
                break;
            }
            idx >>= 1;
            depth -= 1;
        }
    }

    // sort + dedup each level to get canonical, unique, ascending order
    for level in 0..=depth_leaves {
        let level_vec = &mut path_sets[level];
        level_vec.sort_unstable();
        level_vec.dedup();
    }
    path_sets
}
