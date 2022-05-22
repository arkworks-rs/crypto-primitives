use crate::crh::TwoToOneCRHScheme;
use crate::merkle_tree::{Config, DigestConverter, LeafParam, Path, TwoToOneParam};
use crate::CRHScheme;
use ark_std::borrow::Borrow;
use ark_std::vec::Vec;

/// Defines an incremental merkle tree data structure.
/// This merkle tree has runtime fixed height, and assumes number of leaves is 2^height.
///
#[derive(Derivative)]
#[derivative(Clone(bound = "P: Config"))]
pub struct IncrementalMerkleTree<P: Config> {
    /// Store the hash of leaf nodes from left to right
    leaf_nodes: Vec<P::LeafDigest>,
    /// Store the inner hash parameters
    two_to_one_hash_param: TwoToOneParam<P>,
    /// Store the leaf hash parameters
    leaf_hash_param: LeafParam<P>,
    /// Stores the height of the MerkleTree
    height: usize,
    /// Stores the path of the "current leaf"
    current_path: Path<P>,
    /// Stores the root of the IMT
    root: P::InnerDigest,
    /// Is the IMT empty
    empty: bool,
}

impl<P: Config> IncrementalMerkleTree<P> {
    /// Check if this IMT is empty
    pub fn is_empty(&self) -> bool {
        self.empty
    }

    /// The index of the current right most leaf
    pub fn current_index(&self) -> Option<usize> {
        if self.is_empty() {
            None
        } else {
            Some(self.current_path.leaf_index)
        }
    }

    /// The next available index of leaf node
    pub fn next_available(&self) -> Option<usize> {
        let current_index = self.current_path.leaf_index;
        if self.is_empty() {
            Some(0)
        } else if current_index < (1 << (self.height - 1)) - 1 {
            Some(current_index + 1)
        } else {
            None
        }
    }

    /// Create an empty merkle tree such that all leaves are zero-filled.
    pub fn blank(
        leaf_hash_param: &LeafParam<P>,
        two_to_one_hash_param: &TwoToOneParam<P>,
        height: usize,
    ) -> Result<Self, crate::Error> {
        assert!(
            height > 1,
            "the height of incremental merkle tree should be at least 2"
        );
        // use empty leaf digest
        let leaves_digest = vec![];
        Ok(IncrementalMerkleTree {
            /// blank tree doesn't have current_path
            current_path: Path {
                leaf_sibling_hash: P::LeafDigest::default(),
                auth_path: Vec::new(),
                leaf_index: 0,
            },
            leaf_nodes: leaves_digest,
            two_to_one_hash_param: two_to_one_hash_param.clone(),
            leaf_hash_param: leaf_hash_param.clone(),
            root: P::InnerDigest::default(),
            height,
            empty: true,
        })
    }

    /// Append leaf at `next_available`
    /// ```tree_diagram
    ///         [A]
    ///        /   \
    ///      [B]   ()
    ///     / \   /  \
    ///    D [E] ()  ()
    ///   .. / \ ....
    ///    [I]{new leaf}
    /// ```
    /// append({new leaf}) when the `next_availabe` is at 4, would cause a recompute [E], [B], [A]
    pub fn append<T: Borrow<P::Leaf>>(&mut self, new_leaf: T) -> Result<(), crate::Error> {
        assert!(self.next_available() != None, "index out of range");
        let leaf_digest = P::LeafHash::evaluate(&self.leaf_hash_param, new_leaf)?;
        let (path, root) = self.next_path(leaf_digest.clone())?;
        self.leaf_nodes.push(leaf_digest);
        self.current_path = path;
        self.root = root;
        self.empty = false;
        Ok(())
    }

    /// Generate updated path of `next_available` without changing the tree
    /// returns (new_path, new_root)
    pub fn next_path(
        &self,
        new_leaf_digest: P::LeafDigest,
    ) -> Result<(Path<P>, P::InnerDigest), crate::Error> {
        assert!(self.next_available() != None, "index out of range");

        // calculate tree_height and empty hash
        let tree_height = self.height;
        let hash_of_empty_node: P::InnerDigest = P::InnerDigest::default();
        let hash_of_empty_leaf: P::LeafDigest = P::LeafDigest::default();

        // auth path has the capacity of tree_hight - 2
        let mut new_auth_path = Vec::with_capacity(tree_height - 2);

        if self.is_empty() {
            // generate auth path and calculate the root
            let mut current_node = P::TwoToOneHash::evaluate(
                &self.two_to_one_hash_param,
                P::LeafInnerDigestConverter::convert(new_leaf_digest)?,
                P::LeafInnerDigestConverter::convert(P::LeafDigest::default())?,
            )?;
            // all the auth path node are empty nodes
            for _ in 0..tree_height - 2 {
                new_auth_path.push(hash_of_empty_node.clone());
                current_node = P::TwoToOneHash::compress(
                    &self.two_to_one_hash_param,
                    current_node,
                    hash_of_empty_node.clone(),
                )?;
            }

            let path = Path {
                leaf_index: 0,
                auth_path: new_auth_path,
                leaf_sibling_hash: hash_of_empty_leaf,
            };
            Ok((path, current_node))
        } else {
            // compute next path of a non-empty tree
            // Get the indices of the previous and propsed (new) leaf node
            let mut new_index = self.next_available().unwrap();
            let mut old_index = self.current_index().unwrap();
            let old_leaf = self.leaf_nodes[old_index].clone();

            // generate two mutable node: old_current_node, new_current_node to iterate on
            let (old_left_leaf, old_right_leaf) = if is_left_child(old_index) {
                (
                    self.leaf_nodes[old_index].clone(),
                    self.current_path.leaf_sibling_hash.clone(),
                )
            } else {
                (
                    self.current_path.leaf_sibling_hash.clone(),
                    self.leaf_nodes[old_index].clone(),
                )
            };

            let (new_left_leaf, new_right_leaf, leaf_sibling) = if is_left_child(new_index) {
                (
                    new_leaf_digest,
                    hash_of_empty_leaf.clone(),
                    hash_of_empty_leaf,
                )
            } else {
                (old_leaf.clone(), new_leaf_digest, old_leaf)
            };

            let mut old_current_node = P::TwoToOneHash::evaluate(
                &self.two_to_one_hash_param,
                P::LeafInnerDigestConverter::convert(old_left_leaf)?,
                P::LeafInnerDigestConverter::convert(old_right_leaf)?,
            )?;
            let mut new_current_node = P::TwoToOneHash::evaluate(
                &self.two_to_one_hash_param,
                P::LeafInnerDigestConverter::convert(new_left_leaf)?,
                P::LeafInnerDigestConverter::convert(new_right_leaf)?,
            )?;

            // reverse the old_auth_path to make it bottom up
            let mut old_auth_path = self.current_path.auth_path.clone();
            old_auth_path.reverse();

            // build new_auth_path and root recursively
            for x in 0..tree_height - 2 {
                new_index = parent_index_on_level(new_index);
                old_index = parent_index_on_level(old_index);
                if new_index == old_index {
                    // this means the old path and new path are merged,
                    // as a result, no need to update the old_current_node any more

                    // add the auth path node
                    new_auth_path.push(old_auth_path[x].clone());

                    // update the new current node (this is needed to compute the root)
                    let (new_left, new_right) = if is_left_child(new_index) {
                        (new_current_node, hash_of_empty_node.clone())
                    } else {
                        (old_auth_path[x].clone(), new_current_node)
                    };
                    new_current_node = P::TwoToOneHash::compress(
                        &self.two_to_one_hash_param,
                        new_left,
                        new_right,
                    )?;
                } else {
                    // this means old path and new path haven't been merged,
                    // as a reulst, need to update both the new_current_node and new_current_node
                    let auth_node = if is_left_child(new_index) {
                        hash_of_empty_node.clone()
                    } else {
                        old_current_node.clone()
                    };
                    new_auth_path.push(auth_node);

                    // update both old_current_node and new_current_node
                    // update new_current_node
                    let (new_left, new_right) = if is_left_child(new_index) {
                        (new_current_node.clone(), hash_of_empty_node.clone())
                    } else {
                        (old_current_node.clone(), new_current_node)
                    };
                    new_current_node = P::TwoToOneHash::compress(
                        &self.two_to_one_hash_param,
                        new_left,
                        new_right,
                    )?;

                    // We only need to update the old_current_node bottom up when it is right child
                    if !is_left_child(old_index) {
                        old_current_node = P::TwoToOneHash::compress(
                            &self.two_to_one_hash_param,
                            old_auth_path[x].clone(),
                            old_current_node,
                        )?;
                    }
                }
            }

            // reverse new_auth_path to top down
            new_auth_path.reverse();
            let path = Path {
                leaf_index: self.next_available().unwrap(),
                auth_path: new_auth_path,
                leaf_sibling_hash: leaf_sibling,
            };
            Ok((path, new_current_node))
        }
    }

    /// the proof of the current item
    pub fn current_proof(&self) -> Path<P> {
        self.current_path.clone()
    }

    /// root of IMT
    pub fn root(&self) -> P::InnerDigest {
        self.root.clone()
    }
}

/// Return true iff the given index on its current level represents a left child
#[inline]
fn is_left_child(index_on_level: usize) -> bool {
    index_on_level % 2 == 0
}

#[inline]
fn parent_index_on_level(index_on_level: usize) -> usize {
    index_on_level >> 1
}
