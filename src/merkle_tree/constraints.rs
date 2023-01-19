use crate::crh::TwoToOneCRHSchemeGadget;
use crate::merkle_tree::{Config, IdentityDigestConverter};
use crate::{crh::CRHSchemeGadget, merkle_tree::Path};
use ark_ff::Field;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
#[allow(unused)]
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::ToBytesGadget;
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::borrow::Borrow;
use ark_std::fmt::Debug;
use ark_std::vec::Vec;

pub trait DigestVarConverter<From, To: ?Sized> {
    type TargetType: Borrow<To>;
    fn convert(from: From) -> Result<Self::TargetType, SynthesisError>;
}

impl<T> DigestVarConverter<T, T> for IdentityDigestConverter<T> {
    type TargetType = T;

    fn convert(from: T) -> Result<T, SynthesisError> {
        Ok(from)
    }
}

pub struct BytesVarDigestConverter<T: ToBytesGadget<ConstraintF>, ConstraintF: Field> {
    _prev_layer_digest: T,
    _constraint_field: ConstraintF,
}

impl<T: ToBytesGadget<ConstraintF>, ConstraintF: Field> DigestVarConverter<T, [UInt8<ConstraintF>]>
    for BytesVarDigestConverter<T, ConstraintF>
{
    type TargetType = Vec<UInt8<ConstraintF>>;

    fn convert(from: T) -> Result<Self::TargetType, SynthesisError> {
        from.to_non_unique_bytes()
    }
}

pub trait ConfigGadget<P: Config, ConstraintF: Field> {
    type Leaf: Debug + ?Sized;
    type LeafDigest: AllocVar<P::LeafDigest, ConstraintF>
        + EqGadget<ConstraintF>
        + ToBytesGadget<ConstraintF>
        + CondSelectGadget<ConstraintF>
        + R1CSVar<ConstraintF>
        + Debug
        + Clone
        + Sized;
    type LeafInnerConverter: DigestVarConverter<
        Self::LeafDigest,
        <Self::TwoToOneHash as TwoToOneCRHSchemeGadget<P::TwoToOneHash, ConstraintF>>::InputVar,
    >;
    type InnerDigest: AllocVar<P::InnerDigest, ConstraintF>
        + EqGadget<ConstraintF>
        + ToBytesGadget<ConstraintF>
        + CondSelectGadget<ConstraintF>
        + R1CSVar<ConstraintF>
        + Debug
        + Clone
        + Sized;

    type LeafHash: CRHSchemeGadget<
        P::LeafHash,
        ConstraintF,
        InputVar = Self::Leaf,
        OutputVar = Self::LeafDigest,
    >;
    type TwoToOneHash: TwoToOneCRHSchemeGadget<
        P::TwoToOneHash,
        ConstraintF,
        OutputVar = Self::InnerDigest,
    >;
}

type LeafParam<PG, P, ConstraintF> =
    <<PG as ConfigGadget<P, ConstraintF>>::LeafHash as CRHSchemeGadget<
        <P as Config>::LeafHash,
        ConstraintF,
    >>::ParametersVar;
type TwoToOneParam<PG, P, ConstraintF> =
    <<PG as ConfigGadget<P, ConstraintF>>::TwoToOneHash as TwoToOneCRHSchemeGadget<
        <P as Config>::TwoToOneHash,
        ConstraintF,
    >>::ParametersVar;

/// Represents a merkle tree path gadget.
#[derive(Debug, Derivative)]
#[derivative(Clone(bound = "P: Config, ConstraintF: Field, PG: ConfigGadget<P, ConstraintF>"))]
pub struct PathVar<P: Config, ConstraintF: Field, PG: ConfigGadget<P, ConstraintF>> {
    /// `path[i]` is 0 (false) iff ith non-leaf node from top to bottom is left.
    path: Vec<Boolean<ConstraintF>>,
    /// `auth_path[i]` is the entry of sibling of ith non-leaf node from top to bottom.
    auth_path: Vec<PG::InnerDigest>,
    /// The sibling of leaf.
    leaf_sibling: PG::LeafDigest,
    /// Is this leaf the right child?
    leaf_is_right_child: Boolean<ConstraintF>,
}

impl<P: Config, ConstraintF: Field, PG: ConfigGadget<P, ConstraintF>> AllocVar<Path<P>, ConstraintF>
    for PathVar<P, ConstraintF, PG>
where
    P: Config,
    ConstraintF: Field,
{
    #[tracing::instrument(target = "r1cs", skip(cs, f))]
    fn new_variable<T: Borrow<Path<P>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        f().and_then(|val| {
            let leaf_sibling = PG::LeafDigest::new_variable(
                ark_relations::ns!(cs, "leaf_sibling"),
                || Ok(val.borrow().leaf_sibling_hash.clone()),
                mode,
            )?;
            let leaf_position_bit = Boolean::new_variable(
                ark_relations::ns!(cs, "leaf_position_bit"),
                || Ok(val.borrow().leaf_index & 1 == 1),
                mode,
            )?;
            let pos_list: Vec<_> = val.borrow().position_list().collect();
            let path = Vec::new_variable(
                ark_relations::ns!(cs, "path_bits"),
                || Ok(&pos_list[..(pos_list.len() - 1)]),
                mode,
            )?;

            let auth_path = Vec::new_variable(
                ark_relations::ns!(cs, "auth_path_nodes"),
                || Ok(&val.borrow().auth_path[..]),
                mode,
            )?;
            Ok(PathVar {
                path,
                auth_path,
                leaf_sibling,
                leaf_is_right_child: leaf_position_bit,
            })
        })
    }
}

impl<P: Config, ConstraintF: Field, PG: ConfigGadget<P, ConstraintF>> PathVar<P, ConstraintF, PG> {
    /// Set the leaf index of the path to a given value. Verifier can use function before calling `verify`
    /// to check the correctness leaf position.
    /// * `leaf_index`: leaf index encoded in little-endian format
    #[tracing::instrument(target = "r1cs", skip(self))]
    pub fn set_leaf_position(&mut self, leaf_index: Vec<Boolean<ConstraintF>>) {
        // The path to a leaf is described by the branching
        // decisions taken at each node. This corresponds to the position
        // of the leaf.
        let mut path = leaf_index;

        // If leaves are numbered left-to-right starting from zero,
        // then all left children have odd positions (least significant bit is one), while all
        // right children have even positions (least significant bit is zero).
        let leaf_is_right_child = path.remove(0);

        // pad with zero if the length of `path` is too short
        if path.len() < self.auth_path.len() {
            path.extend((0..self.auth_path.len() - path.len()).map(|_| Boolean::constant(false)))
        }

        // truncate if the length of `path` is too long
        path.truncate(self.auth_path.len());

        // branching decision starts from root, so we need to reverse it.
        path.reverse();

        self.path = path;
        self.leaf_is_right_child = leaf_is_right_child;
    }

    /// Return the leaf position index in little-endian form.
    pub fn get_leaf_position(&self) -> Vec<Boolean<ConstraintF>> {
        ark_std::iter::once(self.leaf_is_right_child.clone())
            .chain(self.path.clone().into_iter().rev())
            .collect()
    }

    /// Calculate the root of the Merkle tree assuming that `leaf` is the leaf on the path defined by `self`.
    #[tracing::instrument(target = "r1cs", skip(self, leaf_params, two_to_one_params))]
    pub fn calculate_root(
        &self,
        leaf_params: &LeafParam<PG, P, ConstraintF>,
        two_to_one_params: &TwoToOneParam<PG, P, ConstraintF>,
        leaf: &PG::Leaf,
    ) -> Result<PG::InnerDigest, SynthesisError> {
        let claimed_leaf_hash = PG::LeafHash::evaluate(leaf_params, leaf)?;
        let leaf_sibling_hash = &self.leaf_sibling;

        // calculate hash for the bottom non_leaf_layer

        // We assume that when a bit is 0, it indicates that the currently hashed value H is the left child,
        // and when bit is 1, it indicates our H is the right child.
        // Thus `left_hash` is sibling if the bit `leaf_is_right_child` is 1, and is leaf otherwise.

        let left_hash = self
            .leaf_is_right_child
            .select(leaf_sibling_hash, &claimed_leaf_hash)?;
        let right_hash = self
            .leaf_is_right_child
            .select(&claimed_leaf_hash, leaf_sibling_hash)?;

        // convert leaf digest to inner digest
        let left_hash = PG::LeafInnerConverter::convert(left_hash)?;
        let right_hash = PG::LeafInnerConverter::convert(right_hash)?;

        let mut curr_hash =
            PG::TwoToOneHash::evaluate(two_to_one_params, left_hash.borrow(), right_hash.borrow())?;
        // To traverse up a MT, we iterate over the path from bottom to top (i.e. in reverse)

        // At any given bit, the bit being 0 indicates our currently hashed value is the left,
        // and the bit being 1 indicates our currently hashed value is on the right.
        // Thus `left_hash` is the sibling if bit is 1, and it's the computed hash if bit is 0
        for (bit, sibling) in self.path.iter().rev().zip(self.auth_path.iter().rev()) {
            let left_hash = bit.select(sibling, &curr_hash)?;
            let right_hash = bit.select(&curr_hash, sibling)?;

            curr_hash = PG::TwoToOneHash::compress(two_to_one_params, &left_hash, &right_hash)?;
        }

        Ok(curr_hash)
    }

    /// Check that hashing a Merkle tree path according to `self`, and
    /// with `leaf` as the leaf, leads to a Merkle tree root equalling `root`.
    #[tracing::instrument(target = "r1cs", skip(self, leaf_params, two_to_one_params))]
    pub fn verify_membership(
        &self,
        leaf_params: &LeafParam<PG, P, ConstraintF>,
        two_to_one_params: &TwoToOneParam<PG, P, ConstraintF>,
        root: &PG::InnerDigest,
        leaf: &PG::Leaf,
    ) -> Result<Boolean<ConstraintF>, SynthesisError> {
        let expected_root = self.calculate_root(leaf_params, two_to_one_params, leaf)?;
        Ok(expected_root.is_eq(root)?)
    }

    /// Check that `old_leaf` is the leaf of the Merkle tree on the path defined by
    /// `self`, and then compute the new root when replacing `old_leaf` by `new_leaf`.
    #[tracing::instrument(target = "r1cs", skip(self, leaf_params, two_to_one_params))]
    pub fn update_leaf(
        &self,
        leaf_params: &LeafParam<PG, P, ConstraintF>,
        two_to_one_params: &TwoToOneParam<PG, P, ConstraintF>,
        old_root: &PG::InnerDigest,
        old_leaf: &PG::Leaf,
        new_leaf: &PG::Leaf,
    ) -> Result<PG::InnerDigest, SynthesisError> {
        self.verify_membership(leaf_params, two_to_one_params, old_root, old_leaf)?
            .enforce_equal(&Boolean::TRUE)?;
        Ok(self.calculate_root(leaf_params, two_to_one_params, new_leaf)?)
    }

    /// Check that `old_leaf` is the leaf of the Merkle tree on the path defined by
    /// `self`, and then compute the expected new root when replacing `old_leaf` by `new_leaf`.
    /// Return a boolean indicating whether expected new root equals `new_root`.
    #[tracing::instrument(target = "r1cs", skip(self, leaf_params, two_to_one_params))]
    pub fn update_and_check(
        &self,
        leaf_params: &LeafParam<PG, P, ConstraintF>,
        two_to_one_params: &TwoToOneParam<PG, P, ConstraintF>,
        old_root: &PG::InnerDigest,
        new_root: &PG::InnerDigest,
        old_leaf: &PG::Leaf,
        new_leaf: &PG::Leaf,
    ) -> Result<Boolean<ConstraintF>, SynthesisError> {
        let actual_new_root =
            self.update_leaf(leaf_params, two_to_one_params, old_root, old_leaf, new_leaf)?;
        Ok(actual_new_root.is_eq(&new_root)?)
    }
}
