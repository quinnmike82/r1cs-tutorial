use crate::{Root, SimplePath};
use crate::common::*; // ConstraintF, LeafHashGadget, TwoToOneHashGadget, param vars, etc.
use ark_crypto_primitives::crh::{CRH, TwoToOneCRH};
use ark_crypto_primitives::crh::constraints::TwoToOneCRHGadget;
use ark_crypto_primitives::merkle_tree::constraints::PathVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_relations::ns;

// R1CS equivalents
pub type RootVar =
    <TwoToOneHashGadget as TwoToOneCRHGadget<TwoToOneHash, ConstraintF>>::OutputVar;
pub type SimplePathVar =
    PathVar<crate::MerkleConfig, LeafHashGadget, TwoToOneHashGadget, ConstraintF>;

/// Prove non-membership of `leaf_new` in the old root by showing
/// that at the same index the old tree held a *different* value,
/// while the new root holds `leaf_new`.
pub struct NonMembershipSetDiff {
    // constants embedded in-circuit
    pub leaf_crh_params: <LeafHash as CRH>::Parameters,
    pub two_to_one_crh_params: <TwoToOneHash as TwoToOneCRH>::Parameters,

    // public inputs
    pub old_root: Root,
    pub new_root: Root,
    pub leaf_new: u8,

    // witnesses
    pub path_new: Option<SimplePath>,            // path in new_root for index i
    pub leaf_old_at_index: u8,                   // value at same index in old_root
    pub path_old_same_index: Option<SimplePath>, // path in old_root for index i
}

impl ConstraintSynthesizer<ConstraintF> for NonMembershipSetDiff {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        // Public roots
        let old_root = RootVar::new_input(ns!(cs, "old_root"), || Ok(&self.old_root))?;
        let new_root = RootVar::new_input(ns!(cs, "new_root"), || Ok(&self.new_root))?;

        // Public/new value; old-at-index is witness
        let l_new = UInt8::new_input(ns!(cs, "leaf_new"), || Ok(&self.leaf_new))?;
        let l_old =
            UInt8::new_witness(ns!(cs, "leaf_old_at_index"), || Ok(&self.leaf_old_at_index))?;

        // Hash parameters as constants
        let leaf_params =
            LeafHashParamsVar::new_constant(cs.clone(), &self.leaf_crh_params)?;
        let node_params =
            TwoToOneHashParamsVar::new_constant(cs.clone(), &self.two_to_one_crh_params)?;

        // Paths as witnesses
        let path_new = SimplePathVar::new_witness(ns!(cs, "path_new"), || {
            self.path_new
                .as_ref()
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let path_old = SimplePathVar::new_witness(ns!(cs, "path_old_same_index"), || {
            self.path_old_same_index
                .as_ref()
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Prepare byte vectors (clone so we can also use l_new/l_old later)
        let leaf_new_bytes = vec![l_new.clone()];
        let leaf_old_bytes = vec![l_old.clone()];

        // Membership in new_root at index i with value leaf_new
        let ok_new = path_new.verify_membership(
            &leaf_params,
            &node_params,
            &new_root,
            &leaf_new_bytes.as_slice(), // NOTE: reference *to* the slice reference
        )?;
        ok_new.enforce_equal(&Boolean::TRUE)?;

        // Membership in old_root at index i with (different) value leaf_old_at_index
        let ok_old = path_old.verify_membership(
            &leaf_params,
            &node_params,
            &old_root,
            &leaf_old_bytes.as_slice(), // same here
        )?;
        ok_old.enforce_equal(&Boolean::TRUE)?;

        // Enforce leaf_new != leaf_old_at_index
        let same = l_new.is_eq(&l_old)?;
        same.enforce_equal(&Boolean::FALSE)?;

        Ok(())
    }
}
