use ark_crypto_primitives::crh::TwoToOneCRH;
use ark_crypto_primitives::merkle_tree::{Config, MerkleTree, Path};

pub mod common;
use common::*;

pub mod constraints;
pub mod non_membership_constraints;
// mod constraints_test;

#[derive(Clone)]
pub struct MerkleConfig;
impl Config for MerkleConfig {
    // Our Merkle tree relies on two hashes: one to hash leaves, and one to hash pairs
    // of internal nodes.
    type LeafHash = LeafHash;
    type TwoToOneHash = TwoToOneHash;
}

/// A Merkle tree containing account information.
pub type SimpleMerkleTree = MerkleTree<MerkleConfig>;
/// The root of the account Merkle tree.
pub type Root = <TwoToOneHash as TwoToOneCRH>::Output;
/// A membership proof for a given account.
pub type SimplePath = Path<MerkleConfig>;

// Run this test via `cargo test --release test_merkle_tree`.
#[test]
fn test_merkle_tree() {
    use ark_crypto_primitives::crh::CRH;
    // Let's set up an RNG for use within tests. Note that this is *not* safe
    // for any production use.
    let mut rng = ark_std::test_rng();

    // First, let's sample the public parameters for the hash functions:
    let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

    // Next, let's construct our tree.
    // This follows the API in https://github.com/arkworks-rs/crypto-primitives/blob/6be606259eab0aec010015e2cfd45e4f134cd9bf/src/merkle_tree/mod.rs#L156
    let tree = SimpleMerkleTree::new(
        &leaf_crh_params,
        &two_to_one_crh_params,
        &[1u8, 2u8, 3u8, 10u8, 9u8, 17u8, 70u8, 45u8], // the i-th entry is the i-th leaf.
    )
    .unwrap();

    // Now, let's try to generate a membership proof for the 5th item.
    let proof = tree.generate_proof(4).unwrap(); // we're 0-indexing!
                                                 // This should be a proof for the membership of a leaf with value 9. Let's check that!

    // First, let's get the root we want to verify against:
    let root = tree.root();
    // Next, let's verify the proof!
    let result = proof
        .verify(
            &leaf_crh_params,
            &two_to_one_crh_params,
            &root,
            &[9u8], // The claimed leaf
        )
        .unwrap();
    assert!(result);
}

#[cfg(test)]
mod set_diff_tests {
    use super::*;
    use crate::non_membership_constraints::NonMembershipSetDiff;
    use ark_crypto_primitives::crh::{CRH, TwoToOneCRH};
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};

    #[test]
    fn non_membership_set_diff_satisfied() {
        let mut rng = ark_std::test_rng();

        let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

        // Old tree: index 4 holds 9
        let old_leaves = [1u8,2u8,3u8,10u8,9u8,17u8,70u8,45u8];
        let old_tree = SimpleMerkleTree::new(&leaf_crh_params, &two_to_one_crh_params, &old_leaves).unwrap();

        // New tree: index 4 is changed to 11
        let mut new_leaves = old_leaves;
        new_leaves[4] = 11u8;
        let new_tree = SimpleMerkleTree::new(&leaf_crh_params, &two_to_one_crh_params, &new_leaves).unwrap();

        let idx = 4;
        let path_old = old_tree.generate_proof(idx).unwrap();
        let path_new = new_tree.generate_proof(idx).unwrap();

        let circuit = NonMembershipSetDiff {
            leaf_crh_params: leaf_crh_params.clone(),
            two_to_one_crh_params: two_to_one_crh_params.clone(),
            old_root: old_tree.root(),
            new_root: new_tree.root(),
            leaf_new: new_leaves[idx],
            leaf_old_at_index: old_leaves[idx],
            path_new: Some(path_new),
            path_old_same_index: Some(path_old),
        };

        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn non_membership_set_diff_fails_if_values_equal() {
        let mut rng = ark_std::test_rng();

        let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

        // Old tree
        let leaves = [1u8,2u8,3u8,10u8,9u8,17u8,70u8,45u8];
        let old_tree = SimpleMerkleTree::new(&leaf_crh_params, &two_to_one_crh_params, &leaves).unwrap();

        // New tree = old tree (no change)
        let new_tree = SimpleMerkleTree::new(&leaf_crh_params, &two_to_one_crh_params, &leaves).unwrap();

        let idx = 4; // same value in both: 9
        let path_old = old_tree.generate_proof(idx).unwrap();
        let path_new = new_tree.generate_proof(idx).unwrap();

        let circuit = NonMembershipSetDiff {
            leaf_crh_params: leaf_crh_params.clone(),
            two_to_one_crh_params: two_to_one_crh_params.clone(),
            old_root: old_tree.root(),
            new_root: new_tree.root(),
            leaf_new: leaves[idx],
            leaf_old_at_index: leaves[idx], // same -> should fail
            path_new: Some(path_new),
            path_old_same_index: Some(path_old),
        };

        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap()); // should fail because leaves are equal
    }
}
