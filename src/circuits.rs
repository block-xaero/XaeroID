use ark_bn254::{Bn254, Fr};
use ark_groth16::Proof;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use bytemuck::Zeroable;

use crate::zk_proofs::ProofBytes;

#[derive(Clone)]
pub struct RoleCircuit {
    /// Private: the user's actual role level
    pub my_role: Option<u8>,
    /// Public: minimum required role level
    pub min_role: Option<u8>,
}

// For creating new workspaces/groups
struct GroupCreationCircuit {
    creator_role: Option<u8>,      // Private: your role level
    min_creation_role: Option<u8>, // Public: required role to create groups
    group_seed: Option<Fr>,        // Private: randomness for new group
    new_group_root: Option<Fr>,    // Public: merkle root of new group
}
// Proves: "I have authority to create groups and this is a valid new group"

// Problem: How do you join your FIRST group without existing membership?
struct InvitationCircuit {
    invitation_code: Option<Fr>,       // Private: secret invite code
    invitation_hash: Option<Fr>,       // Public: hash of valid invite
    inviter_pubkey: Option<Fr>,        // Public: who can invite
    new_member_commitment: Option<Fr>, // Public: your identity commitment
}
// Proves: "I have a valid invitation to join this group"

// For granting roles without revealing the delegator's identity
struct DelegationCircuit {
    delegator_role: Option<u8>,      // Private: your role
    target_role: Option<u8>,         // Private: role you're granting
    min_delegation_role: Option<u8>, // Public: minimum role needed to delegate
    delegation_proof: Option<Fr>,    // Public: commitment to delegation
}
// Proves: "Someone with sufficient authority granted this role"
