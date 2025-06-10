use ark_bn254::{Bn254, Fr};
use ark_groth16::Proof;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use bytemuck::Zeroable;

use crate::zk_proofs::ProofBytes;

// Problem: How do you join your FIRST group without existing membership?
struct InvitationCircuit {
    invitation_code: Option<Fr>,       // Private: secret invite code
    invitation_hash: Option<Fr>,       // Public: hash of valid invite
    inviter_pubkey: Option<Fr>,        // Public: who can invite
    new_member_commitment: Option<Fr>, // Public: your identity commitment
}
// Proves: "I have a valid invitation to join this group"
