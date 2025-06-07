#![allow(dead_code)]
//! xaeroID: skeletal types for DID, VC and ZK proofs, with integration traits for seamless app use
use bytemuck::{Pod, Zeroable};

mod credentials;
mod extern_id;
mod identity;

/// A zero-knowledge proof container (e.g. RISC Zero receipt or Groth16 SNARK proof).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct XaeroProof {
    /// The raw proof bytes, stored as a fixed-size array.
    pub zk_proof: [u8; 32],
}

/// Maximum lengths for fixed-size fields
pub const DID_MAX_LEN: usize = 897;
pub const VC_MAX_LEN: usize = 256;
pub const MAX_PROOFS: usize = 4;

/// A fixed-size credential container holding a serialized VC and up to N proofs.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct XaeroCredential {
    /// Serialized VerifiableCredential bytes (e.g. JWT/JSON‑LD) with length.
    pub vc: [u8; VC_MAX_LEN],
    pub vc_len: u16,
    /// Zero‑knowledge proofs associated with this credential.
    pub proofs: [XaeroProof; MAX_PROOFS],
    pub proof_count: u8,
    // 1 byte padding to align to 4‑byte boundary
    pub _pad: [u8; 1],
}
unsafe impl Pod for XaeroCredential {}
unsafe impl Zeroable for XaeroCredential {}

/// The core decentralized identity type, fully Pod‑safe.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct XaeroID {
    /// peer DID bytes (without "did:peer:" prefix) and its length.
    pub did_peer: [u8; DID_MAX_LEN],
    pub did_peer_len: u16,
    /// YOUR RESPONSIBILITY TO KEEP THIS SECRET!
    /// XAEROID gives app engineers and lib experts
    /// control XaeroID and what to do with it.
    pub secret_key: [u8; 1281],
    // 3 bytes padding for alignment
    pub _pad: [u8; 3],
    /// The credential bundle for this identity.
    pub credential: XaeroCredential,
}
unsafe impl Pod for XaeroID {}
unsafe impl Zeroable for XaeroID {}

pub const XAERO_ID_SIZE: usize = std::mem::size_of::<XaeroID>();
/// Trait for DID generation, signing and verification.
pub trait IdentityManager {
    /// Generate a new DID and initialize credentials.
    fn new_id(&self) -> XaeroID;
    /// Sign an arbitrary challenge using the DID keypair.
    fn sign_challenge(&self, xid: &XaeroID, challenge: &[u8]) -> Vec<u8>;
    /// Verify a signed challenge against the DID's public key.
    fn verify_challenge(&self, xid: &XaeroID, challenge: &[u8], signature: &[u8]) -> bool;
}

/// Trait for issuing and verifying verifiable credentials.
pub trait CredentialIssuer {
    /// Issue a credential for the given DID with provided claims.
    fn issue_credential(&self, did: &str, email: String, birth_year: u16) -> XaeroCredential;
    /// Verify the integrity and signature of a credential.
    fn verify_credential(&self, cred: &XaeroCredential) -> bool;
}

/// Trait for creating and verifying zero-knowledge proofs for key Cyan workflows:
/// - user attributes (age, credential validity)
/// - workspace membership (access control)
pub trait ProofProver {
    /// Prove that a private `birth_year` satisfies a public threshold (e.g. age ≥ threshold).
    fn prove_age(&self, birth_year: u16, threshold: u16) -> XaeroProof;
    /// Verify an age proof against the public threshold.
    fn verify_age_proof(&self, proof: &XaeroProof, threshold: u16) -> bool;

    /// Prove possession and integrity of a serialized credential without revealing its contents.
    /// `credential_bytes` is the raw VC serialization (up to VC_MAX_LEN).
    fn prove_credential_possession(&self, credential_bytes: &[u8]) -> XaeroProof;
    /// Verify a credential-possession proof against the public commitment (e.g. hash of VC).
    fn verify_credential_possession(&self, proof: &XaeroProof, public_commitment: &[u8]) -> bool;

    /// Prove membership in a workspace (access control) without revealing additional data.
    /// `workspace_id_bytes` is the raw workspace identifier (e.g. DID of workspace).
    fn prove_workspace_membership(&self, workspace_id_bytes: &[u8]) -> XaeroProof;
    /// Verify a workspace-membership proof for a given workspace identifier.
    fn verify_workspace_membership(&self, proof: &XaeroProof, workspace_id_bytes: &[u8]) -> bool;
}
