#![allow(dead_code)]
//! xaeroID: skeletal types for DID, VC and ZK proofs, with integration traits for seamless app use
#![feature(trivial_bounds)]

use std::hash::{Hash, Hasher};

use bytemuck::{Pod, Zeroable};
use rkyv::{Archive, Deserialize, Serialize};

pub mod credentials;
pub mod extern_id;
pub mod identity;
pub mod zk_proofs;
// mod bellman_proofs;
pub mod cache;
pub mod circuits;
pub mod domain;

/// A zero-knowledge proof container (e.g. RISC Zero receipt or Groth16 SNARK proof).
#[repr(C)]
#[derive(Debug, Clone, Copy, Archive, Serialize, Deserialize)]
#[rkyv(derive(Debug))]
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
#[derive(Debug, Clone, Copy, Archive, Serialize, Deserialize)]
#[rkyv(derive(Debug))]
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
#[derive(Debug, Clone, Copy, Archive, Serialize, Deserialize)]
#[rkyv(derive(Debug))]
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

impl PartialEq for XaeroID {
    fn eq(&self, other: &Self) -> bool {
        self.did_peer_len == other.did_peer_len
            && self.did_peer[..self.did_peer_len as usize]
                == other.did_peer[..other.did_peer_len as usize]
    }
}

impl Eq for XaeroID {}
impl Hash for XaeroID {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Hash only the actual DID peer data, not the padding
        self.did_peer[..self.did_peer_len as usize].hash(state);
        // Optionally include the length for extra safety
        self.did_peer_len.hash(state);
    }
}
impl Hash for ArchivedXaeroID {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Hash the archived u16 directly
        self.did_peer_len.hash(state);

        // Hash only the actual DID peer data
        let len = self.did_peer_len.to_native() as usize;
        self.did_peer[..len].hash(state);
    }
}

impl PartialEq for ArchivedXaeroID {
    fn eq(&self, other: &Self) -> bool {
        // Compare archived u16s directly first
        self.did_peer_len == other.did_peer_len && {
            let len = self.did_peer_len.to_native() as usize;
            self.did_peer[..len] == other.did_peer[..len]
        }
    }
}

impl Eq for ArchivedXaeroID {}
pub const XAERO_ID_SIZE: usize = std::mem::size_of::<XaeroID>();
/// Trait for DID generation, signing and verification.
pub trait IdentityManager {
    /// Generate a new DID and initialize credentials.
    fn new_id(&self) -> XaeroID;
    /// Sign an arbitrary challenge using the DID keypair.
    fn sign_challenge(&self, xid: &XaeroID, challenge: &[u8]) -> [u8; 690];
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
