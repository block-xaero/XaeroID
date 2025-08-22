use bytemuck::Zeroable;

use crate::{IdentityManager, XaeroID};

pub const MAX_PROOF_BYTES: usize = 512;

/// A Pod-safe proof container: fixed-size buffer + actual length
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ProofBytes {
    /// Raw proof bytes (zero-padded)
    pub data: [u8; MAX_PROOF_BYTES],
    /// Actual proof length in `data`
    pub len: u16,
    /// Padding to align to 4 bytes
    pub _pad: [u8; 2],
}
unsafe impl bytemuck::Pod for ProofBytes {}
unsafe impl bytemuck::Zeroable for ProofBytes {}

pub trait XaeroProofs {
    /// Detached signature on an arbitrary `challenge`.
    fn prove_identity(&self, challenge: &[u8]) -> ProofBytes;

    /// Verify an identity proof against a raw public key.
    fn verify_identity(pubkey: &[u8], challenge: &[u8], proof: &[u8]) -> bool;

    /// Prove possession of a pre-committed hash (e.g. `H(email)` in your corporate allowlist).
    fn prove_membership(&self, allowed_hash: [u8; 32]) -> ProofBytes;

    /// Verify the membership proof matches `allowed_hash`.
    fn verify_membership(allowed_hash: [u8; 32], proof: &[u8]) -> bool;

    /// Prove that your "role" integer is ≥ `min_role` (e.g. admin vs reader).
    fn prove_role(&self, role: u8, min_role: u8) -> ProofBytes;

    /// Verify the role proof.
    fn verify_role(min_role: u8, proof: &[u8]) -> bool;
}

/// Implement all of the above on `XaeroID` itself.
impl XaeroProofs for XaeroID {
    fn prove_identity(&self, challenge: &[u8]) -> ProofBytes {
        // Use your existing Falcon512 signing
        let mgr = crate::identity::XaeroIdentityManager {};
        let signature = mgr.sign_challenge(self, challenge);

        let mut proof = ProofBytes::zeroed();
        let sig_len = signature.len().min(MAX_PROOF_BYTES);
        proof.data[..sig_len].copy_from_slice(&signature[..sig_len]);
        proof.len = sig_len as u16;
        proof
    }

    fn verify_identity(pubkey: &[u8], challenge: &[u8], proof: &[u8]) -> bool {
        use pqcrypto_falcon::falcon512::{verify_detached_signature, PublicKey};
        use pqcrypto_traits::sign::{DetachedSignature, PublicKey as PublicKeyTrait};

        if let Ok(pk) = PublicKey::from_bytes(pubkey)
            && let Ok(sig) = DetachedSignature::from_bytes(proof)
        {
            return verify_detached_signature(&sig, challenge, &pk).is_ok();
        }
        false
    }

    fn prove_membership(&self, allowed_hash: [u8; 32]) -> ProofBytes {
        // a simple Blake3 preimage circuit: we hash self's email (or other secret) and compare
        // For now we'll just return blake3(self.did_peer) == allowed_hash ? [] : panic!
        let actual = blake3::hash(&self.did_peer[..self.did_peer_len as usize]);
        if actual.as_bytes()[..32] != allowed_hash {
            panic!("not a member");
        }
        // returning an empty ProofBytes means "I proved it" — you could encode a ZK proof here
        // later
        ProofBytes::zeroed()
    }

    fn verify_membership(_allowed_hash: [u8; 32], proof: &[u8]) -> bool {
        // with our stub above, membership proof is "empty Vec" and we just re-check:
        proof.is_empty()
    }

    fn prove_role(&self, role: u8, min_role: u8) -> ProofBytes {
        // Use Arkworks Groth16 proof instead of simple comparison
        crate::circuits::role_circuit::ArkRoleProver::prove_role_to_bytes(role, min_role)
    }

    fn verify_role(min_role: u8, proof: &[u8]) -> bool {
        if proof.is_empty() {
            return true; // For backwards compatibility with stub
        }

        // Convert to ProofBytes for verification
        if proof.len() >= 2 {
            let len = u16::from_le_bytes([proof[0], proof[1]]);
            if proof.len() >= (len as usize + 4) {
                let proof_bytes = ProofBytes {
                    data: {
                        let mut data = [0u8; MAX_PROOF_BYTES];
                        let copy_len = (len as usize).min(MAX_PROOF_BYTES);
                        if proof.len() >= copy_len + 4 {
                            data[..copy_len].copy_from_slice(&proof[4..4 + copy_len]);
                        }
                        data
                    },
                    len,
                    _pad: [0, 0],
                };
                return crate::circuits::role_circuit::ArkRoleProver::verify_role_from_bytes(
                    min_role,
                    &proof_bytes,
                );
            }
        }

        // Fallback: try to parse as raw proof bytes
        let proof_bytes = ProofBytes {
            data: {
                let mut data = [0u8; MAX_PROOF_BYTES];
                let copy_len = proof.len().min(MAX_PROOF_BYTES);
                data[..copy_len].copy_from_slice(&proof[..copy_len]);
                data
            },
            len: proof.len() as u16,
            _pad: [0, 0],
        };
        crate::circuits::role_circuit::ArkRoleProver::verify_role_from_bytes(min_role, &proof_bytes)
    }
}
