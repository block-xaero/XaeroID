use ark_ff::BigInteger;
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

    /// Self-sovereign: Issue group membership to self
    fn self_issue_membership(&self, group_id: u64) -> ProofBytes;

    /// Self-sovereign: Verify self-issued membership
    fn verify_self_membership(xaero_id_hash: [u8; 32], group_id: u64, proof: &[u8]) -> bool;
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
        // For credential-level roles (permanent professional attributes)
        // Use simple range proof
        if role >= min_role {
            let mut proof = ProofBytes::zeroed();
            proof.data[0] = role;
            proof.data[1] = min_role;
            proof.len = 2;
            proof
        } else {
            ProofBytes::zeroed()
        }
    }

    fn verify_role(min_role: u8, proof: &[u8]) -> bool {
        // Verify credential-level role proof
        if proof.len() == 2 {
            let role = proof[0];
            let proof_min_role = proof[1];
            // Verify this is a proof for the requested minimum
            // and that the role meets the requirement
            return proof_min_role == min_role && role >= min_role;
        }

        // No proof means no role
        false
    }

    fn self_issue_membership(&self, group_id: u64) -> ProofBytes {
        use ark_bn254::Fr;
        use ark_ff::PrimeField;
        use ark_std::UniformRand;
        use rand::rngs::OsRng;

        use crate::circuits::membership_circuit::MembershipProver;

        // Derive self-sovereign issuer secret from XaeroID
        let xaero_hash = blake3::hash(&self.secret_key);
        let issuer_secret = Fr::from_le_bytes_mod_order(xaero_hash.as_bytes());

        // Get XaeroID as Fr
        let xaero_id_bytes = blake3::hash(&self.did_peer[..self.did_peer_len as usize]);
        let xaero_id = Fr::from_le_bytes_mod_order(xaero_id_bytes.as_bytes());

        // Group ID as Fr
        let group_fr = Fr::from(group_id);

        // Generate randomness
        let mut rng = OsRng;
        let token_randomness = Fr::rand(&mut rng);

        // Issue membership to self
        match MembershipProver::issue_membership(
            xaero_id,
            group_fr,
            issuer_secret,
            token_randomness,
        ) {
            Ok((token_commitment, proof)) => {
                // Encode commitment and proof together
                let mut result = ProofBytes::zeroed();

                // First 32 bytes: token commitment
                let commitment_bytes = token_commitment.into_bigint().to_bytes_le();
                let commitment_len = commitment_bytes.len().min(32);
                result.data[..commitment_len].copy_from_slice(&commitment_bytes[..commitment_len]);

                // Next 32 bytes: issuer pubkey (for verification)
                let issuer_pubkey = MembershipProver::derive_issuer_pubkey(issuer_secret);
                let pubkey_bytes = issuer_pubkey.into_bigint().to_bytes_le();
                let pubkey_len = pubkey_bytes.len().min(32);
                result.data[32..32 + pubkey_len].copy_from_slice(&pubkey_bytes[..pubkey_len]);

                // Remaining bytes: the actual proof
                let proof_len = proof.len.min((MAX_PROOF_BYTES - 64) as u16) as usize;
                result.data[64..64 + proof_len].copy_from_slice(&proof.data[..proof_len]);

                result.len = (64 + proof_len) as u16;
                result
            }
            Err(_) => ProofBytes::zeroed(),
        }
    }

    fn verify_self_membership(xaero_id_hash: [u8; 32], group_id: u64, proof: &[u8]) -> bool {
        use ark_bn254::Fr;
        use ark_ff::PrimeField;

        use crate::circuits::membership_circuit::MembershipProver;

        if proof.len() < 64 {
            return false; // Need at least commitment + pubkey
        }

        // Extract commitment (first 32 bytes)
        let token_commitment = Fr::from_le_bytes_mod_order(&proof[..32]);

        // Extract issuer pubkey (next 32 bytes)
        let issuer_pubkey = Fr::from_le_bytes_mod_order(&proof[32..64]);

        // Extract proof bytes
        let proof_bytes = &proof[64..];

        // Convert inputs to Fr
        let xaero_id = Fr::from_le_bytes_mod_order(&xaero_id_hash);
        let group_fr = Fr::from(group_id);

        // Verify the membership proof
        MembershipProver::verify_membership(
            &xaero_id,
            &group_fr,
            &token_commitment,
            &issuer_pubkey,
            proof_bytes,
        )
        .unwrap_or(false)
    }
}

// Helper function to create self-sovereign wallet data
impl XaeroID {
    pub fn create_self_sovereign_wallet(&self, groups: &[u64]) -> Vec<u8> {
        use crate::domain::xaero_wallet::{GroupMembership, XaeroWallet};

        let mut wallet = XaeroWallet::new(*self);

        // Self-issue membership to each group
        for &group_id in groups {
            let proof = self.self_issue_membership(group_id);

            if proof.len > 0 {
                let mut membership = GroupMembership::zeroed();

                // Store group ID
                let group_bytes = group_id.to_le_bytes();
                membership.group_id[..8].copy_from_slice(&group_bytes);

                // Store commitment (from proof data)
                membership.member_token_commitment[..32].copy_from_slice(&proof.data[..32]);

                // Store issuer pubkey (from proof data)
                membership.issuer_pubkey[..32].copy_from_slice(&proof.data[32..64]);

                // Store the actual proof
                let proof_len = (proof.len as usize).saturating_sub(64);
                membership.membership_proof.data[..proof_len]
                    .copy_from_slice(&proof.data[64..64 + proof_len]);
                membership.membership_proof.len = proof_len as u16;

                // Set metadata
                membership.issued_at = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                membership.expires_at = membership.issued_at + (365 * 24 * 60 * 60); // 1 year
                membership.is_active = 1;

                // Add to wallet
                let _ = wallet.add_group_membership(membership);
            }
        }

        // Return serialized wallet
        bytemuck::bytes_of(&wallet).to_vec()
    }
}
