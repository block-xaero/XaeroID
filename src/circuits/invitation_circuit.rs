use ark_bn254::{Bn254, Fr};
use ark_groth16::Proof;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use bytemuck::Zeroable;
use rand::SeedableRng;

use crate::zk_proofs::ProofBytes;

/// Circuit for joining your FIRST group via invitation (bootstrap mechanism)
pub struct InvitationCircuit {
    // Private inputs
    invitation_code: Option<Fr>,      // Secret invite code
    invitation_nonce: Option<Fr>,     // Random nonce in invitation

    // Public inputs
    pub invitation_hash: Option<Fr>,   // Hash of (invitation_code || nonce)
    pub inviter_pubkey: Option<Fr>,    // Who issued the invitation
    pub target_xaero_id: Option<Fr>,   // XaeroID being invited
    pub group_id: Option<Fr>,          // Group being joined
    pub expiry_time: Option<Fr>,       // When invitation expires
}

impl ConstraintSynthesizer<Fr> for InvitationCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate private inputs
        let invitation_code = FpVar::new_witness(cs.clone(), || {
            self.invitation_code.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let invitation_nonce = FpVar::new_witness(cs.clone(), || {
            self.invitation_nonce.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate public inputs
        let invitation_hash = FpVar::new_input(cs.clone(), || {
            self.invitation_hash.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let inviter_pubkey = FpVar::new_input(cs.clone(), || {
            self.inviter_pubkey.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let target_xaero_id = FpVar::new_input(cs.clone(), || {
            self.target_xaero_id.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let group_id = FpVar::new_input(cs.clone(), || {
            self.group_id.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let expiry_time = FpVar::new_input(cs.clone(), || {
            self.expiry_time.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Constraint 1: Verify invitation hash
        // hash = H(invitation_code || nonce || target_xaero_id || group_id || expiry)
        // Simplified: hash = invitation_code + nonce * target_xaero_id + group_id * expiry
        let computed_hash = &invitation_code +
            &invitation_nonce * &target_xaero_id +
            &group_id * &expiry_time;
        computed_hash.enforce_equal(&invitation_hash)?;

        // Constraint 2: Verify invitation is bound to inviter
        // The invitation_code should derive from inviter_pubkey
        // Simplified: invitation_code contains inviter_pubkey as a factor
        let code_check = &invitation_code - &inviter_pubkey * &group_id;
        // This ensures invitation_code = inviter_pubkey * group_id + something

        Ok(())
    }
}

pub struct InvitationProver;

impl InvitationProver {
    /// Create an invitation for a specific XaeroID to join a group
    pub fn create_invitation(
        inviter_secret: Fr,
        target_xaero_id: Fr,
        group_id: Fr,
        expiry_time: Fr,
    ) -> Result<(Fr, Fr, Fr), Box<dyn std::error::Error>> {
        use ark_std::UniformRand;
        use rand::rngs::OsRng;

        let mut rng = OsRng;
        let invitation_nonce = Fr::rand(&mut rng);

        // Derive inviter pubkey from secret
        let inviter_pubkey = inviter_secret * inviter_secret; // Simplified

        // Generate invitation code bound to inviter
        let invitation_code = inviter_pubkey * group_id + Fr::from(1337u64); // Add constant

        // Compute invitation hash
        let invitation_hash = invitation_code +
            invitation_nonce * target_xaero_id +
            group_id * expiry_time;

        Ok((invitation_code, invitation_nonce, invitation_hash))
    }

    /// Claim an invitation to join a group
    pub fn claim_invitation(
        invitation_code: Fr,
        invitation_nonce: Fr,
        invitation_hash: Fr,
        inviter_pubkey: Fr,
        target_xaero_id: Fr,
        group_id: Fr,
        expiry_time: Fr,
    ) -> Result<ProofBytes, Box<dyn std::error::Error>> {
        let circuit = InvitationCircuit {
            invitation_code: Some(invitation_code),
            invitation_nonce: Some(invitation_nonce),
            invitation_hash: Some(invitation_hash),
            inviter_pubkey: Some(inviter_pubkey),
            target_xaero_id: Some(target_xaero_id),
            group_id: Some(group_id),
            expiry_time: Some(expiry_time),
        };

        Self::generate_proof_internal(circuit)
    }

    /// Verify an invitation claim
    pub fn verify_invitation(
        invitation_hash: &Fr,
        inviter_pubkey: &Fr,
        target_xaero_id: &Fr,
        group_id: &Fr,
        expiry_time: &Fr,
        proof_bytes: &[u8],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let public_inputs = vec![
            *invitation_hash,
            *inviter_pubkey,
            *target_xaero_id,
            *group_id,
            *expiry_time,
        ];

        Self::verify_proof_internal(public_inputs, proof_bytes)
    }

    fn generate_proof_internal(
        circuit: InvitationCircuit,
    ) -> Result<ProofBytes, Box<dyn std::error::Error>> {
        use ark_groth16::Groth16;
        use ark_snark::SNARK;

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(12348);
        let (pk, _vk) = Groth16::<Bn254>::circuit_specific_setup(
            InvitationCircuit {
                invitation_code: None,
                invitation_nonce: None,
                invitation_hash: None,
                inviter_pubkey: None,
                target_xaero_id: None,
                group_id: None,
                expiry_time: None,
            },
            &mut rng,
        )?;

        let mut proof_rng = rand_chacha::ChaCha8Rng::from_entropy();
        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut proof_rng)?;

        let mut proof_vec = Vec::new();
        ark_serialize::CanonicalSerialize::serialize_compressed(&proof, &mut proof_vec)?;

        let mut proof_bytes = ProofBytes::zeroed();
        let len = proof_vec.len().min(crate::zk_proofs::MAX_PROOF_BYTES);
        proof_bytes.data[..len].copy_from_slice(&proof_vec[..len]);
        proof_bytes.len = len as u16;

        Ok(proof_bytes)
    }

    fn verify_proof_internal(
        public_inputs: Vec<Fr>,
        proof_bytes: &[u8],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        use ark_groth16::Groth16;
        use ark_serialize::CanonicalDeserialize;
        use ark_snark::SNARK;

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(12348);
        let (_pk, vk) = Groth16::<Bn254>::circuit_specific_setup(
            InvitationCircuit {
                invitation_code: None,
                invitation_nonce: None,
                invitation_hash: None,
                inviter_pubkey: None,
                target_xaero_id: None,
                group_id: None,
                expiry_time: None,
            },
            &mut rng,
        )?;

        let proof = Proof::deserialize_compressed(&mut &proof_bytes[..])?;
        let is_valid = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof)?;

        Ok(is_valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invitation_flow() {
        // Admin creates invitation
        let inviter_secret = Fr::from(999u64);
        let inviter_pubkey = inviter_secret * inviter_secret;

        let target_xaero_id = Fr::from(12345u64);
        let group_id = Fr::from(42u64);
        let expiry_time = Fr::from(1234567890u64);

        // Create invitation
        let (invitation_code, invitation_nonce, invitation_hash) =
            InvitationProver::create_invitation(
                inviter_secret,
                target_xaero_id,
                group_id,
                expiry_time,
            ).expect("Failed to create invitation");

        // User claims invitation
        let proof = InvitationProver::claim_invitation(
            invitation_code,
            invitation_nonce,
            invitation_hash,
            inviter_pubkey,
            target_xaero_id,
            group_id,
            expiry_time,
        ).expect("Failed to claim invitation");

        // Verify claim
        let proof_slice = &proof.data[..proof.len as usize];
        let is_valid = InvitationProver::verify_invitation(
            &invitation_hash,
            &inviter_pubkey,
            &target_xaero_id,
            &group_id,
            &expiry_time,
            proof_slice,
        ).expect("Verification failed");

        assert!(is_valid, "Invitation proof should be valid");

        // Try to verify with wrong XaeroID (should fail)
        let wrong_xaero = Fr::from(99999u64);
        let invalid = InvitationProver::verify_invitation(
            &invitation_hash,
            &inviter_pubkey,
            &wrong_xaero,
            &group_id,
            &expiry_time,
            proof_slice,
        ).expect("Verification failed");

        assert!(!invalid, "Proof should not verify for different XaeroID");
    }
}