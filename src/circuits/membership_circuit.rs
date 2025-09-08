use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::crh::sha256::constraints::{Sha256Gadget, UnitVar};
use ark_groth16::Proof;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use bytemuck::Zeroable;
use rand::SeedableRng;

use crate::zk_proofs::ProofBytes;

pub struct MembershipCircuit {
    // Private inputs
    member_token: Option<Fr>, // hash(xaero_id || group_id || issuer_secret)
    token_randomness: Option<Fr>, // Random blinding factor
    issuer_secret: Option<Fr>, // Issuer's secret key

    // Public inputs
    pub xaero_id: Option<Fr>,         // The XaeroID being bound
    pub group_id: Option<Fr>,         // The group being joined
    pub token_commitment: Option<Fr>, // member_token + randomness
    pub issuer_pubkey: Option<Fr>,    // Issuer's public key (derived from secret)
}

impl ConstraintSynthesizer<Fr> for MembershipCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate private inputs
        let member_token = FpVar::new_witness(cs.clone(), || {
            self.member_token.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let randomness = FpVar::new_witness(cs.clone(), || {
            self.token_randomness
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let issuer_secret = FpVar::new_witness(cs.clone(), || {
            self.issuer_secret.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate public inputs
        let xaero_id = FpVar::new_input(cs.clone(), || {
            self.xaero_id.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let group_id = FpVar::new_input(cs.clone(), || {
            self.group_id.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let token_commitment = FpVar::new_input(cs.clone(), || {
            self.token_commitment
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let issuer_pubkey = FpVar::new_input(cs.clone(), || {
            self.issuer_pubkey.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Constraint 1: Verify issuer's public key matches secret
        // pubkey = hash(secret) - simplified, in practice use proper key derivation
        let computed_pubkey = &issuer_secret * &issuer_secret; // Simple squaring for demo
        computed_pubkey.enforce_equal(&issuer_pubkey)?;

        // Constraint 2: Verify member token is correctly derived
        // member_token = hash(xaero_id || group_id || issuer_secret)
        // For simplicity: member_token = xaero_id + group_id * issuer_secret
        let computed_token = &xaero_id + &group_id * &issuer_secret;
        computed_token.enforce_equal(&member_token)?;

        // Constraint 3: Verify commitment
        let computed_commitment = &member_token + &randomness;
        computed_commitment.enforce_equal(&token_commitment)?;

        Ok(())
    }
}

pub struct MembershipProver;

impl MembershipProver {
    /// Generate member token for a specific XaeroID and group
    pub fn generate_member_token(xaero_id: Fr, group_id: Fr, issuer_secret: Fr) -> Fr {
        xaero_id + group_id * issuer_secret
    }

    /// Derive public key from issuer secret
    pub fn derive_issuer_pubkey(issuer_secret: Fr) -> Fr {
        issuer_secret * issuer_secret
    }

    /// Issue membership proof for a specific XaeroID and group
    pub fn issue_membership(
        xaero_id: Fr,
        group_id: Fr,
        issuer_secret: Fr,
        token_randomness: Fr,
    ) -> Result<(Fr, ProofBytes), Box<dyn std::error::Error>> {
        let member_token = Self::generate_member_token(xaero_id, group_id, issuer_secret);
        let token_commitment = member_token + token_randomness;
        let issuer_pubkey = Self::derive_issuer_pubkey(issuer_secret);

        let circuit = MembershipCircuit {
            member_token: Some(member_token),
            token_randomness: Some(token_randomness),
            issuer_secret: Some(issuer_secret),
            xaero_id: Some(xaero_id),
            group_id: Some(group_id),
            token_commitment: Some(token_commitment),
            issuer_pubkey: Some(issuer_pubkey),
        };

        let proof = Self::generate_proof_internal(circuit)?;
        Ok((token_commitment, proof))
    }

    /// Verify membership proof
    pub fn verify_membership(
        xaero_id: &Fr,
        group_id: &Fr,
        token_commitment: &Fr,
        issuer_pubkey: &Fr,
        proof_bytes: &[u8],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let public_inputs = vec![*xaero_id, *group_id, *token_commitment, *issuer_pubkey];
        Self::verify_proof_internal(public_inputs, proof_bytes)
    }

    fn generate_proof_internal(
        circuit: MembershipCircuit,
    ) -> Result<ProofBytes, Box<dyn std::error::Error>> {
        use ark_groth16::Groth16;
        use ark_snark::SNARK;

        // Load pre-generated keys (in practice)
        // For testing, generate on the fly with fixed seed
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(12345);
        let (pk, _vk) = Groth16::<Bn254>::circuit_specific_setup(
            MembershipCircuit {
                member_token: None,
                token_randomness: None,
                issuer_secret: None,
                xaero_id: None,
                group_id: None,
                token_commitment: None,
                issuer_pubkey: None,
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

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(12345);
        let (_pk, vk) = Groth16::<Bn254>::circuit_specific_setup(
            MembershipCircuit {
                member_token: None,
                token_randomness: None,
                issuer_secret: None,
                xaero_id: None,
                group_id: None,
                token_commitment: None,
                issuer_pubkey: None,
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
    use ark_std::UniformRand;
    use rand::rngs::OsRng;

    use super::*;

    #[test]
    fn test_xaero_bound_membership() {
        let mut rng = OsRng;

        // Issuer setup
        let issuer_secret = Fr::from(999u64); // In practice, random
        let issuer_pubkey = MembershipProver::derive_issuer_pubkey(issuer_secret);

        // User and group
        let xaero_id = Fr::from(12345u64); // User's XaeroID
        let group_id = Fr::from(42u64); // Group to join

        // Issue membership
        let token_randomness = Fr::rand(&mut rng);
        let (token_commitment, proof) =
            MembershipProver::issue_membership(xaero_id, group_id, issuer_secret, token_randomness)
                .expect("Issuance failed");

        // Verify proof
        let proof_slice = &proof.data[..proof.len as usize];
        let is_valid = MembershipProver::verify_membership(
            &xaero_id,
            &group_id,
            &token_commitment,
            &issuer_pubkey,
            proof_slice,
        )
        .expect("Verification failed");

        assert!(is_valid, "Membership proof should be valid");

        // Try to verify with different XaeroID (should fail)
        let wrong_xaero = Fr::from(99999u64);
        let invalid = MembershipProver::verify_membership(
            &wrong_xaero,
            &group_id,
            &token_commitment,
            &issuer_pubkey,
            proof_slice,
        )
        .expect("Verification failed");

        assert!(!invalid, "Proof should not verify for different XaeroID");
    }
}
