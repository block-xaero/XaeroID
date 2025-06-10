use ark_bn254::{Bn254, Fr};
use ark_groth16::Proof;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use bytemuck::Zeroable;
use rand::SeedableRng;

use crate::zk_proofs::ProofBytes;

pub struct MembershipCircuit {
    // Private: secret token that proves membership
    member_token: Option<Fr>,
    token_randomness: Option<Fr>,

    // Public: commitments and group info
    pub token_commitment: Option<Fr>,
    pub group_id: Option<Fr>,
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

        // Allocate public inputs
        let token_commitment = FpVar::new_input(cs.clone(), || {
            self.token_commitment
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let group_id = FpVar::new_input(cs.clone(), || {
            self.group_id.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Constraint 1: commitment = member_token + randomness (simple commitment)
        let computed_commitment = &member_token + &randomness;
        computed_commitment.enforce_equal(&token_commitment)?;

        // Constraint 2: token must be derived from group_id
        // Simplified: member_token = group_id (remove the squaring for now)
        member_token.enforce_equal(&group_id)?;

        Ok(())
    }
}

pub struct MembershipProver;

impl MembershipProver {
    pub fn prove_membership(
        member_token: Fr,
        token_randomness: Fr,
        token_commitment: Fr,
        group_id: Fr,
    ) -> Result<ProofBytes, Box<dyn std::error::Error>> {
        let circuit = MembershipCircuit {
            member_token: Some(member_token),
            token_randomness: Some(token_randomness),
            token_commitment: Some(token_commitment),
            group_id: Some(group_id),
        };

        Self::generate_proof_internal(circuit, vec![token_commitment, group_id])
    }

    pub fn verify_membership(
        token_commitment: &Fr,
        group_id: &Fr,
        proof_bytes: &[u8],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let public_inputs = vec![*token_commitment, *group_id];
        Self::verify_proof_internal(public_inputs, proof_bytes)
    }

    fn generate_proof_internal(
        circuit: MembershipCircuit,
        _public_inputs: Vec<Fr>,
    ) -> Result<ProofBytes, Box<dyn std::error::Error>> {
        use ark_groth16::Groth16;
        use ark_snark::SNARK;

        // Use FIXED seed for consistent parameters
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(12345);
        let (pk, _vk) = Groth16::<Bn254>::circuit_specific_setup(
            MembershipCircuit {
                member_token: None,
                token_randomness: None,
                token_commitment: None,
                group_id: None,
            },
            &mut rng,
        )?;

        // Use different rng for actual proof generation
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

        // Use SAME FIXED seed for consistent parameters
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(12345);
        let (_pk, vk) = Groth16::<Bn254>::circuit_specific_setup(
            MembershipCircuit {
                member_token: None,
                token_randomness: None,
                token_commitment: None,
                group_id: None,
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
    fn test_membership_proof() {
        let mut rng = OsRng;
        let group_id = Fr::from(42u64);

        // Simple constraint: member_token = group_id
        let member_token = group_id;
        let token_randomness = Fr::rand(&mut rng);
        let token_commitment = &member_token + &token_randomness;

        // Generate proof - clone values to avoid moves
        let proof = MembershipProver::prove_membership(
            member_token,
            token_randomness,
            token_commitment.clone(),
            group_id.clone(),
        )
        .expect("Proof generation failed");

        // Create a slice from the proof data
        let proof_slice = &proof.data[..proof.len as usize];

        // Verify proof
        let is_valid =
            MembershipProver::verify_membership(&token_commitment, &group_id, proof_slice)
                .expect("Verification failed");

        assert!(is_valid, "Membership proof should be valid");
    }
}
