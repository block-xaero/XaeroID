use ark_bn254::{Bn254, Fr};
use ark_groth16::Proof;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use bytemuck::Zeroable;
use rand::SeedableRng;

use crate::zk_proofs::ProofBytes;

pub struct WorkspaceCreationCircuit {
    creator_role: Option<u8>,       // Private: your role level
    min_creation_role: Option<u8>,  // Public: required role to create workspaces
    workspace_seed: Option<Fr>,     // Private: randomness for new workspace
    new_workspace_root: Option<Fr>, // Public: merkle root of new workspace
}

impl ConstraintSynthesizer<Fr> for WorkspaceCreationCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Similar to ObjectCreationCircuit but for workspaces
        let creator_role = FpVar::new_witness(cs.clone(), || {
            self.creator_role
                .map(|r| Fr::from(r as u64))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let workspace_seed = FpVar::new_witness(cs.clone(), || {
            self.workspace_seed.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let min_creation_role = FpVar::new_input(cs.clone(), || {
            self.min_creation_role
                .map(|r| Fr::from(r as u64))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let new_workspace_root = FpVar::new_input(cs.clone(), || {
            self.new_workspace_root
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Role authorization constraint
        let role_difference = &creator_role - &min_creation_role;
        let difference_bits = role_difference.to_bits_le()?;
        for i in 8..difference_bits.len() {
            difference_bits[i].enforce_equal(&Boolean::constant(false))?;
        }

        // Workspace root derivation (different from objects)
        let computed_root = &workspace_seed * &creator_role;
        computed_root.enforce_equal(&new_workspace_root)?;

        Ok(())
    }
}

pub struct WorkspaceCreationProver;

impl WorkspaceCreationProver {
    pub fn prove_creation(
        creator_role: u8,
        min_creation_role: u8,
        workspace_seed: Fr,
        new_workspace_root: Fr,
    ) -> Result<ProofBytes, Box<dyn std::error::Error>> {
        let circuit = WorkspaceCreationCircuit {
            creator_role: Some(creator_role),
            min_creation_role: Some(min_creation_role),
            workspace_seed: Some(workspace_seed),
            new_workspace_root: Some(new_workspace_root),
        };

        let public_inputs = vec![Fr::from(min_creation_role as u64), new_workspace_root];

        Self::generate_proof_internal(circuit, public_inputs)
    }

    pub fn verify_creation(
        min_creation_role: u8,
        new_workspace_root: &Fr,
        proof_bytes: &[u8],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let public_inputs = vec![Fr::from(min_creation_role as u64), *new_workspace_root];

        Self::verify_proof_internal(public_inputs, proof_bytes)
    }

    fn generate_proof_internal(
        circuit: WorkspaceCreationCircuit,
        _public_inputs: Vec<Fr>,
    ) -> Result<ProofBytes, Box<dyn std::error::Error>> {
        use ark_groth16::Groth16;
        use ark_snark::SNARK;

        // Use FIXED seed for consistent parameters
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(12347);
        let (pk, _vk) = Groth16::<Bn254>::circuit_specific_setup(
            WorkspaceCreationCircuit {
                creator_role: None,
                min_creation_role: None,
                workspace_seed: None,
                new_workspace_root: None,
            },
            &mut rng,
        )?;

        // Use different rng for actual proof generation
        let mut proof_rng = rand_chacha::ChaCha8Rng::from_entropy();
        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut proof_rng)?;

        // Serialize to bytes
        let mut proof_vec = Vec::new();
        ark_serialize::CanonicalSerialize::serialize_compressed(&proof, &mut proof_vec)?;

        // Convert to ProofBytes
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
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(12347);
        let (_pk, vk) = Groth16::<Bn254>::circuit_specific_setup(
            WorkspaceCreationCircuit {
                creator_role: None,
                min_creation_role: None,
                workspace_seed: None,
                new_workspace_root: None,
            },
            &mut rng,
        )?;

        // Deserialize and verify proof
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
    fn test_workspace_creation_proof() {
        let mut rng = OsRng;
        let creator_role = 7u8;
        let min_creation_role = 4u8;
        let workspace_seed = Fr::rand(&mut rng);

        // The circuit expects: new_workspace_root = workspace_seed * creator_role
        let new_workspace_root = &workspace_seed * &Fr::from(creator_role as u64);

        // Generate proof
        let proof = WorkspaceCreationProver::prove_creation(
            creator_role,
            min_creation_role,
            workspace_seed,
            new_workspace_root.clone(),
        )
        .expect("Workspace proof generation failed");

        // Create a slice from the proof data
        let proof_slice = &proof.data[..proof.len as usize];

        // Verify proof
        let is_valid = WorkspaceCreationProver::verify_creation(
            min_creation_role,
            &new_workspace_root,
            proof_slice,
        )
        .expect("Workspace verification failed");

        assert!(is_valid, "Workspace creation proof should be valid");
    }
}
