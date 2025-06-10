use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use bytemuck::Zeroable;
use rand::SeedableRng;

use crate::zk_proofs::ProofBytes;

pub struct ObjectCreationCircuit {
    creator_role: Option<u8>,      // Private: your role level
    min_creation_role: Option<u8>, // Public: required role to create objects
    object_seed: Option<Fr>,       // Private: randomness for new object
    new_object_root: Option<Fr>,   // Public: merkle root of new object
}

impl ConstraintSynthesizer<Fr> for ObjectCreationCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate private inputs
        let creator_role = FpVar::new_witness(cs.clone(), || {
            self.creator_role
                .map(|r| Fr::from(r as u64))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let object_seed = FpVar::new_witness(cs.clone(), || {
            self.object_seed.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate public inputs
        let min_creation_role = FpVar::new_input(cs.clone(), || {
            self.min_creation_role
                .map(|r| Fr::from(r as u64))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let new_object_root = FpVar::new_input(cs.clone(), || {
            self.new_object_root
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Constraint 1: creator_role >= min_creation_role
        let role_difference = &creator_role - &min_creation_role;
        let difference_bits = role_difference.to_bits_le()?;
        // Ensure only 8 bits (roles 0-255)
        for i in 8..difference_bits.len() {
            difference_bits[i].enforce_equal(&Boolean::constant(false))?;
        }

        // Constraint 2: new_object_root = object_seed + creator_role
        let computed_root = &object_seed + &creator_role;
        computed_root.enforce_equal(&new_object_root)?;

        Ok(())
    }
}

pub struct ObjectCreationProver;

impl ObjectCreationProver {
    pub fn prove_creation(
        creator_role: u8,
        min_creation_role: u8,
        object_seed: Fr,
        new_object_root: Fr,
    ) -> Result<ProofBytes, Box<dyn std::error::Error>> {
        let circuit = ObjectCreationCircuit {
            creator_role: Some(creator_role),
            min_creation_role: Some(min_creation_role),
            object_seed: Some(object_seed),
            new_object_root: Some(new_object_root),
        };

        let public_inputs = vec![Fr::from(min_creation_role as u64), new_object_root];

        Self::generate_proof_internal(circuit, public_inputs)
    }

    pub fn verify_creation(
        min_creation_role: u8,
        new_object_root: &Fr,
        proof_bytes: &[u8],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let public_inputs = vec![Fr::from(min_creation_role as u64), *new_object_root];

        Self::verify_proof_internal(public_inputs, proof_bytes)
    }

    fn generate_proof_internal(
        circuit: ObjectCreationCircuit,
        _public_inputs: Vec<Fr>,
    ) -> Result<ProofBytes, Box<dyn std::error::Error>> {
        use ark_groth16::Groth16;
        use ark_snark::SNARK;

        // Use FIXED seed for consistent parameters
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(12346);
        let (pk, _vk) = Groth16::<Bn254>::circuit_specific_setup(
            ObjectCreationCircuit {
                creator_role: None,
                min_creation_role: None,
                object_seed: None,
                new_object_root: None,
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
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(12346);
        let (_pk, vk) = Groth16::<Bn254>::circuit_specific_setup(
            ObjectCreationCircuit {
                creator_role: None,
                min_creation_role: None,
                object_seed: None,
                new_object_root: None,
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
    fn test_object_creation_proof() {
        let mut rng = OsRng;
        let creator_role = 5u8;
        let min_creation_role = 3u8;
        let object_seed = Fr::rand(&mut rng);

        // The circuit expects: new_object_root = object_seed + creator_role
        let new_object_root = &object_seed + &Fr::from(creator_role as u64);

        // Generate proof
        let proof = ObjectCreationProver::prove_creation(
            creator_role,
            min_creation_role,
            object_seed,
            new_object_root.clone(),
        )
        .expect("Object proof generation failed");

        // Create a slice from the proof data
        let proof_slice = &proof.data[..proof.len as usize];

        // Verify proof
        let is_valid =
            ObjectCreationProver::verify_creation(min_creation_role, &new_object_root, proof_slice)
                .expect("Object verification failed");

        assert!(is_valid, "Object creation proof should be valid");
    }
}
