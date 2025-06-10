use ark_bn254::{Bn254, Fr};
use ark_groth16::Proof;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use bytemuck::Zeroable;

use crate::zk_proofs::ProofBytes;

/// Circuit that proves: my_role >= min_role without revealing my_role
#[derive(Clone)]
pub struct RoleCircuit {
    /// Private: the user's actual role level
    pub my_role: Option<u8>,
    /// Public: minimum required role level
    pub min_role: Option<u8>,
}

impl ConstraintSynthesizer<Fr> for RoleCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate private input: my_role
        let my_role_var = FpVar::new_witness(cs.clone(), || {
            self.my_role
                .map(|r| Fr::from(r as u64))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate public input: min_role
        let min_role_var = FpVar::new_input(cs.clone(), || {
            self.min_role
                .map(|r| Fr::from(r as u64))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Constraint: my_role >= min_role
        // We compute difference = my_role - min_role and ensure it's >= 0
        let difference = &my_role_var - &min_role_var;

        // For simplicity, we'll constrain that difference can be represented as 8 bits
        // This means roles are in range 0-255 and difference is 0-255
        let difference_bits = difference.to_bits_le()?;

        // Ensure only 8 bits are used (roles 0-255)
        for i in 8..difference_bits.len() {
            difference_bits[i].enforce_equal(&Boolean::constant(false))?;
        }

        Ok(())
    }
}

/// Arkworks-based implementation for role proofs
pub struct ArkRoleProver;

// In a real implementation, these would be generated once in a trusted setup
// For testing, we'll use a fixed seed to ensure deterministic parameters
fn get_test_parameters() -> Result<
    (
        ark_groth16::ProvingKey<Bn254>,
        ark_groth16::VerifyingKey<Bn254>,
    ),
    Box<dyn std::error::Error>,
> {
    use ark_groth16::Groth16;
    use ark_snark::SNARK;
    use ark_std::rand::SeedableRng;

    // Use a fixed seed for deterministic parameters in tests
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(12345);

    let setup_circuit = RoleCircuit {
        my_role: None,
        min_role: None,
    };

    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(setup_circuit, &mut rng)?;
    Ok((pk, vk))
}

impl ArkRoleProver {
    /// Generate a Groth16 proof that user's role >= min_role
    pub fn prove_role_groth16(
        my_role: u8,
        min_role: u8,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        use ark_groth16::Groth16;
        use ark_snark::SNARK;
        use ark_std::rand::SeedableRng;

        let (pk, _vk) = get_test_parameters()?;

        // Create circuit instance with actual values
        let circuit = RoleCircuit {
            my_role: Some(my_role),
            min_role: Some(min_role),
        };

        // Use a random seed for proof generation
        let mut rng = rand_chacha::ChaCha8Rng::from_entropy();

        // Generate proof
        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng)?;

        // Serialize proof to bytes
        let mut proof_bytes = Vec::new();
        ark_serialize::CanonicalSerialize::serialize_compressed(&proof, &mut proof_bytes)?;

        Ok(proof_bytes)
    }

    /// Verify a Groth16 role proof
    pub fn verify_role_groth16(
        min_role: u8,
        proof_bytes: &[u8],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        use ark_groth16::Groth16;
        use ark_serialize::CanonicalDeserialize;
        use ark_snark::SNARK;

        let (_pk, vk) = get_test_parameters()?;

        // Deserialize proof
        let proof = Proof::deserialize_compressed(&mut &proof_bytes[..])?;

        // Public inputs (just min_role in our case)
        let min_role_fr = Fr::from(min_role as u64);
        let public_inputs = vec![min_role_fr];

        // Verify proof
        let is_valid = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof)?;

        Ok(is_valid)
    }
}

/// Helper functions that you can call from your existing XaeroProofs implementation
impl ArkRoleProver {
    /// Generate a Groth16 role proof and return as ProofBytes
    pub fn prove_role_to_bytes(my_role: u8, min_role: u8) -> ProofBytes {
        match Self::prove_role_groth16(my_role, min_role) {
            Ok(proof_vec) => {
                let mut proof = ProofBytes::zeroed();
                let len = proof_vec.len().min(crate::zk_proofs::MAX_PROOF_BYTES);
                proof.data[..len].copy_from_slice(&proof_vec[..len]);
                proof.len = len as u16;
                proof
            }
            Err(_) => {
                // Return empty proof on error
                ProofBytes::zeroed()
            }
        }
    }

    /// Verify a Groth16 role proof from ProofBytes
    pub fn verify_role_from_bytes(min_role: u8, proof: &ProofBytes) -> bool {
        if proof.len == 0 {
            return false;
        }

        let proof_slice = &proof.data[..proof.len as usize];
        Self::verify_role_groth16(min_role, proof_slice).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arkworks_role_proof() {
        // Test valid role
        let proof = ArkRoleProver::prove_role_groth16(5, 3).expect("proof generation failed");
        assert!(ArkRoleProver::verify_role_groth16(3, &proof).expect("verification failed"));

        // Test that proof doesn't verify for higher minimum
        assert!(!ArkRoleProver::verify_role_groth16(6, &proof).expect("verification failed"));
    }

    #[test]
    fn test_proof_bytes_conversion() {
        // Test the ProofBytes conversion functions
        let proof_bytes = ArkRoleProver::prove_role_to_bytes(7, 4);
        assert!(proof_bytes.len > 0);
        assert!(ArkRoleProver::verify_role_from_bytes(4, &proof_bytes));
        assert!(!ArkRoleProver::verify_role_from_bytes(8, &proof_bytes));
    }
}
