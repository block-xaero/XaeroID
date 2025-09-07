use ark_bn254::{Bn254, Fr};
use ark_groth16::Proof;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use bytemuck::{Pod, Zeroable};
use rand::SeedableRng;

use crate::zk_proofs::ProofBytes;

/// Circuit that proves: I have role >= min_role for a specific XaeroID
#[derive(Clone)]
pub struct RoleCircuit {
    // Private inputs
    my_role: Option<u8>,         // User's actual role level
    role_token: Option<Fr>,      // Token proving role assignment
    role_randomness: Option<Fr>, // Blinding factor

    // Public inputs
    pub xaero_id: Option<Fr>,        // XaeroID this role is bound to
    pub group_id: Option<Fr>,        // Group context for the role
    pub min_role: Option<u8>,        // Minimum required role level
    pub role_commitment: Option<Fr>, // Commitment to role token
    pub issuer_pubkey: Option<Fr>,   // Who issued this role
}

#[allow(clippy::needless_range_loop)]
impl ConstraintSynthesizer<Fr> for RoleCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate private inputs
        let my_role_var = FpVar::new_witness(cs.clone(), || {
            self.my_role
                .map(|r| Fr::from(r as u64))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let role_token = FpVar::new_witness(cs.clone(), || {
            self.role_token.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let role_randomness = FpVar::new_witness(cs.clone(), || {
            self.role_randomness
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate public inputs
        let xaero_id = FpVar::new_input(cs.clone(), || {
            self.xaero_id.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let group_id = FpVar::new_input(cs.clone(), || {
            self.group_id.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let min_role_var = FpVar::new_input(cs.clone(), || {
            self.min_role
                .map(|r| Fr::from(r as u64))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let role_commitment = FpVar::new_input(cs.clone(), || {
            self.role_commitment
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let issuer_pubkey = FpVar::new_input(cs.clone(), || {
            self.issuer_pubkey.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Constraint 1: my_role >= min_role
        let difference = &my_role_var - &min_role_var;
        let difference_bits = difference.to_bits_le()?;
        for i in 8..difference_bits.len() {
            difference_bits[i].enforce_equal(&Boolean::constant(false))?;
        }

        // Constraint 2: Role token is correctly formed
        // role_token = H(xaero_id || group_id || my_role || issuer_pubkey)
        // Simplified: role_token = xaero_id + group_id * my_role + issuer_pubkey
        let computed_token = &xaero_id + &group_id * &my_role_var + &issuer_pubkey;
        computed_token.enforce_equal(&role_token)?;

        // Constraint 3: Verify commitment
        let computed_commitment = &role_token + &role_randomness;
        computed_commitment.enforce_equal(&role_commitment)?;

        Ok(())
    }
}

/// Role proof generation and verification
pub struct RoleProver;

impl RoleProver {
    /// Issue a role to a specific XaeroID
    pub fn issue_role(
        xaero_id: Fr,
        group_id: Fr,
        role_level: u8,
        issuer_secret: Fr,
    ) -> Result<(Fr, Fr, Fr), Box<dyn std::error::Error>> {
        use ark_std::UniformRand;
        use rand::rngs::OsRng;

        let mut rng = OsRng;
        let role_randomness = Fr::rand(&mut rng);

        // Derive issuer pubkey
        let issuer_pubkey = issuer_secret * issuer_secret; // Simplified

        // Generate role token bound to XaeroID
        let role_token = xaero_id + group_id * Fr::from(role_level as u64) + issuer_pubkey;

        // Create commitment
        let role_commitment = role_token + role_randomness;

        Ok((role_token, role_randomness, role_commitment))
    }

    /// Prove that you have sufficient role
    pub fn prove_role(
        xaero_id: Fr,
        group_id: Fr,
        my_role: u8,
        min_role: u8,
        role_token: Fr,
        role_randomness: Fr,
        role_commitment: Fr,
        issuer_pubkey: Fr,
    ) -> Result<ProofBytes, Box<dyn std::error::Error>> {
        let circuit = RoleCircuit {
            my_role: Some(my_role),
            role_token: Some(role_token),
            role_randomness: Some(role_randomness),
            xaero_id: Some(xaero_id),
            group_id: Some(group_id),
            min_role: Some(min_role),
            role_commitment: Some(role_commitment),
            issuer_pubkey: Some(issuer_pubkey),
        };

        Self::generate_proof_internal(circuit)
    }

    /// Verify a role proof
    pub fn verify_role(
        xaero_id: &Fr,
        group_id: &Fr,
        min_role: u8,
        role_commitment: &Fr,
        issuer_pubkey: &Fr,
        proof_bytes: &[u8],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let public_inputs = vec![
            *xaero_id,
            *group_id,
            Fr::from(min_role as u64),
            *role_commitment,
            *issuer_pubkey,
        ];

        Self::verify_proof_internal(public_inputs, proof_bytes)
    }

    fn generate_proof_internal(
        circuit: RoleCircuit,
    ) -> Result<ProofBytes, Box<dyn std::error::Error>> {
        use ark_groth16::Groth16;
        use ark_snark::SNARK;

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(12350);
        let (pk, _vk) = Groth16::<Bn254>::circuit_specific_setup(
            RoleCircuit {
                my_role: None,
                role_token: None,
                role_randomness: None,
                xaero_id: None,
                group_id: None,
                min_role: None,
                role_commitment: None,
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

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(12350);
        let (_pk, vk) = Groth16::<Bn254>::circuit_specific_setup(
            RoleCircuit {
                my_role: None,
                role_token: None,
                role_randomness: None,
                xaero_id: None,
                group_id: None,
                min_role: None,
                role_commitment: None,
                issuer_pubkey: None,
            },
            &mut rng,
        )?;

        let proof = Proof::deserialize_compressed(&mut &proof_bytes[..])?;
        let is_valid = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof)?;

        Ok(is_valid)
    }
}

/// Composite role credential for storage
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RoleCredential {
    pub xaero_id: [u8; 32],
    pub group_id: [u8; 32],
    pub role_level: u8,
    pub role_commitment: [u8; 32], // Fr serialized
    pub issuer_pubkey: [u8; 32],   // Fr serialized
    pub issued_at: u64,
    pub expires_at: u64,
    pub _padding: [u8; 7],
}

unsafe impl Pod for RoleCredential {}
unsafe impl Zeroable for RoleCredential {}

impl RoleCredential {
    pub fn new(
        xaero_id: [u8; 32],
        group_id: [u8; 32],
        role_level: u8,
        role_commitment: [u8; 32],
        issuer_pubkey: [u8; 32],
        issued_at: u64,
        expires_at: u64,
    ) -> Self {
        Self {
            xaero_id,
            group_id,
            role_level,
            role_commitment,
            issuer_pubkey,
            issued_at,
            expires_at,
            _padding: [0; 7],
        }
    }

    pub fn is_valid_at(&self, timestamp: u64) -> bool {
        timestamp >= self.issued_at && timestamp <= self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xaero_bound_role_proof() {
        // Setup
        let issuer_secret = Fr::from(999u64);
        let issuer_pubkey = issuer_secret * issuer_secret;

        let xaero_id = Fr::from(12345u64);
        let group_id = Fr::from(42u64);
        let my_role = 5u8;
        let min_role = 3u8;

        // Issue role
        let (role_token, role_randomness, role_commitment) =
            RoleProver::issue_role(xaero_id, group_id, my_role, issuer_secret)
                .expect("Failed to issue role");

        // Generate proof
        let proof = RoleProver::prove_role(
            xaero_id,
            group_id,
            my_role,
            min_role,
            role_token,
            role_randomness,
            role_commitment,
            issuer_pubkey,
        )
        .expect("Failed to generate proof");

        // Verify proof
        let proof_slice = &proof.data[..proof.len as usize];
        let is_valid = RoleProver::verify_role(
            &xaero_id,
            &group_id,
            min_role,
            &role_commitment,
            &issuer_pubkey,
            proof_slice,
        )
        .expect("Verification failed");

        assert!(is_valid, "Role proof should be valid");

        // Try to verify with different XaeroID (should fail)
        let wrong_xaero = Fr::from(99999u64);
        let invalid = RoleProver::verify_role(
            &wrong_xaero,
            &group_id,
            min_role,
            &role_commitment,
            &issuer_pubkey,
            proof_slice,
        )
        .expect("Verification failed");

        assert!(!invalid, "Proof should not verify for different XaeroID");

        // Try to verify with higher minimum (should fail)
        let too_high_min = 6u8;
        let invalid2 = RoleProver::verify_role(
            &xaero_id,
            &group_id,
            too_high_min,
            &role_commitment,
            &issuer_pubkey,
            proof_slice,
        )
        .expect("Verification failed");

        assert!(!invalid2, "Proof should not verify for role below minimum");
    }

    #[test]
    fn test_role_credential_pod() {
        let cred = RoleCredential::new([1u8; 32], [2u8; 32], 5, [3u8; 32], [4u8; 32], 1000, 2000);

        // Test POD serialization
        let bytes = bytemuck::bytes_of(&cred);
        let recovered: &RoleCredential = bytemuck::from_bytes(bytes);

        assert_eq!(recovered.role_level, 5);
        assert!(recovered.is_valid_at(1500));
        assert!(!recovered.is_valid_at(2001));
    }
}
