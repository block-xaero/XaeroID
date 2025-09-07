use ark_bn254::{Bn254, Fr};
use ark_groth16::Proof;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use bytemuck::Zeroable;
use rand::SeedableRng;

use crate::zk_proofs::ProofBytes;

/// Circuit for delegating roles/permissions without revealing delegator identity
pub struct DelegationCircuit {
    // Private inputs
    delegator_role: Option<u8>,       // Delegator's current role level
    delegator_token: Option<Fr>,      // Delegator's membership token
    delegation_nonce: Option<Fr>,     // Random nonce for this delegation

    // Public inputs
    pub target_xaero_id: Option<Fr>,  // Who receives the delegation
    pub target_role: Option<u8>,      // Role being granted
    pub min_delegation_role: Option<u8>, // Minimum role needed to delegate
    pub delegation_commitment: Option<Fr>, // Commitment to this delegation
    pub group_id: Option<Fr>,         // Group context for delegation
}

#[allow(clippy::needless_range_loop)]
impl ConstraintSynthesizer<Fr> for DelegationCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate private inputs
        let delegator_role = FpVar::new_witness(cs.clone(), || {
            self.delegator_role
                .map(|r| Fr::from(r as u64))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let delegator_token = FpVar::new_witness(cs.clone(), || {
            self.delegator_token.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let delegation_nonce = FpVar::new_witness(cs.clone(), || {
            self.delegation_nonce.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate public inputs
        let target_xaero_id = FpVar::new_input(cs.clone(), || {
            self.target_xaero_id.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let target_role = FpVar::new_input(cs.clone(), || {
            self.target_role
                .map(|r| Fr::from(r as u64))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let min_delegation_role = FpVar::new_input(cs.clone(), || {
            self.min_delegation_role
                .map(|r| Fr::from(r as u64))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let delegation_commitment = FpVar::new_input(cs.clone(), || {
            self.delegation_commitment.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let group_id = FpVar::new_input(cs.clone(), || {
            self.group_id.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Constraint 1: Delegator has sufficient role
        // delegator_role >= min_delegation_role
        let role_difference = &delegator_role - &min_delegation_role;
        let difference_bits = role_difference.to_bits_le()?;
        for i in 8..difference_bits.len() {
            difference_bits[i].enforce_equal(&Boolean::constant(false))?;
        }

        // Constraint 2: Delegator can grant up to their own level
        // delegator_role >= target_role
        let grant_difference = &delegator_role - &target_role;
        let grant_bits = grant_difference.to_bits_le()?;
        for i in 8..grant_bits.len() {
            grant_bits[i].enforce_equal(&Boolean::constant(false))?;
        }

        // Constraint 3: Verify delegation commitment
        // commitment = H(delegator_token || target_xaero_id || target_role || nonce || group_id)
        // Simplified: commitment = delegator_token + target_xaero_id * target_role + nonce * group_id
        let computed_commitment = &delegator_token +
            &target_xaero_id * &target_role +
            &delegation_nonce * &group_id;
        computed_commitment.enforce_equal(&delegation_commitment)?;

        Ok(())
    }
}

pub struct DelegationProver;

impl DelegationProver {
    /// Create a delegation proof
    pub fn create_delegation(
        delegator_role: u8,
        delegator_token: Fr,  // From their membership proof
        target_xaero_id: Fr,
        target_role: u8,
        min_delegation_role: u8,
        group_id: Fr,
    ) -> Result<(Fr, ProofBytes), Box<dyn std::error::Error>> {
        use ark_std::UniformRand;
        use rand::rngs::OsRng;

        let mut rng = OsRng;
        let delegation_nonce = Fr::rand(&mut rng);

        // Compute delegation commitment
        let delegation_commitment = delegator_token +
            target_xaero_id * Fr::from(target_role as u64) +
            delegation_nonce * group_id;

        let circuit = DelegationCircuit {
            delegator_role: Some(delegator_role),
            delegator_token: Some(delegator_token),
            delegation_nonce: Some(delegation_nonce),
            target_xaero_id: Some(target_xaero_id),
            target_role: Some(target_role),
            min_delegation_role: Some(min_delegation_role),
            delegation_commitment: Some(delegation_commitment),
            group_id: Some(group_id),
        };

        let proof = Self::generate_proof_internal(circuit)?;
        Ok((delegation_commitment, proof))
    }

    /// Verify a delegation proof
    pub fn verify_delegation(
        target_xaero_id: &Fr,
        target_role: u8,
        min_delegation_role: u8,
        delegation_commitment: &Fr,
        group_id: &Fr,
        proof_bytes: &[u8],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let public_inputs = vec![
            *target_xaero_id,
            Fr::from(target_role as u64),
            Fr::from(min_delegation_role as u64),
            *delegation_commitment,
            *group_id,
        ];

        Self::verify_proof_internal(public_inputs, proof_bytes)
    }

    fn generate_proof_internal(
        circuit: DelegationCircuit,
    ) -> Result<ProofBytes, Box<dyn std::error::Error>> {
        use ark_groth16::Groth16;
        use ark_snark::SNARK;

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(12349);
        let (pk, _vk) = Groth16::<Bn254>::circuit_specific_setup(
            DelegationCircuit {
                delegator_role: None,
                delegator_token: None,
                delegation_nonce: None,
                target_xaero_id: None,
                target_role: None,
                min_delegation_role: None,
                delegation_commitment: None,
                group_id: None,
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

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(12349);
        let (_pk, vk) = Groth16::<Bn254>::circuit_specific_setup(
            DelegationCircuit {
                delegator_role: None,
                delegator_token: None,
                delegation_nonce: None,
                target_xaero_id: None,
                target_role: None,
                min_delegation_role: None,
                delegation_commitment: None,
                group_id: None,
            },
            &mut rng,
        )?;

        let proof = Proof::deserialize_compressed(&mut &proof_bytes[..])?;
        let is_valid = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof)?;

        Ok(is_valid)
    }
}

/// Helper struct for tracking delegation chains
#[derive(Clone)]
pub struct DelegationChain {
    pub delegations: Vec<DelegationRecord>,
    pub max_depth: u8,  // Prevent infinite delegation chains
}

#[derive(Clone)]
pub struct DelegationRecord {
    pub target_xaero_id: Fr,
    pub role: u8,
    pub delegation_commitment: Fr,
    pub proof: ProofBytes,
    pub timestamp: u64,
    pub group_id: Fr,
}

impl DelegationChain {
    pub fn new(max_depth: u8) -> Self {
        Self {
            delegations: Vec::new(),
            max_depth,
        }
    }

    pub fn add_delegation(&mut self, record: DelegationRecord) -> Result<(), &'static str> {
        if self.delegations.len() >= self.max_depth as usize {
            return Err("Delegation chain too deep");
        }

        // Verify role is not increasing (can only delegate equal or lower)
        if let Some(last) = self.delegations.last() {
            if record.role > last.role {
                return Err("Cannot delegate higher role than possessed");
            }
        }

        self.delegations.push(record);
        Ok(())
    }

    pub fn verify_chain(&self, group_id: Fr) -> Result<bool, Box<dyn std::error::Error>> {
        // Verify each delegation in the chain
        for (i, record) in self.delegations.iter().enumerate() {
            let min_role = if i == 0 { 1 } else { self.delegations[i-1].role };

            let proof_slice = &record.proof.data[..record.proof.len as usize];
            let is_valid = DelegationProver::verify_delegation(
                &record.target_xaero_id,
                record.role,
                min_role,
                &record.delegation_commitment,
                &group_id,
                proof_slice,
            )?;

            if !is_valid {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::UniformRand;
    use rand::rngs::OsRng;

    #[test]
    fn test_delegation_proof() {
        let mut rng = OsRng;

        // Setup
        let delegator_role = 5u8;  // Admin level
        let delegator_token = Fr::rand(&mut rng);  // From membership proof
        let target_xaero_id = Fr::from(12345u64);
        let target_role = 3u8;  // Moderator level
        let min_delegation_role = 4u8;  // Need at least level 4 to delegate
        let group_id = Fr::from(42u64);

        // Create delegation
        let (commitment, proof) = DelegationProver::create_delegation(
            delegator_role,
            delegator_token,
            target_xaero_id,
            target_role,
            min_delegation_role,
            group_id,
        ).expect("Failed to create delegation");

        // Verify delegation
        let proof_slice = &proof.data[..proof.len as usize];
        let is_valid = DelegationProver::verify_delegation(
            &target_xaero_id,
            target_role,
            min_delegation_role,
            &commitment,
            &group_id,
            proof_slice,
        ).expect("Verification failed");

        assert!(is_valid, "Delegation proof should be valid");

        // Try to verify with wrong target (should fail)
        let wrong_target = Fr::from(99999u64);
        let invalid = DelegationProver::verify_delegation(
            &wrong_target,
            target_role,
            min_delegation_role,
            &commitment,
            &group_id,
            proof_slice,
        ).expect("Verification failed");

        assert!(!invalid, "Proof should not verify for different target");
    }

    #[test]
    fn test_delegation_chain() {
        let mut rng = OsRng;
        let group_id = Fr::from(42u64);

        let mut chain = DelegationChain::new(3);

        // First delegation: role 5 -> role 4
        let record1 = DelegationRecord {
            target_xaero_id: Fr::from(100u64),
            role: 4,
            delegation_commitment: Fr::rand(&mut rng),
            proof: ProofBytes::zeroed(),  // Would be real proof
            timestamp: 1000,
            group_id,
        };

        // Second delegation: role 4 -> role 3
        let record2 = DelegationRecord {
            target_xaero_id: Fr::from(200u64),
            role: 3,
            delegation_commitment: Fr::rand(&mut rng),
            proof: ProofBytes::zeroed(),
            timestamp: 2000,
            group_id,
        };

        assert!(chain.add_delegation(record1).is_ok());
        assert!(chain.add_delegation(record2).is_ok());

        // Try to delegate higher role (should fail)
        let bad_record = DelegationRecord {
            target_xaero_id: Fr::from(300u64),
            role: 5,  // Higher than previous!
            delegation_commitment: Fr::rand(&mut rng),
            proof: ProofBytes::zeroed(),
            timestamp: 3000,
            group_id,
        };

        assert!(chain.add_delegation(bad_record).is_err());
    }
}