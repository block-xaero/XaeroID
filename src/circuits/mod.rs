use ark_bn254::Bn254;
use ark_groth16::ProvingKey;

pub mod delegation_circuit;
pub mod invitation_circuit;
pub mod membership_circuit;
pub(crate) mod object_circuit;
pub mod role_circuit;
pub mod workspace_circuit;

use rand::rngs::OsRng;

use crate::zk_proofs::ProofBytes;

pub trait Circuit {
    type PublicInputs;
    type PrivateInputs;
    fn setup(rng: &mut OsRng) -> Result<ProvingKey<Bn254>, Box<dyn std::error::Error>>;

    fn generate_proof(
        private_inputs: Self::PrivateInputs,
        public_inputs: Self::PublicInputs,
    ) -> Result<ProofBytes, Box<dyn std::error::Error>>;

    fn verify_proof(
        proof: ProofBytes,
        public_inputs: Self::PublicInputs,
        proof_bytes: ProofBytes,
    ) -> Result<(), Box<dyn std::error::Error>>;
}
