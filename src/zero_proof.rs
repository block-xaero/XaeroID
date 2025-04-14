use risc0_zkvm::Receipt;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ZeroProof {
    pub timestamp: u64,
    pub proof: Receipt,
}
