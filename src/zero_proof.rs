use rkyv::{Archive, Deserialize, Serialize};
use xaeroflux::core::XaeroData;

#[repr(C)]
#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
#[rkyv(derive(Debug))]
pub struct ZeroProof {
    pub payload: Vec<u8>,
    pub journal: Vec<u8>,
    pub seal: Vec<u32>,
}

pub trait ZeroProofMarker {}

impl ZeroProofMarker for ZeroProof {}

