use rkyv::{Archive, Deserialize, Serialize};

#[repr(C)]
#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
#[rkyv(derive(Debug))]
pub struct ZeroProof {
    pub payload: Vec<u8>,
    pub journal: Vec<u8>,
    pub seal: Vec<u32>,
}
