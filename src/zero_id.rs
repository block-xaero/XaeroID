use rkyv::{Archive, Deserialize, Serialize};

#[repr(C)]
#[derive(Debug, Clone, Archive, Serialize, Deserialize, PartialEq, Eq)]
#[rkyv(derive(Debug))]
pub struct ZeroId {
    pub did_peer: [u8; 512],
    pub pubkey: [u8; 64],
    pub signature: [u8; 64],
}
impl Default for ZeroId {
    fn default() -> Self {
        Self::new()
    }
}

impl ZeroId {
    pub fn new() -> Self {
        ZeroId {
            did_peer: [0; 512],
            pubkey: [0; 64],
            signature: [0; 64],
        }
    }
}
impl From<&str> for ZeroId {
    fn from(value: &str) -> Self {
        let bytes: &[u8] = value.as_bytes();
        let did_peer = bytes[..512].try_into().unwrap_or_else(|_| {
            panic!(
                "Slice with length {} does not fit into array of length {}",
                bytes.len(),
                512
            )
        });
        let pubkey: [u8; 64] = bytes[512..576].try_into().unwrap_or_else(|_| {
            panic!(
                "Slice with length {} does not fit into array of length {}",
                bytes.len(),
                64
            )
        });
        let signature: [u8; 64] = bytes[576..640].try_into().unwrap_or_else(|_| {
            panic!(
                "Slice with length {} does not fit into array of length {}",
                bytes.len(),
                64
            )
        });
        ZeroId {
            did_peer,
            pubkey,
            signature,
        }
    }
}
