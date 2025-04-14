use std::cmp::Ordering;

use serde::{Deserialize, Serialize};
use ssi::crypto::k256::sha2::digest::typenum::Zero;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[repr(C)]
pub struct ZeroId {
    #[serde(with = "serde_arrays")]
    pub did_peer: [u8; 512],
    #[serde(with = "serde_arrays")]
    pub pubkey: [u8; 64],
    #[serde(with = "serde_arrays")]
    pub signature: [u8; 64],
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
        let did_peer = bytes[..512].try_into().expect(
            format!(
                "Slice with length {} does not fit into array of length {}",
                bytes.len(),
                512
            )
            .as_str(),
        );
        let pubkey: [u8; 64] = bytes[512..576].try_into().expect(
            format!(
                "Slice with length {} does not fit into array of length {}",
                bytes.len(),
                64
            )
            .as_str(),
        );
        let signature: [u8; 64] = bytes[576..640].try_into().expect(
            format!(
                "Slice with length {} does not fit into array of length {}",
                bytes.len(),
                64
            )
            .as_str(),
        );
        ZeroId {
            did_peer,
            pubkey,
            signature,
        }
    }
}
