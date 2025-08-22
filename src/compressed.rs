use crate::{XaeroCredential, XaeroID};

// Only public data for QR codes
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct XaeroPublicData {
    pub did_peer: [u8; 897], // Public key
    pub did_peer_len: u16,
    pub credential: XaeroCredential, // VC + ZK proofs (public)
    pub timestamp: u64,              // For freshness/versioning
    pub _pad: [u8; 6],               // Alignment
}

unsafe impl bytemuck::Pod for XaeroPublicData {}
unsafe impl bytemuck::Zeroable for XaeroPublicData {}

pub trait Compressor {
    fn compress_public(&self, xaero_id: &XaeroID) -> Vec<u8>;
    fn decompress_public(&self, compressed: &[u8]) -> Option<XaeroPublicData>;

    // Full compression (for secure sync between devices)
    fn compress_full(&self, xaero_id: &XaeroID) -> Vec<u8>;
    fn decompress_full(&self, compressed: &[u8]) -> Option<XaeroID>;
}

pub struct XaeroCompressor;

impl Compressor for XaeroCompressor {
    fn compress_public(&self, xaero_id: &XaeroID) -> Vec<u8> {
        let public_data = XaeroPublicData {
            did_peer: xaero_id.did_peer,
            did_peer_len: xaero_id.did_peer_len,
            credential: xaero_id.credential,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            _pad: [0; 6],
        };

        let public_bytes = bytemuck::bytes_of(&public_data);
        lz4_flex::compress_prepend_size(public_bytes)
    }

    fn decompress_public(&self, compressed: &[u8]) -> Option<XaeroPublicData> {
        let decompressed = lz4_flex::decompress_size_prepended(compressed).ok()?;

        if decompressed.len() == std::mem::size_of::<XaeroPublicData>() {
            Some(*bytemuck::from_bytes(&decompressed))
        } else {
            None
        }
    }

    // Full compression for secure device-to-device sync
    fn compress_full(&self, xaero_id: &XaeroID) -> Vec<u8> {
        let xaero_id_bytes = bytemuck::bytes_of(xaero_id);
        lz4_flex::compress_prepend_size(xaero_id_bytes)
    }

    fn decompress_full(&self, compressed: &[u8]) -> Option<XaeroID> {
        let decompressed = lz4_flex::decompress_size_prepended(compressed).ok()?;

        if decompressed.len() == std::mem::size_of::<XaeroID>() {
            Some(*bytemuck::from_bytes(&decompressed))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{identity::XaeroIdentityManager, IdentityManager};

    #[test]
    fn test_public_compression_roundtrip() {
        let manager = XaeroIdentityManager {};
        let xaero_id = manager.new_id();
        let compressor = XaeroCompressor;

        // Compress public data
        let compressed = compressor.compress_public(&xaero_id);

        // Should be smaller than full XaeroID
        assert!(compressed.len() < std::mem::size_of::<XaeroID>());

        // Decompress and verify
        let public_data = compressor.decompress_public(&compressed).unwrap();

        assert_eq!(public_data.did_peer_len, xaero_id.did_peer_len);
        assert_eq!(public_data.did_peer, xaero_id.did_peer);
        assert_eq!(
            public_data.credential.proof_count,
            xaero_id.credential.proof_count
        );
    }

    #[test]
    fn test_full_compression_roundtrip() {
        let manager = XaeroIdentityManager {};
        let original = manager.new_id();
        let compressor = XaeroCompressor;

        let compressed = compressor.compress_full(&original);
        let restored = compressor.decompress_full(&compressed).unwrap();

        // Should be identical
        assert_eq!(original.did_peer_len, restored.did_peer_len);
        assert_eq!(original.secret_key, restored.secret_key);
    }

    #[test]
    fn test_compression_size_difference() {
        let manager = XaeroIdentityManager {};
        let xaero_id = manager.new_id();
        let compressor = XaeroCompressor;

        let public_compressed = compressor.compress_public(&xaero_id);
        let full_compressed = compressor.compress_full(&xaero_id);

        println!("Original size: {} bytes", std::mem::size_of::<XaeroID>());
        println!("Public compressed: {} bytes", public_compressed.len());
        println!("Full compressed: {} bytes", full_compressed.len());

        // Public should be significantly smaller
        assert!(public_compressed.len() < full_compressed.len());
    }
}
