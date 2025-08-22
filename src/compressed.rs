use crate::XaeroID;

// LZ4 compression is variable-length output, so we need a buffer
pub const MAX_COMPRESSED_SIZE: usize = std::mem::size_of::<XaeroID>() + 256; // Extra space for LZ4 overhead

pub trait Compressor {
    fn compress(&self, xaero_id: &XaeroID) -> Vec<u8>; // Variable length output
    fn decompress(&self, compressed: &[u8]) -> Option<XaeroID>;
}

pub struct XaeroCompressor;

impl Compressor for XaeroCompressor {
    fn compress(&self, xaero_id: &XaeroID) -> Vec<u8> {
        let xaero_id_bytes = bytemuck::bytes_of(xaero_id);
        lz4_flex::compress_prepend_size(xaero_id_bytes) // Includes size prefix
    }

    fn decompress(&self, compressed: &[u8]) -> Option<XaeroID> {
        let decompressed = lz4_flex::decompress_size_prepended(compressed).ok()?;

        if decompressed.len() == std::mem::size_of::<XaeroID>() {
            Some(*bytemuck::from_bytes(&decompressed))
        } else {
            None
        }
    }
}

// FFI-friendly fixed-size version if you need it
#[repr(C)]
pub struct CompressedXaeroID {
    pub data: [u8; MAX_COMPRESSED_SIZE],
    pub actual_size: u16,
}

impl XaeroCompressor {
    pub fn compress_fixed_size(&self, xaero_id: &XaeroID) -> Option<CompressedXaeroID> {
        let compressed = self.compress(xaero_id);

        if compressed.len() <= MAX_COMPRESSED_SIZE {
            let mut result = CompressedXaeroID {
                data: [0; MAX_COMPRESSED_SIZE],
                actual_size: compressed.len() as u16,
            };
            result.data[..compressed.len()].copy_from_slice(&compressed);
            Some(result)
        } else {
            None // Compression failed to fit in buffer
        }
    }
}