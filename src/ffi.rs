// Add these functions to your ffi.rs

use std::ffi::c_char;

use crate::{
    compressed::XaeroPublicData, identity::XaeroIdentityManager, IdentityManager, XaeroID,
};

// Generate new XaeroID
#[unsafe(no_mangle)]
pub extern "C" fn xaero_generate_id(out_xid: *mut XaeroID) -> bool {
    if out_xid.is_null() {
        return false;
    }

    let manager = XaeroIdentityManager {};
    let xid = manager.new_id();

    unsafe {
        *out_xid = xid;
    }

    true
}

// Get the size of XaeroID for Swift buffer allocation
#[unsafe(no_mangle)]
pub extern "C" fn xaero_get_id_size() -> usize {
    std::mem::size_of::<XaeroID>()
}

// Get the size of XaeroPublicData for Swift buffer allocation
#[unsafe(no_mangle)]
pub extern "C" fn xaero_get_public_data_size() -> usize {
    std::mem::size_of::<XaeroPublicData>()
}

// Check if XaeroID has any credentials/proofs
#[unsafe(no_mangle)]
pub extern "C" fn xaero_has_credentials(xid: *const XaeroID) -> bool {
    if xid.is_null() {
        return false;
    }

    let xid = unsafe { &*xid };
    xid.credential.proof_count > 0
}

// Add a basic identity proof to XaeroID (for first-time setup)
#[unsafe(no_mangle)]
pub extern "C" fn xaero_add_identity_proof(
    xid: *mut XaeroID,
    challenge: *const u8,
    challenge_len: usize,
) -> bool {
    if xid.is_null() || challenge.is_null() {
        return false;
    }

    let xid_mut = unsafe { &mut *xid };
    let challenge_slice = unsafe { std::slice::from_raw_parts(challenge, challenge_len) };

    // Generate identity proof using XaeroProofs trait
    use crate::zk_proofs::XaeroProofs;
    let proof_bytes = xid_mut.prove_identity(challenge_slice);

    // Add to credential proofs if there's space
    if (xid_mut.credential.proof_count as usize) < crate::MAX_PROOFS {
        let proof_index = xid_mut.credential.proof_count as usize;

        // Store first 32 bytes of proof as XaeroProof
        let mut zk_proof = [0u8; 32];
        let copy_len = proof_bytes.len.min(32) as usize;
        zk_proof[..copy_len].copy_from_slice(&proof_bytes.data[..copy_len]);

        xid_mut.credential.proofs[proof_index] = crate::XaeroProof { zk_proof };
        xid_mut.credential.proof_count += 1;

        true
    } else {
        false
    }
}

// Get basic info about XaeroID (DID length, proof count, etc.)
#[unsafe(no_mangle)]
pub extern "C" fn xaero_get_info(
    xid: *const XaeroID,
    out_did_len: *mut u16,
    out_proof_count: *mut u8,
    out_has_secret_key: *mut bool,
) -> bool {
    if xid.is_null()
        || out_did_len.is_null()
        || out_proof_count.is_null()
        || out_has_secret_key.is_null()
    {
        return false;
    }

    let xid = unsafe { &*xid };

    unsafe {
        *out_did_len = xid.did_peer_len;
        *out_proof_count = xid.credential.proof_count;
        *out_has_secret_key = xid.secret_key.iter().any(|&b| b != 0);
    }

    true
}

// Extract DID string (for display purposes)
#[unsafe(no_mangle)]
pub extern "C" fn xaero_get_did_string(
    xid: *const XaeroID,
    out_buffer: *mut c_char,
    buffer_len: usize,
) -> bool {
    if xid.is_null() || out_buffer.is_null() {
        return false;
    }

    let xid = unsafe { &*xid };

    // Convert to did:peer string
    let did_bytes = &xid.did_peer[..xid.did_peer_len as usize];
    let did_array: [u8; 897] = match did_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return false,
    };

    let did_string = crate::identity::encode_peer_did(&did_array);
    let did_cstring = match std::ffi::CString::new(did_string) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let did_bytes = did_cstring.as_bytes_with_nul();
    if did_bytes.len() > buffer_len {
        return false;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(
            did_bytes.as_ptr() as *const c_char,
            out_buffer,
            did_bytes.len(),
        );
    }
    true
}

// Add these compression functions to your ffi.rs

use crate::compressed::{XaeroCompressor, Compressor};

// Compress XaeroID public data for QR code
#[unsafe(no_mangle)]
pub extern "C" fn xaero_compress_public(
    xid: *const XaeroID,
    out_buffer: *mut u8,
    buffer_capacity: usize,
    actual_size: *mut usize
) -> bool {
    if xid.is_null() || out_buffer.is_null() || actual_size.is_null() {
        return false;
    }

    let xid = unsafe { &*xid };
    let compressor = XaeroCompressor;
    let compressed = compressor.compress_public(xid);

    if compressed.len() > buffer_capacity {
        return false;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(
            compressed.as_ptr(),
            out_buffer,
            compressed.len()
        );
        *actual_size = compressed.len();
    }

    true
}

// Decompress public data from QR code
#[unsafe(no_mangle)]
pub extern "C" fn xaero_decompress_public(
    compressed: *const u8,
    compressed_len: usize,
    out_public_data: *mut XaeroPublicData
) -> bool {
    if compressed.is_null() || out_public_data.is_null() {
        return false;
    }

    let compressed_slice = unsafe {
        std::slice::from_raw_parts(compressed, compressed_len)
    };

    let compressor = XaeroCompressor;

    if let Some(public_data) = compressor.decompress_public(compressed_slice) {
        unsafe {
            *out_public_data = public_data;
        }
        true
    } else {
        false
    }
}

// Sign challenge with XaeroID
#[unsafe(no_mangle)]
pub extern "C" fn xaero_sign_challenge(
    xid: *const XaeroID,
    challenge: *const u8,
    challenge_len: usize,
    out_signature: *mut u8, // Must be at least 690 bytes for Falcon512
    signature_len: *mut usize
) -> bool {
    if xid.is_null() || challenge.is_null() || out_signature.is_null() || signature_len.is_null() {
        return false;
    }

    let xid = unsafe { &*xid };
    let challenge_slice = unsafe {
        std::slice::from_raw_parts(challenge, challenge_len)
    };

    let manager = XaeroIdentityManager {};
    let signature = manager.sign_challenge(xid, challenge_slice);

    unsafe {
        let copy_len = signature.len().min(690); // Falcon512 signature size
        std::ptr::copy_nonoverlapping(
            signature.as_ptr(),
            out_signature,
            copy_len
        );
        *signature_len = copy_len;
    }

    true
}

// Verify challenge signature
#[unsafe(no_mangle)]
pub extern "C" fn xaero_verify_challenge(
    xid: *const XaeroID,
    challenge: *const u8,
    challenge_len: usize,
    signature: *const u8,
    signature_len: usize
) -> bool {
    if xid.is_null() || challenge.is_null() || signature.is_null() {
        return false;
    }

    let xid = unsafe { &*xid };
    let challenge_slice = unsafe {
        std::slice::from_raw_parts(challenge, challenge_len)
    };
    let signature_slice = unsafe {
        std::slice::from_raw_parts(signature, signature_len)
    };

    let manager = XaeroIdentityManager {};
    manager.verify_challenge(xid, challenge_slice, signature_slice)
}

// Get maximum compressed size for buffer allocation
#[unsafe(no_mangle)]
pub extern "C" fn xaero_get_max_compressed_size() -> usize {
    // Conservative estimate: original size + compression overhead
    std::mem::size_of::<XaeroPublicData>() + 256
}

// Get Falcon512 signature size
#[unsafe(no_mangle)]
pub extern "C" fn xaero_get_signature_size() -> usize {
    690 // Falcon512 signature size
}

// Compress full XaeroID (for secure storage/sync)
#[unsafe(no_mangle)]
pub extern "C" fn xaero_compress_full(
    xid: *const XaeroID,
    out_buffer: *mut u8,
    buffer_capacity: usize,
    actual_size: *mut usize
) -> bool {
    if xid.is_null() || out_buffer.is_null() || actual_size.is_null() {
        return false;
    }

    let xid = unsafe { &*xid };
    let compressor = XaeroCompressor;
    let compressed = compressor.compress_full(xid);

    if compressed.len() > buffer_capacity {
        return false;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(
            compressed.as_ptr(),
            out_buffer,
            compressed.len()
        );
        *actual_size = compressed.len();
    }

    true
}

// Decompress full XaeroID (from secure storage/sync)
#[unsafe(no_mangle)]
pub extern "C" fn xaero_decompress_full(
    compressed: *const u8,
    compressed_len: usize,
    out_xid: *mut XaeroID
) -> bool {
    if compressed.is_null() || out_xid.is_null() {
        return false;
    }

    let compressed_slice = unsafe {
        std::slice::from_raw_parts(compressed, compressed_len)
    };

    let compressor = XaeroCompressor;

    if let Some(xid) = compressor.decompress_full(compressed_slice) {
        unsafe {
            *out_xid = xid;
        }
        true
    } else {
        false
    }
}
