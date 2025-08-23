// Add these functions to your ffi.rs

use std::ffi::c_char;

use crate::{compressed::XaeroPublicData, identity::XaeroIdentityManager, IdentityManager, XaeroID};

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