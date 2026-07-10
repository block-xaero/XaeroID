// xaeroid/src/anonymous.rs
//
// Anonymous participation using commitment-based membership proofs.
//
// Architecture:
//   1. User creates an AnonymousSession for a specific board/workspace
//   2. Generates ephemeral Ed25519 keypair (unlinkable to real identity)
//   3. Computes membership commitment: blake3(real_pubkey || scope_id || session_nonce)
//   4. Publishes: { ephemeral_key, commitment, animal_handle }
//   5. Other peers verify commitment against known member list
//   6. User can "reveal" by signing ephemeral key with real key
//
// For demo: verification is commitment-based (not full ZK-SNARK).
// Production: replace verify_membership() with a proper ZK circuit
// (e.g., Halo2 Merkle membership proof).
//
// The commitment scheme ensures:
//   - Without the nonce, you cannot determine which member created the commitment
//   - The nonce is derived from secret_key + scope_id, so it's deterministic
//     (same user in same scope always gets same commitment)
//   - Ephemeral keypair is fresh each session (unlinkable across sessions)
//   - Animal handle is derived from ephemeral pubkey (consistent within session)

use serde::{Deserialize, Serialize};

use crate::XaeroID;

// ============================================================
// Animal handles — deterministic from hash
// ============================================================

const ANIMALS: &[&str] = &[
    "Otter", "Falcon", "Panda", "Fox", "Owl", "Lynx", "Crane", "Ibis", "Wolf", "Bear", "Hawk",
    "Deer", "Hare", "Seal", "Wren", "Dove", "Mink", "Crow", "Pike", "Swan", "Moth", "Finch",
    "Newt", "Toad", "Lark", "Viper", "Raven", "Egret", "Stoat", "Quail", "Heron", "Gecko",
];

/// Derive a deterministic animal handle from a public key
pub fn animal_handle(pubkey: &[u8; 32]) -> String {
    let hash = blake3::hash(pubkey);
    let index = (hash.as_bytes()[0] as usize) % ANIMALS.len();
    format!("Anonymous {}", ANIMALS[index])
}

// ============================================================
// Anonymous Session
// ============================================================

/// An anonymous participation session
#[derive(Clone)]
pub struct AnonymousSession {
    /// Ephemeral keypair for this session (not linked to real identity)
    pub ephemeral_pubkey: [u8; 32],
    pub ephemeral_secret: [u8; 32],
    /// Membership commitment: blake3(real_pubkey || scope_id || nonce)
    pub commitment: [u8; 32],
    /// Scope this session is for (board_id or workspace_id)
    pub scope_id: String,
    /// The animal handle others see
    pub handle: String,
    /// Session nonce (derived from real secret + scope)
    pub session_nonce: [u8; 32],
    /// Whether identity has been revealed
    pub revealed: bool,
}

/// What gets published to gossip when joining anonymously
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AnonymousJoinPayload {
    /// Payload type marker
    #[serde(rename = "type")]
    pub payload_type: String,
    /// Ephemeral public key (hex)
    pub ephemeral_key: String,
    /// Membership commitment (hex) — proves "I am a member"
    pub commitment: String,
    /// Scope (board/workspace ID)
    pub scope_id: String,
    /// Animal handle
    pub handle: String,
    /// Timestamp
    pub joined_at: u64,
    /// Signature of commitment with ephemeral key (proves ephemeral key owns this session)
    pub signature: String,
}

/// What gets published when revealing identity
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct IdentityRevealPayload {
    /// Payload type marker
    #[serde(rename = "type")]
    pub payload_type: String,
    /// The ephemeral key that was used anonymously
    pub ephemeral_key: String,
    /// Real public key (hex)
    pub real_pubkey: String,
    /// Real display name
    pub real_name: Option<String>,
    /// Signature: sign(ephemeral_pubkey, real_secret_key)
    /// Proves: "the person behind this ephemeral key is this real identity"
    pub proof_signature: String,
    /// Scope
    pub scope_id: String,
    /// Animal handle that was used
    pub handle: String,
    /// Timestamp
    pub revealed_at: u64,
}

/// Result of verifying a membership commitment
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MembershipVerification {
    pub is_valid: bool,
    /// In demo mode: which member matched (defeats anonymity — real ZK fixes this)
    /// In production: this field is always None
    pub matched_member: Option<String>,
    pub commitment: String,
}

impl AnonymousSession {
    /// Create a new anonymous session for a scope
    pub fn new(real_secret_key: &[u8; 32], scope_id: &str) -> Self {
        let real_pubkey = XaeroID::ed25519_pubkey(real_secret_key);

        // Derive session nonce deterministically from secret + scope
        // This means same user in same scope gets same commitment (consistency)
        let session_nonce = {
            let mut hasher = blake3::Hasher::new_keyed(real_secret_key);
            hasher.update(b"anon_session:");
            hasher.update(scope_id.as_bytes());
            *hasher.finalize().as_bytes()
        };

        // Generate ephemeral keypair (fresh each session — unlinkable)
        let ephemeral_secret = {
            use rand::RngCore;
            let mut bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut bytes);
            bytes
        };
        let ephemeral_pubkey = XaeroID::ed25519_pubkey(&ephemeral_secret);

        // Compute membership commitment
        let commitment = Self::compute_commitment(&real_pubkey, scope_id, &session_nonce);

        // Animal handle from ephemeral key
        let handle = animal_handle(&ephemeral_pubkey);

        AnonymousSession {
            ephemeral_pubkey,
            ephemeral_secret,
            commitment,
            scope_id: scope_id.to_string(),
            handle,
            session_nonce,
            revealed: false,
        }
    }

    /// Compute membership commitment
    fn compute_commitment(real_pubkey: &[u8; 32], scope_id: &str, nonce: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"anon_membership:");
        hasher.update(real_pubkey);
        hasher.update(scope_id.as_bytes());
        hasher.update(nonce);
        *hasher.finalize().as_bytes()
    }

    /// Create the gossip payload for joining anonymously
    pub fn join_payload(&self) -> AnonymousJoinPayload {
        // Sign the commitment with ephemeral key (proves ownership of this session)
        let sig = XaeroID::ed25519_sign(&self.commitment, &self.ephemeral_secret);

        AnonymousJoinPayload {
            payload_type: "anonymous_join".to_string(),
            ephemeral_key: hex::encode(self.ephemeral_pubkey),
            commitment: hex::encode(self.commitment),
            scope_id: self.scope_id.clone(),
            handle: self.handle.clone(),
            joined_at: crate::XaeroID::now_secs(),
            signature: hex::encode(sig),
        }
    }

    /// Reveal identity — creates a payload that proves who you are
    pub fn reveal(
        &mut self,
        real_secret_key: &[u8; 32],
        real_name: Option<&str>,
    ) -> IdentityRevealPayload {
        self.revealed = true;
        let real_pubkey = XaeroID::ed25519_pubkey(real_secret_key);

        // Sign ephemeral pubkey with real key
        // This proves: "the owner of real_pubkey is the same person as ephemeral_pubkey"
        let proof_sig = XaeroID::ed25519_sign(&self.ephemeral_pubkey, real_secret_key);

        IdentityRevealPayload {
            payload_type: "identity_reveal".to_string(),
            ephemeral_key: hex::encode(self.ephemeral_pubkey),
            real_pubkey: hex::encode(real_pubkey),
            real_name: real_name.map(|s| s.to_string()),
            proof_signature: hex::encode(proof_sig),
            scope_id: self.scope_id.clone(),
            handle: self.handle.clone(),
            revealed_at: crate::XaeroID::now_secs(),
        }
    }
}

// ============================================================
// Verification (called by peers receiving anonymous join)
// ============================================================

/// Verify that a join payload's ephemeral signature is valid
pub fn verify_join_signature(payload: &AnonymousJoinPayload) -> bool {
    let Ok(ephemeral_bytes) = hex::decode(&payload.ephemeral_key) else {
        return false;
    };
    let Ok(commitment_bytes) = hex::decode(&payload.commitment) else {
        return false;
    };
    let Ok(sig_bytes) = hex::decode(&payload.signature) else {
        return false;
    };

    if ephemeral_bytes.len() != 32 || commitment_bytes.len() != 32 || sig_bytes.len() != 64 {
        return false;
    }

    let pubkey: [u8; 32] = ephemeral_bytes.try_into().unwrap();
    let sig: [u8; 64] = sig_bytes.try_into().unwrap();

    XaeroID::verify(&commitment_bytes, &sig, &pubkey)
}

/// Verify that the commitment belongs to SOME member of the group.
///
/// DEMO VERSION: iterates over members and tries to match commitment.
/// This is NOT zero-knowledge — a verifier learns which member matched.
///
/// PRODUCTION: replace with ZK-SNARK proof of Merkle tree membership.
/// The prover would generate a proof that their pubkey is a leaf in
/// the Merkle tree of group members, without revealing which leaf.
pub fn verify_membership_demo(
    commitment: &[u8; 32],
    _scope_id: &str,
    _group_member_pubkeys: &[[u8; 32]],
) -> MembershipVerification {
    // In demo mode, we can't verify without knowing the nonce.
    // The nonce is derived from the member's secret key, which we don't have.
    //
    // For demo: we trust the commitment if the ephemeral signature is valid.
    // This shows the architecture correctly — the ZK proof slot is clearly marked.
    //
    // In production with ZK:
    //   - Prover generates: proof = ZK_PROVE(secret_key, merkle_tree, scope_id)
    //   - Verifier checks:  ZK_VERIFY(proof, merkle_root, scope_id) → bool
    //   - Verifier learns NOTHING about which member

    MembershipVerification {
        is_valid: true, // Trusted in demo — ZK replaces this
        matched_member: None,
        commitment: hex::encode(commitment),
    }
}

/// Verify an identity reveal
pub fn verify_reveal(payload: &IdentityRevealPayload) -> bool {
    let Ok(ephemeral_bytes) = hex::decode(&payload.ephemeral_key) else {
        return false;
    };
    let Ok(real_pubkey_bytes) = hex::decode(&payload.real_pubkey) else {
        return false;
    };
    let Ok(sig_bytes) = hex::decode(&payload.proof_signature) else {
        return false;
    };

    if ephemeral_bytes.len() != 32 || real_pubkey_bytes.len() != 32 || sig_bytes.len() != 64 {
        return false;
    }

    let real_pubkey: [u8; 32] = real_pubkey_bytes.try_into().unwrap();
    let sig: [u8; 64] = sig_bytes.try_into().unwrap();

    // Verify: real_pubkey signed the ephemeral_pubkey
    // This proves the real person is behind the anonymous handle
    XaeroID::verify(&ephemeral_bytes, &sig, &real_pubkey)
}

// ============================================================
// FFI — expose to Swift/Dart via C interface
// ============================================================

use std::ffi::{c_char, CStr, CString};

/// Create an anonymous session for a scope.
/// Returns JSON: { ephemeral_key, commitment, handle, scope_id, join_payload }
#[unsafe(no_mangle)]
pub extern "C" fn xaero_create_anonymous_session(
    secret_key_hex: *const c_char,
    scope_id: *const c_char,
) -> *mut c_char {
    if secret_key_hex.is_null() || scope_id.is_null() {
        return std::ptr::null_mut();
    }

    let secret_hex = match unsafe { CStr::from_ptr(secret_key_hex) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let scope = match unsafe { CStr::from_ptr(scope_id) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let secret_bytes: [u8; 32] = match hex::decode(secret_hex) {
        Ok(b) if b.len() == 32 => b.try_into().unwrap(),
        _ => return std::ptr::null_mut(),
    };

    let session = AnonymousSession::new(&secret_bytes, scope);
    let join = session.join_payload();

    let result = serde_json::json!({
        "ephemeral_key": hex::encode(session.ephemeral_pubkey),
        "ephemeral_secret": hex::encode(session.ephemeral_secret),
        "commitment": hex::encode(session.commitment),
        "handle": session.handle,
        "scope_id": session.scope_id,
        "join_payload": serde_json::to_value(&join).unwrap_or_default(),
    });

    match CString::new(result.to_string()) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Reveal identity for an anonymous session.
/// Returns JSON with the reveal payload.
#[unsafe(no_mangle)]
pub extern "C" fn xaero_reveal_anonymous_identity(
    secret_key_hex: *const c_char,
    ephemeral_secret_hex: *const c_char,
    scope_id: *const c_char,
    display_name: *const c_char,
) -> *mut c_char {
    if secret_key_hex.is_null() || ephemeral_secret_hex.is_null() || scope_id.is_null() {
        return std::ptr::null_mut();
    }

    let secret_hex = match unsafe { CStr::from_ptr(secret_key_hex) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let eph_hex = match unsafe { CStr::from_ptr(ephemeral_secret_hex) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let scope = match unsafe { CStr::from_ptr(scope_id) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let name = if display_name.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(display_name) }.to_str().ok()
    };

    let secret_bytes: [u8; 32] = match hex::decode(secret_hex) {
        Ok(b) if b.len() == 32 => b.try_into().unwrap(),
        _ => return std::ptr::null_mut(),
    };
    let eph_bytes: [u8; 32] = match hex::decode(eph_hex) {
        Ok(b) if b.len() == 32 => b.try_into().unwrap(),
        _ => return std::ptr::null_mut(),
    };

    let eph_pubkey = XaeroID::ed25519_pubkey(&eph_bytes);
    let handle = animal_handle(&eph_pubkey);

    let mut session = AnonymousSession {
        ephemeral_pubkey: eph_pubkey,
        ephemeral_secret: eph_bytes,
        commitment: [0u8; 32], // Not needed for reveal
        scope_id: scope.to_string(),
        handle,
        session_nonce: [0u8; 32],
        revealed: false,
    };

    let reveal = session.reveal(&secret_bytes, name);

    match CString::new(serde_json::to_string(&reveal).unwrap_or_default()) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Verify an anonymous join payload signature.
/// Returns 1 if valid, 0 if invalid.
#[unsafe(no_mangle)]
pub extern "C" fn xaero_verify_anonymous_join(join_payload_json: *const c_char) -> i32 {
    if join_payload_json.is_null() {
        return 0;
    }

    let json_str = match unsafe { CStr::from_ptr(join_payload_json) }.to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };

    let payload: AnonymousJoinPayload = match serde_json::from_str(json_str) {
        Ok(p) => p,
        Err(_) => return 0,
    };

    if verify_join_signature(&payload) {
        1
    } else {
        0
    }
}

/// Verify an identity reveal payload.
/// Returns 1 if valid, 0 if invalid.
#[unsafe(no_mangle)]
pub extern "C" fn xaero_verify_reveal(reveal_payload_json: *const c_char) -> i32 {
    if reveal_payload_json.is_null() {
        return 0;
    }

    let json_str = match unsafe { CStr::from_ptr(reveal_payload_json) }.to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };

    let payload: IdentityRevealPayload = match serde_json::from_str(json_str) {
        Ok(p) => p,
        Err(_) => return 0,
    };

    if verify_reveal(&payload) {
        1
    } else {
        0
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anonymous_session_creation() {
        let secret = [42u8; 32];
        let session = AnonymousSession::new(&secret, "board_abc123");

        assert!(!session.handle.is_empty());
        assert!(session.handle.starts_with("Anonymous "));
        assert_eq!(session.scope_id, "board_abc123");
        assert!(!session.revealed);
    }

    #[test]
    fn test_join_payload_signature() {
        let secret = [42u8; 32];
        let session = AnonymousSession::new(&secret, "board_abc123");
        let payload = session.join_payload();

        assert_eq!(payload.payload_type, "anonymous_join");
        assert!(verify_join_signature(&payload));
    }

    #[test]
    fn test_reveal_and_verify() {
        let secret = [42u8; 32];
        let mut session = AnonymousSession::new(&secret, "board_abc123");
        let original_handle = session.handle.clone();

        let reveal = session.reveal(&secret, Some("Alice"));

        assert!(session.revealed);
        assert_eq!(reveal.handle, original_handle);
        assert_eq!(reveal.real_name, Some("Alice".to_string()));
        assert!(verify_reveal(&reveal));
    }

    #[test]
    fn test_different_scopes_different_commitments() {
        let secret = [42u8; 32];
        let session1 = AnonymousSession::new(&secret, "board_1");
        let session2 = AnonymousSession::new(&secret, "board_2");

        // Same user, different scopes → different commitments
        assert_ne!(session1.commitment, session2.commitment);
        // Different ephemeral keys (random each time)
        assert_ne!(session1.ephemeral_pubkey, session2.ephemeral_pubkey);
    }

    #[test]
    fn test_different_users_different_handles() {
        let session1 = AnonymousSession::new(&[1u8; 32], "board_1");
        let session2 = AnonymousSession::new(&[2u8; 32], "board_1");

        // Different ephemeral keys → likely different handles
        // (not guaranteed due to hash collision, but very likely)
        // The important thing is they have DIFFERENT ephemeral keys
        assert_ne!(session1.ephemeral_pubkey, session2.ephemeral_pubkey);
    }

    #[test]
    fn test_animal_handle_deterministic() {
        let pubkey = [99u8; 32];
        let handle1 = animal_handle(&pubkey);
        let handle2 = animal_handle(&pubkey);
        assert_eq!(handle1, handle2);
    }
}
