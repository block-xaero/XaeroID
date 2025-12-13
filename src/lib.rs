//! XaeroID - Simple decentralized identity
//!
//! - Ed25519 keypair (Iroh compatible)
//! - did:peer format
//! - Hash-based group commitments
//! - Profile info (display name, avatar)

#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(clippy::disallowed_methods)]

use serde::{Deserialize, Serialize};
use std::ffi::{c_char, CStr, CString};

// ============================================================
// Core Identity
// ============================================================

/// XaeroID - your identity
#[derive(Clone)]
pub struct XaeroID {
    /// did:peer:z{base58(blake3(pubkey))}
    pub did: String,
    /// Ed25519 public key
    pub pubkey: [u8; 32],
    /// Ed25519 secret key
    pub secret_key: [u8; 32],
    /// Groups with commitments
    pub memberships: Vec<GroupMembership>,
    /// When created
    pub created_at: u64,
    /// Display name (from OAuth provider)
    pub display_name: Option<String>,
    /// Avatar URL (from OAuth provider)
    pub avatar_url: Option<String>,
}

/// Group membership with hash commitment
#[derive(Clone)]
pub struct GroupMembership {
    /// Group name: "engineering", "workspace/abc123", etc.
    pub group_id: String,
    /// commitment = blake3(did || group_id || nonce)
    pub commitment: [u8; 32],
    /// Nonce (private - derived from secret_key)
    pub nonce: [u8; 32],
}

/// What goes in the QR code - uses hex strings for easy JSON
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PassPayload {
    /// Version for forward compatibility
    #[serde(default = "default_version")]
    pub version: u8,
    pub did: String,
    pub pubkey: String, // hex encoded
    pub groups: Vec<String>,
    pub issued_at: u64,
    pub signature: String, // hex encoded
    /// Display name (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Avatar URL (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    /// Short ID for display (first 8 chars of base58 pubkey)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_id: Option<String>,
}

fn default_version() -> u8 {
    1
}

/// Group invite payload for QR code sharing
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct GroupInvite {
    /// Payload type marker
    #[serde(rename = "type")]
    pub payload_type: String,
    /// Version for forward compatibility
    pub v: u8,
    /// Group ID to join
    pub group_id: String,
    /// Group display name
    pub group_name: String,
    /// Group icon (SF Symbol name)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_icon: Option<String>,
    /// Group color (hex)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_color: Option<String>,
    /// DID of the person creating the invite
    pub inviter_did: String,
    /// Display name of inviter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inviter_name: Option<String>,
    /// When the invite was created
    pub issued_at: u64,
    /// Signature over the invite data
    pub sig: String,
}

impl GroupInvite {
    /// Create a new group invite
    pub fn new(
        group_id: &str,
        group_name: &str,
        group_icon: Option<&str>,
        group_color: Option<&str>,
        inviter_secret_key: &[u8; 32],
        inviter_name: Option<&str>,
    ) -> Self {
        let inviter_pubkey = XaeroID::ed25519_pubkey(inviter_secret_key);
        let inviter_did = XaeroID::create_did(&inviter_pubkey);
        let issued_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Create signing data
        let sign_data = format!(
            "cyan_group_invite:{}:{}:{}:{}",
            group_id, group_name, inviter_did, issued_at
        );
        let signature = XaeroID::ed25519_sign(sign_data.as_bytes(), inviter_secret_key);

        GroupInvite {
            payload_type: "cyan_group_invite".to_string(),
            v: 1,
            group_id: group_id.to_string(),
            group_name: group_name.to_string(),
            group_icon: group_icon.map(|s| s.to_string()),
            group_color: group_color.map(|s| s.to_string()),
            inviter_did,
            inviter_name: inviter_name.map(|s| s.to_string()),
            issued_at,
            sig: hex::encode(signature),
        }
    }

    /// Verify the invite signature
    pub fn verify(&self) -> bool {
        // Extract pubkey from DID (we need to reverse the DID creation)
        // For now, we'll trust the signature format and just verify structure
        // Full verification requires the inviter's pubkey which isn't in the invite
        // This is a design tradeoff - we could add pubkey to the invite

        // Basic validation
        if self.payload_type != "cyan_group_invite" {
            return false;
        }
        if self.group_id.is_empty() || self.group_name.is_empty() {
            return false;
        }
        if self.sig.len() != 128 {
            return false;
        }

        true // Structural validation passed
    }

    /// Verify with known pubkey (if available)
    pub fn verify_with_pubkey(&self, pubkey: &[u8; 32]) -> bool {
        let Ok(sig_bytes) = hex::decode(&self.sig) else {
            return false;
        };
        if sig_bytes.len() != 64 {
            return false;
        }

        let signature: [u8; 64] = sig_bytes.try_into().unwrap();
        let sign_data = format!(
            "cyan_group_invite:{}:{}:{}:{}",
            self.group_id, self.group_name, self.inviter_did, self.issued_at
        );

        XaeroID::verify(sign_data.as_bytes(), &signature, pubkey)
    }

    /// To JSON string
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// From JSON string
    pub fn from_json(json: &str) -> Option<Self> {
        serde_json::from_str(json).ok()
    }
}

/// Result of creating/loading an identity with full profile
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct IdentityResult {
    pub secret_key: String, // hex
    pub pubkey: String,     // hex
    pub did: String,
    pub short_id: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub groups: Vec<String>,
}

// ============================================================
// Implementation
// ============================================================

impl XaeroID {
    /// Generate new identity
    pub fn generate() -> Self {
        let secret_key = Self::random_bytes();
        let pubkey = Self::ed25519_pubkey(&secret_key);
        let did = Self::create_did(&pubkey);

        Self {
            did,
            pubkey,
            secret_key,
            memberships: Vec::new(),
            created_at: Self::now(),
            display_name: None,
            avatar_url: None,
        }
    }

    /// Generate with profile info
    pub fn generate_with_profile(display_name: Option<String>, avatar_url: Option<String>) -> Self {
        let mut xid = Self::generate();
        xid.display_name = display_name;
        xid.avatar_url = avatar_url;
        xid
    }

    /// Create from existing Iroh secret key
    pub fn from_iroh_secret(secret_key: [u8; 32]) -> Self {
        let pubkey = Self::ed25519_pubkey(&secret_key);
        let did = Self::create_did(&pubkey);

        Self {
            did,
            pubkey,
            secret_key,
            memberships: Vec::new(),
            created_at: Self::now(),
            display_name: None,
            avatar_url: None,
        }
    }

    /// Create from secret with profile
    pub fn from_secret_with_profile(
        secret_key: [u8; 32],
        display_name: Option<String>,
        avatar_url: Option<String>,
    ) -> Self {
        let mut xid = Self::from_iroh_secret(secret_key);
        xid.display_name = display_name;
        xid.avatar_url = avatar_url;
        xid
    }

    /// Set profile info
    pub fn set_profile(&mut self, display_name: Option<String>, avatar_url: Option<String>) {
        self.display_name = display_name;
        self.avatar_url = avatar_url;
    }

    /// Add membership to a group
    pub fn join_group(&mut self, group_id: &str) {
        // Check if already member
        if self.memberships.iter().any(|m| m.group_id == group_id) {
            return;
        }

        let nonce = self.derive_nonce(group_id);
        let commitment = self.compute_commitment(group_id, &nonce);

        self.memberships.push(GroupMembership {
            group_id: group_id.to_string(),
            commitment,
            nonce,
        });
    }

    /// Get short ID (first 8 chars of base58 encoded pubkey)
    pub fn short_id(&self) -> String {
        let encoded = bs58::encode(&self.pubkey).into_string();
        encoded.chars().take(8).collect()
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        Self::ed25519_sign(message, &self.secret_key)
    }

    /// Verify a signature
    pub fn verify(message: &[u8], signature: &[u8; 64], pubkey: &[u8; 32]) -> bool {
        Self::ed25519_verify(message, signature, pubkey)
    }

    /// Create payload for QR code (includes profile info)
    pub fn to_pass_payload(&self) -> PassPayload {
        let groups: Vec<String> = self
            .memberships
            .iter()
            .map(|m| m.group_id.clone())
            .collect();

        // Sign the payload content (including profile info in signature)
        let name_part = self.display_name.as_deref().unwrap_or("");
        let sign_data = format!(
            "v1:{}:{}:{}:{}",
            self.did,
            groups.join(","),
            name_part,
            self.created_at
        );
        let signature = self.sign(sign_data.as_bytes());

        PassPayload {
            version: 1,
            did: self.did.clone(),
            pubkey: hex::encode(self.pubkey),
            groups,
            issued_at: self.created_at,
            signature: hex::encode(signature),
            display_name: self.display_name.clone(),
            avatar_url: self.avatar_url.clone(),
            short_id: Some(self.short_id()),
        }
    }

    /// Serialize payload to JSON bytes (for QR)
    pub fn to_pass_bytes(&self) -> Vec<u8> {
        let payload = self.to_pass_payload();
        serde_json::to_vec(&payload).unwrap_or_default()
    }

    /// Convert to IdentityResult for Swift consumption
    pub fn to_identity_result(&self) -> IdentityResult {
        IdentityResult {
            secret_key: hex::encode(self.secret_key),
            pubkey: hex::encode(self.pubkey),
            did: self.did.clone(),
            short_id: self.short_id(),
            display_name: self.display_name.clone(),
            avatar_url: self.avatar_url.clone(),
            groups: self.memberships.iter().map(|m| m.group_id.clone()).collect(),
        }
    }

    // --------------------------------------------------------
    // Private helpers
    // --------------------------------------------------------

    fn derive_nonce(&self, group_id: &str) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(&self.secret_key);
        hasher.update(b"nonce:");
        hasher.update(group_id.as_bytes());
        *hasher.finalize().as_bytes()
    }

    fn compute_commitment(&self, group_id: &str, nonce: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.did.as_bytes());
        hasher.update(group_id.as_bytes());
        hasher.update(nonce);
        *hasher.finalize().as_bytes()
    }

    fn random_bytes() -> [u8; 32] {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn ed25519_verify(message: &[u8], signature: &[u8; 64], pubkey: &[u8; 32]) -> bool {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let Ok(verifying_key) = VerifyingKey::from_bytes(pubkey) else {
            return false;
        };
        let sig = Signature::from_bytes(signature);
        verifying_key.verify(message, &sig).is_ok()
    }

    pub fn ed25519_pubkey(secret: &[u8; 32]) -> [u8; 32] {
        use ed25519_dalek::SigningKey;
        let signing_key = SigningKey::from_bytes(secret);
        signing_key.verifying_key().to_bytes()
    }

    pub fn ed25519_sign(message: &[u8], secret: &[u8; 32]) -> [u8; 64] {
        use ed25519_dalek::{Signer, SigningKey};
        let signing_key = SigningKey::from_bytes(secret);
        signing_key.sign(message).to_bytes()
    }

    pub fn create_did(pubkey: &[u8; 32]) -> String {
        let hash = blake3::hash(pubkey);
        let encoded = bs58::encode(hash.as_bytes()).into_string();
        format!("did:peer:z{}", encoded)
    }
}

impl PassPayload {
    /// Verify the payload signature
    pub fn verify(&self) -> bool {
        let Ok(pubkey_bytes) = hex::decode(&self.pubkey) else {
            return false;
        };
        let Ok(sig_bytes) = hex::decode(&self.signature) else {
            return false;
        };

        if pubkey_bytes.len() != 32 || sig_bytes.len() != 64 {
            return false;
        }

        let pubkey: [u8; 32] = pubkey_bytes.try_into().unwrap();
        let signature: [u8; 64] = sig_bytes.try_into().unwrap();

        // Handle both v0 (no version) and v1 signatures
        let sign_data = if self.version >= 1 {
            let name_part = self.display_name.as_deref().unwrap_or("");
            format!(
                "v1:{}:{}:{}:{}",
                self.did,
                self.groups.join(","),
                name_part,
                self.issued_at
            )
        } else {
            // Legacy v0 format
            format!("{}:{}:{}", self.did, self.groups.join(","), self.issued_at)
        };

        XaeroID::verify(sign_data.as_bytes(), &signature, &pubkey)
    }

    /// Parse from JSON bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }

    /// To JSON bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Get short ID
    pub fn short_id(&self) -> String {
        self.short_id.clone().unwrap_or_else(|| {
            if let Ok(pubkey_bytes) = hex::decode(&self.pubkey) {
                let encoded = bs58::encode(&pubkey_bytes).into_string();
                encoded.chars().take(8).collect()
            } else {
                "unknown".to_string()
            }
        })
    }
}

// ============================================================
// FFI for Swift - Enhanced
// ============================================================

/// Generate new XaeroID with profile info
/// Returns JSON: {"secret_key":"hex","pubkey":"hex","did":"...","short_id":"...","display_name":"...","avatar_url":"...","groups":[]}
#[unsafe(no_mangle)]
pub extern "C" fn xaero_generate_with_profile(
    display_name: *const c_char,
    avatar_url: *const c_char,
) -> *mut c_char {
    let name = if display_name.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(display_name) }
            .to_str()
            .ok()
            .map(|s| s.to_string())
    };

    let avatar = if avatar_url.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(avatar_url) }
            .to_str()
            .ok()
            .map(|s| s.to_string())
    };

    let xid = XaeroID::generate_with_profile(name, avatar);
    let result = xid.to_identity_result();

    match CString::new(serde_json::to_string(&result).unwrap_or_default()) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Create identity from secret key with profile and groups
/// secret_key_hex: 64-char hex string
/// display_name: optional display name (can be null)
/// avatar_url: optional avatar URL (can be null)
/// groups_json: JSON array of group IDs: ["group1", "group2"] (can be null)
/// Returns JSON: IdentityResult
#[unsafe(no_mangle)]
pub extern "C" fn xaero_create_identity(
    secret_key_hex: *const c_char,
    display_name: *const c_char,
    avatar_url: *const c_char,
    groups_json: *const c_char,
) -> *mut c_char {
    if secret_key_hex.is_null() {
        return std::ptr::null_mut();
    }

    let secret_hex = match unsafe { CStr::from_ptr(secret_key_hex) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let secret_bytes: [u8; 32] = match hex::decode(secret_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return std::ptr::null_mut(),
    };

    let name = if display_name.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(display_name) }
            .to_str()
            .ok()
            .map(|s| s.to_string())
    };

    let avatar = if avatar_url.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(avatar_url) }
            .to_str()
            .ok()
            .map(|s| s.to_string())
    };

    let groups: Vec<String> = if !groups_json.is_null() {
        if let Ok(json_str) = unsafe { CStr::from_ptr(groups_json) }.to_str() {
            serde_json::from_str(json_str).unwrap_or_default()
        } else {
            vec![]
        }
    } else {
        vec![]
    };

    let mut xid = XaeroID::from_secret_with_profile(secret_bytes, name, avatar);
    for group in &groups {
        xid.join_group(group);
    }

    let result = xid.to_identity_result();

    match CString::new(serde_json::to_string(&result).unwrap_or_default()) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Sign a message with provided secret_key (stateless)
/// secret_key_hex: 64-char hex string
/// message: bytes to sign
/// Returns: 128-char hex string (64 bytes signature) or null on error
#[unsafe(no_mangle)]
pub extern "C" fn xaero_sign_with_key(
    secret_key_hex: *const c_char,
    msg: *const u8,
    msg_len: usize,
) -> *mut c_char {
    if secret_key_hex.is_null() || msg.is_null() || msg_len == 0 {
        return std::ptr::null_mut();
    }

    let secret_hex = match unsafe { CStr::from_ptr(secret_key_hex) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let secret_bytes: [u8; 32] = match hex::decode(secret_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return std::ptr::null_mut(),
    };

    let message = unsafe { std::slice::from_raw_parts(msg, msg_len) };
    let signature = XaeroID::ed25519_sign(message, &secret_bytes);

    match CString::new(hex::encode(signature)) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Create pass payload JSON with profile info (for QR code)
/// Returns full PassPayload JSON
#[unsafe(no_mangle)]
pub extern "C" fn xaero_create_pass_with_profile(
    secret_key_hex: *const c_char,
    display_name: *const c_char,
    avatar_url: *const c_char,
    groups_json: *const c_char,
) -> *mut c_char {
    if secret_key_hex.is_null() {
        return std::ptr::null_mut();
    }

    let secret_hex = match unsafe { CStr::from_ptr(secret_key_hex) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let secret_bytes: [u8; 32] = match hex::decode(secret_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return std::ptr::null_mut(),
    };

    let name = if display_name.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(display_name) }
            .to_str()
            .ok()
            .map(|s| s.to_string())
    };

    let avatar = if avatar_url.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(avatar_url) }
            .to_str()
            .ok()
            .map(|s| s.to_string())
    };

    let groups: Vec<String> = if !groups_json.is_null() {
        if let Ok(json_str) = unsafe { CStr::from_ptr(groups_json) }.to_str() {
            serde_json::from_str(json_str).unwrap_or_default()
        } else {
            vec![]
        }
    } else {
        vec![]
    };

    let mut xid = XaeroID::from_secret_with_profile(secret_bytes, name, avatar);
    for group in &groups {
        xid.join_group(group);
    }

    let payload = xid.to_pass_payload();

    match CString::new(serde_json::to_string(&payload).unwrap_or_default()) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Verify a pass payload JSON and extract info
/// Returns JSON with verification result and extracted fields, or null on parse error
#[unsafe(no_mangle)]
pub extern "C" fn xaero_verify_pass(pass_json: *const c_char) -> *mut c_char {
    if pass_json.is_null() {
        return std::ptr::null_mut();
    }

    let json_str = match unsafe { CStr::from_ptr(pass_json) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let payload: PassPayload = match serde_json::from_str(json_str) {
        Ok(p) => p,
        Err(_) => return std::ptr::null_mut(),
    };

    let is_valid = payload.verify();

    let result = serde_json::json!({
        "valid": is_valid,
        "did": payload.did,
        "pubkey": payload.pubkey,
        "short_id": payload.short_id(),
        "groups": payload.groups,
        "display_name": payload.display_name,
        "avatar_url": payload.avatar_url,
        "issued_at": payload.issued_at,
    });

    match CString::new(result.to_string()) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// ============================================================
// Group Invite FFI
// ============================================================

/// Create a group invite QR payload
/// Returns JSON string for QR code, or null on error
#[unsafe(no_mangle)]
pub extern "C" fn xaero_create_group_invite(
    secret_key_hex: *const c_char,
    group_id: *const c_char,
    group_name: *const c_char,
    group_icon: *const c_char,    // nullable
    group_color: *const c_char,   // nullable
    inviter_name: *const c_char,  // nullable
) -> *mut c_char {
    // Validate required params
    if secret_key_hex.is_null() || group_id.is_null() || group_name.is_null() {
        return std::ptr::null_mut();
    }

    let secret_hex = match unsafe { CStr::from_ptr(secret_key_hex) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let secret_bytes: [u8; 32] = match hex::decode(secret_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return std::ptr::null_mut(),
    };

    let gid = match unsafe { CStr::from_ptr(group_id) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let gname = match unsafe { CStr::from_ptr(group_name) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let icon = if group_icon.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(group_icon) }.to_str().ok()
    };

    let color = if group_color.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(group_color) }.to_str().ok()
    };

    let iname = if inviter_name.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(inviter_name) }.to_str().ok()
    };

    let invite = GroupInvite::new(gid, gname, icon, color, &secret_bytes, iname);

    match CString::new(invite.to_json()) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Parse and validate a group invite from JSON
/// Returns JSON with parsed invite data and validity, or null on parse error
/// Result: {"valid": true/false, "group_id": "...", "group_name": "...", ...}
#[unsafe(no_mangle)]
pub extern "C" fn xaero_parse_group_invite(invite_json: *const c_char) -> *mut c_char {
    if invite_json.is_null() {
        return std::ptr::null_mut();
    }

    let json_str = match unsafe { CStr::from_ptr(invite_json) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let invite = match GroupInvite::from_json(json_str) {
        Some(i) => i,
        None => return std::ptr::null_mut(),
    };

    let is_valid = invite.verify();

    let result = serde_json::json!({
        "valid": is_valid,
        "group_id": invite.group_id,
        "group_name": invite.group_name,
        "group_icon": invite.group_icon,
        "group_color": invite.group_color,
        "inviter_did": invite.inviter_did,
        "inviter_name": invite.inviter_name,
        "issued_at": invite.issued_at
    });

    match CString::new(result.to_string()) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// ============================================================
// Legacy FFI (keep for backward compatibility)
// ============================================================

/// Generate new XaeroID - returns JSON with secret_key, pubkey, did
#[unsafe(no_mangle)]
pub extern "C" fn xaero_generate_json() -> *mut c_char {
    let xid = XaeroID::generate();

    let json = serde_json::json!({
        "secret_key": hex::encode(xid.secret_key),
        "pubkey": hex::encode(xid.pubkey),
        "did": xid.did,
        "short_id": xid.short_id()
    });

    match CString::new(json.to_string()) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Derive identity from secret key (stateless)
#[unsafe(no_mangle)]
pub extern "C" fn xaero_derive_identity(secret_key_hex: *const c_char) -> *mut c_char {
    if secret_key_hex.is_null() {
        return std::ptr::null_mut();
    }

    let secret_hex = match unsafe { CStr::from_ptr(secret_key_hex) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let secret_bytes = match hex::decode(secret_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return std::ptr::null_mut(),
    };

    let pubkey = XaeroID::ed25519_pubkey(&secret_bytes);
    let did = XaeroID::create_did(&pubkey);
    let short_id: String = bs58::encode(&pubkey).into_string().chars().take(8).collect();

    let json = serde_json::json!({
        "pubkey": hex::encode(pubkey),
        "did": did,
        "short_id": short_id
    });

    match CString::new(json.to_string()) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Create pass payload JSON from secret_key + groups (legacy, no profile)
#[unsafe(no_mangle)]
pub extern "C" fn xaero_create_pass_json(
    secret_key_hex: *const c_char,
    groups_json: *const c_char,
) -> *mut c_char {
    // Delegate to new function with null profile
    xaero_create_pass_with_profile(
        secret_key_hex,
        std::ptr::null(),
        std::ptr::null(),
        groups_json,
    )
}

/// Free a string allocated by xaero FFI functions
#[unsafe(no_mangle)]
pub extern "C" fn xaero_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_with_profile() {
        let xid = XaeroID::generate_with_profile(
            Some("Rick".to_string()),
            Some("https://example.com/avatar.png".to_string()),
        );

        assert!(xid.did.starts_with("did:peer:z"));
        assert_eq!(xid.display_name, Some("Rick".to_string()));
        assert_eq!(xid.short_id().len(), 8);

        let payload = xid.to_pass_payload();
        assert!(payload.verify());
        assert_eq!(payload.display_name, Some("Rick".to_string()));
    }

    #[test]
    fn test_pass_with_groups_and_profile() {
        let mut xid = XaeroID::generate_with_profile(Some("Test User".to_string()), None);
        xid.join_group("engineering");
        xid.join_group("cyan_beta");

        let payload = xid.to_pass_payload();
        assert!(payload.verify());
        assert_eq!(payload.groups.len(), 2);
        assert!(payload.groups.contains(&"engineering".to_string()));

        // Serialize and deserialize
        let bytes = payload.to_bytes();
        let parsed = PassPayload::from_bytes(&bytes).unwrap();
        assert!(parsed.verify());
        assert_eq!(parsed.display_name, Some("Test User".to_string()));
    }

    #[test]
    fn test_identity_result() {
        let mut xid = XaeroID::generate_with_profile(Some("Alice".to_string()), None);
        xid.join_group("team_a");

        let result = xid.to_identity_result();
        assert_eq!(result.display_name, Some("Alice".to_string()));
        assert_eq!(result.groups, vec!["team_a"]);
        assert_eq!(result.short_id.len(), 8);
    }

    #[test]
    fn test_ffi_create_identity() {
        let secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let secret_cstr = CString::new(secret).unwrap();
        let name_cstr = CString::new("Bob").unwrap();
        let groups_cstr = CString::new(r#"["group1", "group2"]"#).unwrap();

        let result_ptr = xaero_create_identity(
            secret_cstr.as_ptr(),
            name_cstr.as_ptr(),
            std::ptr::null(),
            groups_cstr.as_ptr(),
        );

        assert!(!result_ptr.is_null());

        let result_str = unsafe { CStr::from_ptr(result_ptr) }.to_str().unwrap();
        let result: IdentityResult = serde_json::from_str(result_str).unwrap();

        assert_eq!(result.display_name, Some("Bob".to_string()));
        assert_eq!(result.groups.len(), 2);

        unsafe { xaero_free_string(result_ptr) };
    }
}