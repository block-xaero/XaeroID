//! XaeroID - Simple decentralized identity
//!
//! - Ed25519 keypair (Iroh compatible)
//! - did:peer format
//! - Hash-based group commitments
//! - That's it.

use serde::{Deserialize, Serialize};

// ============================================================
// Core Identity
// ============================================================

/// XaeroID - your identity
#[derive(Clone, Serialize, Deserialize)]
pub struct XaeroID {
    /// did:peer:z{base58(blake3(pubkey))}
    pub did: String,

    /// Ed25519 public key
    pub pubkey: [u8; 32],

    /// Ed25519 secret key
    #[serde(skip_serializing)]
    pub secret_key: [u8; 32],

    /// Groups with commitments
    pub memberships: Vec<GroupMembership>,

    /// When created
    pub created_at: u64,
}

/// Group membership with hash commitment
#[derive(Clone, Serialize, Deserialize)]
pub struct GroupMembership {
    /// Group name: "engineering", "workspace/abc123", etc.
    pub group_id: String,

    /// commitment = blake3(did || group_id || nonce)
    pub commitment: [u8; 32],

    /// Nonce (private - derived from secret_key)
    #[serde(skip_serializing)]
    pub nonce: [u8; 32],
}

/// What goes in the QR code
#[derive(Clone, Serialize, Deserialize)]
pub struct PassPayload {
    pub did: String,
    #[serde(with = "hex_array_32")]
    pub pubkey: [u8; 32],
    pub groups: Vec<String>,
    pub issued_at: u64,
    #[serde(with = "hex_array_64")]
    pub signature: [u8; 64],
}

// Hex serialization for [u8; 32]
mod hex_array_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(d: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes.try_into().map_err(|_| serde::de::Error::custom("wrong length"))
    }
}

// Hex serialization for [u8; 64]
mod hex_array_64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(d: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes.try_into().map_err(|_| serde::de::Error::custom("wrong length"))
    }
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
        }
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
        }
    }

    /// Add membership to a group
    pub fn join_group(&mut self, group_id: &str) {
        let nonce = self.derive_nonce(group_id);
        let commitment = self.compute_commitment(group_id, &nonce);

        self.memberships.push(GroupMembership {
            group_id: group_id.to_string(),
            commitment,
            nonce,
        });
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        Self::ed25519_sign(message, &self.secret_key)
    }

    /// Verify a signature
    pub fn verify(message: &[u8], signature: &[u8; 64], pubkey: &[u8; 32]) -> bool {
        Self::ed25519_verify(message, signature, pubkey)
    }

    /// Create payload for QR code
    pub fn to_pass_payload(&self) -> PassPayload {
        let groups: Vec<String> = self.memberships.iter().map(|m| m.group_id.clone()).collect();

        // Sign the payload content
        let sign_data = format!("{}:{}:{}", self.did, groups.join(","), self.created_at);
        let signature = self.sign(sign_data.as_bytes());

        PassPayload {
            did: self.did.clone(),
            pubkey: self.pubkey,
            groups,
            issued_at: self.created_at,
            signature,
        }
    }

    /// Serialize payload to JSON bytes (for QR)
    pub fn to_pass_bytes(&self) -> Vec<u8> {
        let payload = self.to_pass_payload();
        serde_json::to_vec(&payload).unwrap_or_default()
    }

    // --------------------------------------------------------
    // Private helpers
    // --------------------------------------------------------

    fn create_did(pubkey: &[u8; 32]) -> String {
        let hash = blake3::hash(pubkey);
        let encoded = bs58::encode(hash.as_bytes()).into_string();
        format!("did:peer:z{}", encoded)
    }

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

    fn ed25519_pubkey(secret: &[u8; 32]) -> [u8; 32] {
        use ed25519_dalek::SigningKey;
        let signing_key = SigningKey::from_bytes(secret);
        signing_key.verifying_key().to_bytes()
    }

    fn ed25519_sign(message: &[u8], secret: &[u8; 32]) -> [u8; 64] {
        use ed25519_dalek::{Signer, SigningKey};
        let signing_key = SigningKey::from_bytes(secret);
        signing_key.sign(message).to_bytes()
    }

    fn ed25519_verify(message: &[u8], signature: &[u8; 64], pubkey: &[u8; 32]) -> bool {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let Ok(verifying_key) = VerifyingKey::from_bytes(pubkey) else {
            return false;
        };
        let sig = Signature::from_bytes(signature);
        verifying_key.verify(message, &sig).is_ok()
    }
}

impl PassPayload {
    /// Verify the payload signature
    pub fn verify(&self) -> bool {
        let sign_data = format!("{}:{}:{}", self.did, self.groups.join(","), self.issued_at);
        XaeroID::verify(sign_data.as_bytes(), &self.signature, &self.pubkey)
    }

    /// Parse from JSON bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }
}

// ============================================================
// FFI for Swift
// ============================================================

use std::ffi::{c_char, CStr};

/// Generate new XaeroID - returns pointer
#[unsafe(no_mangle)]
pub extern "C" fn xaero_generate() -> *mut XaeroID {
    let xid = Box::new(XaeroID::generate());
    Box::into_raw(xid)
}

/// Free XaeroID
#[unsafe(no_mangle)]
pub extern "C" fn xaero_free(xid: *mut XaeroID) {
    if !xid.is_null() {
        unsafe {
            drop(Box::from_raw(xid));
        }
    }
}

/// Get DID string
#[unsafe(no_mangle)]
pub extern "C" fn xaero_get_did(
    xid: *const XaeroID,
    out: *mut c_char,
    out_len: usize,
) -> bool {
    if xid.is_null() || out.is_null() || out_len == 0 {
        return false;
    }

    let did = unsafe { &(*xid).did };

    if did.len() >= out_len {
        return false;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(did.as_ptr(), out as *mut u8, did.len());
        *out.add(did.len()) = 0; // null terminate
    }

    true
}

/// Get public key (32 bytes)
#[unsafe(no_mangle)]
pub extern "C" fn xaero_get_pubkey(xid: *const XaeroID, out: *mut u8) -> bool {
    if xid.is_null() || out.is_null() {
        return false;
    }

    unsafe {
        std::ptr::copy_nonoverlapping((*xid).pubkey.as_ptr(), out, 32);
    }
    true
}

/// Sign a message
#[unsafe(no_mangle)]
pub extern "C" fn xaero_sign(
    xid: *const XaeroID,
    msg: *const u8,
    msg_len: usize,
    out_sig: *mut u8,
) -> bool {
    if xid.is_null() || msg.is_null() || out_sig.is_null() || msg_len == 0 {
        return false;
    }

    let message = unsafe { std::slice::from_raw_parts(msg, msg_len) };
    let xid_ref = unsafe { &*xid };
    let signature = xid_ref.sign(message);

    unsafe {
        std::ptr::copy_nonoverlapping(signature.as_ptr(), out_sig, 64);
    }
    true
}

/// Verify a signature
#[unsafe(no_mangle)]
pub extern "C" fn xaero_verify(
    pubkey: *const u8,
    msg: *const u8,
    msg_len: usize,
    sig: *const u8,
) -> bool {
    if pubkey.is_null() || msg.is_null() || sig.is_null() || msg_len == 0 {
        return false;
    }

    let pk: [u8; 32] = unsafe { std::slice::from_raw_parts(pubkey, 32).try_into().unwrap() };
    let message = unsafe { std::slice::from_raw_parts(msg, msg_len) };
    let signature: [u8; 64] = unsafe { std::slice::from_raw_parts(sig, 64).try_into().unwrap() };

    XaeroID::verify(message, &signature, &pk)
}

/// Add group and create pass payload JSON
#[unsafe(no_mangle)]
pub extern "C" fn xaero_create_pass_payload(
    xid: *const XaeroID,
    groups: *const *const c_char,
    groups_count: usize,
    out: *mut u8,
    out_capacity: usize,
    out_len: *mut usize,
) -> bool {
    if xid.is_null() || out.is_null() || out_len.is_null() {
        return false;
    }

    let xid_ref = unsafe { &*xid };

    // Clone and add groups
    let mut xid_clone = xid_ref.clone();

    if !groups.is_null() && groups_count > 0 {
        for i in 0..groups_count {
            let g = unsafe { *groups.add(i) };
            if !g.is_null() {
                if let Ok(s) = unsafe { CStr::from_ptr(g) }.to_str() {
                    xid_clone.join_group(s);
                }
            }
        }
    }

    let bytes = xid_clone.to_pass_bytes();

    if bytes.len() > out_capacity {
        return false;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
        *out_len = bytes.len();
    }

    true
}

/// Verify pass payload JSON
#[unsafe(no_mangle)]
pub extern "C" fn xaero_verify_pass_payload(json: *const u8, json_len: usize) -> bool {
    if json.is_null() || json_len == 0 {
        return false;
    }

    let bytes = unsafe { std::slice::from_raw_parts(json, json_len) };

    match PassPayload::from_bytes(bytes) {
        Some(p) => p.verify(),
        None => false,
    }
}

/// Join a group (mutates XaeroID)
#[unsafe(no_mangle)]
pub extern "C" fn xaero_join_group(xid: *mut XaeroID, group_id: *const c_char) -> bool {
    if xid.is_null() || group_id.is_null() {
        return false;
    }

    let group = match unsafe { CStr::from_ptr(group_id) }.to_str() {
        Ok(s) => s,
        Err(_) => return false,
    };

    unsafe {
        (*xid).join_group(group);
    }
    true
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate() {
        let xid = XaeroID::generate();
        assert!(xid.did.starts_with("did:peer:z"));
        assert_eq!(xid.pubkey.len(), 32);
    }

    #[test]
    fn test_sign_verify() {
        let xid = XaeroID::generate();
        let msg = b"hello world";
        let sig = xid.sign(msg);
        assert!(XaeroID::verify(msg, &sig, &xid.pubkey));
    }

    #[test]
    fn test_group_membership() {
        let mut xid = XaeroID::generate();
        xid.join_group("engineering");
        xid.join_group("backend");

        assert_eq!(xid.memberships.len(), 2);
        assert_eq!(xid.memberships[0].group_id, "engineering");
    }

    #[test]
    fn test_pass_payload() {
        let mut xid = XaeroID::generate();
        xid.join_group("cyan_users");

        let payload = xid.to_pass_payload();
        assert!(payload.verify());
        assert_eq!(payload.groups, vec!["cyan_users"]);
    }

    #[test]
    fn test_pass_bytes_roundtrip() {
        let mut xid = XaeroID::generate();
        xid.join_group("test");

        let bytes = xid.to_pass_bytes();
        let parsed = PassPayload::from_bytes(&bytes).unwrap();

        assert!(parsed.verify());
        assert_eq!(parsed.did, xid.did);
    }
}