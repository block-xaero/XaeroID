use bytemuck::Zeroable;
// ----------------------------------------------------------------
// DID:PEER (Falcon-512) support
//
// Format: `did:peer:<multibase(Base58BTC, public_key_bytes)>`
//
// - `public_key_bytes` is your 897-byte Falcon-512 raw public key.
// - We use Base58BTC multibase (“z” prefix) so the string is URL-safe.
//
// Example usage:
//   let did = encode_peer_did(&xid.did_peer);
//   let pk  = decode_peer_did(&did)?;  // back to [u8; 897]
// ----------------------------------------------------------------
use multibase::{decode, encode, Base};
use pqcrypto_falcon::{
    falcon512::{verify_detached_signature, PublicKey},
    falcon512_detached_sign,
};
use pqcrypto_traits::sign::{
    DetachedSignature, PublicKey as PublicKeyTrait, SecretKey as SecretKeyTrait,
};
use thiserror::Error;

use crate::{IdentityManager, XaeroID};

/// Errors when encoding/decoding a did:peer.
#[derive(Debug, Error)]
pub enum DidPeerError {
    #[error("invalid DID format")]
    InvalidFormat,
    #[error("multibase decode error")]
    MultibaseError(#[from] multibase::Error),
    #[error("wrong key length: expected 897, got {0}")]
    InvalidKeyLength(usize),
}

/// Encode a 897-byte Falcon public key into a `did:peer:` string.
pub fn encode_peer_did(pubkey: &[u8; 897]) -> String {
    let mb = encode(Base::Base58Btc, pubkey);
    format!("did:peer:{mb}")
}

/// Decode a `did:peer:` string back into the 897-byte Falcon public key.
pub fn decode_peer_did(did: &str) -> Result<[u8; 897], DidPeerError> {
    const PREFIX: &str = "did:peer:";
    if !did.starts_with(PREFIX) {
        return Err(DidPeerError::InvalidFormat);
    }
    let mb_str = &did[PREFIX.len()..];
    let (_base, data) = decode(mb_str)?;
    if data.len() != 897 {
        return Err(DidPeerError::InvalidKeyLength(data.len()));
    }
    let mut arr = [0u8; 897];
    arr.copy_from_slice(&data);
    Ok(arr)
}
/// The Falcon-based identity manager used for Cyan/XaeroID.
///
/// - Generates a Falcon keypair and embeds the public and secret key in a XaeroID.
/// - Provides signing and verification of challenge messages using detached Falcon signatures.
/// - All identity material is embedded in XaeroID for cloudless, portable use.
pub struct XaeroIdentityManager {}
impl IdentityManager for XaeroIdentityManager {
    fn new_id(&self) -> XaeroID {
        use pqcrypto_falcon::falcon512::*;
        let (pk, sk) = keypair(); // [u8; 897], [u8; 1280]
        let mut xid = XaeroID::zeroed();
        xid.secret_key[..1281].copy_from_slice(sk.as_bytes());
        xid.did_peer_len = 897;
        xid.did_peer[..897].copy_from_slice(pk.as_bytes());
        xid
    }

    fn sign_challenge(&self, xid: &XaeroID, challenge: &[u8]) -> Vec<u8> {
        use pqcrypto_falcon::falcon512::SecretKey;
        let sk = SecretKey::from_bytes(&xid.secret_key).expect("invalid secret key");
        falcon512_detached_sign(challenge, &sk).as_bytes().to_vec()
    }

    fn verify_challenge(&self, xid: &XaeroID, challenge: &[u8], signature: &[u8]) -> bool {
        let pk = PublicKey::from_bytes(&xid.did_peer[..xid.did_peer_len as usize]);
        if let Ok(pk) = pk {
            let sig = DetachedSignature::from_bytes(signature).expect("invalid signature");
            verify_detached_signature(&sig, challenge, &pk).is_ok()
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_falcon_identity_generation_and_roundtrip() {
        let mgr = XaeroIdentityManager {};
        let xid = mgr.new_id();
        assert_eq!(xid.did_peer_len, 897);
        assert_ne!(xid.did_peer, [0u8; 897]);
        assert_ne!(xid.secret_key, [0u8; 1281]);
    }

    #[test]
    fn test_sign_and_verify_challenge() {
        let mgr = XaeroIdentityManager {};
        let xid = mgr.new_id();
        let challenge: [u8; 32] = rand::random::<[u8; 32]>();
        let sig = mgr.sign_challenge(&xid, &challenge);
        assert!(mgr.verify_challenge(&xid, &challenge, &sig));
    }

    #[test]
    fn test_invalid_signature_rejected() {
        let mgr = XaeroIdentityManager {};
        let xid = mgr.new_id();
        let challenge: [u8; 32] = rand::random::<[u8; 32]>();
        let mut sig = mgr.sign_challenge(&xid, &challenge);
        sig[0] ^= 0xFF; // Corrupt it
        assert!(!mgr.verify_challenge(&xid, &challenge, &sig));
    }

    #[test]
    fn test_invalid_did_peer_rejected() {
        let mgr = XaeroIdentityManager {};
        let mut xid = mgr.new_id();
        let challenge: [u8; 32] = rand::random::<[u8; 32]>();
        let sig = mgr.sign_challenge(&xid, &challenge);
        xid.did_peer[0] ^= 0xFF; // Corrupt public key
        assert!(!mgr.verify_challenge(&xid, &challenge, &sig));
    }
}
