// credentials.rs

use bytemuck::{Pod, Zeroable};
use pqcrypto_falcon::falcon512::{detached_sign, SecretKey};
use pqcrypto_traits::sign::{DetachedSignature as PKTrait, SecretKey as SKTrait};

use crate::{CredentialIssuer, XaeroCredential, XaeroID, XaeroProof, MAX_PROOFS, VC_MAX_LEN};

/// Maximum email length in the credential claims.
pub const EMAIL_MAX_LEN: usize = 64;

/// Fixed-size, Pod-safe credential claims.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct CredentialClaims {
    /// User’s birth year (for age checks).
    pub birth_year: u16,
    /// UTF-8 bytes of the user’s email.
    pub email: [u8; EMAIL_MAX_LEN],
    /// Actual length of the email slice.
    pub email_len: u8,
    /// Padding for alignment.
    pub _pad: [u8; 1],
}
unsafe impl Pod for CredentialClaims {}
unsafe impl Zeroable for CredentialClaims {}

/// A Falcon-backed credential issuer: it holds its own XaeroID
/// so it can sign credentials out-of-band.
pub struct FalconCredentialIssuer {
    /// The issuer’s own identity (must contain secret_key).
    pub issuer_xid: XaeroID,
}

impl CredentialIssuer for FalconCredentialIssuer {
    fn issue_credential(
        &self,
        _subject_did: &str,
        email: String,
        birth_year: u16,
    ) -> XaeroCredential {
        // 1) Build the Pod claims
        let mut email_buf = [0u8; EMAIL_MAX_LEN];
        let len = email.len().min(EMAIL_MAX_LEN);
        email_buf[..len].copy_from_slice(&email.as_bytes()[..len]);

        let claims = CredentialClaims {
            birth_year,
            email: email_buf,
            email_len: len as u8,
            _pad: [0],
        };
        let payload = bytemuck::bytes_of(&claims);

        // 2) Sign the claims with the issuer’s secret key
        let sk =
            SecretKey::from_bytes(&self.issuer_xid.secret_key).expect("invalid issuer secret key");
        let sig = detached_sign(payload, &sk);

        // 3) Pack into a XaeroCredential
        let mut vc_buf = [0u8; VC_MAX_LEN];
        // store the raw claims
        vc_buf[..payload.len()].copy_from_slice(payload);

        // Option A) If you want to embed the full signature here (signature ~666 bytes),
        // you can either increase VC_MAX_LEN or slice it across multiple proofs.
        // For now we’ll store only a hash of the signature in proofs[0].
        let sig_bytes = sig.as_bytes();
        let mut zk_proof = [0u8; 32];
        zk_proof.copy_from_slice(&blake3::hash(sig_bytes).as_bytes()[..32]);

        XaeroCredential {
            vc: vc_buf,
            vc_len: payload.len() as u16,
            proofs: [XaeroProof { zk_proof }; MAX_PROOFS],
            proof_count: 1,
            _pad: [0],
        }
    }

    fn verify_credential(&self, cred: &XaeroCredential) -> bool {
        // 1) Extract the raw claims
        let payload = &cred.vc[..cred.vc_len as usize];
        if payload.len() != std::mem::size_of::<CredentialClaims>() {
            return false;
        }

        // 2) Recover the stored proof (signature-hash) from proofs[0]
        let expected_hash = &cred.proofs[0].zk_proof;

        // 3) Recompute signature-hash: first, we’d need the full signature. In this simple seed, we
        //    assume the issuer’s public key can verify a detached signature that you fetch
        //    separately. For now we just check that payload-length matches and proof_count==1.
        cred.proof_count == 1 && expected_hash.iter().any(|&b| b != 0)
    }
}

#[cfg(test)]
mod tests {
    use std::mem;

    use super::*;
    use crate::{identity::XaeroIdentityManager, IdentityManager};

    #[test]
    fn test_issue_and_verify() {
        // 1) Create an issuer with its own Falcon ID
        let manager = XaeroIdentityManager {};
        let issuer_xid = manager.new_id();
        let issuer = FalconCredentialIssuer { issuer_xid };

        // 2) Issue a credential
        let email = "alice@example.com".to_string();
        let birth_year = 1990u16;
        let cred = issuer.issue_credential("did:peer:dummy", email.clone(), birth_year);

        // 3) Check vc_len matches the size of our claims struct
        let expected_size = mem::size_of::<CredentialClaims>();
        assert_eq!(cred.vc_len as usize, expected_size);

        // 4) We stored exactly one proof
        assert_eq!(cred.proof_count, 1);

        // 5) That proof must be non-zero (hashed signature)
        assert!(cred.proofs[0].zk_proof.iter().any(|&b| b != 0));

        // 6) And verify_credential should return true
        assert!(issuer.verify_credential(&cred));
    }

    #[test]
    fn test_verify_fails_on_zero_proof() {
        let manager = XaeroIdentityManager {};
        let issuer_xid = manager.new_id();
        let issuer = FalconCredentialIssuer { issuer_xid };

        // Issue a credential, then zero-out the hash
        let mut cred = issuer.issue_credential("did:peer:dummy", "bob@example.com".into(), 1985);
        cred.proof_count = 1;
        cred.proofs[0].zk_proof = [0u8; 32];

        // Now verification must fail
        assert!(!issuer.verify_credential(&cred));
    }

    #[test]
    fn test_verify_fails_on_wrong_vc_len() {
        let manager = XaeroIdentityManager {};
        let issuer_xid = manager.new_id();
        let issuer = FalconCredentialIssuer { issuer_xid };

        // Issue a credential, then tamper with vc_len
        let mut cred = issuer.issue_credential("did:peer:dummy", "carol@example.com".into(), 2000);
        cred.vc_len = cred.vc_len.wrapping_add(1);

        assert!(!issuer.verify_credential(&cred));
    }

    #[test]
    fn test_verify_fails_on_proof_count_zero() {
        let manager = XaeroIdentityManager {};
        let issuer_xid = manager.new_id();
        let issuer = FalconCredentialIssuer { issuer_xid };

        // Issue a credential, then set proof_count to zero
        let mut cred = issuer.issue_credential("did:peer:dummy", "dan@example.com".into(), 1970);
        cred.proof_count = 0;

        assert!(!issuer.verify_credential(&cred));
    }
}
