# xaeroID

## Overview

**xaeroID** is a minimal, self-contained Rust library for cloudless, self-sovereign identity. It uses a post-quantum Falcon-512 keypair and a simple `did:peer` scheme to let you generate, store, sign, and verify identities entirely on-device—no servers, no cloud, no heavy async/runtime dependencies.

---

## What xaeroID Provides

- **Pod-safe XaeroID**  
  A fixed-size struct containing your entire identity (897 B Falcon public key + 1281 B Falcon secret key).
- **IdentityManager**  
  Generate a new `XaeroID`, sign arbitrary challenges, and verify signatures—all offline.
- **DID:peer Support**  
  Encode your 897 B public key as `did:peer:z…` (Base58BTC multibase) and decode it back.
- **Credential Issuance (Stub)**  
  Pod-safe `CredentialClaims` type plus a `FalconCredentialIssuer` you can extend with real ZK-SNARK proofs.
- **FFI-ready**  
  Built as `cdylib`/`staticlib`/`rlib` so you can expose it to Dart, iOS, Android, etc.

---

## Key Features

### Identity Management

- `new_id() -> XaeroID`
- `sign_challenge(&XaeroID, &[u8]) -> Vec<u8>`
- `verify_challenge(&XaeroID, &[u8], &[u8]) -> bool`

### DID:peer Encoding

- `encode_peer_did(&[u8; 897]) -> String`
- `decode_peer_did(&str) -> Result<[u8; 897], Error>`

_No HTTP resolver needed: your DID string contains the full public key._

### Credential Issuance (Stub)

- `CredentialClaims { birth_year: u16, email: [u8;64], … }`
- `FalconCredentialIssuer` signs claims with your Falcon key
- Placeholder for integration with Arkworks Groth16 circuits

---
XaeroID is designed as a library to provide a portable, flexible foundation for decentralized applications:

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
xaeroid            = { path = "../xaeroid" }
pqcrypto-falcon    = "0.4"
bytemuck           = "1.23"
multibase          = "0.10"
thiserror          = "1.0"
rand               = "0.8"