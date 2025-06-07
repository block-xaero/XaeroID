Changelog

All notable changes to the xaeroID project will be documented in this file.

<!--
### Upcoming (0.2.0-m2)
- Integrate Groth16 ZK-SNARK proof generation and verification
- Expand CredentialIssuer to embed real zk proofs
-->

[0.2.0-m1] - 2025-06-07

Added
•	IdentityManager trait with methods:
•	new_id() -> XaeroID for Falcon-512 keypair generation
•	sign_challenge(&XaeroID, &[u8]) -> Vec<u8> for detached signature creation
•	verify_challenge(&XaeroID, &[u8], &[u8]) -> bool for signature verification
•	XaeroID Pod-safe struct (897 B public key + 1281 B secret key)
•	DID:peer support:
•	encode_peer_did(&[u8; 897]) -> String (Base58BTC multibase)
•	decode_peer_did(&str) -> Result<[u8; 897], Error> for offline resolution
•	Multibase and thiserror dependencies added for DID encoding/decoding and error handling
•	CredentialIssuer stub:
•	CredentialClaims Pod-safe struct for claims (email, birth_year)
•	FalconCredentialIssuer skeleton for signing claims with Falcon keys

Changed
•	Bumped crate version to 0.2.0-m1 and Rust edition to 2024
•	Updated Cargo.toml:
•	Added multibase = "0.10.1", thiserror = "1.0", and rand = "0.8"
•	Disabled default features on large dependencies to minimize footprint
•	Cleaned up tests in identity.rs to use rand::random::<[u8;32]>() instead of reserved .gen() method

Removed
•	Temporary use rand::Rng imports and .gen() calls

Fixed
•	Patch for test suite to compile under Rust 2024 and Clippy -D warnings
•	GitHub Actions workflow updated to target xaeroID (removed xaeroflux refs)
