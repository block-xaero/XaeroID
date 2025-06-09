Changelog

All notable changes to the xaeroID project will be documented in this file.

### Upcoming (0.3.0-m1)
- Complete ZK-SNARK circuit implementation for xaeroflux integration
- Add P2P control plane event types for identity management
- Backend state management for group membership and role verification

[0.2.0-m2] - 2025-06-09

Added
- Zero-Knowledge Proof Infrastructure:
- Arkworks integration with bn254 curve and Groth16 proving system
- Three core ZK circuits for privacy-preserving identity:
- RoleCircuit: Prove sufficient permissions without revealing exact role
- MembershipCircuit: Prove group membership without revealing identity
- PreimageCircuit: Prove knowledge of secrets (email, password) without disclosure
- ZK proof generation and verification with arkworks-groth16
- Circuit trait abstraction for extensible proof systems
- Enhanced Credential System:
- ZKCredentialIssuer with embedded zero-knowledge proofs
- Privacy-preserving credential verification without revealing claims
- Integration hooks for xaeroflux control plane events
- Development Dependencies:
- arkworks-bn254 = "0.5" for elliptic curve operations
- arkworks-groth16 = "0.5" for SNARK proof systems
- arkworks-std = "0.5" for constraint system utilities

Changed
- Expanded CredentialIssuer to support ZK-SNARK proof embedding
- Updated circuit architecture to support xaeroflux P2P identity events
- Enhanced error handling for cryptographic operations

Fixed
- Circuit constraint generation for privacy-preserving proofs
- Memory-safe ZK proof serialization for P2P gossip protocols

[0.2.0-m1] - 2025-06-07

Added
- IdentityManager trait with methods:
- new_id() -> XaeroID for Falcon-512 keypair generation
- sign_challenge(&XaeroID, &[u8]) -> Vec<u8> for detached signature creation
- verify_challenge(&XaeroID, &[u8], &[u8]) -> bool for signature verification
- XaeroID Pod-safe struct (897 B public key + 1281 B secret key)
- DID:peer support:
- encode_peer_did(&[u8; 897]) -> String (Base58BTC multibase)
- decode_peer_did(&str) -> Result<[u8; 897], Error> for offline resolution
- Multibase and thiserror dependencies added for DID encoding/decoding and error handling
- CredentialIssuer stub:
- CredentialClaims Pod-safe struct for claims (email, birth_year)
- FalconCredentialIssuer skeleton for signing claims with Falcon keys

Changed
- Bumped crate version to 0.2.0-m2 and Rust edition to 2024
- Updated Cargo.toml:
- Added multibase = "0.10.1", thiserror = "1.0", and rand = "0.8"
- Disabled default features on large dependencies to minimize footprint
- Cleaned up tests in identity.rs to use rand::random::<[u8;32]>() instead of reserved .gen() method

Removed
- Temporary use rand::Rng imports and .gen() calls

Fixed
- Patch for test suite to compile under Rust 2024 and Clippy -D warnings
- GitHub Actions workflow updated to target xaeroID (removed xaeroflux refs)