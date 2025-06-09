# xaeroID

## Overview

**xaeroID** is a cloudless, privacy-preserving identity system for peer-to-peer applications. Built on post-quantum Falcon-512 cryptography and zero-knowledge proofs, it enables self-sovereign identity management without servers, clouds, or centralized authorities.

Perfect for integration with distributed systems like **xaeroflux**, xaeroID provides cryptographic primitives for group membership, role-based access control, and credential verification—all while preserving user privacy through cutting-edge ZK-SNARK technology.

---

## What xaeroID Provides

### 🔐 **Post-Quantum Identity**
- **Pod-safe XaeroID**: Fixed-size struct (897B public + 1281B secret key)
- **Falcon-512 signatures**: Quantum-resistant cryptographic foundation
- **DID:peer support**: Offline-resolvable decentralized identifiers

### 🎭 **Zero-Knowledge Proofs**
- **RoleCircuit**: Prove sufficient permissions without revealing exact role
- **MembershipCircuit**: Prove group membership without revealing identity
- **PreimageCircuit**: Prove knowledge of secrets without disclosure
- **Arkworks integration**: Groth16 SNARKs on BN254 curve

### 🌐 **P2P Integration Ready**
- **xaeroflux compatibility**: Built for distributed event systems
- **FFI-ready**: Export to Dart, iOS, Android, WASM
- **Memory-safe**: Zero-copy serialization with bytemuck

---

## Key Features

- Identity Management
- DID:Peer falcon512 based - quantum safe cryptography.
- Verifiable credential issuance.
- Zk Proofs based on `arkworks` library.

### Usage
Add to your Cargo.toml:
```toml
[dependencies]
xaeroid = "0.2.0-m2"

# Core dependencies (automatically included)
pqcrypto-falcon = "0.4"
arkworks-bn254 = "0.5" 
arkworks-groth16 = "0.5"
arkworks-std = "0.5"
bytemuck = "1.23"
multibase = "0.10"
thiserror = "1.0"
rand = "0.8"
blake3 = "1.5"
```