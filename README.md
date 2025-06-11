# XaeroID

**A zero-knowledge proof wallet system with decentralized identity (DID) built on Falcon-512 post-quantum cryptography.**

XaeroID provides a complete framework for managing decentralized identities, verifiable credentials, and zero-knowledge proofs in a Pod-safe, portable format that works both standalone and as part of larger systems.

## 🌟 Features

### Post-Quantum Security
- **Falcon-512** signatures for quantum-resistant identity proofs
- DID:peer standard compliance with multibase encoding
- Future-proof cryptographic primitives

### Zero-Knowledge Proof System
- **Groth16 SNARKs** on BN254 curve via Arkworks
- Multiple proof circuits for different use cases:
    - **Membership proofs** - prove group membership without revealing identity
    - **Role-based proofs** - prove authority levels without exposing exact role
    - **Object/Workspace creation** - prove creation rights with privacy
    - **Identity challenges** - cryptographic identity verification
    - **Age verification** - prove age thresholds without revealing exact age

### Verifiable Credentials
- Standards-compliant credential issuance and verification
- Embedded ZK proofs for privacy-preserving assertions
- Falcon-512 signed credentials with hash-based integrity

### Pod-Safe Architecture
- Zero-copy serialization with `bytemuck`
- Fixed-size structures for predictable memory layout
- Cross-platform compatibility and deterministic sizes
- Cloudless, portable identity that works offline

## 🚀 Quick Start

### Basic Identity Creation

```rust
use xaeroid::{XaeroIdentityManager, IdentityManager};

// Create a new identity manager
let manager = XaeroIdentityManager {};

// Generate a new DID with embedded Falcon-512 keypair
let identity = manager.new_id();

// Get the DID string
let did = format!("did:peer:{}", 
    multibase::encode(multibase::Base::Base58Btc, &identity.did_peer));

println!("New identity: {}", did);
```

### Wallet Operations

```rust
use xaeroid::domain::xaero_wallet::{XaeroWallet, WalletProofType};
use ark_bn254::Fr;

// Create a wallet from identity
let mut wallet = XaeroWallet::new(identity);

// Prove membership in a group
let group_id = Fr::from(42u64);
let token_randomness = Fr::from(12345u64);

wallet.prove_and_store_membership(group_id, token_randomness)
    .expect("Membership proof failed");

// Prove role authority
wallet.prove_and_store_role(5, 3) // My role: 5, Required: 3
    .expect("Role proof failed");

// Sign challenges
let challenge = b"authenticate me";
let signature = wallet.sign_challenge(challenge);
assert!(wallet.verify_challenge(challenge, &signature));
```

### Credential Issuance

```rust
use xaeroid::{FalconCredentialIssuer, CredentialIssuer};

// Create issuer with its own identity
let issuer_identity = manager.new_id();
let issuer = FalconCredentialIssuer { 
    issuer_xid: issuer_identity 
};

// Issue a credential
let credential = issuer.issue_credential(
    "did:peer:example",
    "alice@example.com".to_string(),
    1990
);

// Verify the credential
assert!(issuer.verify_credential(&credential));
```

### Event Integration (Optional)

XaeroID supports optional event emission for integration with event streaming systems:

```rust
use xaeroid::domain::xaero_wallet::{WalletEventSink, BlackholeEventSink};

// Use blackhole sink for standalone operation (no events)
let sink = BlackholeEventSink;

// Prove membership with event emission
wallet.prove_and_store_membership_with_sink(
    group_id, 
    token_randomness, 
    Some(&sink)
).expect("Proof with events failed");

// Implement custom event sink for your system
struct MyEventSink;
impl WalletEventSink for MyEventSink {
    fn emit_wallet_event(&self, wallet_id: &str, op: WalletCrdtOp) -> Result<(), Box<dyn std::error::Error>> {
        // Handle wallet state changes
        println!("Wallet event: {:?}", op);
        Ok(())
    }
    
    fn emit_identity_event(&self, wallet_id: &str, event: IdentityEvent) -> Result<(), Box<dyn std::error::Error>> {
        // Handle identity events  
        println!("Identity event: {:?}", event);
        Ok(())
    }
}
```

## 🏗️ Architecture

### Core Components

#### XaeroID - The Identity Core
```rust
pub struct XaeroID {
    pub did_peer: [u8; 897],      // Falcon-512 public key
    pub did_peer_len: u16,        // Actual length used
    pub secret_key: [u8; 1281],   // Falcon-512 secret key  
    pub credential: XaeroCredential, // Embedded VC
}
```

#### XaeroWallet - Proof Container
```rust
pub struct XaeroWallet {
    pub identity: XaeroID,                               // Core identity
    pub wallet_proofs: [WalletProofEntry; 16],          // ZK proof storage
    pub wallet_proof_count: u16,                        // Number of proofs
}
```

#### Proof Types
- **Identity** - Challenge-response authentication
- **Membership** - Group membership without revealing identity
- **Role** - Authority level proofs
- **ObjectCreation** - Resource creation authorization
- **WorkspaceCreation** - Workspace creation authorization
- **Delegation** - Authority delegation proofs
- **Invitation** - Group invitation proofs
- **Age** - Age threshold verification
- **CredentialPossession** - Credential ownership proofs

### Zero-Knowledge Circuits

XaeroID implements several Groth16 circuits for privacy-preserving operations:

#### Membership Circuit
Proves group membership without revealing the member's identity:
```
Constraint: token_commitment = member_token + randomness
Constraint: member_token = group_id
Public: token_commitment, group_id
Private: member_token, randomness
```

#### Role Circuit
Proves sufficient authority without revealing exact role:
```
Constraint: my_role >= min_role (via bit decomposition)
Public: min_role
Private: my_role
```

#### Object Creation Circuit
Proves object creation rights:
```
Constraint: creator_role >= min_creation_role
Constraint: new_object_root = object_seed + creator_role
Public: min_creation_role, new_object_root
Private: creator_role, object_seed
```

## 🔧 Integration Patterns

### Standalone Usage
```rust
// Pure wallet operations - no external dependencies
let mut wallet = XaeroWallet::new(identity);
wallet.prove_and_store_membership(group_id, randomness)?;
let proofs = wallet.find_wallet_proofs(WalletProofType::Membership);
```

### Event-Driven Integration
```rust
// With event emission for external systems
struct MyEventBridge;
impl WalletEventSink for MyEventBridge {
    fn emit_wallet_event(&self, wallet_id: &str, op: WalletCrdtOp) -> Result<(), Box<dyn std::error::Error>> {
        // Forward to your event system
        my_event_system.publish(wallet_id, op);
        Ok(())
    }
}

let bridge = MyEventBridge;
wallet.prove_and_store_membership_with_sink(group_id, randomness, Some(&bridge))?;
```

### Serialization & Storage
```rust
// Pod-safe serialization
let wallet_bytes = wallet.to_bytes();
let recovered_wallet = XaeroWallet::from_bytes(wallet_bytes).unwrap();

// Store to file, database, or network
std::fs::write("wallet.bin", wallet_bytes)?;
```

## 🛡️ Security Considerations

### Key Management
- **Secret keys are embedded in XaeroID** - Applications must secure these appropriately
- Falcon-512 provides post-quantum security against both classical and quantum attacks
- No key derivation - each identity uses a unique keypair

### Proof Security
- Groth16 provides zero-knowledge, succinctness, and non-interactive verification
- Trusted setup uses deterministic seeds for reproducible parameters
- All circuits implement proper constraint satisfaction

### Memory Safety
- Pod-safe structures prevent memory corruption
- Fixed-size arrays eliminate buffer overflow risks
- Zero-copy operations minimize attack surface

## 📋 Requirements

### Dependencies
- `ark-bn254` - Elliptic curve for SNARKs
- `ark-groth16` - Groth16 proof system
- `pqcrypto-falcon` - Post-quantum Falcon signatures
- `bytemuck` - Pod-safe serialization
- `blake3` - Cryptographic hashing
- `multibase` - DID encoding

### System Requirements
- 64-bit architecture (recommended)
- Minimum 4GB RAM for proof generation
- Rust 1.70+ with `trivial_bounds` feature

## 🔮 Roadmap

### Immediate (RC1)
- [x] Core identity and wallet functionality
- [x] Basic ZK proof circuits
- [x] Falcon-512 DID implementation
- [x] Pod-safe serialization
- [x] Event sink integration

### Short Term
- [ ] Additional proof circuits (delegation, invitation)
- [ ] Proof verification optimizations
- [ ] Enhanced credential schemas
- [ ] Key rotation mechanisms

### Medium Term
- [ ] Hardware security module integration
- [ ] Multi-signature support
- [ ] Batch proof generation
- [ ] Mobile platform support

### Long Term
- [ ] Quantum-resistant credential formats
- [ ] Zero-knowledge virtual machine integration
- [ ] Cross-chain identity bridges
- [ ] Formal verification of circuits

## 📄 License

MIT License - see LICENSE file for details.

## 🤝 Contributing

We welcome contributions! Please see CONTRIBUTING.md for guidelines.

### Development Setup
```bash
git clone https://github.com/your-org/xaeroid
cd xaeroid
cargo test
```

### Running Examples
```bash
cargo run --example basic_wallet
cargo run --example credential_flow
cargo run --example zk_proofs
```

## 📞 Support

- **Documentation**: [docs.rs/xaeroid](https://docs.rs/xaeroid)
- **Issues**: [GitHub Issues](https://github.com/your-org/xaeroid/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/xaeroid/discussions)

---

**XaeroID - Secure, Private, Post-Quantum Identity for the Decentralized Web**