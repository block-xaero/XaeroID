# XaeroID

Dead simple decentralized identity.

## What it does

- Generates Ed25519 keypair (Iroh compatible)
- Creates `did:peer` identifier
- Hash-based group commitments
- Signs payloads for QR codes

## Usage (Rust)

```rust
use xaeroid::XaeroID;

// Generate identity
let mut xid = XaeroID::generate();

// Join groups
xid.join_group("engineering");
xid.join_group("backend");

// Get DID
println!("{}", xid.did);  // did:peer:z6Mk...

// Create QR payload
let payload = xid.to_pass_payload();
let bytes = xid.to_pass_bytes();  // JSON for QR
```

## Usage (Swift via FFI)

```swift
let xid = XaeroID()
xid.joinGroup("engineering")

print(xid.did!)  // did:peer:z6Mk...

let payload = xid.passPayload()  // Data for QR
```

## QR Payload Format

```json
{
  "did": "did:peer:z6Mk...",
  "pubkey": [32 bytes],
  "groups": ["engineering", "backend"],
  "issued_at": 1701388800,
  "signature": [64 bytes]
}
```

## Build

```bash
cargo build --release

# For iOS/macOS static lib
cargo build --release --target aarch64-apple-darwin
```

## FFI Functions

```c
CXaeroID xaero_generate();
bool xaero_join_group(CXaeroID* xid, const char* group);
bool xaero_get_did(CXaeroID* xid, char* out, size_t len);
bool xaero_get_pass_payload(CXaeroID* xid, uint8_t* out, size_t cap, size_t* len);
bool xaero_verify_pass(uint8_t* payload, size_t len);
void xaero_free(CXaeroID xid);
```

## License

MPL v2.0