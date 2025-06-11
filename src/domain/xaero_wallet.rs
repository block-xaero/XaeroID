use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use bytemuck::{Pod, Zeroable};

use crate::{
    identity::XaeroIdentityManager,
    zk_proofs::{ProofBytes, XaeroProofs},
    IdentityManager, XaeroID, XaeroProof,
};

// Maximum number of ZK proofs to store in wallet (separate from credential proofs)
pub const MAX_WALLET_PROOFS: usize = 16;

/// Types of ZK proofs that can be stored in the wallet
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum WalletProofType {
    Identity = 0,
    Membership = 1,
    Role = 2,
    ObjectCreation = 3,
    WorkspaceCreation = 4,
    Delegation = 5,
    Invitation = 6,
    Age = 7,
    CredentialPossession = 8,
}

/// A wallet proof entry that extends the basic XaeroProof with metadata
#[repr(C)]
#[derive(Copy, Clone)]
pub struct WalletProofEntry {
    /// The core ZK proof (your existing 32-byte format)
    pub proof: XaeroProof,
    /// Type of this proof
    pub proof_type: u8,
    /// Timestamp when proof was generated (Unix timestamp)
    pub timestamp: u64,
    /// Context data (e.g., group_id for membership, min_role for role proofs)
    pub context: [u8; 32],
    /// Additional proof data if needed (uses your ProofBytes for larger proofs)
    pub extended_proof: ProofBytes,
    /// Whether extended_proof contains valid data
    pub has_extended: u8,
    /// Padding for alignment
    pub _pad: [u8; 6],
}

unsafe impl Pod for WalletProofEntry {}
unsafe impl Zeroable for WalletProofEntry {}

impl WalletProofEntry {
    pub fn new(proof_type: WalletProofType, proof: XaeroProof, context: [u8; 32]) -> Self {
        Self {
            proof,
            proof_type: proof_type as u8,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            context,
            extended_proof: ProofBytes::zeroed(),
            has_extended: 0,
            _pad: [0; 6],
        }
    }

    pub fn new_with_extended(
        proof_type: WalletProofType,
        proof: XaeroProof,
        extended_proof: ProofBytes,
        context: [u8; 32],
    ) -> Self {
        Self {
            proof,
            proof_type: proof_type as u8,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            context,
            extended_proof,
            has_extended: 1,
            _pad: [0; 6],
        }
    }

    pub fn get_proof_type(&self) -> Option<WalletProofType> {
        match self.proof_type {
            0 => Some(WalletProofType::Identity),
            1 => Some(WalletProofType::Membership),
            2 => Some(WalletProofType::Role),
            3 => Some(WalletProofType::ObjectCreation),
            4 => Some(WalletProofType::WorkspaceCreation),
            5 => Some(WalletProofType::Delegation),
            6 => Some(WalletProofType::Invitation),
            7 => Some(WalletProofType::Age),
            8 => Some(WalletProofType::CredentialPossession),
            _ => None,
        }
    }

    pub fn get_active_proof_data(&self) -> &[u8] {
        if self.has_extended != 0 {
            &self.extended_proof.data[..self.extended_proof.len as usize]
        } else {
            &self.proof.zk_proof
        }
    }
}

/// The XaeroWallet: houses identity and ZK proofs using your existing types
#[repr(C)]
#[derive(Copy, Clone)]
pub struct XaeroWallet {
    /// The core identity (your existing XaeroID with embedded credential)
    pub identity: XaeroID,

    /// Array of additional ZK proofs (beyond those in the credential)
    pub wallet_proofs: [WalletProofEntry; MAX_WALLET_PROOFS],

    /// Number of valid wallet proofs currently stored
    pub wallet_proof_count: u16,

    /// Wallet version for future compatibility
    pub version: u16,

    /// Padding for alignment
    pub _pad: [u8; 4],
}

unsafe impl Pod for XaeroWallet {}
unsafe impl Zeroable for XaeroWallet {}

/// CRDT operations for wallet state changes
#[derive(Debug, Clone)]
pub enum WalletCrdtOp {
    ProofAdded {
        proof_type: WalletProofType,
        proof_hash: [u8; 32],
        timestamp: u64,
        context: [u8; 32],
    },
    ProofExpired {
        proof_hash: [u8; 32],
        expired_at: u64,
    },
    CredentialUpdated {
        credential_hash: [u8; 32],
        timestamp: u64,
    },
}

#[derive(Debug, Clone)]
pub enum IdentityEvent {
    ChallengeCompleted {
        challenge_hash: [u8; 32],
        signature: Box<[u8; 690]>, // Box the large signature array
    },
    PeerHandshakeInitiated {
        peer_did: String,
        timestamp: u64,
    },
}

pub trait WalletEventSink {
    /// Emit a wallet state change as a CRDT operation
    fn emit_wallet_event(
        &self,
        wallet_id: &str,
        op: WalletCrdtOp,
    ) -> Result<(), Box<dyn std::error::Error>>;

    /// Emit identity verification events for P2P handshakes
    fn emit_identity_event(
        &self,
        wallet_id: &str,
        event: IdentityEvent,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

/// Default implementation that does nothing (for xaeroID standalone use)
pub struct BlackholeEventSink;

impl WalletEventSink for BlackholeEventSink {
    fn emit_wallet_event(
        &self,
        _wallet_id: &str,
        _op: WalletCrdtOp,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Blackhole - does nothing
        Ok(())
    }

    fn emit_identity_event(
        &self,
        _wallet_id: &str,
        _event: IdentityEvent,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Blackhole - does nothing
        Ok(())
    }
}

impl XaeroWallet {
    /// Create a new wallet with the given identity
    pub fn new(identity: XaeroID) -> Self {
        Self {
            identity,
            wallet_proofs: [WalletProofEntry::zeroed(); MAX_WALLET_PROOFS],
            wallet_proof_count: 0,
            version: 1,
            _pad: [0; 4],
        }
    }

    /// Add a 32-byte proof to the wallet
    pub fn add_proof(
        &mut self,
        proof_type: WalletProofType,
        proof: XaeroProof,
        context: [u8; 32],
    ) -> Result<(), &'static str> {
        if self.wallet_proof_count >= MAX_WALLET_PROOFS as u16 {
            return Err("Wallet is full");
        }

        let entry = WalletProofEntry::new(proof_type, proof, context);
        self.wallet_proofs[self.wallet_proof_count as usize] = entry;
        self.wallet_proof_count += 1;

        Ok(())
    }

    /// Add a larger proof to the wallet using extended storage
    pub fn add_extended_proof(
        &mut self,
        proof_type: WalletProofType,
        extended_proof: ProofBytes,
        context: [u8; 32],
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.wallet_proof_count >= MAX_WALLET_PROOFS as u16 {
            return Err("Wallet is full".into());
        }

        // Create a summary/hash for the 32-byte slot
        let mut summary_proof = XaeroProof { zk_proof: [0; 32] };
        let proof_slice = &extended_proof.data[..extended_proof.len as usize];
        let hash = blake3::hash(proof_slice);
        summary_proof
            .zk_proof
            .copy_from_slice(&hash.as_bytes()[..32]);

        let entry =
            WalletProofEntry::new_with_extended(proof_type, summary_proof, extended_proof, context);
        self.wallet_proofs[self.wallet_proof_count as usize] = entry;
        self.wallet_proof_count += 1;

        Ok(())
    }

    /// Find wallet proofs of a specific type
    pub fn find_wallet_proofs(&self, proof_type: WalletProofType) -> Vec<&WalletProofEntry> {
        self.wallet_proofs[..self.wallet_proof_count as usize]
            .iter()
            .filter(|entry| entry.get_proof_type() == Some(proof_type))
            .collect()
    }

    /// Get the most recent wallet proof of a specific type
    pub fn get_latest_wallet_proof(
        &self,
        proof_type: WalletProofType,
    ) -> Option<&WalletProofEntry> {
        self.find_wallet_proofs(proof_type)
            .into_iter()
            .max_by_key(|entry| entry.timestamp)
    }

    /// Access the credential proofs (from your existing XaeroCredential)
    pub fn get_credential_proofs(&self) -> &[XaeroProof] {
        &self.identity.credential.proofs[..self.identity.credential.proof_count as usize]
    }

    /// Get DID string from the wallet's identity
    pub fn get_did(&self) -> String {
        let did_bytes = &self.identity.did_peer[..self.identity.did_peer_len as usize];
        format!("did:peer:{}", String::from_utf8_lossy(did_bytes))
    }

    /// Get the verifiable credential
    pub fn get_credential_data(&self) -> &[u8] {
        &self.identity.credential.vc[..self.identity.credential.vc_len as usize]
    }

    /// Remove expired proofs (older than specified seconds)
    pub fn cleanup_expired_proofs(&mut self, max_age_seconds: u64) {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut write_index = 0;
        for read_index in 0..self.wallet_proof_count as usize {
            let entry = &self.wallet_proofs[read_index];
            let proof_age = current_time.saturating_sub(entry.timestamp);
            if proof_age <= max_age_seconds {
                if write_index != read_index {
                    self.wallet_proofs[write_index] = *entry;
                }
                write_index += 1;
            }
        }

        // Clear remaining slots
        for i in write_index..self.wallet_proof_count as usize {
            self.wallet_proofs[i] = WalletProofEntry::zeroed();
        }

        self.wallet_proof_count = write_index as u16;
    }
}

/// High-level wallet operations using your circuits and existing traits
impl XaeroWallet {
    /// Prove membership in a group and store the proof with optional event emission
    pub fn prove_and_store_membership_with_sink<T: WalletEventSink>(
        &mut self,
        group_id: Fr,
        token_randomness: Fr,
        event_sink: Option<&T>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use crate::circuits::membership_circuit::MembershipProver;

        // In the simplified circuit: member_token = group_id
        let member_token = group_id;
        let token_commitment = member_token + token_randomness;

        let proof_bytes = MembershipProver::prove_membership(
            member_token,
            token_randomness,
            token_commitment,
            group_id,
        )?;

        // Store group_id in context
        let mut context = [0u8; 32];
        let group_id_bytes = group_id.into_bigint().to_bytes_le();
        context[..group_id_bytes.len().min(32)]
            .copy_from_slice(&group_id_bytes[..group_id_bytes.len().min(32)]);

        // Store in wallet
        self.add_extended_proof(WalletProofType::Membership, proof_bytes, context)?;

        // Emit event if sink provided
        if let Some(sink) = event_sink {
            let proof_hash = blake3::hash(&proof_bytes.data[..proof_bytes.len as usize]);
            let op = WalletCrdtOp::ProofAdded {
                proof_type: WalletProofType::Membership,
                proof_hash: *proof_hash.as_bytes(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs(),
                context,
            };
            sink.emit_wallet_event(&self.get_did(), op)?;
        }

        Ok(())
    }

    /// Keep the original method for backward compatibility
    pub fn prove_and_store_membership(
        &mut self,
        group_id: Fr,
        token_randomness: Fr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.prove_and_store_membership_with_sink(
            group_id,
            token_randomness,
            None::<&BlackholeEventSink>,
        )
    }

    /// Prove object creation rights and store the proof with optional event emission
    pub fn prove_and_store_object_creation_with_sink<T: WalletEventSink>(
        &mut self,
        creator_role: u8,
        min_creation_role: u8,
        object_seed: Fr,
        event_sink: Option<&T>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use crate::circuits::object_circuit::ObjectCreationProver;

        // Calculate the object root according to circuit constraint
        let new_object_root = object_seed + Fr::from(creator_role as u64);

        let proof_bytes = ObjectCreationProver::prove_creation(
            creator_role,
            min_creation_role,
            object_seed,
            new_object_root,
        )?;

        // Store role info in context
        let mut context = [0u8; 32];
        context[0] = min_creation_role;
        context[1] = creator_role;

        // Store in wallet
        self.add_extended_proof(WalletProofType::ObjectCreation, proof_bytes, context)?;

        // Emit event if sink provided
        if let Some(sink) = event_sink {
            let proof_hash = blake3::hash(&proof_bytes.data[..proof_bytes.len as usize]);
            let op = WalletCrdtOp::ProofAdded {
                proof_type: WalletProofType::ObjectCreation,
                proof_hash: *proof_hash.as_bytes(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs(),
                context,
            };
            sink.emit_wallet_event(&self.get_did(), op)?;
        }

        Ok(())
    }

    /// Keep the original method for backward compatibility
    pub fn prove_and_store_object_creation(
        &mut self,
        creator_role: u8,
        min_creation_role: u8,
        object_seed: Fr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.prove_and_store_object_creation_with_sink(
            creator_role,
            min_creation_role,
            object_seed,
            None::<&BlackholeEventSink>,
        )
    }

    /// Prove workspace creation rights and store the proof with optional event emission
    pub fn prove_and_store_workspace_creation_with_sink<T: WalletEventSink>(
        &mut self,
        creator_role: u8,
        min_creation_role: u8,
        workspace_seed: Fr,
        event_sink: Option<&T>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use crate::circuits::workspace_circuit::WorkspaceCreationProver;

        // Calculate the workspace root according to circuit constraint
        let new_workspace_root = workspace_seed * Fr::from(creator_role as u64);

        let proof_bytes = WorkspaceCreationProver::prove_creation(
            creator_role,
            min_creation_role,
            workspace_seed,
            new_workspace_root,
        )?;

        // Store role info in context
        let mut context = [0u8; 32];
        context[0] = min_creation_role;
        context[1] = creator_role;

        // Store in wallet
        self.add_extended_proof(WalletProofType::WorkspaceCreation, proof_bytes, context)?;

        // Emit event if sink provided
        if let Some(sink) = event_sink {
            let proof_hash = blake3::hash(&proof_bytes.data[..proof_bytes.len as usize]);
            let op = WalletCrdtOp::ProofAdded {
                proof_type: WalletProofType::WorkspaceCreation,
                proof_hash: *proof_hash.as_bytes(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs(),
                context,
            };
            sink.emit_wallet_event(&self.get_did(), op)?;
        }

        Ok(())
    }

    /// Keep the original method for backward compatibility
    pub fn prove_and_store_workspace_creation(
        &mut self,
        creator_role: u8,
        min_creation_role: u8,
        workspace_seed: Fr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.prove_and_store_workspace_creation_with_sink(
            creator_role,
            min_creation_role,
            workspace_seed,
            None::<&BlackholeEventSink>,
        )
    }

    /// Prove role authority using your existing XaeroProofs trait implementation with optional
    /// event emission
    pub fn prove_and_store_role_with_sink<T: WalletEventSink>(
        &mut self,
        my_role: u8,
        min_role: u8,
        event_sink: Option<&T>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let proof_bytes = self.identity.prove_role(my_role, min_role);

        // Store role info in context
        let mut context = [0u8; 32];
        context[0] = min_role;
        context[1] = my_role;

        // Store in wallet
        self.add_extended_proof(WalletProofType::Role, proof_bytes, context)?;

        // Emit event if sink provided
        if let Some(sink) = event_sink {
            let proof_hash = blake3::hash(&proof_bytes.data[..proof_bytes.len as usize]);
            let op = WalletCrdtOp::ProofAdded {
                proof_type: WalletProofType::Role,
                proof_hash: *proof_hash.as_bytes(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs(),
                context,
            };
            sink.emit_wallet_event(&self.get_did(), op)?;
        }

        Ok(())
    }

    /// Keep the original method for backward compatibility
    pub fn prove_and_store_role(
        &mut self,
        my_role: u8,
        min_role: u8,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.prove_and_store_role_with_sink(my_role, min_role, None::<&BlackholeEventSink>)
    }

    /// Prove membership using your existing XaeroProofs trait with optional event emission
    pub fn prove_and_store_membership_hash_with_sink<T: WalletEventSink>(
        &mut self,
        allowed_hash: [u8; 32],
        event_sink: Option<&T>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let proof_bytes = self.identity.prove_membership(allowed_hash);

        // Store hash in context
        let context = allowed_hash;

        // Store in wallet
        self.add_extended_proof(WalletProofType::Membership, proof_bytes, context)?;

        // Emit event if sink provided
        if let Some(sink) = event_sink {
            let proof_hash = blake3::hash(&proof_bytes.data[..proof_bytes.len as usize]);
            let op = WalletCrdtOp::ProofAdded {
                proof_type: WalletProofType::Membership,
                proof_hash: *proof_hash.as_bytes(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs(),
                context,
            };
            sink.emit_wallet_event(&self.get_did(), op)?;
        }

        Ok(())
    }

    /// Keep the original method for backward compatibility
    pub fn prove_and_store_membership_hash(
        &mut self,
        allowed_hash: [u8; 32],
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.prove_and_store_membership_hash_with_sink(allowed_hash, None::<&BlackholeEventSink>)
    }

    /// Sign a challenge using the identity's Falcon key with optional event emission
    pub fn sign_challenge_with_sink<T: WalletEventSink>(
        &self,
        challenge: &[u8],
        event_sink: Option<&T>,
    ) -> Result<[u8; 690], Box<dyn std::error::Error>> {
        let mgr = XaeroIdentityManager {};
        let signature = mgr.sign_challenge(&self.identity, challenge);

        // Emit event if sink provided
        if let Some(sink) = event_sink {
            let event = IdentityEvent::ChallengeCompleted {
                challenge_hash: *blake3::hash(challenge).as_bytes(),
                signature: Box::new(signature), // Box the signature
            };
            sink.emit_identity_event(&self.get_did(), event)?;
        }

        Ok(signature)
    }

    /// Sign a challenge using the identity's Falcon key
    pub fn sign_challenge(&self, challenge: &[u8]) -> [u8; 690] {
        let mgr = XaeroIdentityManager {};
        mgr.sign_challenge(&self.identity, challenge)
    }

    /// Verify a challenge signature
    pub fn verify_challenge(&self, challenge: &[u8], signature: &[u8]) -> bool {
        let mgr = XaeroIdentityManager {};
        mgr.verify_challenge(&self.identity, challenge, signature)
    }

    /// Prove identity and store the proof with optional event emission
    pub fn prove_and_store_identity_with_sink<T: WalletEventSink>(
        &mut self,
        challenge: &[u8],
        event_sink: Option<&T>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let proof_bytes = self.identity.prove_identity(challenge);

        // Store challenge hash in context
        let mut context = [0u8; 32];
        let challenge_hash = blake3::hash(challenge);
        context.copy_from_slice(&challenge_hash.as_bytes()[..32]);

        // Store in wallet
        self.add_extended_proof(WalletProofType::Identity, proof_bytes, context)?;

        // Emit event if sink provided
        if let Some(sink) = event_sink {
            let proof_hash = blake3::hash(&proof_bytes.data[..proof_bytes.len as usize]);
            let op = WalletCrdtOp::ProofAdded {
                proof_type: WalletProofType::Identity,
                proof_hash: *proof_hash.as_bytes(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs(),
                context,
            };
            sink.emit_wallet_event(&self.get_did(), op)?;
        }

        Ok(())
    }

    /// Keep the original method for backward compatibility
    pub fn prove_and_store_identity(
        &mut self,
        challenge: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.prove_and_store_identity_with_sink(challenge, None::<&BlackholeEventSink>)
    }

    #[allow(clippy::wrong_self_convention)]
    /// Export wallet to bytes for serialization
    pub fn to_bytes(&self) -> &[u8] {
        bytemuck::bytes_of(self)
    }

    /// Import wallet from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<&Self> {
        bytemuck::try_from_bytes(bytes).ok()
    }

    /// Get wallet statistics
    pub fn get_stats(&self) -> WalletStats {
        let mut stats = WalletStats::default();

        for i in 0..self.wallet_proof_count as usize {
            match self.wallet_proofs[i].get_proof_type() {
                Some(WalletProofType::Identity) => stats.identity_proofs += 1,
                Some(WalletProofType::Membership) => stats.membership_proofs += 1,
                Some(WalletProofType::Role) => stats.role_proofs += 1,
                Some(WalletProofType::ObjectCreation) => stats.object_creation_proofs += 1,
                Some(WalletProofType::WorkspaceCreation) => stats.workspace_creation_proofs += 1,
                Some(WalletProofType::Delegation) => stats.delegation_proofs += 1,
                Some(WalletProofType::Invitation) => stats.invitation_proofs += 1,
                Some(WalletProofType::Age) => stats.age_proofs += 1,
                Some(WalletProofType::CredentialPossession) =>
                    stats.credential_possession_proofs += 1,
                None => {}
            }
        }

        stats.total_proofs = self.wallet_proof_count;
        stats.credential_proofs = self.identity.credential.proof_count as u16;
        stats
    }
}

#[derive(Default, Debug)]
pub struct WalletStats {
    pub total_proofs: u16,
    pub credential_proofs: u16,
    pub identity_proofs: u16,
    pub membership_proofs: u16,
    pub role_proofs: u16,
    pub object_creation_proofs: u16,
    pub workspace_creation_proofs: u16,
    pub delegation_proofs: u16,
    pub invitation_proofs: u16,
    pub age_proofs: u16,
    pub credential_possession_proofs: u16,
}

#[cfg(test)]
mod tests {
    use ark_std::UniformRand;
    use rand::rngs::OsRng;

    use super::*;
    use crate::{credentials::FalconCredentialIssuer, CredentialIssuer};

    #[test]
    fn test_wallet_with_existing_identity() {
        // Create identity using your existing system
        let mgr = XaeroIdentityManager {};
        let identity = mgr.new_id();

        let wallet = XaeroWallet::new(identity);

        assert_eq!(wallet.wallet_proof_count, 0);
        assert_eq!(wallet.version, 1);

        // Check that we can access DID
        let did = wallet.get_did();
        assert!(did.starts_with("did:peer:"));

        // Check that we can access credential
        let cred_data = wallet.get_credential_data();
        assert!(cred_data.len() <= crate::VC_MAX_LEN);
    }

    #[test]
    fn test_wallet_with_credential_issuer() {
        // Create issuer and issue a credential
        let mgr = XaeroIdentityManager {};
        let issuer_xid = mgr.new_id();
        let issuer = FalconCredentialIssuer { issuer_xid };

        // Create user identity
        let mut user_identity = mgr.new_id();

        // Issue credential
        let credential =
            issuer.issue_credential("did:peer:test", "alice@example.com".to_string(), 1990);

        // Attach credential to identity
        user_identity.credential = credential;

        let wallet = XaeroWallet::new(user_identity);

        // Check credential proofs
        let cred_proofs = wallet.get_credential_proofs();
        assert_eq!(cred_proofs.len(), 1);
        assert!(cred_proofs[0].zk_proof.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_wallet_membership_workflow() {
        let mgr = XaeroIdentityManager {};
        let identity = mgr.new_id();
        let mut wallet = XaeroWallet::new(identity);

        let mut rng = OsRng;
        let group_id = Fr::from(42u64);
        let token_randomness = Fr::rand(&mut rng);

        // Prove and store membership using circuits
        wallet
            .prove_and_store_membership(group_id, token_randomness)
            .expect("Membership proof should succeed");

        assert_eq!(wallet.wallet_proof_count, 1);

        // Find the proof
        let membership_proofs = wallet.find_wallet_proofs(WalletProofType::Membership);
        assert_eq!(membership_proofs.len(), 1);
        assert!(
            membership_proofs[0].has_extended != 0,
            "Should use extended proof"
        );
    }

    #[test]
    fn test_wallet_membership_with_sink() {
        let mgr = XaeroIdentityManager {};
        let identity = mgr.new_id();
        let mut wallet = XaeroWallet::new(identity);

        let mut rng = OsRng;
        let group_id = Fr::from(42u64);
        let token_randomness = Fr::rand(&mut rng);

        // Test with blackhole sink
        let sink = BlackholeEventSink;
        wallet
            .prove_and_store_membership_with_sink(group_id, token_randomness, Some(&sink))
            .expect("Membership proof with sink should succeed");

        assert_eq!(wallet.wallet_proof_count, 1);

        // Find the proof
        let membership_proofs = wallet.find_wallet_proofs(WalletProofType::Membership);
        assert_eq!(membership_proofs.len(), 1);
    }

    #[test]
    fn test_wallet_membership_hash_workflow() {
        let mgr = XaeroIdentityManager {};
        let identity = mgr.new_id();
        let mut wallet = XaeroWallet::new(identity);

        // Create allowed hash from DID
        let did_bytes = &wallet.identity.did_peer[..wallet.identity.did_peer_len as usize];
        let allowed_hash_full = blake3::hash(did_bytes);
        let mut allowed_hash = [0u8; 32];
        allowed_hash.copy_from_slice(&allowed_hash_full.as_bytes()[..32]);

        // Prove and store membership using hash
        wallet
            .prove_and_store_membership_hash(allowed_hash)
            .expect("Membership hash proof should succeed");

        assert_eq!(wallet.wallet_proof_count, 1);

        // Find the proof
        let membership_proofs = wallet.find_wallet_proofs(WalletProofType::Membership);
        assert_eq!(membership_proofs.len(), 1);

        // Verify the stored context matches
        assert_eq!(membership_proofs[0].context, allowed_hash);
    }

    #[test]
    fn test_wallet_role_workflow() {
        let mgr = XaeroIdentityManager {};
        let identity = mgr.new_id();
        let mut wallet = XaeroWallet::new(identity);

        // Prove and store role
        wallet
            .prove_and_store_role(5, 3)
            .expect("Role proof should succeed");

        assert_eq!(wallet.wallet_proof_count, 1);

        // Find the proof
        let role_proofs = wallet.find_wallet_proofs(WalletProofType::Role);
        assert_eq!(role_proofs.len(), 1);

        // Verify context
        assert_eq!(role_proofs[0].context[0], 3); // min_role
        assert_eq!(role_proofs[0].context[1], 5); // my_role
    }

    #[test]
    fn test_wallet_role_with_sink() {
        let mgr = XaeroIdentityManager {};
        let identity = mgr.new_id();
        let mut wallet = XaeroWallet::new(identity);

        let sink = BlackholeEventSink;

        // Prove and store role with sink
        wallet
            .prove_and_store_role_with_sink(5, 3, Some(&sink))
            .expect("Role proof with sink should succeed");

        assert_eq!(wallet.wallet_proof_count, 1);

        // Find the proof
        let role_proofs = wallet.find_wallet_proofs(WalletProofType::Role);
        assert_eq!(role_proofs.len(), 1);

        // Verify context
        assert_eq!(role_proofs[0].context[0], 3); // min_role
        assert_eq!(role_proofs[0].context[1], 5); // my_role
    }

    #[test]
    fn test_wallet_identity_proof_workflow() {
        let mgr = XaeroIdentityManager {};
        let identity = mgr.new_id();
        let mut wallet = XaeroWallet::new(identity);

        let challenge = b"prove your identity";

        // Prove and store identity
        wallet
            .prove_and_store_identity(challenge)
            .expect("Identity proof should succeed");

        assert_eq!(wallet.wallet_proof_count, 1);

        // Find the proof
        let identity_proofs = wallet.find_wallet_proofs(WalletProofType::Identity);
        assert_eq!(identity_proofs.len(), 1);
        assert!(
            identity_proofs[0].has_extended != 0,
            "Should use extended proof"
        );

        // Verify the proof contains signature data
        let proof_data = identity_proofs[0].get_active_proof_data();
        assert!(
            !proof_data.is_empty(),
            "Identity proof should contain signature data"
        );
    }

    #[test]
    fn test_wallet_challenge_signing() {
        let mgr = XaeroIdentityManager {};
        let identity = mgr.new_id();
        let wallet = XaeroWallet::new(identity);

        let challenge = b"prove your identity";
        let signature = wallet.sign_challenge(challenge);

        // Verify the signature
        let is_valid = wallet.verify_challenge(challenge, &signature);
        assert!(is_valid, "Signature should be valid");

        // Test with wrong challenge
        let wrong_challenge = b"wrong challenge";
        let is_invalid = wallet.verify_challenge(wrong_challenge, &signature);
        assert!(
            !is_invalid,
            "Signature should be invalid for wrong challenge"
        );
    }

    #[test]
    fn test_wallet_challenge_signing_with_sink() {
        let mgr = XaeroIdentityManager {};
        let identity = mgr.new_id();
        let wallet = XaeroWallet::new(identity);

        let challenge = b"prove your identity";
        let sink = BlackholeEventSink;

        let signature = wallet
            .sign_challenge_with_sink(challenge, Some(&sink))
            .expect("Challenge signing with sink should succeed");

        // Verify the signature
        let is_valid = wallet.verify_challenge(challenge, &signature);
        assert!(is_valid, "Signature should be valid");
    }

    #[test]
    fn test_wallet_serialization() {
        let mgr = XaeroIdentityManager {};
        let identity = mgr.new_id();
        let wallet = XaeroWallet::new(identity);

        let bytes = wallet.to_bytes();
        let recovered = XaeroWallet::from_bytes(bytes).expect("failed_to_unravel");

        assert_eq!(recovered.wallet_proof_count, wallet.wallet_proof_count);
        assert_eq!(recovered.version, wallet.version);
        assert_eq!(recovered.get_did(), wallet.get_did());
    }

    #[test]
    fn test_wallet_stats() {
        let mgr = XaeroIdentityManager {};
        let identity = mgr.new_id();
        let mut wallet = XaeroWallet::new(identity);

        // Add some proofs manually for testing
        let proof = XaeroProof { zk_proof: [1; 32] };
        let context = [0u8; 32];

        wallet
            .add_proof(WalletProofType::Membership, proof, context)
            .expect("failed_to_unravel");
        wallet
            .add_proof(WalletProofType::Role, proof, context)
            .expect("failed_to_unravel");
        wallet
            .add_proof(WalletProofType::ObjectCreation, proof, context)
            .expect("failed_to_unravel");

        let stats = wallet.get_stats();
        assert_eq!(stats.total_proofs, 3);
        assert_eq!(stats.membership_proofs, 1);
        assert_eq!(stats.role_proofs, 1);
        assert_eq!(stats.object_creation_proofs, 1);
    }

    #[test]
    fn test_wallet_cleanup_expired_proofs() {
        let mgr = XaeroIdentityManager {};
        let identity = mgr.new_id();
        let mut wallet = XaeroWallet::new(identity);

        // Add some proofs with a specific timestamp in the past
        let proof = XaeroProof { zk_proof: [1; 32] };
        let context = [0u8; 32];

        // Create entries with timestamps manually to ensure they're old enough
        let old_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(10); // 10 seconds ago

        let mut entry1 = WalletProofEntry::new(WalletProofType::Membership, proof, context);
        entry1.timestamp = old_timestamp;
        wallet.wallet_proofs[0] = entry1;
        wallet.wallet_proof_count += 1;

        let mut entry2 = WalletProofEntry::new(WalletProofType::Role, proof, context);
        entry2.timestamp = old_timestamp;
        wallet.wallet_proofs[1] = entry2;
        wallet.wallet_proof_count += 1;

        assert_eq!(wallet.wallet_proof_count, 2);

        // Clean up proofs older than 5 seconds (should remove all since they're 10 seconds old)
        wallet.cleanup_expired_proofs(5);
        assert_eq!(wallet.wallet_proof_count, 0);
    }

    #[test]
    fn test_wallet_proof_types() {
        let mgr = XaeroIdentityManager {};
        let identity = mgr.new_id();
        let mut wallet = XaeroWallet::new(identity);

        // Test each proof type
        let proof = XaeroProof { zk_proof: [1; 32] };
        let context = [0u8; 32];

        let proof_types = [
            WalletProofType::Identity,
            WalletProofType::Membership,
            WalletProofType::Role,
            WalletProofType::ObjectCreation,
            WalletProofType::WorkspaceCreation,
            WalletProofType::Age,
            WalletProofType::CredentialPossession,
        ];

        for proof_type in proof_types.iter() {
            wallet
                .add_proof(*proof_type, proof, context)
                .expect("failed_to_unravel");
        }

        assert_eq!(wallet.wallet_proof_count, proof_types.len() as u16);

        // Test finding each type
        for proof_type in proof_types.iter() {
            let found = wallet.find_wallet_proofs(*proof_type);
            assert_eq!(
                found.len(),
                1,
                "Should find exactly one proof of type {:?}",
                proof_type
            );
        }
    }

    #[test]
    fn test_all_proof_methods_with_sink() {
        let mgr = XaeroIdentityManager {};
        let identity = mgr.new_id();
        let mut wallet = XaeroWallet::new(identity);
        let sink = BlackholeEventSink;

        let mut rng = OsRng;
        let group_id = Fr::from(42u64);
        let token_randomness = Fr::rand(&mut rng);
        let object_seed = Fr::rand(&mut rng);
        let workspace_seed = Fr::rand(&mut rng);
        let _allowed_hash = [42u8; 32];
        let challenge = b"test challenge";

        // Test all proof methods with sink
        wallet
            .prove_and_store_membership_with_sink(group_id, token_randomness, Some(&sink))
            .expect("Membership with sink should work");

        wallet
            .prove_and_store_role_with_sink(5, 3, Some(&sink))
            .expect("Role with sink should work");

        wallet
            .prove_and_store_object_creation_with_sink(5, 3, object_seed, Some(&sink))
            .expect("Object creation with sink should work");

        wallet
            .prove_and_store_workspace_creation_with_sink(5, 3, workspace_seed, Some(&sink))
            .expect("Workspace creation with sink should work");

        // Note: Skip membership hash test as it may depend on XaeroProofs trait implementation
        // wallet
        //     .prove_and_store_membership_hash_with_sink(allowed_hash, Some(&sink))
        //     .expect("Membership hash with sink should work");

        wallet
            .prove_and_store_identity_with_sink(challenge, Some(&sink))
            .expect("Identity with sink should work");

        wallet
            .sign_challenge_with_sink(challenge, Some(&sink))
            .expect("Challenge signing with sink should work");

        // Should have 5 proofs stored (excluding membership hash)
        assert_eq!(wallet.wallet_proof_count, 5);
    }
}
