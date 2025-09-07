use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use bytemuck::{Pod, Zeroable};

use crate::{
    identity::XaeroIdentityManager,
    zk_proofs::{ProofBytes, XaeroProofs},
    IdentityManager, XaeroID, XaeroProof,
};

// Maximum numbers for storage
pub const MAX_WALLET_PROOFS: usize = 16;
pub const MAX_GROUP_MEMBERSHIPS: usize = 10;
pub const MAX_ROLE_ASSIGNMENTS: usize = 10;

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

/// Group membership record with ZK proof
#[repr(C)]
#[derive(Copy, Clone)]
pub struct GroupMembership {
    pub group_id: [u8; 32],
    pub member_token_commitment: [u8; 32],  // Fr serialized
    pub issuer_pubkey: [u8; 32],            // Fr serialized
    pub membership_proof: ProofBytes,        // The ZK proof
    pub issued_at: u64,
    pub expires_at: u64,
    pub is_active: u8,
    pub _padding: [u8; 7],
}

unsafe impl Pod for GroupMembership {}
unsafe impl Zeroable for GroupMembership {}

/// Role assignment record with ZK proof
#[repr(C)]
#[derive(Copy, Clone)]
pub struct RoleAssignment {
    pub group_id: [u8; 32],
    pub role_level: u8,
    pub role_commitment: [u8; 32],  // Fr serialized
    pub issuer_pubkey: [u8; 32],    // Fr serialized
    pub role_proof: ProofBytes,     // The ZK proof
    pub issued_at: u64,
    pub expires_at: u64,
    pub is_active: u8,
    pub _padding: [u8; 6],
}

unsafe impl Pod for RoleAssignment {}
unsafe impl Zeroable for RoleAssignment {}

/// Invitation record for joining groups
#[repr(C)]
#[derive(Copy, Clone)]
pub struct PendingInvitation {
    pub invitation_hash: [u8; 32],
    pub inviter_pubkey: [u8; 32],
    pub group_id: [u8; 32],
    pub invitation_code: [u8; 32],  // Private, encrypted
    pub invitation_nonce: [u8; 32], // Private, encrypted
    pub expiry_time: u64,
    pub is_claimed: u8,
    pub _padding: [u8; 7],
}

unsafe impl Pod for PendingInvitation {}
unsafe impl Zeroable for PendingInvitation {}

/// A wallet proof entry that extends the basic XaeroProof with metadata
#[repr(C)]
#[derive(Copy, Clone)]
pub struct WalletProofEntry {
    pub proof: XaeroProof,
    pub proof_type: u8,
    pub timestamp: u64,
    pub context: [u8; 32],
    pub extended_proof: ProofBytes,
    pub has_extended: u8,
    pub _pad: [u8; 6],
}

unsafe impl Pod for WalletProofEntry {}
unsafe impl Zeroable for WalletProofEntry {}

/// The XaeroWallet with group/role management
#[repr(C)]
#[derive(Copy, Clone)]
pub struct XaeroWallet {
    /// The core identity
    pub identity: XaeroID,

    /// Group memberships with proofs
    pub group_memberships: [GroupMembership; MAX_GROUP_MEMBERSHIPS],
    pub group_count: u8,

    /// Role assignments with proofs
    pub role_assignments: [RoleAssignment; MAX_ROLE_ASSIGNMENTS],
    pub role_count: u8,

    /// Pending invitations
    pub pending_invitations: [PendingInvitation; MAX_GROUP_MEMBERSHIPS],
    pub invitation_count: u8,

    /// Array of additional ZK proofs
    pub wallet_proofs: [WalletProofEntry; MAX_WALLET_PROOFS],
    pub wallet_proof_count: u16,

    /// Issuer secret (encrypted) - only for XaeroPass Generator
    pub issuer_secret_encrypted: [u8; 32],
    pub is_issuer: u8,

    /// Wallet version
    pub version: u16,

    /// Padding
    pub _pad: [u8; 2],
}

unsafe impl Pod for XaeroWallet {}
unsafe impl Zeroable for XaeroWallet {}

/// CRDT operations for wallet state changes
#[derive(Debug, Clone)]
pub enum WalletCrdtOp {
    GroupAdded {
        group_id: [u8; 32],
        issuer_pubkey: [u8; 32],
        timestamp: u64,
    },
    RoleAssigned {
        group_id: [u8; 32],
        role_level: u8,
        timestamp: u64,
    },
    InvitationReceived {
        invitation_hash: [u8; 32],
        group_id: [u8; 32],
        expiry: u64,
    },
    InvitationClaimed {
        invitation_hash: [u8; 32],
        group_id: [u8; 32],
        timestamp: u64,
    },
    ProofAdded {
        proof_type: WalletProofType,
        proof_hash: [u8; 32],
        timestamp: u64,
        context: [u8; 32],
    },
}

pub trait WalletEventSink {
    fn emit_wallet_event(
        &self,
        wallet_id: &str,
        op: WalletCrdtOp,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

impl XaeroWallet {
    /// Create a new wallet with the given identity
    pub fn new(identity: XaeroID) -> Self {
        Self {
            identity,
            group_memberships: [GroupMembership::zeroed(); MAX_GROUP_MEMBERSHIPS],
            group_count: 0,
            role_assignments: [RoleAssignment::zeroed(); MAX_ROLE_ASSIGNMENTS],
            role_count: 0,
            pending_invitations: [PendingInvitation::zeroed(); MAX_GROUP_MEMBERSHIPS],
            invitation_count: 0,
            wallet_proofs: [WalletProofEntry::zeroed(); MAX_WALLET_PROOFS],
            wallet_proof_count: 0,
            issuer_secret_encrypted: [0; 32],
            is_issuer: 0,
            version: 2,
            _pad: [0; 2],
        }
    }

    /// Initialize as an issuer (for XaeroPass Generator app)
    pub fn init_as_issuer(&mut self, issuer_secret: Fr, encryption_key: &[u8; 32]) {
        // Encrypt the issuer secret (simplified - use proper encryption in production)
        let secret_bytes = issuer_secret.into_bigint().to_bytes_le();
        for i in 0..32.min(secret_bytes.len()) {
            self.issuer_secret_encrypted[i] = secret_bytes[i] ^ encryption_key[i];
        }
        self.is_issuer = 1;
    }

    /// Decrypt issuer secret (for XaeroPass Generator app)
    fn get_issuer_secret(&self, encryption_key: &[u8; 32]) -> Option<Fr> {
        if self.is_issuer == 0 {
            return None;
        }

        let mut decrypted = [0u8; 32];
        for i in 0..32 {
            decrypted[i] = self.issuer_secret_encrypted[i] ^ encryption_key[i];
        }

        Some(Fr::from_le_bytes_mod_order(&decrypted))
    }

    /// Issue initial group memberships to a XaeroID (Genesis groups)
    pub fn issue_genesis_groups(
        &self,
        target_xaero_id: Fr,
        group_ids: Vec<Fr>,
        encryption_key: &[u8; 32],
    ) -> Result<Vec<GroupMembership>, Box<dyn std::error::Error>> {
        use crate::circuits::membership_circuit::MembershipProver;
        use ark_std::UniformRand;
        use rand::rngs::OsRng;

        let issuer_secret = self.get_issuer_secret(encryption_key)
            .ok_or("Not authorized as issuer")?;

        let issuer_pubkey = MembershipProver::derive_issuer_pubkey(issuer_secret);
        let mut memberships = Vec::new();
        let mut rng = OsRng;

        for group_id in group_ids {
            let token_randomness = Fr::rand(&mut rng);
            let (token_commitment, proof) = MembershipProver::issue_membership(
                target_xaero_id,
                group_id,
                issuer_secret,
                token_randomness,
            )?;

            let mut membership = GroupMembership::zeroed();

            // Convert Fr values to bytes
            let group_bytes = group_id.into_bigint().to_bytes_le();
            membership.group_id[..group_bytes.len().min(32)]
                .copy_from_slice(&group_bytes[..group_bytes.len().min(32)]);

            let commitment_bytes = token_commitment.into_bigint().to_bytes_le();
            membership.member_token_commitment[..commitment_bytes.len().min(32)]
                .copy_from_slice(&commitment_bytes[..commitment_bytes.len().min(32)]);

            let pubkey_bytes = issuer_pubkey.into_bigint().to_bytes_le();
            membership.issuer_pubkey[..pubkey_bytes.len().min(32)]
                .copy_from_slice(&pubkey_bytes[..pubkey_bytes.len().min(32)]);

            membership.membership_proof = proof;
            membership.issued_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            membership.expires_at = membership.issued_at + (365 * 24 * 60 * 60); // 1 year
            membership.is_active = 1;

            memberships.push(membership);
        }

        Ok(memberships)
    }

    /// Add a group membership to the wallet
    pub fn add_group_membership(&mut self, membership: GroupMembership) -> Result<(), &'static str> {
        if self.group_count >= MAX_GROUP_MEMBERSHIPS as u8 {
            return Err("Maximum groups reached");
        }

        self.group_memberships[self.group_count as usize] = membership;
        self.group_count += 1;
        Ok(())
    }

    /// Issue a role to a XaeroID for a specific group
    pub fn issue_role(
        &self,
        target_xaero_id: Fr,
        group_id: Fr,
        role_level: u8,
        encryption_key: &[u8; 32],
    ) -> Result<RoleAssignment, Box<dyn std::error::Error>> {
        use crate::circuits::role_circuit::RoleProver;
        use ark_std::UniformRand;
        use rand::rngs::OsRng;

        let issuer_secret = self.get_issuer_secret(encryption_key)
            .ok_or("Not authorized as issuer")?;

        let (role_token, role_randomness, role_commitment) = RoleProver::issue_role(
            target_xaero_id,
            group_id,
            role_level,
            issuer_secret,
        )?;

        let issuer_pubkey = issuer_secret * issuer_secret; // Simplified

        // Generate proof
        let proof = RoleProver::prove_role(
            target_xaero_id,
            group_id,
            role_level,
            1, // min_role for proof
            role_token,
            role_randomness,
            role_commitment,
            issuer_pubkey,
        )?;

        let mut assignment = RoleAssignment::zeroed();

        // Convert values to bytes
        let group_bytes = group_id.into_bigint().to_bytes_le();
        assignment.group_id[..group_bytes.len().min(32)]
            .copy_from_slice(&group_bytes[..group_bytes.len().min(32)]);

        assignment.role_level = role_level;

        let commitment_bytes = role_commitment.into_bigint().to_bytes_le();
        assignment.role_commitment[..commitment_bytes.len().min(32)]
            .copy_from_slice(&commitment_bytes[..commitment_bytes.len().min(32)]);

        let pubkey_bytes = issuer_pubkey.into_bigint().to_bytes_le();
        assignment.issuer_pubkey[..pubkey_bytes.len().min(32)]
            .copy_from_slice(&pubkey_bytes[..pubkey_bytes.len().min(32)]);

        assignment.role_proof = proof;
        assignment.issued_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        assignment.expires_at = assignment.issued_at + (90 * 24 * 60 * 60); // 90 days
        assignment.is_active = 1;

        Ok(assignment)
    }

    /// Add a role assignment to the wallet
    pub fn add_role_assignment(&mut self, assignment: RoleAssignment) -> Result<(), &'static str> {
        if self.role_count >= MAX_ROLE_ASSIGNMENTS as u8 {
            return Err("Maximum roles reached");
        }

        self.role_assignments[self.role_count as usize] = assignment;
        self.role_count += 1;
        Ok(())
    }

    /// Create an invitation for someone to join a group
    pub fn create_invitation(
        &self,
        target_xaero_id: Fr,
        group_id: Fr,
        encryption_key: &[u8; 32],
    ) -> Result<PendingInvitation, Box<dyn std::error::Error>> {
        use crate::circuits::invitation_circuit::InvitationProver;

        let issuer_secret = self.get_issuer_secret(encryption_key)
            .ok_or("Not authorized as issuer")?;

        let expiry_time = Fr::from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs() + (7 * 24 * 60 * 60) // 7 days
        );

        let (invitation_code, invitation_nonce, invitation_hash) =
            InvitationProver::create_invitation(
                issuer_secret,
                target_xaero_id,
                group_id,
                expiry_time,
            )?;

        let mut invitation = PendingInvitation::zeroed();

        // Store invitation data
        let hash_bytes = invitation_hash.into_bigint().to_bytes_le();
        invitation.invitation_hash[..hash_bytes.len().min(32)]
            .copy_from_slice(&hash_bytes[..hash_bytes.len().min(32)]);

        let pubkey = issuer_secret * issuer_secret;
        let pubkey_bytes = pubkey.into_bigint().to_bytes_le();
        invitation.inviter_pubkey[..pubkey_bytes.len().min(32)]
            .copy_from_slice(&pubkey_bytes[..pubkey_bytes.len().min(32)]);

        let group_bytes = group_id.into_bigint().to_bytes_le();
        invitation.group_id[..group_bytes.len().min(32)]
            .copy_from_slice(&group_bytes[..group_bytes.len().min(32)]);

        // Encrypt invitation code and nonce (simplified)
        let code_bytes = invitation_code.into_bigint().to_bytes_le();
        for i in 0..32.min(code_bytes.len()) {
            invitation.invitation_code[i] = code_bytes[i] ^ encryption_key[i];
        }

        let nonce_bytes = invitation_nonce.into_bigint().to_bytes_le();
        for i in 0..32.min(nonce_bytes.len()) {
            invitation.invitation_nonce[i] = nonce_bytes[i] ^ encryption_key[(i + 16) % 32];
        }

        invitation.expiry_time = expiry_time.into_bigint().0[0];
        invitation.is_claimed = 0;

        Ok(invitation)
    }

    /// Add an invitation to the wallet
    pub fn add_invitation(&mut self, invitation: PendingInvitation) -> Result<(), &'static str> {
        if self.invitation_count >= MAX_GROUP_MEMBERSHIPS as u8 {
            return Err("Maximum invitations reached");
        }

        self.pending_invitations[self.invitation_count as usize] = invitation;
        self.invitation_count += 1;
        Ok(())
    }

    /// Claim an invitation and join a group
    pub fn claim_invitation(
        &mut self,
        invitation_index: usize,
        encryption_key: &[u8; 32],
    ) -> Result<GroupMembership, Box<dyn std::error::Error>> {
        use crate::circuits::invitation_circuit::InvitationProver;

        if invitation_index >= self.invitation_count as usize {
            return Err("Invalid invitation index".into());
        }

        let invitation = &mut self.pending_invitations[invitation_index];
        if invitation.is_claimed != 0 {
            return Err("Invitation already claimed".into());
        }

        // Decrypt invitation code and nonce
        let mut code_decrypted = [0u8; 32];
        for i in 0..32 {
            code_decrypted[i] = invitation.invitation_code[i] ^ encryption_key[i];
        }
        let invitation_code = Fr::from_le_bytes_mod_order(&code_decrypted);

        let mut nonce_decrypted = [0u8; 32];
        for i in 0..32 {
            nonce_decrypted[i] = invitation.invitation_nonce[i] ^ encryption_key[(i + 16) % 32];
        }
        let invitation_nonce = Fr::from_le_bytes_mod_order(&nonce_decrypted);

        // Convert stored values back to Fr
        let invitation_hash = Fr::from_le_bytes_mod_order(&invitation.invitation_hash);
        let inviter_pubkey = Fr::from_le_bytes_mod_order(&invitation.inviter_pubkey);
        let group_id = Fr::from_le_bytes_mod_order(&invitation.group_id);
        let expiry_time = Fr::from(invitation.expiry_time);

        // Get XaeroID as Fr
        let xaero_id_bytes = blake3::hash(&self.identity.did_peer[..self.identity.did_peer_len as usize]);
        let target_xaero_id = Fr::from_le_bytes_mod_order(xaero_id_bytes.as_bytes());

        // Claim the invitation
        let proof = InvitationProver::claim_invitation(
            invitation_code,
            invitation_nonce,
            invitation_hash,
            inviter_pubkey,
            target_xaero_id,
            group_id,
            expiry_time,
        )?;

        // Create group membership from invitation
        let mut membership = GroupMembership::zeroed();
        membership.group_id = invitation.group_id;
        membership.issuer_pubkey = invitation.inviter_pubkey;

        // Use invitation hash as commitment (simplified)
        membership.member_token_commitment = invitation.invitation_hash;

        // Convert proof to ProofBytes
        let mut proof_bytes = ProofBytes::zeroed();
        let copy_len = proof.data.len().min(proof_bytes.data.len());
        proof_bytes.data[..copy_len].copy_from_slice(&proof.data[..copy_len]);
        proof_bytes.len = copy_len as u16;
        proof_bytes.len = proof.len;
        membership.membership_proof = proof_bytes;

        membership.issued_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        membership.expires_at = invitation.expiry_time;
        membership.is_active = 1;

        // Mark invitation as claimed
        invitation.is_claimed = 1;

        // Add to group memberships
        self.add_group_membership(membership)?;

        Ok(membership)
    }

    /// Get active group memberships
    pub fn get_active_groups(&self) -> Vec<&GroupMembership> {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.group_memberships[..self.group_count as usize]
            .iter()
            .filter(|m| m.is_active != 0 && m.expires_at > current_time)
            .collect()
    }

    /// Get roles for a specific group
    pub fn get_roles_for_group(&self, group_id: [u8; 32]) -> Vec<&RoleAssignment> {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.role_assignments[..self.role_count as usize]
            .iter()
            .filter(|r| r.group_id == group_id && r.is_active != 0 && r.expires_at > current_time)
            .collect()
    }

    /// Get highest role level for a group
    pub fn get_highest_role_for_group(&self, group_id: [u8; 32]) -> Option<u8> {
        self.get_roles_for_group(group_id)
            .iter()
            .map(|r| r.role_level)
            .max()
    }

    /// Verify a group membership
    pub fn verify_membership(&self, group_index: usize) -> Result<bool, Box<dyn std::error::Error>> {
        use crate::circuits::membership_circuit::MembershipProver;

        if group_index >= self.group_count as usize {
            return Ok(false);
        }

        let membership = &self.group_memberships[group_index];

        // Convert bytes back to Fr
        let xaero_id_bytes = blake3::hash(&self.identity.did_peer[..self.identity.did_peer_len as usize]);
        let xaero_id = Fr::from_le_bytes_mod_order(xaero_id_bytes.as_bytes());
        let group_id = Fr::from_le_bytes_mod_order(&membership.group_id);
        let token_commitment = Fr::from_le_bytes_mod_order(&membership.member_token_commitment);
        let issuer_pubkey = Fr::from_le_bytes_mod_order(&membership.issuer_pubkey);

        let proof_slice = &membership.membership_proof.data[..membership.membership_proof.len as usize];

        MembershipProver::verify_membership(
            &xaero_id,
            &group_id,
            &token_commitment,
            &issuer_pubkey,
            proof_slice,
        )
    }

    /// Export wallet to bytes
    pub fn to_bytes(&self) -> &[u8] {
        bytemuck::bytes_of(self)
    }

    /// Import wallet from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<&Self> {
        bytemuck::try_from_bytes(bytes).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{credentials::FalconCredentialIssuer, CredentialIssuer};
    use crate::identity::XaeroIdentityManager;

    #[test]
    fn test_wallet_as_issuer() {
        let mgr = XaeroIdentityManager {};
        let identity = mgr.new_id();
        let mut wallet = XaeroWallet::new(identity);

        // Initialize as issuer
        let issuer_secret = Fr::from(999u64);
        let encryption_key = [42u8; 32];
        wallet.init_as_issuer(issuer_secret, &encryption_key);

        assert_eq!(wallet.is_issuer, 1);

        // Verify we can retrieve the secret
        let retrieved = wallet.get_issuer_secret(&encryption_key).unwrap();
        assert_eq!(retrieved, issuer_secret);
    }

    #[test]
    fn test_issue_genesis_groups() {
        let mgr = XaeroIdentityManager {};
        let issuer_identity = mgr.new_id();
        let mut issuer_wallet = XaeroWallet::new(issuer_identity);

        // Setup issuer
        let issuer_secret = Fr::from(999u64);
        let encryption_key = [42u8; 32];
        issuer_wallet.init_as_issuer(issuer_secret, &encryption_key);

        // Issue groups to a target XaeroID
        let target_xaero_id = Fr::from(12345u64);
        let group_ids = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];

        let memberships = issuer_wallet.issue_genesis_groups(
            target_xaero_id,
            group_ids,
            &encryption_key,
        ).expect("Failed to issue genesis groups");

        assert_eq!(memberships.len(), 3);

        // Create target wallet and add memberships
        let target_identity = mgr.new_id();
        let mut target_wallet = XaeroWallet::new(target_identity);

        for membership in memberships {
            target_wallet.add_group_membership(membership)
                .expect("Failed to add membership");
        }

        assert_eq!(target_wallet.group_count, 3);
    }

    #[test]
    fn test_role_assignment() {
        let mgr = XaeroIdentityManager {};
        let issuer_identity = mgr.new_id();
        let mut issuer_wallet = XaeroWallet::new(issuer_identity);

        // Setup issuer
        let issuer_secret = Fr::from(999u64);
        let encryption_key = [42u8; 32];
        issuer_wallet.init_as_issuer(issuer_secret, &encryption_key);

        // Issue role
        let target_xaero_id = Fr::from(12345u64);
        let group_id = Fr::from(42u64);
        let role_level = 5u8;

        let assignment = issuer_wallet.issue_role(
            target_xaero_id,
            group_id,
            role_level,
            &encryption_key,
        ).expect("Failed to issue role");

        assert_eq!(assignment.role_level, role_level);

        // Add to target wallet
        let target_identity = mgr.new_id();
        let mut target_wallet = XaeroWallet::new(target_identity);
        target_wallet.add_role_assignment(assignment)
            .expect("Failed to add role");

        assert_eq!(target_wallet.role_count, 1);

        // Check highest role
        let group_bytes = group_id.into_bigint().to_bytes_le();
        let mut group_id_bytes = [0u8; 32];
        group_id_bytes[..group_bytes.len().min(32)]
            .copy_from_slice(&group_bytes[..group_bytes.len().min(32)]);

        let highest = target_wallet.get_highest_role_for_group(group_id_bytes);
        assert_eq!(highest, Some(role_level));
    }

    #[test]
    fn test_invitation_flow() {
        let mgr = XaeroIdentityManager {};

        // Create issuer
        let issuer_identity = mgr.new_id();
        let mut issuer_wallet = XaeroWallet::new(issuer_identity);
        let issuer_secret = Fr::from(999u64);
        let encryption_key = [42u8; 32];
        issuer_wallet.init_as_issuer(issuer_secret, &encryption_key);

        // Create target
        let target_identity = mgr.new_id();
        let mut target_wallet = XaeroWallet::new(target_identity);

        // Create invitation
        let target_xaero_id = Fr::from(12345u64);
        let group_id = Fr::from(42u64);

        let invitation = issuer_wallet.create_invitation(
            target_xaero_id,
            group_id,
            &encryption_key,
        ).expect("Failed to create invitation");

        // Add to target wallet
        target_wallet.add_invitation(invitation)
            .expect("Failed to add invitation");

        assert_eq!(target_wallet.invitation_count, 1);

        // Claim invitation
        let membership = target_wallet.claim_invitation(0, &encryption_key)
            .expect("Failed to claim invitation");

        assert_eq!(target_wallet.group_count, 1);
        assert_eq!(target_wallet.pending_invitations[0].is_claimed, 1);
    }
}