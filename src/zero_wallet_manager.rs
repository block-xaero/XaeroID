use std::collections::HashMap;

use crate::{
    nft::Nft,
    zero_id::ZeroId,
    zero_proof::ZeroProof,
    zero_wallet::{ZeroWallet, MAX_NFTS},
};
pub trait ZeroWalletManager {
    fn new() -> Self;
    fn add_proofs(&mut self, proofs: HashMap<String, ZeroProof>);
    fn add_proof(&mut self, proof: ZeroProof);
    fn remove_proof(&mut self, proof_id: &str);
    fn add_nft(&mut self, nft: Option<Nft>);
    fn remove_nft(&mut self, nft_id: &str);
    fn get_proof(&self, proof_id: &str) -> Option<&ZeroProof>;
    fn get_nft(&self, nft_id: &str) -> Option<&Nft>;
    fn list_proofs(&self) -> Vec<&ZeroProof>;
    fn list_nfts(&self) -> Vec<&Nft>;
    fn get_id(&self) -> &ZeroId;
    fn set_id(&mut self, id: ZeroId);
    fn get_proofs(&self) -> &HashMap<String, ZeroProof>;
    fn get_nfts(&self) -> &[Option<Nft>; MAX_NFTS];
    fn set_proofs(&mut self, proofs: HashMap<String, ZeroProof>);
    fn set_nfts(&mut self, nfts: [Option<Nft>; MAX_NFTS]);
    fn clear_proofs(&mut self);
    fn clear_nfts(&mut self);
    fn clear(&mut self);
    fn is_empty(&self) -> bool;
    fn is_full(&self) -> bool;
    fn is_valid(&self) -> bool;
    fn is_valid_proof(&self, proof: &ZeroProof) -> bool;
    fn is_valid_nft(&self, nft: &Nft) -> bool;
    fn is_valid_id(&self, id: &ZeroId) -> bool;
    fn is_valid_proofs(&self, proofs: &HashMap<String, ZeroProof>) -> bool;
    fn is_valid_nfts(&self, nfts: &[Option<Nft>; MAX_NFTS]) -> bool;
    fn is_valid_wallet(&self) -> bool;
    fn is_valid_wallet_id(&self) -> bool;
    fn is_valid_wallet_proofs(&self) -> bool;
    fn is_valid_wallet_nfts(&self) -> bool;
    fn is_valid_wallet_proof(&self, proof: &ZeroProof) -> bool;
}

/// Represents a wallet that contains a ZeroId, a collection of proofs, and a collection of NFTs.
impl ZeroWalletManager for ZeroWallet {
    fn new() -> Self {
        let nfts: [Option<Nft>; MAX_NFTS] = array_init::array_init(|_| None);
        Self {
            id: ZeroId {
                did_peer: [0; 512],
                pubkey: [0; 64],
                signature: [0; 64],
            },
            proofs: HashMap::new(),
            nfts,
        }
    }

    fn add_proofs(&mut self, proofs: HashMap<String, ZeroProof>) {
        for (id, proof) in proofs {
            self.proofs.insert(id, proof);
        }
    }

    fn add_proof(&mut self, proof: ZeroProof) {
        // Using timestamp as the key for the proof
        let key = proof.timestamp.to_string();
        self.proofs.insert(key, proof);
    }

    fn remove_proof(&mut self, proof_id: &str) {
        self.proofs.remove(proof_id);
    }

    fn add_nft(&mut self, nft: Option<Nft>) {
        // Find the first empty slot and insert the NFT
        for slot in &mut self.nfts {
            if slot.is_none() {
                *slot = Some(nft.expect("msg: NFT should not be None"));
                return;
            }
        }
        // If we get here, the array is full and the NFT wasn't added
    }

    fn remove_nft(&mut self, _nft_id: &str) {
        // Find the NFT with the matching ID and remove it
        todo!()
    }

    fn get_proof(&self, proof_id: &str) -> Option<&ZeroProof> {
        self.proofs.get(proof_id)
    }

    fn get_nft(&self, _nft_id: &str) -> Option<&Nft> {
        todo!()
    }

    fn list_proofs(&self) -> Vec<&ZeroProof> {
        self.proofs.values().collect()
    }

    fn list_nfts(&self) -> Vec<&Nft> {
        self.nfts.iter().filter_map(|slot| slot.as_ref()).collect()
    }

    fn get_id(&self) -> &ZeroId {
        &self.id
    }

    fn set_id(&mut self, id: ZeroId) {
        self.id = id;
    }

    fn get_proofs(&self) -> &HashMap<String, ZeroProof> {
        &self.proofs
    }

    fn get_nfts(&self) -> &[Option<Nft>; MAX_NFTS] {
        &self.nfts
    }

    fn set_proofs(&mut self, proofs: HashMap<String, ZeroProof>) {
        self.proofs = proofs;
    }

    fn set_nfts(&mut self, nfts: [Option<Nft>; MAX_NFTS]) {
        for (i, nft) in nfts.into_iter().enumerate() {
            self.nfts[i] = nft;
        }
    }

    fn clear_proofs(&mut self) {
        self.proofs.clear();
    }

    fn clear_nfts(&mut self) {
        for slot in &mut self.nfts {
            *slot = None;
        }
    }

    fn clear(&mut self) {
        self.clear_proofs();
        self.clear_nfts();
        self.id = ZeroId {
            did_peer: [0; 512],
            pubkey: [0; 64],
            signature: [0; 64],
        };
    }

    fn is_empty(&self) -> bool {
        self.proofs.is_empty() && self.nfts.iter().all(Option::is_none)
    }

    fn is_full(&self) -> bool {
        self.nfts.iter().all(Option::is_some)
    }

    fn is_valid(&self) -> bool {
        self.is_valid_id(&self.id) && self.is_valid_proofs(&self.proofs) && self.is_valid_wallet()
    }

    fn is_valid_proof(&self, proof: &ZeroProof) -> bool {
        // You'll need to implement validation logic for proofs
        // This might involve verifying the Receipt using RISC Zero
        // For now, a simple non-zero timestamp check
        proof.timestamp > 0
    }

    fn is_valid_nft(&self, nft: &Nft) -> bool {
        // Check if the NFT is valid
        // Check if the NFT has a valid ID and is not empty
        !nft.zero_id.did_peer.iter().all(|&b| b == 0)
            && !nft.zero_id.pubkey.iter().all(|&b| b == 0)
            && !nft.zero_id.signature.iter().all(|&b| b == 0)
    }

    fn is_valid_id(&self, id: &ZeroId) -> bool {
        // Check if the ZeroId is valid
        // Example: check if the did_peer is not all zeros and signature is valid
        !id.did_peer.iter().all(|&b| b == 0)
            && !id.pubkey.iter().all(|&b| b == 0)
            && !id.signature.iter().all(|&b| b == 0)
        // You might want to add crypto verification here
    }

    fn is_valid_proofs(&self, proofs: &HashMap<String, ZeroProof>) -> bool {
        // Check if all proofs are valid
        proofs.values().all(|proof| self.is_valid_proof(proof))
    }

    fn is_valid_nfts(&self, nfts: &[Option<Nft>; MAX_NFTS]) -> bool {
        // Check if all NFTs are valid
        nfts.iter()
            .filter_map(|nft| nft.as_ref())
            .all(|nft| self.is_valid_nft(nft))
    }

    fn is_valid_wallet(&self) -> bool {
        self.is_valid_wallet_id() && self.is_valid_wallet_proofs() && self.is_valid_wallet_nfts()
    }

    fn is_valid_wallet_id(&self) -> bool {
        self.is_valid_id(&self.id)
    }

    fn is_valid_wallet_proofs(&self) -> bool {
        self.proofs
            .values()
            .all(|proof| self.is_valid_wallet_proof(proof))
    }

    fn is_valid_wallet_nfts(&self) -> bool {
        self.nfts
            .iter()
            .filter_map(|slot| slot.as_ref())
            .all(|nft| self.is_valid_nft(nft))
    }

    fn is_valid_wallet_proof(&self, proof: &ZeroProof) -> bool {
        // You might want to verify that the proof is related to this wallet
        // For example, check if the proof is signed by the wallet's private key
        self.is_valid_proof(proof)
        // Additional wallet-specific verification can be added here
    }
}
