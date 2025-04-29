use std::collections::HashMap;

use crate::{
    nft::Nft,
    zero_id::ZeroId,
    zero_proof::ZeroProof,
    zero_wallet::MAX_NFTS,
};
pub trait ZeroWalletManager {
    fn new() -> Self;
    fn add_proofs(&mut self, proofs: Vec<ZeroProof>);
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
