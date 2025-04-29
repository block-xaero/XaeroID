use crate::{nft::Nft, zero_id::ZeroId, zero_proof::ZeroProof};

pub trait ZeroWalletManager {
    fn zero_id(&self) -> ZeroId;
    fn proofs(&self) -> Vec<ZeroProof>;
    fn nfts(&self) -> Vec<Nft>;
    fn add_proofs(&mut self, proofs: Vec<ZeroProof>);
    fn add_nfts(&mut self, nfts: Vec<Nft>);
}
