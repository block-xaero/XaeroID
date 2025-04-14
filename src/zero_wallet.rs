use std::collections::HashMap;

use crate::{nft::Nft, zero_id::ZeroId, zero_proof::ZeroProof};
pub const MAX_NFTS: usize = 10;
/// Represents a wallet that contains a ZeroId, a collection of proofs, and a collection of NFTs.
/// The wallet can hold a maximum of 10 NFTs.
/// The `ZeroWallet` struct is used to manage the user's digital assets and their associated proofs.
/// The `id` field is a unique identifier for the wallet.
/// The `proofs` field is a collection of proofs associated with the wallet.    
/// The `nfts` field is an array of `LocalNft` objects, which represent the NFTs owned by the wallet.
/// The `nfts` field is limited to a maximum of 10 NFTs.
#[derive(Debug)]
#[repr(C)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ZeroWallet {
    pub id: ZeroId,
    pub proofs: HashMap<String, ZeroProof>,
    pub nfts: [Option<Nft>; MAX_NFTS],
}
