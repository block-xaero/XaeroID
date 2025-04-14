use crate::zero_id::ZeroId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
enum ContentType {
    DrippImage,
    DrippVideo,
    DrippAudio,
    DrippDocument,
    DrippPost,
    DrippArt,
}

#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Nft {
    pub zero_id: ZeroId,
    #[serde(with = "serde_arrays")]
    pub content_hash: [u8; 1024],
    #[serde(with = "serde_arrays")]
    pub signature: [u8; 64],
    pub content_type: ContentType,
}
