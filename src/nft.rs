use rkyv::{Archive, Deserialize, Serialize};

use crate::zero_id::ZeroId;


#[repr(C)]
#[derive(Debug, Clone, Archive, Serialize, Deserialize, PartialEq, Eq)]
#[rkyv(derive(Debug))]
pub enum ContentType {
    Image,
    Video,
    Audio,
    Doc,
    Post,
    Art,
}

#[repr(C)]
#[derive(Clone, Archive, Serialize, Deserialize)]
pub struct Nft {
    pub zero_id: ZeroId,
    pub content_hash: [u8; 1024],
    pub signature: [u8; 64],
    pub content_type: ContentType,
}
