use std::any::Any;

use bytemuck::{bytes_of, Zeroable};
use pqcrypto_traits::sign::PublicKey as PublicKeyTrait;

use crate::{IdentityManager, XaeroID};

pub struct XaeroIdentityManager {}
impl IdentityManager for XaeroIdentityManager {
    fn new_id(&self) -> XaeroID {
        use pqcrypto_falcon::falcon512::*;
        use rand::rngs::OsRng;
        let (pk, sk) = keypair(); // [u8; 897], [u8; 1280]
        let mut xid = XaeroID::zeroed();
        xid.did_peer_len = 897;
        xid.did_peer[..897].copy_from_slice(pk.as_bytes());
        xid
    }

    fn sign_challenge(&self, did: &str, challenge: &[u8]) -> Vec<u8> {
        todo!()
    }

    fn verify_challenge(&self, did: &str, challenge: &[u8], signature: &[u8]) -> bool {
        todo!()
    }
}
