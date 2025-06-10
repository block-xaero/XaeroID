use std::sync::Arc;

use ark_bn254::Fr;
use ark_std::{rand::Rng, UniformRand};
use blake3;
use rand::rngs::OsRng;

use crate::domain::xaero_serde::XaeroIdFr;

pub struct Id {
    pub master_secret: XaeroIdFr,
    pub public_key: XaeroIdFr,
}

pub fn generate_master_secret<R: Rng>(rng: &mut R) -> XaeroIdFr {
    // Generate cryptographically secure random field element
    XaeroIdFr::from(Fr::rand(rng))
}
