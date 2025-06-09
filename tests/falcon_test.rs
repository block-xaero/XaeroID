use pqcrypto_falcon::{falcon512::*, falcon512_detached_sign};
use pqcrypto_traits::sign::{
    DetachedSignature as DetachedSignatureTrait, PublicKey as PublicKeyTrait,
    SecretKey as SecretKeyTrait,
};

#[test]
fn test_falcon_signature_lengths() {
    let (pk, sk) = keypair();
    let challenge = b"test challenge";

    let sig = falcon512_detached_sign(challenge, &sk);

    println!("Public key length: {}", pk.as_bytes().len());
    println!("Secret key length: {}", sk.as_bytes().len());
    println!("Signature length: {}", sig.as_bytes().len());

    // Test multiple signatures to see if length varies
    for i in 0..5 {
        let test_challenge = format!("test challenge {}", i);
        let test_sig = falcon512_detached_sign(test_challenge.as_bytes(), &sk);
        println!("Signature {} length: {}", i, test_sig.as_bytes().len());
    }
}
