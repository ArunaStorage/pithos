use anyhow::Result;
use x25519_dalek::{StaticSecret, PublicKey};
use blake2::Blake2b;
use digest::Digest;
use rand_core::OsRng;

pub fn create_shared_key(writers_secret_key: &[u8], readers_pub_key: &[u8]) -> Result<[u8; 32]> {
    let writers_secret_key = StaticSecret::from_bytes(writers_secret_key);
    let writers_pub_key = PublicKey::from(writers_secret_key);
    let readers_pub_key = PublicKey::from(readers_pub_key);
    let dh_shared_key = writers_secret_key.diffie_hellmann(&readers_pub_key);
    let mut blake_hasher = Blake2b::new();
    blake_hasher.update(dh_shared_key.as_bytes());
    blake_hasher.update(readers_pub_key);
    blake_hasher.update(writers_pub_key.as_bytes());
    let result = blake_hasher.finalize();
    Ok(result.as_slice()[..32].try_into()?)
}

pub fn create_shared_key2(readers_pub_key: &[u8]) -> Result<([u8; 32], &[u8])> {
    let writers_secret_key = StaticSecret::random_from_rng(OsRng);
    let writers_pub_key = PublicKey::from(&writers_secret_key);
    Ok((create_shared_key(writers_secret_key.as_bytes(), readers_pub_key)?, writers_pub_key.as_bytes()))
}