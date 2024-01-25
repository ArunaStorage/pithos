use anyhow::Result;
use openssl::pkey::{Id, PKey};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

pub fn load_private_key_from_pem(filepath: &PathBuf) -> Result<[u8; 32]> {
    // Open file handle and read file bytes
    let mut file = File::open(filepath)?;
    let mut file_content = vec![0u8; file.metadata()?.len() as usize];
    file.read_exact(&mut file_content)?;

    // Parse into private key
    let pkey = PKey::private_key_from_pem(&file_content)?;
    let key_bytes: [u8; 32] = pkey.raw_private_key().try_into()?;
    Ok(key_bytes)
}

pub fn load_private_key_from_string(key_bytes: &[u8]) -> Result<[u8; 32]> {
    let pkey = PKey::private_key_from_raw_bytes(key_bytes, Id::X25519)?;
    let key_bytes: [u8; 32] = pkey.raw_private_key().try_into()?;
    Ok(key_bytes)
}
