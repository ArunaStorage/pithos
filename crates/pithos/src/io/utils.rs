use anyhow::Result;
use openssl::pkey::{Id, PKey};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

pub fn load_private_key_from_pem(filepath: &PathBuf) -> Result<([u8; 32], [u8; 32])> {
    // Open file handle and read file bytes
    let mut file = File::open(filepath)?;
    let mut file_content = vec![0u8; file.metadata()?.len() as usize];
    file.read_exact(&mut file_content)?;

    // Parse into private key
    let private_key = PKey::private_key_from_pem(&file_content)?;
    let mut private_key_bytes: [u8; 32] = [0; 32];
    private_key_bytes.copy_from_slice(private_key.raw_private_key()?.as_slice());

    let mut public_key_bytes: [u8; 32] = [0; 32];
    public_key_bytes.copy_from_slice(private_key.raw_public_key()?.as_slice());

    Ok((private_key_bytes, public_key_bytes))
}

pub fn _load_private_key_from_string(key_bytes: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    // Try to parse bytes as x25519 key
    let private_key = PKey::private_key_from_raw_bytes(key_bytes, Id::X25519)?;

    let mut private_key_bytes: [u8; 32] = [0; 32];
    private_key_bytes.copy_from_slice(private_key.raw_private_key()?.as_slice());

    let mut public_key_bytes: [u8; 32] = [0; 32];
    public_key_bytes.copy_from_slice(private_key.raw_public_key()?.as_slice());

    Ok((private_key_bytes, public_key_bytes))
}

pub fn load_private_key_from_env() -> Result<([u8; 32], [u8; 32])> {
    // Read bytes from env var
    let input_bytes = dotenvy::var("PITHOS_PRIVATE_KEY")?;
    let wat = input_bytes.as_bytes();

    // Parse bytes into private key
    let private_key = PKey::private_key_from_pem(wat)?;
    let mut private_key_bytes: [u8; 32] = [0; 32];
    private_key_bytes.copy_from_slice(private_key.raw_private_key()?.as_slice());

    let mut public_key_bytes: [u8; 32] = [0; 32];
    public_key_bytes.copy_from_slice(private_key.raw_public_key()?.as_slice());

    Ok((private_key_bytes, public_key_bytes))
}
