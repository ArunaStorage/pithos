use anyhow::Result;
use openssl::pkey::{Id, PKey};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

//TODO: Try to load openSSL pem and if fails try to load Crypt4GH pem
pub fn load_key_from_pem(filepath: &PathBuf, private: bool) -> Result<[u8; 32]> {
    // Open file handle and read file bytes
    let mut file = File::open(filepath)?;
    let mut file_content = vec![0u8; file.metadata()?.len() as usize];
    file.read_exact(&mut file_content)?;

    // Parse into key
    let mut key_bytes: [u8; 32] = [0; 32];
    if private {
        key_bytes.copy_from_slice(
            PKey::private_key_from_pem(&file_content)?
                .raw_private_key()?
                .as_slice(),
        );
    } else {
        key_bytes.copy_from_slice(
            PKey::public_key_from_pem(&file_content)?
                .raw_public_key()?
                .as_slice(),
        );
    }

    Ok(key_bytes)
}

pub fn _load_key_from_string(key_bytes: &[u8], private: bool) -> Result<[u8; 32]> {
    // Parse into key
    let mut x25519_key_bytes: [u8; 32] = [0; 32];
    if private {
        x25519_key_bytes.copy_from_slice(
            PKey::private_key_from_raw_bytes(key_bytes, Id::X25519)?
                .raw_private_key()?
                .as_slice(),
        );
    } else {
        x25519_key_bytes.copy_from_slice(
            PKey::public_key_from_raw_bytes(key_bytes, Id::X25519)?
                .raw_public_key()?
                .as_slice(),
        );
    }

    Ok(x25519_key_bytes)
}
