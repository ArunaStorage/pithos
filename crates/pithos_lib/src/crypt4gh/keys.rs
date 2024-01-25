use anyhow::{anyhow, Result};
use base64::prelude::*;
use byteorder::{BigEndian, ReadBytesExt};
use std::{fs::File, io::Read, path::PathBuf};

pub const MAGIC_BYTES: &[u8; 7] = b"c4gh-v1";
pub const KDF_NAMES: [&[u8]; 4] = [b"scrypt", b"pbkdf2_hmac_sha256", b"bcrypt", b"none"];

pub struct LengthEncodedString {
    pub length: u16,
    pub string: Vec<u8>,
}

impl LengthEncodedString {
    pub fn new(string: Vec<u8>) -> Self {
        LengthEncodedString {
            length: string.len() as u16,
            string,
        }
    }
}

pub struct RoundsWithSalt {
    pub length: u16,
    pub rounds: u32,
    pub salt: Vec<u8>,
}

impl TryFrom<&[u8]> for RoundsWithSalt {
    type Error = anyhow::Error;
    fn try_from(mut value: &[u8]) -> Result<Self, Self::Error> {
        let len = value.read_u16::<BigEndian>()?;
        let rounds = value.read_u32::<BigEndian>()?;
        let mut salt = vec![0; len as usize - 4];
        value.read_exact(&mut salt)?;
        Ok(RoundsWithSalt {
            length: len,
            rounds,
            salt,
        })
    }
}

pub struct C4ghKey {
    pub magic: [u8; 7],
    pub kdf_len: u16,
    pub kdf_name: Vec<u8>,
    pub rounds_salt_len: Option<u16>,
    pub rounds: Option<u32>,
    pub salt: Option<Vec<u8>>,
    pub cipher_len: u16,
    pub cipher_name: Vec<u8>,
    pub blop_len: u16,
    pub blop: Vec<u8>,
    pub comment_len: Option<u16>,
    pub comment: Option<Vec<u8>>,
}

impl C4ghKey {
    pub fn from_pem(path: PathBuf) -> Result<Self> {
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let lines = contents.lines().collect::<Vec<_>>();
        if lines.len() != 3 {
            return Err(anyhow!("Invalid Line count != 3"));
        }
        if !lines[0].starts_with("-----BEGIN CRYPT4GH")
            || !lines[2].starts_with("-----END CRYPT4GH")
        {
            return Err(anyhow!("Invalid PEM header/footer"));
        }
        let bytes = BASE64_STANDARD.decode(&lines[1])?;
        Ok(C4ghKey::try_from(bytes.as_slice())?)
    }
}

impl TryFrom<&[u8]> for C4ghKey {
    type Error = anyhow::Error;
    fn try_from(mut value: &[u8]) -> Result<Self, Self::Error> {
        let mut magic: [u8; 7];
        value.read_exact(&mut magic)?;
        if &magic != MAGIC_BYTES {
            return Err(anyhow::Error::msg("Invalid magic bytes"));
        }
        let kdf_len = value.read_u16::<BigEndian>()?;
        let mut kdf_name = vec![0; kdf_len as usize];
        value.read_exact(&mut kdf_name)?;
        if !KDF_NAMES.contains(&kdf_name.as_slice()) {
            return Err(anyhow::Error::msg("Invalid KDF name"));
        }
        let (rounds_salt_len, rounds, salt) = if kdf_name != b"none" {
            let rounds_salt_len = value.read_u16::<BigEndian>()?;
            let rounds = value.read_u32::<BigEndian>()?;
            let mut salt = vec![0; rounds_salt_len as usize - 4];
            value.read_exact(&mut salt)?;
            (Some(rounds_salt_len), Some(rounds), Some(salt))
        } else {
            (None, None, None)
        };
        let cipher_len = value.read_u16::<BigEndian>()?;
        let mut cipher_name = vec![0; cipher_len as usize];
        value.read_exact(&mut cipher_name)?;
        if kdf_name == b"none" && cipher_name != b"none" {
            return Err(anyhow::Error::msg("Invalid cipher name, not none!"));
        }
        let blop_len = value.read_u16::<BigEndian>()?;
        let mut blop = vec![0; blop_len as usize];
        value.read_exact(&mut blop)?;
        let (comment_len, comment) = if value.len() > 0 {
            let comment_len = value.read_u16::<BigEndian>()?;
            let mut comment = vec![0; comment_len as usize];
            value.read_exact(&mut comment)?;
            (Some(comment_len), Some(comment))
        } else {
            (None, None)
        };
        Ok(C4ghKey {
            magic,
            kdf_len,
            kdf_name,
            rounds_salt_len,
            rounds,
            salt,
            cipher_len,
            cipher_name,
            blop_len,
            blop,
            comment_len,
            comment,
        })
    }
}
