use anyhow::{anyhow, Result};
use base64::prelude::*;
use byteorder::{BigEndian, ReadBytesExt};
use std::fmt::Debug;
use std::{fs::File, io::Read, path::PathBuf};

pub const MAGIC_BYTES: &[u8; 7] = b"c4gh-v1";
pub const KDF_NAMES: [&[u8]; 3] = [b"scrypt", b"bcrypt", b"none"];

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

impl Debug for C4ghKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("C4ghKey")
            .field(
                "magic",
                &std::string::String::from_utf8(self.magic.to_vec()),
            )
            .field("kdf_len", &self.kdf_len)
            .field(
                "kdf_name",
                &std::string::String::from_utf8(self.kdf_name.clone()),
            )
            .field("rounds_salt_len", &self.rounds_salt_len)
            .field("rounds", &self.rounds)
            .field("salt", &self.salt)
            .field("cipher_len", &self.cipher_len)
            .field(
                "cipher_name",
                &std::string::String::from_utf8(self.cipher_name.clone()),
            )
            .field("blop_len", &self.blop_len)
            .field("blop", &self.blop)
            .field("comment_len", &self.comment_len)
            .field("comment", &self.comment)
            .finish()
    }
}

impl C4ghKey {
    pub fn from_pem(path: PathBuf) -> Result<Self> {
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        Self::from_string(&contents)
    }

    pub fn from_string(c4gh_file_content: &str) -> Result<Self> {
        let lines = c4gh_file_content.lines().collect::<Vec<_>>();
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

    pub fn decrypt(&self, passkey: Option<String>) -> Result<[u8; 32]> {
        let key = match (std::str::from_utf8(&self.kdf_name), passkey) {
            (Ok("none"), _) => None,
            (Ok("scrypt"), Some(passkey)) => {
                let mut result: [u8; 32] = [0; 32];
                scrypt::scrypt(
                    passkey.as_bytes(),
                    self.salt.as_ref().ok_or_else(|| anyhow!("No salt"))?,
                    &scrypt::Params::new(14, 8, 1, 32)?,
                    &mut result,
                )?;
                Some(result)
            }
            (Ok("bcrypt"), Some(key)) => {
                todo!()
            }
            _ => {
                return Err(anyhow!("Invalid KDF name"));
            }
        };

        Ok(key.ok_or_else(|| anyhow!("No key"))?)
    }
}

impl TryFrom<&[u8]> for C4ghKey {
    type Error = anyhow::Error;
    fn try_from(mut value: &[u8]) -> Result<Self, Self::Error> {
        let mut magic: [u8; 7] = [0; 7];
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

#[cfg(test)]
mod tests {
    use crate::crypt4gh::keys::C4ghKey;

    #[test]
    fn test_key() {
        let key = "-----BEGIN CRYPT4GH PRIVATE KEY-----\nYzRnaC12MQAGc2NyeXB0ABQAAAAAr3pX96oPff2/UdadCKHrEgARY2hhY2hhMjBfcG9seTEzMDUAPCgPmYBf3Tc6r54U254IHuo4kjJ86XxBsNhTkFfu+awzY2QFEZKzynlVgLo9H5BrVr8neP3APu3SF51nNg==\n-----END CRYPT4GH PRIVATE KEY-----";

        // Parse pem key
        let key = C4ghKey::from_string(key).unwrap();
        let res = key.decrypt(Some("12345".to_string())).unwrap();

        assert_eq!(
            res,
            [
                244, 169, 234, 69, 56, 160, 188, 24, 80, 91, 176, 222, 106, 44, 34, 216, 52, 194,
                112, 70, 127, 198, 83, 247, 34, 188, 166, 106, 240, 56, 81, 221,
            ]
        )
    }
}
