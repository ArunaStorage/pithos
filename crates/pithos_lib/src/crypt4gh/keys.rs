use byteorder::BigEndian;
use byteorder::{ReadBytesExt, WriteBytesExt};
use tokio::io::AsyncReadExt;

pub const MAGIC_BYTES: &[u8; 7] = b"c4gh-v1";
pub const KDF_NAMES: [&[u8]; 4] = [b"scrypt", b"pbkdf2_hmac_sha256", b"bcrypt", b"none"];

pub struct LengthEncodedString {
    pub length: u16,
    pub string: Vec<u8>,
}

impl TryFrom<&[u8]> for LengthEncodedString {
    type Error = anyhow::Error;
    fn try_from(mut value: &[u8]) -> Result<Self, Self::Error> {
        let len = value.read_u16::<BigEndian>()?;
        let mut string = vec![0; len as usize];
        value.read_exact(&mut string)?;
        Ok(LengthEncodedString {
            length: len,
            string,
        })
    }
}

pub struct RoundsWithSalt {
    pub length: u16,
    pub rounds: u32,
    pub salt: Vec<u8>,
}

pub struct C4ghKey {
    pub magic:[u8; 7],
    pub kdf_name: LengthEncodedString,
    pub rounds_salt: RoundsWithSalt,
    pub cipher_name: LengthEncodedString,
    pub blop: LengthEncodedString,
    pub comment: LengthEncodedString,
}



impl TryFrom<&[u8]> for C4ghKey {
    type Error = anyhow::Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut magic: [u8; 7];
        value.read_exact(magic)?;
        if magic != MAGIC_BYTES {
            return Err(anyhow::Error::msg("Invalid magic bytes"));
        }
        let kdf_name = LengthEncodedString::try_from(value)?;
        if !KDF_NAMES.contains(&kdf_name.string) {
            return Err(anyhow::Error::msg("Invalid KDF name"));
        }

    }
}