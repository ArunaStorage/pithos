use std::io::{Read, Write};

use anyhow::{anyhow, bail, Result};
use byteorder::{ByteOrder, LittleEndian};
use byteorder::{ReadBytesExt, WriteBytesExt};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::aead::OsRng;
use chacha20poly1305::{AeadCore, Nonce};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use crypto_kx::{Keypair, PublicKey, SecretKey};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct FileContext {
    // FileName
    pub file_name: String,
    // Input size
    pub input_size: u64,
    // Filesize
    pub file_size: u64,
    // FileSubpath without filename
    pub file_path: Option<String>,
    // UserId
    pub uid: Option<u64>,
    // GroupId
    pub gid: Option<u64>,
    // Octal like mode
    pub mode: Option<u32>,
    // Created at
    pub mtime: Option<u64>,
    // Should this file be skipped by decompressors
    pub compression: bool,
    // Encryption key
    pub encryption_key: Option<Vec<u8>>,
    // Owners pubkey
    pub owners_pubkey: Option<[u8; 32]>,
    // Is this file a directory
    pub is_dir: bool,
    // Is this file a symlink
    pub is_symlink: bool,
    // Expected SHA1 hash
    pub expected_sha1: Option<String>,
    // Expected MD5 hash
    pub expected_md5: Option<String>,
}

impl FileContext {
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn get_path(&self) -> String {
        match &self.file_path {
            Some(p) => p.clone() + "/" + &self.file_name,
            None => self.file_name.clone(),
        }
    }
}

// Flags:
// only the last 2 bytes are in use
// 0000 0000 0000 0000
// 0000 0000 0000 0001 -> Is encrypted
// 0000 0000 0000 0010 -> Is compressed
// 0000 0000 0000 0100 -> Has semantic metadata
// 0000 0000 0000 1000 -> Has blocklist
// 0000 0000 0001 0000 -> Has encryption metadata

pub enum Flag {
    Encrypted = 0,
    Compressed = 1,
    HasEncryptionMetadata = 2,
    HasBlockList = 3,
    HasRangeTable = 4,
    RangeTableEncrypted = 5,
    HasSemanticMetadata = 6,
    SemanticMetadataEncrypted = 7,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct EndOfFileMetadata {
    pub magic_bytes: [u8; 4], // Should be 0x50, 0x2A, 0x4D, 0x18
    pub len: u32,
    pub version: u32,
    pub file_name_length: u16,
    pub file_name: String, // UTF-8 encoded bytes
    pub raw_file_size: u64,
    pub file_hash_sha256: [u8; 32],
    pub file_hash_md5: [u8; 16],
    pub flags: u64,
    pub disk_file_size: u64,
    pub disk_hash_sha256: [u8; 32], // Everything except disk_hash_sha1 is expected to be 0
    // Optional
    pub semantic_len: Option<u64>,
    pub blocklist_len: Option<u64>,
    pub encryption_len: Option<u64>,
    // Required
    pub eof_metadata_len: u64,
}

impl EndOfFileMetadata {
    pub fn init() -> Self {
        Self {
            magic_bytes: [0x50, 0x2A, 0x4D, 0x18],
            len: 0, // Required for zstd skippable frame
            version: 1,
            file_name_length: 0,
            file_name: String::new(),
            raw_file_size: 0,
            file_hash_sha256: [0; 32],
            file_hash_md5: [0; 16],
            flags: 0,
            disk_file_size: 0,
            disk_hash_sha256: [0; 32],
            semantic_len: None,
            blocklist_len: None,
            encryption_len: None,
            eof_metadata_len: 0,
        }
    }

    pub fn update_with_file_ctx(&mut self, ctx: &FileContext) -> Result<()> {
        if ctx.file_name.len() > 512 {
            bail!("Filename too long");
        }

        self.file_name = ctx.file_name.clone();
        self.file_name_length = ctx.file_name.len() as u16;
        Ok(())
    }

    pub fn set_flag(&mut self, flag: Flag) {
        Self::set_flag_bit(&mut self.flags, flag as u8)
    }

    pub fn unset_flag(&mut self, flag: Flag) {
        Self::unset_flag_bit(&mut self.flags, flag as u8)
    }

    pub fn is_flag_set(&self, flag: Flag) -> bool {
        Self::is_flag_bit_set(&self.flags, flag as u8)
    }

    pub fn is_flag_set_u64(val: u64, flag: Flag) -> bool {
        Self::is_flag_bit_set(&val, flag as u8)
    }

    fn set_flag_bit(target: &mut u64, flag_id: u8) {
        *target |= 1 << flag_id
    }

    fn unset_flag_bit(target: &mut u64, flag_id: u8) {
        *target &= !(1 << flag_id) // 1101 & 1111 = 1101
    }

    fn is_flag_bit_set(target: &u64, flag_id: u8) -> bool {
        target >> flag_id & 1 == 1 // 11011101 >> 4 = 1101 & 0001 = 0001 == 0001 -> true
    }

    pub fn finalize(&mut self) {
        let mut full_size =
            4 + 4 + 4 + 2 + self.file_name_length as usize + 8 + 32 + 16 + 8 + 8 + 32 + 8;
        if self.semantic_len.is_some() {
            full_size += 8;
        }
        if self.blocklist_len.is_some() {
            full_size += 8;
        }
        if self.encryption_len.is_some() {
            full_size += 8;
        }
        self.len = full_size as u32 - 8;
        self.eof_metadata_len = full_size as u64;
    }
}

impl TryFrom<&[u8]> for EndOfFileMetadata {
    type Error = anyhow::Error;

    fn try_from(mut value: &[u8]) -> Result<Self, Self::Error> {
        let mut magic_bytes = [0; 4];
        value.read_exact(&mut magic_bytes)?;
        if magic_bytes != [0x50, 0x2A, 0x4D, 0x18] {
            return Err(anyhow!("Received invalid message"));
        }
        let len = value.read_u32::<LittleEndian>()?;
        let version = value.read_u32::<LittleEndian>()?;
        if version != 1 {
            return Err(anyhow!("Unsupported version"));
        }
        let file_name_length = value.read_u16::<LittleEndian>()?;
        let mut file_name_buf = vec![0u8; file_name_length as usize];
        value.read_exact(&mut file_name_buf)?;
        let raw_file_size = value.read_u64::<LittleEndian>()?;
        let mut file_hash_sha256 = [0; 32];
        value.read_exact(&mut file_hash_sha256)?;
        let mut file_hash_md5 = [0; 16];
        value.read_exact(&mut file_hash_md5)?;
        let flags = value.read_u64::<LittleEndian>()?;
        let disk_file_size = value.read_u64::<LittleEndian>()?;
        let mut disk_hash_sha256 = [0; 32];
        value.read_exact(&mut disk_hash_sha256)?;
        let semantic_len = if Self::is_flag_set_u64(flags, Flag::HasSemanticMetadata) {
            Some(value.read_u64::<LittleEndian>()?)
        } else {
            None
        };
        let blocklist_len = if Self::is_flag_set_u64(flags, Flag::HasBlockList) {
            Some(value.read_u64::<LittleEndian>()?)
        } else {
            None
        };
        let encryption_len = if Self::is_flag_set_u64(flags, Flag::HasEncryptionMetadata) {
            Some(value.read_u64::<LittleEndian>()?)
        } else {
            None
        };

        let eof_metadata_len = value.read_u64::<LittleEndian>()?;
        if eof_metadata_len != value.len() as u64 {
            return Err(anyhow!("Invalid EOF metadata length"));
        }

        Ok(Self {
            magic_bytes,
            len,
            version,
            file_name_length,
            file_name: std::str::from_utf8(&file_name_buf)?.to_string(),
            raw_file_size,
            file_hash_sha256,
            file_hash_md5,
            flags,
            disk_file_size,
            disk_hash_sha256,
            semantic_len,
            blocklist_len,
            encryption_len,
            eof_metadata_len,
        })
    }
}

impl TryInto<Vec<u8>> for EndOfFileMetadata {
    type Error = anyhow::Error;
    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let mut buffer = Vec::with_capacity(self.eof_metadata_len as usize);
        buffer.write_all(&self.magic_bytes)?;
        buffer.write_u32::<LittleEndian>(self.len)?;
        buffer.write_u32::<LittleEndian>(self.version)?;
        buffer.write_u16::<LittleEndian>(self.file_name_length)?;
        buffer.write_all(self.file_name.as_bytes())?;
        buffer.write_u64::<LittleEndian>(self.raw_file_size)?;
        buffer.write_all(&self.file_hash_sha256)?;
        buffer.write_all(&self.file_hash_md5)?;
        buffer.write_u64::<LittleEndian>(self.flags)?;
        buffer.write_u64::<LittleEndian>(self.disk_file_size)?;
        buffer.write_all(&self.disk_hash_sha256)?;
        if let Some(semantic_len) = self.semantic_len {
            buffer.write_u64::<LittleEndian>(semantic_len)?;
        }
        if let Some(blocklist_len) = self.blocklist_len {
            buffer.write_u64::<LittleEndian>(blocklist_len)?;
        }
        if let Some(encryption_len) = self.encryption_len {
            buffer.write_u64::<LittleEndian>(encryption_len)?;
        }
        buffer.write_u64::<LittleEndian>(self.eof_metadata_len)?;
        Ok(buffer)
    }
}

pub struct DecryptedKey {
    pub keys: Vec<[u8; 32]>,
    pub readers_pubkey: [u8; 32],
}

pub enum Keys {
    Encrypted(Vec<u8>),
    Decrypted(DecryptedKey),
}

pub enum PacketKeyFlags {
    ContainsExclusiveRangeTableKey = 0,
    ContainsExclusiveSemanticMetadataKey = 1,
    ContainsExclusiveRangeAndMetadataKey = 2,
}

pub struct EncryptionPacket {
    pub len: u32,
    pub pubkey: [u8; 32],
    pub flags: u8,
    pub nonce: [u8; 12],
    pub keys: Keys,
    pub mac: [u8; 16],
}

impl EncryptionPacket {
    pub fn new(unencrypted_keys: Vec<[u8; 32]>, readers_pubkey: [u8; 32]) -> Self {
        Self {
            len: 0,
            pubkey: [0; 32],
            nonce: [0; 12],
            flags: 0,
            keys: Keys::Decrypted(DecryptedKey {
                keys: unencrypted_keys,
                readers_pubkey,
            }),
            mac: [0; 16],
        }
    }

    pub fn encrypt(&mut self, writers_secret_key: Option<[u8; 32]>) -> Result<()> {
        match &self.keys {
            Keys::Decrypted(keys) => {
                let keypair = match writers_secret_key {
                    Some(key) => Keypair::from(SecretKey::from(key)),
                    None => Keypair::generate(&mut OsRng),
                };
                let session_key = keypair
                    .session_keys_from(&PublicKey::from(keys.readers_pubkey))
                    .tx;
                let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

                let concatenated_keys = keys.keys.concat();
                let data = ChaCha20Poly1305::new_from_slice(session_key.as_ref())
                    .map_err(|_| anyhow!("Invalid key length"))?
                    .encrypt(&nonce, concatenated_keys.as_slice())
                    .map_err(|_| anyhow!("Error while encrypting keys"))?;
                let (enc_keys, mac) = data.split_at(concatenated_keys.len());

                self.len = (4 + 32 + 12 + enc_keys.len() + 16) as u32;
                self.pubkey = *keypair.public().as_ref();
                self.keys = Keys::Encrypted(enc_keys.to_vec());
                self.mac = mac.try_into()?;
            }
            Keys::Encrypted(_) => return Err(anyhow!("Keys already encrypted")),
        }
        Ok(())
    }

    pub fn decrypt(&mut self, readers_secret_key: [u8; 32]) -> Result<()> {
        match &self.keys {
            Keys::Encrypted(keys) => {
                let keypair = Keypair::from(SecretKey::from(readers_secret_key));
                let session_key = keypair.session_keys_from(&PublicKey::from(self.pubkey)).rx;
                let nonce = Nonce::from_slice(&self.nonce);
                let dec_keys = ChaCha20Poly1305::new_from_slice(session_key.as_ref())?
                    .decrypt(
                        nonce.into(),
                        vec![keys.as_slice(), self.mac.as_slice()]
                            .concat()
                            .as_slice(),
                    )
                    .map_err(|_| anyhow!("Error while decrypting keys"))?;

                self.keys = Keys::Decrypted(DecryptedKey {
                    keys: dec_keys
                        .chunks_exact(32)
                        .map(|x| <[u8; 32]>::try_from(x))
                        .collect::<Result<Vec<_>, _>>()?,
                    readers_pubkey: *keypair.public().as_ref(),
                });
            }
            Keys::Decrypted(_) => return Err(anyhow!("Keys already decrypted")),
        }
        Ok(())
    }
}

pub struct EncryptionMetadata {
    pub magic_bytes: [u8; 4], // Should be 0x51, 0x2A, 0x4D, 0x18
    pub len: u32,
    pub packets: Vec<EncryptionPacket>,
}

impl EncryptionMetadata {
    pub fn new(_header_packets: Vec<EncryptionPacket>) -> Self {
        Self {
            magic_bytes: [0x51, 0x2A, 0x4D, 0x18],
            len: 0, // (Sum of all packages len)
            packets: vec![],
        }
    }

    pub fn encrypt_all(&mut self, writers_secret_key: Option<[u8; 32]>) -> Result<()> {
        for packet in &mut self.packets {
            packet.encrypt(writers_secret_key)?;
        }
        Ok(())
    }
}

impl TryFrom<&[u8]> for EncryptionMetadata {
    type Error = anyhow::Error;

    fn try_from(mut value: &[u8]) -> Result<Self, Self::Error> {
        let mut magic_bytes = [0; 4];
        value.read_exact(&mut magic_bytes)?;
        if magic_bytes != [0x51, 0x2A, 0x4D, 0x18] {
            return Err(anyhow!("Received invalid message"));
        }
        let len = value.read_u32::<LittleEndian>()?;
        if len as usize != value[8..].len() {
            return Err(anyhow!("Invalid blocklist length"));
        }
        let mut packets = Vec::new();
        let mut offset = 8;
        while offset < len as usize {
            let packet_len = value.read_u32::<LittleEndian>()?;
            let mut pubkey = [0; 32];
            value.read_exact(&mut pubkey)?;
            let flags = value.read_u8()?;
            let mut nonce = [0; 12];
            value.read_exact(&mut nonce)?;
            let mut keys = vec![0u8; packet_len as usize - 48];
            value.read_exact(&mut keys)?;
            let mut mac = [0; 16];
            value.read_exact(&mut mac)?;
            packets.push(EncryptionPacket {
                len: packet_len,
                pubkey,
                flags,
                nonce,
                keys: Keys::Encrypted(keys),
                mac,
            });
            offset += packet_len as usize;
        }
        Ok(Self {
            magic_bytes,
            len,
            packets,
        })
    }
}

impl TryInto<Vec<u8>> for EncryptionMetadata {
    type Error = anyhow::Error;
    fn try_into(self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        buffer.write_all(&self.magic_bytes)?;
        buffer.write_u32::<LittleEndian>(self.len)?;
        for packet in self.packets {
            buffer.write_u32::<LittleEndian>(packet.len)?;
            buffer.write_all(&packet.pubkey)?;
            buffer.write_all(&packet.nonce)?;
            match packet.keys {
                Keys::Encrypted(keys) => buffer.write_all(&keys)?,
                Keys::Decrypted(_) => {
                    bail!("Encryption metadata contains unencrypted keys")
                }
            }
            buffer.write_all(&packet.mac)?;
        }
        Ok(buffer)
    }
}

pub struct BlockList {
    pub magic_bytes: [u8; 4], // Should be 0x52, 0x2A, 0x4D, 0x18
    pub len: u32,
    pub blocklist: Vec<u8>,
}

impl BlockList {
    pub fn new(blocklist: Vec<u8>) -> Self {
        Self {
            magic_bytes: [0x52, 0x2A, 0x4D, 0x18],
            len: blocklist.len() as u32,
            blocklist,
        }
    }
}

impl TryFrom<&[u8]> for BlockList {
    type Error = anyhow::Error;

    fn try_from(mut value: &[u8]) -> Result<Self, Self::Error> {
        let mut magic_bytes: [u8; 4] = [0; 4];
        value.read_exact(&mut magic_bytes)?;
        if magic_bytes != [0x52, 0x2A, 0x4D, 0x18] {
            return Err(anyhow!("Received invalid message"));
        }
        let len = value.read_u32::<LittleEndian>()?;

        if len as usize != value[8..].len() {
            return Err(anyhow!("Invalid blocklist length"));
        }
        let mut blocklist = Vec::new();
        value.read_to_end(&mut blocklist)?;
        Ok(Self {
            magic_bytes,
            len,
            blocklist,
        })
    }
}

impl TryInto<Vec<u8>> for BlockList {
    type Error = anyhow::Error;
    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let mut buffer = Vec::with_capacity(8 + self.len as usize);
        buffer.write_all(&self.magic_bytes)?;
        buffer.write_u32::<LittleEndian>(self.len)?;
        buffer.write_all(&self.blocklist)?;
        Ok(buffer)
    }
}

pub struct RangeTable {
    pub magic_bytes: [u8; 4], // Should be 0x53, 0x2A, 0x4D, 0x18
    pub len: u32,
    pub sections: Vec<RangeTableEntry>,
}

pub struct RangeTableEntry {
    pub tag_len: u8, // Max 255 bytes
    pub tag: String,
    pub start: u64,
    pub end: u64,
}

pub struct SemanticMetadata {
    pub magic_bytes: [u8; 4], // Should be 0x54, 0x2A, 0x4D, 0x18
    pub len: u32,
    pub semantic: String, // JSON encoded string
}

impl SemanticMetadata {
    pub fn new(semantic: String) -> Self {
        Self {
            magic_bytes: [0x54, 0x2A, 0x4D, 0x18],
            len: semantic.len() as u32,
            semantic,
        }
    }
}

impl TryFrom<&[u8]> for SemanticMetadata {
    type Error = anyhow::Error;

    fn try_from(mut value: &[u8]) -> Result<Self, Self::Error> {
        let mut magic_bytes: [u8; 4] = [0; 4];
        value.read_exact(&mut magic_bytes)?;
        if magic_bytes != [0x53, 0x2A, 0x4D, 0x18] {
            return Err(anyhow!("Received invalid message"));
        }

        let len = value.read_u32::<LittleEndian>()?;

        if len as usize != value[8..].len() {
            return Err(anyhow!("Invalid semantic length"));
        }

        let semantic = String::from_utf8(value[8..].to_vec())?;

        Ok(Self {
            magic_bytes,
            len,
            semantic,
        })
    }
}

impl TryInto<Vec<u8>> for SemanticMetadata {
    type Error = anyhow::Error;
    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let mut buffer = Vec::new();
        buffer.write_all(&self.magic_bytes)?;
        buffer.write_u32::<LittleEndian>(self.len)?;
        buffer.write_all(self.semantic.as_bytes())?;
        Ok(buffer)
    }
}
