use crate::helpers::flag_helpers::{self, set_flag_bit_u8};
use anyhow::{anyhow, bail, Result};
use byteorder::LittleEndian;
use byteorder::{ReadBytesExt, WriteBytesExt};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::aead::OsRng;
use chacha20poly1305::{AeadCore, Nonce};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use crypto_kx::{Keypair, PublicKey, SecretKey};
use std::fmt::Display;
use std::io::{Read, Write};
use std::path::PathBuf;
use tracing::debug;

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

pub enum FileContextFlag {
    IsDir = 0,
    IsSymlink = 1,
    HasUID = 2,
    HasGID = 3,
    HasMode = 4,
    HasMtime = 5,
    HasSha1 = 6,
    HasMd5 = 7,
}
pub struct Symlink {
    pub len: u16,
    pub target: String,
}

pub struct FileContextHeader {
    pub file_path_len: u16,
    pub file_path: String,             // FileName /foo/bar/
    pub flag: u8,                      // is_dir, is_symlink, ...
    pub file_start: Option<u64>,       //
    pub file_end: Option<u64>,         //
    pub symlink: Option<Symlink>,      // Symlink
    pub uid: Option<u64>,              // UserId
    pub gid: Option<u64>,              // GroupId
    pub mode: Option<u32>,             // Octal like mode
    pub mtime: Option<u64>,            // Created at
    pub expected_sha1: Option<String>, // Expected SHA1 hash
    pub expected_md5: Option<String>,  // Expected MD5 hash
}

impl FileContextHeader {
    pub fn new() -> Self {
        FileContextHeader {
            file_path_len: 0,
            file_path: "".to_string(),
            flag: 0,
            file_start: None,
            file_end: None,
            symlink: None,
            uid: None,
            gid: None,
            mode: None,
            mtime: None,
            expected_sha1: None,
            expected_md5: None,
        }
    }

    pub fn set_flag(&mut self, flag: FileContextFlag) {
        flag_helpers::set_flag_bit_u8(&mut self.flag, flag as u8)
    }

    pub fn unset_flag(&mut self, flag: Flag) {
        flag_helpers::unset_flag_bit_u8(&mut self.flag, flag as u8)
    }

    pub fn is_flag_set(&self, flag: Flag) -> bool {
        flag_helpers::is_flag_bit_set_u8(&self.flag, flag as u8)
    }
}

#[derive(Debug, PartialEq)]
pub enum ProbeResult {
    Unknown,
    Compression,
    NoCompression,
}

pub const ZSTD_MAGIC_BYTES: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];
pub const ZSTD_MAGIC_BYTES_SKIPPABLE_0: [u8; 4] = [0x50, 0x2A, 0x4D, 0x18];
pub const ZSTD_MAGIC_BYTES_SKIPPABLE_1: [u8; 4] = [0x51, 0x2A, 0x4D, 0x18];
pub const ZSTD_MAGIC_BYTES_SKIPPABLE_2: [u8; 4] = [0x52, 0x2A, 0x4D, 0x18];
pub const ZSTD_MAGIC_BYTES_SKIPPABLE_3: [u8; 4] = [0x53, 0x2A, 0x4D, 0x18];
pub const ZSTD_MAGIC_BYTES_SKIPPABLE_4: [u8; 4] = [0x54, 0x2A, 0x4D, 0x18];
pub const ZSTD_MAGIC_BYTES_SKIPPABLE_5: [u8; 4] = [0x55, 0x2A, 0x4D, 0x18];
pub const ZSTD_MAGIC_BYTES_SKIPPABLE_6: [u8; 4] = [0x56, 0x2A, 0x4D, 0x18];
pub const ZSTD_MAGIC_BYTES_SKIPPABLE_7: [u8; 4] = [0x57, 0x2A, 0x4D, 0x18];
pub const ZSTD_MAGIC_BYTES_SKIPPABLE_8: [u8; 4] = [0x58, 0x2A, 0x4D, 0x18];
pub const ZSTD_MAGIC_BYTES_SKIPPABLE_9: [u8; 4] = [0x59, 0x2A, 0x4D, 0x18];
pub const ZSTD_MAGIC_BYTES_SKIPPABLE_10: [u8; 4] = [0x5A, 0x2A, 0x4D, 0x18];
pub const ZSTD_MAGIC_BYTES_SKIPPABLE_11: [u8; 4] = [0x5B, 0x2A, 0x4D, 0x18];
pub const ZSTD_MAGIC_BYTES_SKIPPABLE_12: [u8; 4] = [0x5C, 0x2A, 0x4D, 0x18];
pub const ZSTD_MAGIC_BYTES_SKIPPABLE_13: [u8; 4] = [0x5D, 0x2A, 0x4D, 0x18];
pub const ZSTD_MAGIC_BYTES_SKIPPABLE_14: [u8; 4] = [0x5E, 0x2A, 0x4D, 0x18];
pub const ZSTD_MAGIC_BYTES_SKIPPABLE_15: [u8; 4] = [0x5F, 0x2A, 0x4D, 0x18];
pub const ZSTD_MAGIC_BYTES_ALL: [[u8; 4]; 17] = [
    ZSTD_MAGIC_BYTES,
    ZSTD_MAGIC_BYTES_SKIPPABLE_0,
    ZSTD_MAGIC_BYTES_SKIPPABLE_1,
    ZSTD_MAGIC_BYTES_SKIPPABLE_2,
    ZSTD_MAGIC_BYTES_SKIPPABLE_3,
    ZSTD_MAGIC_BYTES_SKIPPABLE_4,
    ZSTD_MAGIC_BYTES_SKIPPABLE_5,
    ZSTD_MAGIC_BYTES_SKIPPABLE_6,
    ZSTD_MAGIC_BYTES_SKIPPABLE_7,
    ZSTD_MAGIC_BYTES_SKIPPABLE_8,
    ZSTD_MAGIC_BYTES_SKIPPABLE_9,
    ZSTD_MAGIC_BYTES_SKIPPABLE_10,
    ZSTD_MAGIC_BYTES_SKIPPABLE_11,
    ZSTD_MAGIC_BYTES_SKIPPABLE_12,
    ZSTD_MAGIC_BYTES_SKIPPABLE_13,
    ZSTD_MAGIC_BYTES_SKIPPABLE_14,
    ZSTD_MAGIC_BYTES_SKIPPABLE_15,
];

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
    pub raw_file_size: u64,
    pub file_hash_sha256: [u8; 32],
    pub file_hash_md5: [u8; 16],
    pub flags: u64,
    pub disk_file_size: u64,
    pub disk_hash_sha256: [u8; 32], // Everything except disk_hash_sha1 is expected to be 0
    // Optional
    pub semantic_len: Option<u64>,
    pub range_table_len: u64,
    pub blocklist_len: Option<u64>,
    pub encryption_len: Option<u64>,
    // Required
    pub eof_metadata_len: u64,
}

impl Display for EndOfFileMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "==== EndOfFileMetadata ====\n")?;
        write!(f, "Len: {}\n", self.len)?;
        write!(f, "Version: {}\n", self.version)?;
        write!(f, "Raw file size: {}\n", self.raw_file_size)?;
        write!(f, "File hash SHA256: {:?}\n", self.file_hash_sha256)?;
        write!(f, "File hash MD5: {:?}\n", self.file_hash_md5)?;
        write!(f, "Flags: {}\n", self.flags)?;
        write!(f, "Disk file size: {}\n", self.disk_file_size)?;
        write!(f, "Disk hash SHA256: {:?}\n", self.disk_hash_sha256)?;
        write!(f, "Semantic metadata len: {:?}\n", self.semantic_len)?;
        write!(f, "Range table len: {:?}\n", self.range_table_len)?;
        write!(f, "Block list len: {:?}\n", self.blocklist_len)?;
        write!(f, "Encryption meta len: {:?}\n", self.encryption_len)?;
        write!(f, "Technical metadata len: {:?}\n", self.eof_metadata_len)?;

        Ok(())
    }
}

impl EndOfFileMetadata {
    pub fn init() -> Self {
        Self {
            magic_bytes: [0x50, 0x2A, 0x4D, 0x18],
            len: 0, // Required for zstd skippable frame
            version: 1,
            raw_file_size: 0,
            file_hash_sha256: [0; 32],
            file_hash_md5: [0; 16],
            flags: 0,
            disk_file_size: 0,
            disk_hash_sha256: [0; 32],
            semantic_len: None,
            range_table_len: 0,
            blocklist_len: None,
            encryption_len: None,
            eof_metadata_len: 0,
        }
    }

    pub fn set_flag(&mut self, flag: Flag) {
        flag_helpers::set_flag_bit(&mut self.flags, flag as u8)
    }

    pub fn unset_flag(&mut self, flag: Flag) {
        flag_helpers::unset_flag_bit(&mut self.flags, flag as u8)
    }

    pub fn is_flag_set(&self, flag: Flag) -> bool {
        flag_helpers::is_flag_bit_set(&self.flags, flag as u8)
    }

    pub fn is_flag_set_u64(val: u64, flag: Flag) -> bool {
        flag_helpers::is_flag_bit_set(&val, flag as u8)
    }

    pub fn finalize(&mut self) {
        let mut full_size =
            4 + 4 + 4 + 8 + 32 + 16 + 8 + 8 + 32 + 8 + 8;
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
        let original_len = value.len();
        let mut magic_bytes = [0; 4];
        value.read_exact(&mut magic_bytes)?;
        if magic_bytes != ZSTD_MAGIC_BYTES_SKIPPABLE_0 {
            return Err(anyhow!("Received invalid eof metadata message"));
        }
        let len = value.read_u32::<LittleEndian>()?;
        let version = value.read_u32::<LittleEndian>()?;
        if version != 1 {
            return Err(anyhow!("Unsupported version"));
        }
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
        let range_table_len = value.read_u64::<LittleEndian>()?;
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
        if eof_metadata_len != original_len as u64 {
            return Err(anyhow!(
                "Invalid EOF metadata length {} != {}",
                eof_metadata_len,
                value.len()
            ));
        }

        if !value.is_empty() {
            return Err(anyhow!("Invalid EOF metadata length"));
        }

        Ok(Self {
            magic_bytes,
            len,
            version,
            raw_file_size,
            file_hash_sha256,
            file_hash_md5,
            flags,
            disk_file_size,
            disk_hash_sha256,
            semantic_len,
            range_table_len,
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
        buffer.write_u64::<LittleEndian>(self.raw_file_size)?;
        buffer.write_all(&self.file_hash_sha256)?;
        buffer.write_all(&self.file_hash_md5)?;
        buffer.write_u64::<LittleEndian>(self.flags)?;
        buffer.write_u64::<LittleEndian>(self.disk_file_size)?;
        buffer.write_all(&self.disk_hash_sha256)?;
        if let Some(semantic_len) = self.semantic_len {
            buffer.write_u64::<LittleEndian>(semantic_len)?;
        }
        buffer.write_u64::<LittleEndian>(self.range_table_len)?;
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

#[derive(Debug)]
pub struct DecryptedKey {
    pub keys: Vec<[u8; 32]>,
    pub readers_pubkey: [u8; 32],
}

#[derive(Debug)]
pub enum Keys {
    Encrypted(Vec<u8>),
    Decrypted(DecryptedKey),
}

#[repr(u8)]
pub enum PacketKeyFlags {
    ContainsExclusiveRangeTableKey = 0, // Index 0 is reserved for range table key
    ContainsExclusiveSemanticMetadataKey = 1, // Index 0 or 1 is reserved for semantic metadata key
    ContainsExclusiveRangeAndMetadataKey = 2, // Index 0 is reserved for a combined range table and semantic metadata key
}

#[derive(Debug)]
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
                    .session_keys_to(&PublicKey::from(keys.readers_pubkey)).tx;

                let hex_key: String = session_key.as_ref().iter().map(|b| format!("{:02x}", b)).collect();
                debug!(enc_shared_key = ?hex_key);

                let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
                debug!(?nonce);

                let concatenated_keys = keys.keys.concat();
                let data = ChaCha20Poly1305::new_from_slice(session_key.as_ref())
                    .map_err(|_| anyhow!("Invalid key length"))?
                    .encrypt(&nonce, concatenated_keys.as_slice())
                    .map_err(|_| anyhow!("Error while encrypting keys"))?;
                let (enc_keys, mac) = data.split_at(concatenated_keys.len());

                self.len = (4 + 32 + 1 + 12 + enc_keys.len() + 16) as u32;
                self.pubkey = *keypair.public().as_ref();
                self.nonce = nonce.into();
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

                let hex_key: String = session_key.as_ref().iter().map(|b| format!("{:02x}", b)).collect();
                debug!(dec_shared_key = ?hex_key);

                let nonce = Nonce::from_slice(&self.nonce);
                debug!(?nonce);

                let dec_keys = ChaCha20Poly1305::new_from_slice(session_key.as_ref())?
                    .decrypt(
                        nonce,
                        [keys.as_slice(), self.mac.as_slice()].concat().as_slice(),
                    )
                    .map_err(|e| anyhow!("Error while decrypting keys: {e}"))?;

                self.keys = Keys::Decrypted(DecryptedKey {
                    keys: dec_keys
                        .chunks_exact(32)
                        .map(<[u8; 32]>::try_from)
                        .collect::<Result<Vec<_>, _>>()?,
                    readers_pubkey: *keypair.public().as_ref(),
                });
            }
            Keys::Decrypted(_) => return Err(anyhow!("Keys already decrypted")),
        }
        Ok(())
    }

    pub fn set_flag(&mut self, flag: PacketKeyFlags) {
        flag_helpers::set_flag_bit_u8(&mut self.flags, flag as u8)
    }

    pub fn unset_flag(&mut self, flag: PacketKeyFlags) {
        flag_helpers::unset_flag_bit_u8(&mut self.flags, flag as u8)
    }

    pub fn is_flag_set(&self, flag: PacketKeyFlags) -> bool {
        flag_helpers::is_flag_bit_set_u8(&self.flags, flag as u8)
    }

    pub fn extract_keys_with_flags(
        &self,
    ) -> Result<(Option<[u8; 32]>, Option<[u8; 32]>, Vec<[u8; 32]>)> {
        match (
            self.is_flag_set(PacketKeyFlags::ContainsExclusiveRangeTableKey),
            self.is_flag_set(PacketKeyFlags::ContainsExclusiveSemanticMetadataKey),
            self.is_flag_set(PacketKeyFlags::ContainsExclusiveRangeAndMetadataKey),
            &self.keys,
        ) {
            (true, true, false, Keys::Decrypted(keys)) => {
                if keys.keys.len() < 2 {
                    Err(anyhow!("Invalid key count < 2"))
                } else {
                    Ok((
                        keys.keys.first().copied(),
                        keys.keys.get(1).copied(),
                        keys.keys.get(2..).unwrap_or_default().to_vec(),
                    ))
                }
            }
            (true, false, false, Keys::Decrypted(keys)) => {
                if keys.keys.is_empty() {
                    Err(anyhow!("Invalid key count"))
                } else {
                    Ok((
                        keys.keys.first().copied(),
                        None,
                        keys.keys.get(1..).unwrap_or_default().to_vec(),
                    ))
                }
            }
            (false, true, false, Keys::Decrypted(keys)) => {
                if keys.keys.is_empty() {
                    Err(anyhow!("Invalid key count == 0"))
                } else {
                    Ok((
                        None,
                        keys.keys.first().copied(),
                        keys.keys.get(1..).unwrap_or_default().to_vec(),
                    ))
                }
            }
            (false, false, true, Keys::Decrypted(keys)) => {
                if keys.keys.is_empty() {
                    Err(anyhow!("Invalid key count == 0"))
                } else {
                    Ok((
                        keys.keys.first().copied(),
                        keys.keys.first().copied(),
                        keys.keys.get(1..).unwrap_or_default().to_vec(),
                    ))
                }
            }
            (false, false, false, Keys::Decrypted(keys)) => Ok((None, None, keys.keys.clone())),
            (_, _, _, Keys::Decrypted(_)) => {
                Err(anyhow!("Invalid flag combination cant combine and with or"))
            }
            (_, _, _, Keys::Encrypted(_)) => Err(anyhow!("Keys are encrypted")),
        }
    }
}

#[derive(Debug)]
pub struct EncryptionMetadata {
    pub magic_bytes: [u8; 4], // Should be 0x51, 0x2A, 0x4D, 0x18
    pub len: u32,
    pub packets: Vec<EncryptionPacket>,
}

impl EncryptionMetadata {
    pub fn new(header_packets: Vec<EncryptionPacket>) -> Self {
        Self {
            magic_bytes: ZSTD_MAGIC_BYTES_SKIPPABLE_1,
            len: 0, // (Sum of all packages len)
            packets: header_packets,
        }
    }

    pub fn encrypt_all(&mut self, writers_secret_key: Option<[u8; 32]>) -> Result<()> {
        for packet in &mut self.packets {
            packet.encrypt(writers_secret_key)?;
        }

        self.packets.iter().for_each(|p| debug!(?p));
        self.len = self.packets.iter().fold(0, |i, item| {i + item.len});

        Ok(())
    }

    pub fn decrypt(&mut self, readers_secret_key: [u8; 32]) -> Result<()> {
        for packet in &mut self.packets {
            // Try to decrypt as many as possible
            if let Err(e) = packet.decrypt(readers_secret_key) {
                debug!(?e)
            } 
        }
        Ok(())
    }
}

impl TryFrom<&[u8]> for EncryptionMetadata {
    type Error = anyhow::Error;

    fn try_from(mut value: &[u8]) -> Result<Self, Self::Error> {
        let mut magic_bytes = [0; 4];
        value.read_exact(&mut magic_bytes)?;
        if magic_bytes != ZSTD_MAGIC_BYTES_SKIPPABLE_1 {
            return Err(anyhow!("Received invalid encryption metadata message"));
        }
        let len = value.read_u32::<LittleEndian>()?;
        debug!(?len, enc_meta_len = value.len());
        if len as usize != value.len() {
            return Err(anyhow!("Invalid encryption metadata length"));
        }
        let mut packets = Vec::new();
        while !value.is_empty() {
            let packet_len = value.read_u32::<LittleEndian>()?;
            let mut pubkey = [0; 32];
            value.read_exact(&mut pubkey)?;
            let mut nonce = [0; 12];
            value.read_exact(&mut nonce)?;
            let flags = value.read_u8()?;
            let mut keys = vec![0u8; packet_len as usize - (4+32+12+1+16)];
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
        }
        if !value.is_empty() {
            return Err(anyhow!("Invalid semantic metadata length"));
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
            buffer.write_u8(packet.flags)?;
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
            magic_bytes: ZSTD_MAGIC_BYTES_SKIPPABLE_2,
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
        if magic_bytes != ZSTD_MAGIC_BYTES_SKIPPABLE_2 {
            return Err(anyhow!("Received invalid blocklist message"));
        }
        let len = value.read_u32::<LittleEndian>()?;

        if len as usize != value.len() {
            return Err(anyhow!("Invalid blocklist length"));
        }
        let mut blocklist = Vec::new();
        value.read_to_end(&mut blocklist)?;
        if !value.is_empty() {
            return Err(anyhow!("Invalid blocklist length"));
        }
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

pub struct TableOfContents {
    pub magic_bytes: [u8; 4], // Should be 0x53, 0x2A, 0x4D, 0x18
    pub len: u32,
    pub sections: Vec<TableEntry>,
}

pub struct CustomRange {
    pub tag_len: u8, // Max 255 bytes
    pub tag: String,
    pub start: u64,
    pub end: u64,
}

pub struct TableEntry {
    pub variant_type: u8, // 0 = FileContextHeader, 1 = CustomRange
    pub entry: TableEntryVariant,
}
pub enum TableEntryVariant {
    FileContextHeader(FileContextHeader),
    CustomRange(CustomRange)
}

impl TableOfContents {
    pub fn new() -> Self {
        TableOfContents {
            magic_bytes: ZSTD_MAGIC_BYTES_SKIPPABLE_3,
            len: 0,
            sections: vec![],
        }
    }

    pub fn from_encrypted(encrypted: &[u8], key: [u8; 32]) -> Result<Self, anyhow::Error> {
        let (nonce, data) = encrypted.split_at(12);
        let decrypted = ChaCha20Poly1305::new_from_slice(&key)?
            .decrypt(nonce.into(), data)
            .map_err(|_| anyhow!("Error while decrypting range table"))?;
        Self::try_from(decrypted.as_slice())
    }
}

impl TryInto<Vec<u8>> for TableOfContents {
    type Error = anyhow::Error;
    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let mut buffer = Vec::with_capacity(8 + self.len as usize);
        buffer.write_all(&self.magic_bytes)?;
        buffer.write_u32::<LittleEndian>(self.len)?;

        for section in self.sections {
            match section.entry {
                TableEntryVariant::FileContextHeader(ctx) => {
                    buffer.write_u16::<LittleEndian>(ctx.file_path_len)?;
                    buffer.write_all(ctx.file_path.as_bytes())?;
                    buffer.write_u8(ctx.flag)?;
                    if let Some(start) = ctx.file_start {
                        buffer.write_u64::<LittleEndian>(start)?;
                    }
                    if let Some(end) = ctx.file_start {
                        buffer.write_u64::<LittleEndian>(end)?;
                    }
                    if let Some(symlink) = ctx.symlink {
                        buffer.write_u16::<LittleEndian>(symlink.len)?;
                        buffer.write_all(symlink.target.as_bytes())?;
                    }
                    if let Some(uid) = ctx.uid {
                        buffer.write_u64::<LittleEndian>(uid)?;
                    }
                    if let Some(gid) = ctx.gid {
                        buffer.write_u64::<LittleEndian>(gid)?;
                    }
                    if let Some(mode) = ctx.mode {
                        buffer.write_u32::<LittleEndian>(mode)?;
                    }
                    if let Some(mtime) = ctx.mtime {
                        buffer.write_u64::<LittleEndian>(mtime)?;
                    }
                    if let Some(sha1) = ctx.expected_sha1 {
                        buffer.write_all(sha1.as_bytes())?;
                    }
                    if let Some(md5) = ctx.expected_md5 {
                        buffer.write_all(md5.as_bytes())?;
                    }
                }
                TableEntryVariant::CustomRange(range) => {
                    buffer.write_u8(range.tag_len)?;
                    buffer.write_all(range.tag.as_bytes())?;
                    buffer.write_u64::<LittleEndian>(range.start)?;
                    buffer.write_u64::<LittleEndian>(range.end)?;
                }
            }
        }
        Ok(buffer)
    }
}

impl TryFrom<&[u8]> for TableOfContents {
    type Error = anyhow::Error;

    fn try_from(mut value: &[u8]) -> Result<Self, Self::Error> {
        let mut magic_bytes: [u8; 4] = [0; 4];
        value.read_exact(&mut magic_bytes)?;
        if magic_bytes != ZSTD_MAGIC_BYTES_SKIPPABLE_3 {
            return Err(anyhow!("Received invalid range table message"));
        }
        let len = value.read_u32::<LittleEndian>()?;
        if len as usize != value[8..].len() {
            return Err(anyhow!("Invalid range table length"));
        }
        let mut sections = Vec::new();

        while !value.is_empty() {
            let variant = value.read_u8()?;
            match variant {
                0 => {
                    let file_path_len = value.read_u16::<LittleEndian>()?;
                    let mut file_path = vec![0u8; file_path_len as usize];
                    value.read_exact(&mut file_path)?;
                    let flag = value.read_u8()?;

                    let (file_start, file_end, symlink) = if flag_helpers::is_flag_bit_set_u8(&flag, FileContextFlag::IsDir as u8) {
                        // If is dir
                        (None,None,None)
                    } else if flag_helpers::is_flag_bit_set_u8(&flag, FileContextFlag::IsSymlink as u8) {
                        // If is symlink
                        let symlink_len = value.read_u16::<LittleEndian>()?;
                        let mut symlink_target = vec![0u8; symlink_len as usize];
                        value.read_exact(&mut symlink_target)?;
                        (None,None,Some(Symlink {
                            len: symlink_len,
                            target: String::from_utf8(symlink_target)?
                        }))
                    } else {
                        // If is file
                        let start = value.read_u64::<LittleEndian>()?;
                        let end = value.read_u64::<LittleEndian>()?;
                        (Some(start), Some(end), None)
                    };
                    // If has uid
                    let uid = if flag_helpers::is_flag_bit_set_u8(&flag, FileContextFlag::HasUID as u8) {
                        Some(value.read_u64::<LittleEndian>()?)
                    } else {
                        None // or maybe default 1000
                    };
                    // If has uid
                    let gid = if flag_helpers::is_flag_bit_set_u8(&flag, FileContextFlag::HasGID as u8) {
                        Some(value.read_u64::<LittleEndian>()?)
                    } else {
                        None // or maybe default 1000
                    };
                    // If has mode
                    let mode = if flag_helpers::is_flag_bit_set_u8(&flag, FileContextFlag::HasMode as u8) {
                        Some(value.read_u32::<LittleEndian>()?)
                    } else {
                        None // or maybe default 33188 -> 644
                    };
                    // If has mtime
                    let mtime = if flag_helpers::is_flag_bit_set_u8(&flag, FileContextFlag::HasMtime as u8) {
                        Some(value.read_u64::<LittleEndian>()?)
                    } else {
                        None
                    };
                    // if has sha1
                    let expected_sha1 = if flag_helpers::is_flag_bit_set_u8(&flag, FileContextFlag::HasMtime as u8) {
                        let mut sha1 = vec![0u8; 20];
                        value.read_exact(&mut sha1)?;
                        Some(String::from_utf8(sha1)?)
                    } else {
                        None // Or maybe default 0
                    };
                    // If has md5
                    let expected_md5 = if flag_helpers::is_flag_bit_set_u8(&flag, FileContextFlag::HasMtime as u8) {
                        let mut md5 = vec![0u8; 16];
                        value.read_exact(&mut md5)?;
                        Some(String::from_utf8(md5)?)
                    } else {
                        None // Or maybe default 0
                    };

                    sections.push(TableEntry {
                        variant_type: TableEntryVariant::FileContextHeader as u8,
                        entry: TableEntryVariant::FileContextHeader(FileContextHeader {
                            file_path_len,
                            file_path: String::from_utf8(file_path)?,
                            flag,
                            file_start,
                            file_end,
                            symlink,
                            uid,
                            gid,
                            mode,
                            mtime,
                            expected_sha1,
                            expected_md5,
                        }) })
                },
                1 => {
                    let tag_len = value.read_u8()?;
                    let mut tag = vec![0u8; tag_len as usize];
                    value.read_exact(&mut tag)?;
                    let tag = String::from_utf8(tag)?;
                    let start = value.read_u64::<LittleEndian>()?;
                    let end = value.read_u64::<LittleEndian>()?;
                    sections.push(
                        TableEntry {
                            variant_type: TableEntryVariant::CustomRange as u8,
                            entry: TableEntryVariant::CustomRange(CustomRange {
                                tag_len,
                                tag,
                                start,
                                end,
                            })
                        })
                },
                _ => bail!("Invalid content variant")
            }
        }

        if !value.is_empty() {
            return Err(anyhow!("Invalid range table length"));
        }
        Ok(Self {
            magic_bytes,
            len,
            sections,
        })
    }
}

impl TryFrom<FileContext> for TableEntry {
    type Error = anyhow::Error;

    fn try_from(value: FileContext) -> Result<Self> {
        let mut ctx_header = FileContextHeader::new();

        if let Some(path) = value.file_path {
            let mut path = PathBuf::from(path);
            path.push(value.file_name);
            let file_path = path
                .into_os_string()
                .to_str()
                .ok_or_else(|| anyhow!("Invalid path"))?
                .to_string();

            ctx_header.file_path_len = file_path.len().try_into()?;
            ctx_header.file_path = file_path;
        } else {
            ctx_header.file_path_len = value.file_name.len().try_into()?;
            ctx_header.file_path = value.file_name;
        };

        let mut flag = 0;
        if value.is_dir {
            set_flag_bit_u8(&mut flag, FileContextFlag::IsDir as u8);
            ctx_header.file_start = None;
            ctx_header.file_end = None;
        } else if value.is_symlink {
            set_flag_bit_u8(&mut flag, FileContextFlag::IsSymlink as u8);
            ctx_header.file_start = None;
            ctx_header.file_end = None;
            ctx_header.symlink = Some(Symlink {
                len: ctx_header.file_path_len,
                target: ctx_header.file_path,
            });
        } else {
            ctx_header.file_start = Some(0); // ???
            ctx_header.file_end = Some(value.file_size);
        }
        if let Some(uid) = value.uid {
            set_flag_bit_u8(&mut flag, FileContextFlag::HasUID as u8);
            ctx_header.uid = Some(uid);
        }
        if let Some(gid) = value.gid {
            set_flag_bit_u8(&mut flag, FileContextFlag::HasGID as u8);
            ctx_header.gid = Some(gid);
        }
        if let Some(mode) = value.mode {
            set_flag_bit_u8(&mut flag, FileContextFlag::HasMode as u8);
            ctx_header.mode = Some(mode);
        }
        if let Some(mtime) = value.mtime {
            set_flag_bit_u8(&mut flag, FileContextFlag::HasMtime as u8);
            ctx_header.mtime = Some(mtime);
        }
        if let Some(sha1) = value.expected_sha1 {
            set_flag_bit_u8(&mut flag, FileContextFlag::HasSha1 as u8);
            ctx_header.expected_sha1 = Some(sha1);
        }
        if let Some(md5) = value.expected_md5 {
            set_flag_bit_u8(&mut flag, FileContextFlag::HasSha1 as u8);
            ctx_header.expected_sha1 = Some(md5);
        }

        Ok(TableEntry {
            variant_type: TableEntryVariant::FileContextHeader as u8,
            entry: TableEntryVariant::FileContextHeader(ctx_header),
        })
    }
}

#[derive(Clone, Debug)]
pub struct SemanticMetadata {
    pub magic_bytes: [u8; 4], // Should be 0x54, 0x2A, 0x4D, 0x18
    pub len: u32,
    pub semantic: String, // JSON encoded string
}

impl SemanticMetadata {
    pub fn new(semantic: String) -> Self {
        Self {
            magic_bytes: ZSTD_MAGIC_BYTES_SKIPPABLE_4,
            len: semantic.len() as u32,
            semantic,
        }
    }

    pub fn from_encrypted(encrypted: &[u8], key: [u8; 32]) -> Result<Self, anyhow::Error> {
        let (nonce, data) = encrypted.split_at(12);
        let decrypted = ChaCha20Poly1305::new_from_slice(&key)?
            .decrypt(nonce.into(), data)
            .map_err(|_| anyhow!("Error while decrypting semantic metadata"))?;
        Self::try_from(decrypted.as_slice())
    }
}

impl Display for SemanticMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.semantic)
    }
}

impl TryFrom<&[u8]> for SemanticMetadata {
    type Error = anyhow::Error;

    fn try_from(mut value: &[u8]) -> Result<Self, Self::Error> {
        let mut magic_bytes: [u8; 4] = [0; 4];
        value.read_exact(&mut magic_bytes)?;
        if magic_bytes != ZSTD_MAGIC_BYTES_SKIPPABLE_4 {
            return Err(anyhow!("Received invalid semantic metadata message"));
        }

        let len = value.read_u32::<LittleEndian>()?;

        if len as usize != value.len() {
            return Err(anyhow!("Invalid semantic length"));
        }

        let mut semantic = String::with_capacity(len as usize - 8);
        value.read_to_string(&mut semantic)?;

        if !value.is_empty() {
            return Err(anyhow!("Invalid semantic metadata length"));
        }
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
