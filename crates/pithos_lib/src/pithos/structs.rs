use crate::helpers::structs::FileContext;
use anyhow::{anyhow, Result};
use borsh::{BorshDeserialize, BorshSerialize};
use chacha20poly1305::aead::OsRng;
use chacha20poly1305::AeadCore;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use std::fmt::Display;

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

// -------------- EndOfFileMetadata --------------

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct EndOfFileMetadata {
    // 73 Bytes
    pub magic_bytes: [u8; 4], // Should be 0x50, 0x2A, 0x4D, 0x18
    pub len: u32,
    pub version: u8,
    pub raw_file_size: u64,
    pub disk_file_size: u64,
    pub disk_hash_sha256: [u8; 32], // Everything except disk_hash_sha256 is expected to be 0
    pub range_table_len: u64,
    pub encryption_len: u64,
}

impl Display for EndOfFileMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "==== EndOfFileMetadata ====\n")?;
        write!(f, "Len: {}\n", self.len)?;
        write!(f, "Version: {}\n", self.version)?;
        write!(f, "Raw file size: {}\n", self.raw_file_size)?;
        write!(f, "Disk file size: {}\n", self.disk_file_size)?;
        write!(f, "Disk hash SHA256: {:?}\n", self.disk_hash_sha256)?;
        write!(f, "Range table len: {:?}\n", self.range_table_len)?;
        write!(f, "Encryption meta len: {:?}\n", self.encryption_len)?;
        Ok(())
    }
}

impl EndOfFileMetadata {
    pub fn init() -> Self {
        Self {
            magic_bytes: ZSTD_MAGIC_BYTES_SKIPPABLE_0,
            len: 73,
            version: 1,
            raw_file_size: 0,
            disk_file_size: 0,
            disk_hash_sha256: [0; 32],
            range_table_len: 0,
            encryption_len: 0,
        }
    }
}

// -------------- EncryptionMetadata --------------

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct EncryptionMetadata {
    pub magic_bytes: [u8; 4], // Should be 0x51, 0x2A, 0x4D, 0x18
    pub len: u32,             // Required for zstd skippable frame
    pub packets: Vec<EncryptionPacket>,
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub enum EncryptionTarget {
    FileData(PithosRange),     // File Data
    FileMetadata(PithosRange), // Full TableOfContents entry
    FileDataAndMetadata(PithosRange),
    Dir(PithosRange), // Full DirContextHeader
}

#[derive(Debug)]
pub struct DecryptedKey {
    pub keys: Vec<([u8; 32], Vec<EncryptionTarget>)>,
    pub readers_pubkey: [u8; 32],
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct EncryptionPacket {
    pub pubkey: [u8; 32],
    pub nonce: [u8; 12],
    pub keys: Vec<u8>,
    pub mac: [u8; 16],
}

// impl DecryptedKey into EncryptionPacket
// Auto encrypt DecryptedKey with recipient PubKey into EncryptionPacket
impl TryInto<EncryptionPacket> for DecryptedKey {
    type Error = anyhow::Error;

    fn try_into(self) -> std::result::Result<EncryptionPacket, Self::Error> {
        todo!()
    }
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub enum PithosRange {
    // Applies for everything
    All,
    // Exact index
    Index(u64),
    // From start_index to end
    Start(u64),
    // From 0 to end_index
    End(u64),
    // From start_index to end_index
    IndexRange((u64, u64)),
}

// -------------- FileContextHeader --------------

#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug)]
pub struct FileInfo {
    pub uid: Option<u64>,   // UserId
    pub gid: Option<u64>,   // GroupId
    pub mode: Option<u32>,  // Octal like mode
    pub mtime: Option<u64>, // Created at
}

#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug)]
pub struct Hashes {
    pub sha256: Option<[u8; 32]>,
    pub md5: Option<[u8; 16]>,
}

#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug)]
pub struct SymlinkContextHeader {
    pub file_path: String, // FileName /foo/bar/
    pub file_info: Option<FileInfo>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Eq, PartialOrd, Ord, PartialEq, Debug)]
pub struct CustomRange {
    pub tag: String,
    pub start: u64,
    pub end: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct FileContextHeader {
    pub file_path: String, // FilePath empty = SKIP
    pub disk_size: u64,
    pub file_start: u64,
    pub file_end: u64,
    pub compressed: bool,
    pub encrypted: bool,
    pub block_scale: u32, // ChaCha / Compression block scale, should be a multiple of 65536 (default = 1);
    pub index_list: Option<Vec<u32>>, // Raw size of every chunk in order (only if compressed); MAX: 83_886_080, Max raw Blocksize 4GiB
    pub file_info: Option<FileInfo>,
    pub hashes: Option<Hashes>,
    pub metadata: Option<String>,
    pub symlinks: Option<Vec<SymlinkContextHeader>>,
    pub custom_ranges: Option<Vec<CustomRange>>,
}

impl TryFrom<FileContext> for FileContextHeader {
    type Error = anyhow::Error;

    fn try_from(ctx: FileContext) -> Result<Self> {
        Ok(Self {
            file_path: ctx.file_path,
            disk_size: ctx.decompressed_size,
            file_start: 0,
            file_end: 0,
            compressed: ctx.compression,
            encrypted: ctx.encryption_key.data_encrypted(),
            block_scale: ctx.chunk_multiplier.unwrap_or(1),
            index_list: None,
            file_info: ctx.into(),
            hashes: ctx.get_hashes()?,
            metadata: ctx.semantic_metadata,
            symlinks: None,
            custom_ranges: ctx.custom_ranges,
        })
    }
}

#[derive(BorshDeserialize, BorshSerialize, Debug)]
pub struct DirContextHeader {
    pub file_path: String, // FileName /foo/bar/
    pub file_info: Option<FileInfo>,
    pub symlinks: Option<Vec<SymlinkContextHeader>>,
    pub metadata: Option<String>,
}

impl From<FileContext> for DirContextHeader {
    fn from(ctx: FileContext) -> Self {
        Self {
            file_path: ctx.file_path,
            file_info: ctx.into(),
            symlinks: None,
            metadata: ctx.semantic_metadata,
        }
    }
}

#[derive(BorshDeserialize, BorshSerialize, Debug)]
pub enum FileContextVariants {
    FileDecrypted(FileContextHeader),
    FileEncrypted(Vec<u8>),
}

impl FileContextVariants {
    pub fn encrypt(self, key: &[u8; 32]) -> Result<Self> {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let as_bytes = borsh::to_vec(&self)?;
        let data: Vec<u8> = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| anyhow!("Invalid key length"))?
            .encrypt(&nonce, as_bytes.as_slice())
            .map_err(|_| anyhow!("Error while encrypting keys"))?;
        Ok(FileContextVariants::FileEncrypted(
            nonce.to_vec().into_iter().chain(data).collect(),
        ))
    }
}

#[derive(BorshDeserialize, BorshSerialize, Debug)]
pub enum DirContextVariants {
    DirDecrypted(DirContextHeader),
    DirEncrypted(Vec<u8>),
}

impl DirContextVariants {
    pub fn encrypt(self, key: &[u8; 32]) -> Result<Self> {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let as_bytes = borsh::to_vec(&self)?;
        let data: Vec<u8> = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| anyhow!("Invalid key length"))?
            .encrypt(&nonce, as_bytes.as_slice())
            .map_err(|_| anyhow!("Error while encrypting keys"))?;
        Ok(DirContextVariants::DirEncrypted(
            nonce.to_vec().into_iter().chain(data).collect(),
        ))
    }
}

#[derive(BorshDeserialize, BorshSerialize, Debug)]
pub struct TableOfContents {
    pub magic_bytes: [u8; 4], // Should be 0x53, 0x2A, 0x4D, 0x18
    pub len: u32,
    pub directories: Vec<DirContextVariants>,
    pub files: Vec<FileContextVariants>,
}

impl TableOfContents {
    pub fn new() -> Self {
        Self {
            magic_bytes: ZSTD_MAGIC_BYTES_SKIPPABLE_2,
            len: 0,
            directories: Vec::new(),
            files: Vec::new(),
        }
    }
}
