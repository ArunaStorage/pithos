use crate::helpers::flag_helpers::{self, set_flag_bit_u8};
use anyhow::{anyhow, bail, Result};
use byteorder::LittleEndian;
use byteorder::{ReadBytesExt, WriteBytesExt};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, KeyInit};
use std::fmt::Display;
use std::io::{Read, Write};
use std::path::PathBuf;
use rand_core::OsRng;
use tracing::debug;

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

pub struct FileInfo {
    pub uid: Option<u64>,              // UserId
    pub gid: Option<u64>,              // GroupId
    pub mode: Option<u32>,             // Octal like mode
    pub mtime: Option<u64>,            // Created at
}

pub struct Hashes {
    pub sha256: Option<[u8; 32]>,
    pub md5: Option<[u8; 16]>,
}

pub struct CustomRange {
    pub tag: String,
    pub start: u64,
    pub end: u64,
}

pub struct FileContextHeader {
    pub file_path: String, // FilePath empty = SKIP
    pub disk_size: u64,
    pub file_start: u64,
    pub file_end: u64,
    pub compressed: bool,
    pub encrypted: bool,
    pub file_info: Option<FileInfo>,
    pub hashes: Option<Hashes>,
    pub metadata: Option<String>,
    pub symlinks: Option<Vec<SymlinkContextHeader>>,
    pub custom_ranges: Option<Vec<CustomRange>>,
}

pub struct DirContextHeader {
    pub file_path: String, // FileName /foo/bar/
    pub file_info: Option<FileInfo>,
    pub metadata: Option<String>,
}

pub struct SymlinkContextHeader {
    pub file_path: String, // FileName /foo/bar/
    pub file_info: Option<FileInfo>,
}

#[derive(Debug, PartialEq)]
pub enum ProbeResult {
    Unknown,
    Compression,
    NoCompression,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct EndOfFileMetadata { // 73 Bytes
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
            magic_bytes: [0x50, 0x2A, 0x4D, 0x18],
            len: 0,
            version: 1,
            raw_file_size: 0,
            disk_file_size: 0,
            disk_hash_sha256: [0; 32],
            range_table_len: 0,
            encryption_len: 0,
        }
    }
}

#[derive(Debug)]
pub struct EncryptionMetadata {
    pub magic_bytes: [u8; 4], // Should be 0x51, 0x2A, 0x4D, 0x18
    pub len: u32, // Required for zstd skippable frame
    pub packets: Vec<EncryptionPacket>,
}

#[derive(Clone, Debug)]
pub enum EncryptionTarget {
    FileData(PithosRange),      // File Data
    FileMetadata(PithosRange),  // Full TableOfContents entry
    FileDataAndMetadata(PithosRange),
    Dir(PithosRange), // Full DirContextHeader
}

#[derive(Debug)]
pub struct DecryptedKey {
    pub keys: Vec<([u8; 32], Vec<EncryptionTarget>)>,
    pub readers_pubkey: [u8; 32],
}

// impl DecryptedKey into EncryptionPacket
// Auto encrypt DecryptedKey with recipient PubKey into EncryptionPacket
impl TryInto<EncryptionPacket> for DecryptedKey {
    type Error = anyhow::Error;

    fn try_into(self) -> std::result::Result<EncryptionPacket, Self::Error> {
        todo!()
    }
}

#[derive(Debug)]
pub struct EncryptionPacket {
    pub pubkey: [u8; 32],
    pub nonce: [u8; 12],
    pub keys: Vec<u8>,
    pub mac: [u8; 16],
}

#[derive(Clone, Debug)]
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


pub enum FileContextVariants {
    FileDecrypted(FileContextHeader),
    FileEncrypted(Vec<u8>),
}

impl FileContextVariants {
    pub fn encrypt(self, key: &[u8; 32]) -> Self {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let data = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| anyhow!("Invalid key length"))?
            .encrypt(&nonce, todo!("Serialize me"))
            .map_err(|_| anyhow!("Error while encrypting keys"))?;
        FileContextVariants::FileEncrypted(nonce.as_ref().to_vec().concat(data))
    }
}

pub enum DirContextVariants {
    DirDecrypted(DirContextHeader),
    DirEncrypted(Vec<u8>),
}

impl DirContextVariants {
    pub fn encrypt(self, key: &[u8; 32]) -> Self {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let data = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| anyhow!("Invalid key length"))?
            .encrypt(&nonce, todo!("Serialize me"))
            .map_err(|_| anyhow!("Error while encrypting keys"))?;
        DirContextVariants::DirEncrypted(nonce.as_ref().to_vec().concat(data))
    }
}

pub struct TableOfContents {
    pub magic_bytes: [u8; 4], // Should be 0x53, 0x2A, 0x4D, 0x18
    pub len: u32,
    pub directories: Vec<DirContextVariants>,
    pub files: Vec<FileContextVariants>,
}

//
// impl TryInto<Vec<u8>> for PithosRange {
//     type Error = anyhow::Error;
//
//     fn try_into(self) -> std::prelude::v1::Result<Vec<u8>, Self::Error> {
//         let mut buffer: Vec<_> = Vec::with_capacity(24);
//         match self {
//             PithosRange::All => buffer.write_u8(0)?,
//             PithosRange::Index(index) => {
//                 buffer.write_u8(1)?;
//                 buffer.write_u64::<LittleEndian>(index)?
//             }
//             PithosRange::Start(start) => {
//                 buffer.write_u8(2)?;
//                 buffer.write_u64::<LittleEndian>(start.start)?
//             }
//             PithosRange::End(end) => {
//                 buffer.write_u8(3)?;
//                 buffer.write_u64::<LittleEndian>(end.end)?
//             }
//             PithosRange::IndexRange(range) => {
//                 buffer.write_u8(4)?;
//                 buffer.write_u64::<LittleEndian>(range.start)?;
//                 buffer.write_u64::<LittleEndian>(range.end)?
//             }
//         }
//
//         Ok(buffer)
//     }
// }
//
// impl TryFrom<&[u8]> for PithosRange {
//     type Error = anyhow::Error;
//
//     fn try_from(mut value: &[u8]) -> Result<Self, Self::Error> {
//         Ok(match value.read_u8()? {
//             0 => PithosRange::All,
//             1 => PithosRange::Index(value.read_u64::<LittleEndian>()?),
//             2 => PithosRange::Start(value.read_u64::<LittleEndian>()?..),
//             3 => PithosRange::End(..value.read_u64::<LittleEndian>()?),
//             4 => {
//                 let start = value.read_u64::<LittleEndian>()?;
//                 let end = value.read_u64::<LittleEndian>()?;
//                 PithosRange::IndexRange(start..end)
//             }
//             _ => bail!("Invalid range variant"),
//         })
//     }
// }
//
// impl DecryptedKey {
//     pub fn keys_into_bytes(&self) -> Result<Vec<u8>> {
//         let mut buf = vec![];
//         for (key, ranges) in self.keys {
//             buf.write_all(&key);
//             buf.write_u32::<LittleEndian>(ranges.len() as u32);
//             for range in ranges {
//                 buf.write_all(TryInto::<Vec<u8>>::try_into(range)?.as_slice());
//             }
//         }
//
//         Ok(buf)
//     }
//
//     pub fn from_bytes_with_pubkey(mut bytes: &[u8], pubkey: [u8; 32]) -> Result<Self> {
//         let mut keys = vec![];
//         while bytes.len() > 0 {
//             let mut key: [u8; 32];
//             bytes.read_exact(&mut key)?;
//             let mut ranges = vec![];
//             for index in 0..bytes.read_u32::<LittleEndian>()? {
//                 let range = match bytes.read_u8()? {
//                     0 => PithosRange::All,
//                     1 => PithosRange::Index(bytes.read_u64::<LittleEndian>()?),
//                     2 => PithosRange::Start(bytes.read_u64::<LittleEndian>()?..),
//                     3 => PithosRange::End(..bytes.read_u64::<LittleEndian>()?),
//                     4 => {
//                         let start = bytes.read_u64::<LittleEndian>()?;
//                         let end = bytes.read_u64::<LittleEndian>()?;
//                         PithosRange::IndexRange(start..end)
//                     }
//                     _ => bail!("Invalid range variant"),
//                 };
//                 ranges.push(range)
//             }
//             keys.push((key, ranges))
//         }
//
//         Ok(Self {
//             keys,
//             readers_pubkey: pubkey,
//         })
//     }
// }
//
//
// impl EncryptionPacket {
//     pub fn new(
//         unencrypted_keys: Vec<([u8; 32], Vec<PithosRange>)>,
//         readers_pubkey: [u8; 32],
//     ) -> Self {
//         Self {
//             len: 0,
//             pubkey: [0; 32],
//             nonce: [0; 12],
//             flags: 0,
//             keys: Keys::Decrypted(DecryptedKey {
//                 keys: unencrypted_keys,
//                 readers_pubkey,
//             }),
//             mac: [0; 16],
//         }
//     }
//
//     pub fn encrypt(&mut self, writers_secret_key: Option<[u8; 32]>) -> Result<()> {
//         match &self.keys {
//             Keys::Decrypted(keys) => {
//                 let keypair = match writers_secret_key {
//                     Some(key) => Keypair::from(SecretKey::from(key)),
//                     None => Keypair::generate(&mut OsRng),
//                 };
//                 let session_key = keypair
//                     .session_keys_to(&PublicKey::from(keys.readers_pubkey))
//                     .tx;
//
//                 let hex_key: String = session_key
//                     .as_ref()
//                     .iter()
//                     .map(|b| format!("{:02x}", b))
//                     .collect();
//                 debug!(enc_shared_key = ?hex_key);
//
//                 let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
//                 debug!(?nonce);
//
//                 let concatenated_keys = keys.keys_into_bytes()?;
//                 let data = ChaCha20Poly1305::new_from_slice(session_key.as_ref())
//                     .map_err(|_| anyhow!("Invalid key length"))?
//                     .encrypt(&nonce, concatenated_keys.as_slice())
//                     .map_err(|_| anyhow!("Error while encrypting keys"))?;
//                 let (enc_keys, mac) = data.split_at(concatenated_keys.len());
//
//                 self.len = (4 + 32 + 1 + 12 + enc_keys.len() + 16) as u32;
//                 self.pubkey = *keypair.public().as_ref();
//                 self.nonce = nonce.into();
//                 self.keys = Keys::Encrypted(enc_keys.to_vec());
//                 self.mac = mac.try_into()?;
//             }
//             Keys::Encrypted(_) => return Err(anyhow!("Keys already encrypted")),
//         }
//         Ok(())
//     }
//
//     pub fn decrypt(&mut self, readers_secret_key: [u8; 32]) -> Result<()> {
//         match &self.keys {
//             Keys::Encrypted(keys) => {
//                 let keypair = Keypair::from(SecretKey::from(readers_secret_key));
//                 let session_key = keypair.session_keys_from(&PublicKey::from(self.pubkey)).rx;
//
//                 let hex_key: String = session_key
//                     .as_ref()
//                     .iter()
//                     .map(|b| format!("{:02x}", b))
//                     .collect();
//                 debug!(dec_shared_key = ?hex_key);
//
//                 let nonce = Nonce::from_slice(&self.nonce);
//                 debug!(?nonce);
//
//                 let dec_keys = ChaCha20Poly1305::new_from_slice(session_key.as_ref())?
//                     .decrypt(
//                         nonce,
//                         [keys.as_slice(), self.mac.as_slice()].concat().as_slice(),
//                     )
//                     .map_err(|e| anyhow!("Error while decrypting keys: {e}"))?;
//
//                 self.keys = Keys::Decrypted(DecryptedKey::from_bytes_with_pubkey(
//                     &dec_keys,
//                     *keypair.public().as_ref(),
//                 )?);
//             }
//             Keys::Decrypted(_) => return Err(anyhow!("Keys already decrypted")),
//         }
//         Ok(())
//     }
//
//     pub fn set_flag(&mut self, flag: PacketKeyFlags) {
//         flag_helpers::set_flag_bit_u8(&mut self.flags, flag as u8)
//     }
//
//     pub fn unset_flag(&mut self, flag: PacketKeyFlags) {
//         flag_helpers::unset_flag_bit_u8(&mut self.flags, flag as u8)
//     }
//
//     pub fn is_flag_set(&self, flag: PacketKeyFlags) -> bool {
//         flag_helpers::is_flag_bit_set_u8(&self.flags, flag as u8)
//     }
//
//     pub fn extract_keys_with_flags(
//         &self,
//     ) -> Result<(Option<[u8; 32]>, Option<[u8; 32]>, Vec<[u8; 32]>)> {
//         match (
//             self.is_flag_set(PacketKeyFlags::ContainsExclusiveRangeTableKey),
//             self.is_flag_set(PacketKeyFlags::ContainsExclusiveSemanticMetadataKey),
//             self.is_flag_set(PacketKeyFlags::ContainsExclusiveRangeAndMetadataKey),
//             &self.keys,
//         ) {
//             (true, true, false, Keys::Decrypted(keys)) => {
//                 if keys.keys.len() < 2 {
//                     Err(anyhow!("Invalid key count < 2"))
//                 } else {
//                     Ok((
//                         keys.keys.first().copied(),
//                         keys.keys.get(1).copied(),
//                         keys.keys.get(2..).unwrap_or_default().to_vec(),
//                     ))
//                 }
//             }
//             (true, false, false, Keys::Decrypted(keys)) => {
//                 if keys.keys.is_empty() {
//                     Err(anyhow!("Invalid key count"))
//                 } else {
//                     Ok((
//                         keys.keys.first().copied(),
//                         None,
//                         keys.keys.get(1..).unwrap_or_default().to_vec(),
//                     ))
//                 }
//             }
//             (false, true, false, Keys::Decrypted(keys)) => {
//                 if keys.keys.is_empty() {
//                     Err(anyhow!("Invalid key count == 0"))
//                 } else {
//                     Ok((
//                         None,
//                         keys.keys.first().copied(),
//                         keys.keys.get(1..).unwrap_or_default().to_vec(),
//                     ))
//                 }
//             }
//             (false, false, true, Keys::Decrypted(keys)) => {
//                 if keys.keys.is_empty() {
//                     Err(anyhow!("Invalid key count == 0"))
//                 } else {
//                     Ok((
//                         keys.keys.first().copied(),
//                         keys.keys.first().copied(),
//                         keys.keys.get(1..).unwrap_or_default().to_vec(),
//                     ))
//                 }
//             }
//             (false, false, false, Keys::Decrypted(keys)) => Ok((None, None, keys.keys.clone())),
//             (_, _, _, Keys::Decrypted(_)) => {
//                 Err(anyhow!("Invalid flag combination cant combine and with or"))
//             }
//             (_, _, _, Keys::Encrypted(_)) => Err(anyhow!("Keys are encrypted")),
//         }
//     }
// }



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
        self.len = self.packets.iter().fold(0, |i, item| i + item.len);

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
                    buffer.write_u16::<LittleEndian>(ctx.flags)?;

                    if let Some(disk_size) = ctx.disk_size {
                        buffer.write_u64::<LittleEndian>(disk_size)?;
                    }
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
                    let flags = value.read_u16::<LittleEndian>()?;
                    let (disk_size, file_start, file_end, symlink) =
                        if flag_helpers::is_flag_bit_set_u16(&flags, FileContextFlag::Dir as u16) {
                            // If is dir
                            (None, None, None, None)
                        } else if flag_helpers::is_flag_bit_set_u16(
                            &flags,
                            FileContextFlag::Symlink as u16,
                        ) {
                            // If is symlink
                            let symlink_len = value.read_u16::<LittleEndian>()?;
                            let mut symlink_target = vec![0u8; symlink_len as usize];
                            value.read_exact(&mut symlink_target)?;
                            (
                                None,
                                None,
                                None,
                                Some(Symlink {
                                    len: symlink_len,
                                    target: String::from_utf8(symlink_target)?,
                                }),
                            )
                        } else {
                            // If is file
                            let disk_size = value.read_u64::<LittleEndian>()?;
                            let start = value.read_u64::<LittleEndian>()?;
                            let end = value.read_u64::<LittleEndian>()?;
                            (Some(disk_size), Some(start), Some(end), None)
                        };
                    // If has uid
                    let uid =
                        if flag_helpers::is_flag_bit_set_u16(&flags, FileContextFlag::UID as u16) {
                            Some(value.read_u64::<LittleEndian>()?)
                        } else {
                            None // or maybe default 1000
                        };
                    // If has uid
                    let gid =
                        if flag_helpers::is_flag_bit_set_u16(&flags, FileContextFlag::GID as u16) {
                            Some(value.read_u64::<LittleEndian>()?)
                        } else {
                            None // or maybe default 1000
                        };
                    // If has mode
                    let mode = if flag_helpers::is_flag_bit_set_u16(
                        &flags,
                        FileContextFlag::Mode as u16,
                    ) {
                        Some(value.read_u32::<LittleEndian>()?)
                    } else {
                        None // or maybe default 33188 -> 644
                    };
                    // If has mtime
                    let mtime =
                        if flag_helpers::is_flag_bit_set_u16(&flags, FileContextFlag::Mtime as u16)
                        {
                            Some(value.read_u64::<LittleEndian>()?)
                        } else {
                            None
                        };
                    // if has sha1
                    let expected_sha1 =
                        if flag_helpers::is_flag_bit_set_u16(&flags, FileContextFlag::Mtime as u16)
                        {
                            let mut sha1 = vec![0u8; 20];
                            value.read_exact(&mut sha1)?;
                            Some(String::from_utf8(sha1)?)
                        } else {
                            None // Or maybe default 0
                        };
                    // If has md5
                    let expected_md5 =
                        if flag_helpers::is_flag_bit_set_u16(&flags, FileContextFlag::Mtime as u16)
                        {
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
                            flags,
                            disk_size,
                            file_start,
                            file_end,
                            symlink,
                            uid,
                            gid,
                            mode,
                            mtime,
                            expected_sha1,
                            expected_md5,
                        }),
                    })
                }
                1 => {
                    let tag_len = value.read_u8()?;
                    let mut tag = vec![0u8; tag_len as usize];
                    value.read_exact(&mut tag)?;
                    let tag = String::from_utf8(tag)?;
                    let start = value.read_u64::<LittleEndian>()?;
                    let end = value.read_u64::<LittleEndian>()?;
                    sections.push(TableEntry {
                        variant_type: TableEntryVariant::CustomRange as u8,
                        entry: TableEntryVariant::CustomRange(CustomRange {
                            tag_len,
                            tag,
                            start,
                            end,
                        }),
                    })
                }
                _ => bail!("Invalid content variant"),
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
            set_flag_bit_u8(&mut flag, FileContextFlag::Dir as u8);
            ctx_header.file_start = None;
            ctx_header.file_end = None;
        } else if value.is_symlink {
            set_flag_bit_u8(&mut flag, FileContextFlag::Symlink as u8);
            ctx_header.file_start = None;
            ctx_header.file_end = None;
            ctx_header.symlink = Some(Symlink {
                len: ctx_header.file_path_len,
                target: ctx_header.file_path.clone(),
            });
        } else {
            ctx_header.file_start = Some(0); // ???
            ctx_header.file_end = Some(value.file_size);
        }
        if let Some(uid) = value.uid {
            set_flag_bit_u8(&mut flag, FileContextFlag::UID as u8);
            ctx_header.uid = Some(uid);
        }
        if let Some(gid) = value.gid {
            set_flag_bit_u8(&mut flag, FileContextFlag::GID as u8);
            ctx_header.gid = Some(gid);
        }
        if let Some(mode) = value.mode {
            set_flag_bit_u8(&mut flag, FileContextFlag::Mode as u8);
            ctx_header.mode = Some(mode);
        }
        if let Some(mtime) = value.mtime {
            set_flag_bit_u8(&mut flag, FileContextFlag::Mtime as u8);
            ctx_header.mtime = Some(mtime);
        }
        if let Some(sha1) = value.expected_sha1 {
            set_flag_bit_u8(&mut flag, FileContextFlag::Sha256 as u8);
            ctx_header.expected_sha1 = Some(sha1);
        }
        if let Some(md5) = value.expected_md5 {
            set_flag_bit_u8(&mut flag, FileContextFlag::Sha256 as u8);
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
