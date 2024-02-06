use std::num::ParseIntError;

use crate::helpers::notifications::DirOrFileIdx;
use crate::pithos::structs::{CustomRange, FileInfo, Hashes};
use anyhow::{anyhow, bail, Result};

#[derive(Debug, PartialEq, Default, Clone)]
pub enum ProbeResult {
    #[default]
    Unknown,
    Compression,
    NoCompression,
}

#[derive(Eq, PartialEq, PartialOrd, Ord, Clone, Copy, Debug)]
pub struct Range {
    pub from: u64,
    pub to: u64,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub enum EncryptionKey {
    #[default]
    None,
    Same(Vec<u8>),
    DataOnly(Vec<u8>),
    Individual((Vec<u8>, Vec<u8>)),
}

impl EncryptionKey {
    pub fn data_encrypted(&self) -> bool {
        match self {
            EncryptionKey::None => false,
            EncryptionKey::Same(_) => true,
            EncryptionKey::DataOnly(_) => true,
            EncryptionKey::Individual((_, _)) => true,
        }
    }

    pub fn get_data_key(&self) -> Option<Vec<u8>> {
        match self {
            EncryptionKey::None => None,
            EncryptionKey::Same(key) => Some(key.clone()),
            EncryptionKey::DataOnly(key) => Some(key.clone()),
            EncryptionKey::Individual((key, _)) => Some(key.clone()),
        }
    }

    pub fn into_keys(&self) -> Result<Vec<[u8; 32]>> {
        let result: Vec<[u8; 32]> = match &self {
            EncryptionKey::None => vec![],
            EncryptionKey::Same(key) => vec![key.as_slice().try_into()?],
            EncryptionKey::DataOnly(key) => vec![key.as_slice().try_into()?],
            EncryptionKey::Individual((key, key2)) => {
                vec![key.as_slice().try_into()?, key2.as_slice().try_into()?]
            }
        };

        Ok(result)
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct FileContext {
    pub idx: usize,
    // FileName
    pub file_path: String,
    // Input size compressed
    pub compressed_size: u64,
    // Filesize decompressed
    pub decompressed_size: u64,
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
    // ChunkMultiplier num or 1
    pub chunk_multiplier: Option<u32>,
    // Encryption Key(s)
    pub encryption_key: EncryptionKey,
    // Recipients pubkeys
    pub recipients_pubkeys: Vec<[u8; 32]>,
    // Is this file a directory
    pub is_dir: bool,
    // Is this file a symlink
    pub symlink_target: Option<String>,
    // Expected SHA256 hash
    pub expected_sha256: Option<String>,
    // Expected MD5 hash
    pub expected_md5: Option<String>,
    // Semantic Metadata
    pub semantic_metadata: Option<String>,
    // Custom Ranges
    pub custom_ranges: Option<Vec<CustomRange>>,
}

impl Into<Option<FileInfo>> for FileContext {
    fn into(self) -> Option<FileInfo> {
        if self.uid.is_some() || self.gid.is_some() || self.mode.is_some() || self.mtime.is_some() {
            return Some(FileInfo {
                uid: self.uid,
                gid: self.gid,
                mode: self.mode,
                mtime: self.mtime,
            });
        }
        None
    }
}

impl From<&FileContext> for Option<FileInfo> {
    fn from(value: &FileContext) -> Self {
        if value.uid.is_some()
            || value.gid.is_some()
            || value.mode.is_some()
            || value.mtime.is_some()
        {
            return Some(FileInfo {
                uid: value.uid,
                gid: value.gid,
                mode: value.mode,
                mtime: value.mtime,
            });
        }
        None
    }
}

impl FileContext {
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn get_hashes(&self) -> Result<Option<Hashes>> {
        if self.expected_sha256.is_none() && self.expected_sha256.is_none() {
            return Ok(None);
        }

        let mut hashes = Hashes {
            sha256: None,
            md5: None,
        };

        // Validate hash lengths?

        if let Some(sha256) = &self.expected_sha256 {
            let sha256_bytes: [u8; 32] = decode_hex(&sha256)?
                .try_into()
                .map_err(|_| anyhow!("Provided SHA256 has invalid length"))?;
            hashes.sha256 = Some(sha256_bytes);
        }
        if let Some(md5) = &self.expected_md5 {
            let md5_bytes: [u8; 16] = decode_hex(&md5)?
                .try_into()
                .map_err(|_| anyhow!("Provided MD5 has invalid length"))?;
            hashes.md5 = Some(md5_bytes)
        }

        Ok(Some(hashes))
    }
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let result: Result<Vec<u8>, ParseIntError> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect();

    match result {
        Ok(bytes) => Ok(bytes),
        Err(err) => bail!(err),
    }
}
