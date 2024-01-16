use anyhow::{anyhow, bail, Result};
use byteorder::{ByteOrder, LittleEndian};
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
    HasSemanticMetadata = 2,
    HasBlocklist = 3,
    HasEncryptionMetadata = 4,
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
}

impl TryFrom<&[u8]> for EndOfFileMetadata {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut magic_bytes = [0; 4];

        magic_bytes.copy_from_slice(&value[0..4]);

        if magic_bytes != [0x50, 0x2A, 0x4D, 0x18] {
            return Err(anyhow!("Received invalid message"));
        }

        let len = LittleEndian::read_u32(&value[4..8]);

        let version = LittleEndian::read_u32(&value[8..12]);

        if version != 1 {
            return Err(anyhow!("Unsupported version"));
        }

        let file_name_length = LittleEndian::read_u16(&value[12..14]);

        let mut file_name = String::new();
        file_name.push_str(
            std::str::from_utf8(&value[14..14 + file_name_length as usize])
                .map_err(|_| anyhow!("Invalid filename"))?,
        );
        let mut offset = 14 + file_name_length as usize; 
        let raw_file_size = LittleEndian::read_u64(&value[offset..8 + offset]);
        offset += 8;
        let mut file_hash_sha256 = [0; 32];
        file_hash_sha256.copy_from_slice(&value[offset..32 + offset]);
        offset += 32;
        let mut file_hash_md5 = [0; 16];
        file_hash_md5.copy_from_slice(&value[offset..16 + offset]);
        offset += 16;

        let flags = LittleEndian::read_u64(&value[offset..8 + offset]);
        offset += 8;
        let semantic_start = LittleEndian::read_u64(&value[offset..8 + offset]);
        offset += 8;
        let blocklist_start = LittleEndian::read_u64(&value[offset..8 + offset]);
        offset += 8;
        let encryption_start = LittleEndian::read_u64(&value[offset..8 + offset]);
        offset += 8;
        let disk_file_size = LittleEndian::read_u64(&value[offset..8 + offset]);
        offset += 8;
        let mut disk_hash_sha256 = [0; 32];
        disk_hash_sha256.copy_from_slice(&value[offset..32 + offset]);
        offset += 32;
        let semantic_len = if Self::is_flag_set_u64(flags, Flag::HasSemanticMetadata) {
            let semantic_len = LittleEndian::read_u64(&value[offset..8 + offset]);
            offset += 8;
            Some(semantic_len)
        }else{
            None
        };
        let blocklist_len = if Self::is_flag_set_u64(flags, Flag::HasBlocklist) {
            let blocklist_len = LittleEndian::read_u64(&value[offset..8 + offset]);
            offset += 8;
            Some(blocklist_len)
        }else{
            None
        };
        let encryption_len = if Self::is_flag_set_u64(flags, Flag::HasEncryptionMetadata) {
            let encryption_len = LittleEndian::read_u64(&value[offset..8 + offset]);
            offset += 8;
            Some(encryption_len)
        }else{
            None
        };

        let eof_metadata_len = LittleEndian::read_u64(&value[offset..8 + offset]);
        if eof_metadata_len != (offset + 8) as u64 || eof_metadata_len != value.len() as u64{
            return Err(anyhow!("Invalid EOF metadata length"));
        }

        Ok(Self {
            magic_bytes,
            len,
            version,
            file_name_length,
            file_name,
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

impl Into<Vec<u8>> for EndOfFileMetadata {
    fn into(self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(self.eof_metadata_len as usize);
        buffer[0..4].copy_from_slice(&self.magic_bytes);
        LittleEndian::write_u32(&mut buffer[4..8], self.len);
        LittleEndian::write_u32(&mut buffer[8..12], self.version);
        LittleEndian::write_u16(&mut buffer[12..14], self.file_name_length);
        buffer[14..14 + self.file_name_length as usize].copy_from_slice(&self.file_name.as_bytes());
        let mut offset = 14 + self.file_name_length as usize; 
        LittleEndian::write_u64(&mut buffer[offset..offset + 8], self.raw_file_size);
        offset += 8;
        buffer[offset..8 + offset].copy_from_slice(&self.file_hash_sha256);
        offset += 32;
        buffer[offset..16 + offset].copy_from_slice(&self.file_hash_md5);
        offset += 16;
        LittleEndian::write_u64(&mut buffer[offset..8 + offset], self.flags);
        if let Some(semantic_len) = self.semantic_len {
            LittleEndian::write_u64(&mut buffer[offset..8 + offset], semantic_len);
            offset += 8;
        }
        if let Some(blocklist_len) = self.blocklist_len {
            LittleEndian::write_u64(&mut buffer[offset..8 + offset], blocklist_len);
            offset += 8;
        }
        if let Some(encryption_len) = self.encryption_len {
            LittleEndian::write_u64(&mut buffer[offset..8 + offset], encryption_len);
            offset += 8;
        }
        LittleEndian::write_u64(&mut buffer[offset..8 + offset], self.eof_metadata_len);
        buffer
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

pub struct EncryptionPacket {
    pub len: u32,
    pub pubkey: [u8; 32],
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
    pub padding: Vec<u8>, // -> Multiple of 512 Bytes
}

impl EncryptionMetadata {
    pub fn new(_header_packets: Vec<EncryptionPacket>) -> Self {
        Self {
            magic_bytes: [0x51, 0x2A, 0x4D, 0x18],
            len: 0, // (Sum of all packages len)
            packets: vec![],
            padding: vec![],
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

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() % 512 != 0 {
            return Err(anyhow!("Invalid encryption metadata len"));
        }
        let mut magic_bytes = [0; 4];
        magic_bytes.copy_from_slice(&value[0..4]);

        if magic_bytes != [0x51, 0x2A, 0x4D, 0x18] {
            return Err(anyhow!("Received invalid message"));
        }

        let len = LittleEndian::read_u32(&value[4..8]);

        if len as usize != value[8..].len() {
            return Err(anyhow!("Invalid blocklist length"));
        }

        let mut packets = Vec::new();
        let mut offset = 8;
        while offset < len as usize {
            let packet_len = LittleEndian::read_u32(&value[offset..offset + 4]);
            let mut pubkey = [0; 32];
            pubkey.copy_from_slice(&value[offset + 4..offset + 36]);
            let mut nonce = [0; 12];
            nonce.copy_from_slice(&value[offset + 36..offset + 48]);
            let key_offset = offset + 48;
            let mut keys = vec![];
            keys.copy_from_slice(&value[key_offset..key_offset + packet_len as usize - 16]);
            let mut mac = [0; 16];
            mac.copy_from_slice(
                &value[offset + packet_len as usize - 16..offset + packet_len as usize],
            );
            packets.push(EncryptionPacket {
                len: packet_len,
                pubkey,
                nonce,
                keys: Keys::Encrypted(keys),
                mac,
            });
            offset += packet_len as usize;
        }
        let mut padding = Vec::new();
        padding.copy_from_slice(&value[offset..]);
        Ok(Self {
            magic_bytes,
            len,
            packets,
            padding,
        })
    }
}

impl TryInto<Vec<u8>> for EncryptionMetadata {
    type Error = anyhow::Error;
    fn try_into(self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.magic_bytes);
        LittleEndian::write_u32(&mut buffer, self.len);
        for packet in self.packets {
            LittleEndian::write_u32(&mut buffer, packet.len);
            buffer.extend_from_slice(&packet.pubkey);
            buffer.extend_from_slice(&packet.nonce);
            match packet.keys {
                Keys::Encrypted(keys) => buffer.extend_from_slice(&keys),
                Keys::Decrypted(_) => {
                    bail!("Encryption metadata contains unencrypted keys")
                }
            }
            buffer.extend_from_slice(&packet.mac);
        }
        buffer.extend_from_slice(&self.padding);
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

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut magic_bytes: [u8; 4] = [0; 4];
        magic_bytes.copy_from_slice(&value[0..4]);

        if magic_bytes != [0x52, 0x2A, 0x4D, 0x18] {
            return Err(anyhow!("Received invalid message"));
        }

        let len = LittleEndian::read_u32(&value[4..8]);

        if len as usize != value[8..].len() {
            return Err(anyhow!("Invalid blocklist length"));
        }

        let mut blocklist = Vec::new();
        blocklist.copy_from_slice(&value[8..]);
        Ok(Self {
            magic_bytes,
            len,
            blocklist,
        })
    }
}

impl Into<Vec<u8>> for BlockList {
    fn into(self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.magic_bytes);
        LittleEndian::write_u32(&mut buffer, self.len);
        buffer.extend_from_slice(&self.blocklist);
        buffer
    }
}

pub struct SemanticMetadata {
    pub magic_bytes: [u8; 4], // Should be 0x53, 0x2A, 0x4D, 0x18
    pub len: u32,
    pub semantic: String, // JSON encoded string
}

impl SemanticMetadata {
    pub fn new(semantic: String) -> Self {
        Self {
            magic_bytes: [0x53, 0x2A, 0x4D, 0x18],
            len: semantic.len() as u32,
            semantic,
        }
    }
}

impl TryFrom<&[u8]> for SemanticMetadata {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut magic_bytes: [u8; 4] = [0; 4];
        magic_bytes.copy_from_slice(&value[0..4]);

        if magic_bytes != [0x53, 0x2A, 0x4D, 0x18] {
            return Err(anyhow!("Received invalid message"));
        }

        let len = LittleEndian::read_u32(&value[4..8]);

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

impl Into<Vec<u8>> for SemanticMetadata {
    fn into(self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.magic_bytes);
        LittleEndian::write_u32(&mut buffer, self.len);
        buffer.extend_from_slice(self.semantic.as_bytes());
        buffer
    }
}
