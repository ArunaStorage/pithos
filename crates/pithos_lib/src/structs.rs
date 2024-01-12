use crate::transformer::FileContext;
use anyhow::{anyhow, Result};
use byteorder::{ByteOrder, LittleEndian};
use chacha20poly1305::aead::generic_array::sequence::GenericSequence;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use crypto_kx::{Keypair, PublicKey};
use rand_core::OsRng;

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



pub struct EndOfFileMetadata {
    pub magic_bytes: [u8; 4], // Should be 0x50, 0x2A, 0x4D, 0x18
    pub len: u32,
    pub version: u32,
    pub file_name: [u8; 512],
    pub file_size: u64,
    pub file_hash_sha1: [u8; 32],
    pub file_hash_md5: [u8; 16],
    pub flags: u64,
    pub semantic_start: u64,
    pub blocklist_start: u64,
    pub encryption_start: u64,
    pub disk_hash_sha1: [u8; 32], // Everything except disk_hash_sha1 is 0
    pub extra: [u8; 380],         // CURRENTLY UNUSED IGNORED FOR hashing
}

impl EndOfFileMetadata {
    pub fn init() -> Self {
        Self {
            magic_bytes: [0x50, 0x2A, 0x4D, 0x18],
            len: 1016,
            version: 1,
            file_name: [0; 512],
            file_size: 0,
            file_hash_sha1: [0; 32],
            file_hash_md5: [0; 16],
            flags: 0,
            semantic_start: 0,
            blocklist_start: 0,
            encryption_start: 0,
            disk_hash_sha1: [0; 32],
            extra: [0; 380],
        }
    }

    pub fn update_with_file_ctx(&mut self, ctx: &FileContext) -> Result<()> {
        if ctx.file_name.len() <= 512 {
            self.file_name[..ctx.file_name.len()].copy_from_slice(&ctx.file_name.as_bytes());
        } else {
            Err(anyhow!("Filename too long"))
        }

        self.file_size = ctx.file_size;
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

impl TryFrom<&[u8; 1024]> for EndOfFileMetadata {
    type Error = anyhow::Error;

    fn try_from(value: &[u8; 1024]) -> Result<Self, Self::Error> {
        let mut magic_bytes = [0; 4];

        magic_bytes.copy_from_slice(&value[0..4]);

        if magic_bytes != [0x50, 0x2A, 0x4D, 0x18] {
            return Err(anyhow!("Received invalid message"));
        }

        let len = LittleEndian::read_u32(&value[4..8]);

        if len as usize != 1016 {
            return Err(anyhow!("Invalid EOFMetadata length"));
        }

        let version = LittleEndian::read_u32(&value[8..12]);

        let mut file_name = [0; 512];
        file_name.copy_from_slice(&value[12..524]);

        let file_size = LittleEndian::read_u64(&value[524..532]);
        let mut file_hash_sha1 = [0; 32];
        file_hash_sha1.copy_from_slice(&value[532..564]);

        let mut file_hash_md5 = [0; 16];
        file_hash_md5.copy_from_slice(&value[564..580]);

        let flags = LittleEndian::read_u64(&value[580..588]);
        let semantic_start = LittleEndian::read_u64(&value[588..596]);
        let blocklist_start = LittleEndian::read_u64(&value[596..604]);
        let encryption_start = LittleEndian::read_u64(&value[604..612]);

        let mut disk_hash_sha1 = [0; 32];
        disk_hash_sha1.copy_from_slice(&value[612..644]);

        let mut extra = [0; 380];
        extra.copy_from_slice(&value[644..1024]);

        Ok(Self {
            magic_bytes,
            len,
            version,
            file_name,
            file_size,
            file_hash_sha1,
            file_hash_md5,
            flags,
            semantic_start,
            blocklist_start,
            encryption_start,
            disk_hash_sha1,
            extra,
        })
    }
}

impl Into<[u8; 1024]> for EndOfFileMetadata {
    fn into(self) -> [u8; 1024] {
        let mut buffer = [0; 1024];
        buffer[0..4].copy_from_slice(&self.magic_bytes);
        LittleEndian::write_u32(&mut buffer[4..8], self.len);
        LittleEndian::write_u32(&mut buffer[8..12], self.version);
        buffer[12..524].copy_from_slice(&self.file_name);
        LittleEndian::write_u64(&mut buffer[524..532], self.file_size);
        buffer[532..564].copy_from_slice(&self.file_hash_sha1);
        buffer[564..580].copy_from_slice(&self.file_hash_md5);
        LittleEndian::write_u64(&mut buffer[580..588], self.flags);
        LittleEndian::write_u64(&mut buffer[588..596], self.semantic_start);
        LittleEndian::write_u64(&mut buffer[596..604], self.blocklist_start);
        LittleEndian::write_u64(&mut buffer[604..612], self.encryption_start);
        buffer[612..644].copy_from_slice(&self.disk_hash_sha1);
        buffer[644..1024].copy_from_slice(&self.extra);
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

    pub fn encrypt(
        &mut self,
        writers_secret_key: Option<[u8; 32]>,
    ) -> Result<()> {
        match &self.keys {
            Keys::Decrypted(keys) => {
                let keypair = match writers_secret_key {
                    Some(key) => Keypair::from(key),
                    None => Keypair::generate(&mut OsRng),
                };
                let session_key = keypair
                    .session_keys_from(&PublicKey::from(keys.readers_pubkey))
                    .tx
                    .as_ref();
                let nonce = Nonce::generate(&mut OsRng);

                let concatenated_keys = keys.keys.concat();
                let (enc_keys, mac) = ChaCha20Poly1305::new(&Key::from(session_key))
                    .encrypt(nonce.into(), concatenated_keys.as_slice())
                    .map_err(|e| anyhow!("Error while encrypting keys"))?
                    .split_at(concatenated_keys.len());

                self.len = (4 + 32 + 12 + enc_keys.len() + 16) as u32;
                self.pubkey = keypair.public().into();
                self.keys = Keys::Encrypted(enc_keys.to_vec());
                self.mac = mac.into();
            }
            Keys::Encrypted(_) => Err(anyhow!("Keys already encrypted")),
        }
        Ok(())
    }

    pub fn decrypt(&mut self, readers_secret_key: [u8; 32]) -> Result<()> {
        match &self.keys {
            Keys::Encrypted(keys) => {
                let keypair = Keypair::from(readers_secret_key);
                let session_key = keypair
                    .session_keys_from(&PublicKey::from(self.pubkey))
                    .rx
                    .as_ref();
                let nonce = Nonce::from_slice(&self.nonce);
                let dec_keys = ChaCha20Poly1305::new(&Key::from(session_key))
                    .decrypt(nonce.into(), vec![keys, &self.mac])
                    .map_err(|e| anyhow!("Error while decrypting keys"))?;

                self.keys = Keys::Decrypted(DecryptedKey {
                    keys: dec_keys.chunks_exact(32).map(|x| x.try_into()).collect()?,
                    readers_pubkey: keypair.public().into(),
                });
            }
            Keys::Decrypted(_) => Err(anyhow!("Keys already decrypted")),
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
    pub fn new(header_packets: Vec<EncryptionPacket>) -> Self {
        Self {
            magic_bytes: [0x51, 0x2A, 0x4D, 0x18],
            len: 0, // (Sum of all packages len)
            packets: vec![],
            padding: vec![],
        }
    }

    pub fn encrypt_all(
        &mut self,
        writers_secret_key: Option<[u8; 32]>,
    ) -> Result<()> {
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
            let mut key_offset = offset + 48;
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

impl Into<Vec<u8>> for EncryptionMetadata {
    fn into(self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.magic_bytes);
        LittleEndian::write_u32(&mut buffer, self.len);
        for packet in self.packets {
            LittleEndian::write_u32(&mut buffer, packet.len);
            buffer.extend_from_slice(&packet.pubkey);
            buffer.extend_from_slice(&packet.nonce);
            for key in packet.keys {
                buffer.extend_from_slice(&key.0);
            }
            buffer.extend_from_slice(&packet.mac);
        }
        buffer.extend_from_slice(&self.padding);
        buffer
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
