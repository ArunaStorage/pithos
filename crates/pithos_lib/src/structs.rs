use anyhow::anyhow;
use byteorder::{ByteOrder, LittleEndian};

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

pub struct EncryptedKey(pub [u8; 32]);

pub struct EncryptionPacket {
    pub len: u32,
    pub pubkey: [u8; 32],
    pub nonce: [u8; 12],
    pub keys: Vec<EncryptedKey>,
    pub mac: [u8; 16],
}

pub struct EncryptionMetadata {
    pub magic_bytes: [u8; 4], // Should be 0x51, 0x2A, 0x4D, 0x18
    pub len: u32,
    pub packets: Vec<EncryptionPacket>,
    pub padding: Vec<u8>, // -> Multiple of 512 Bytes
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
            let mut keys = Vec::new();
            let mut key_offset = offset + 48;
            while key_offset < offset + packet_len as usize - 16 {
                let mut key = [0; 32];
                key.copy_from_slice(&value[key_offset..key_offset + 32]);
                keys.push(EncryptedKey(key));
                key_offset += 32;
            }

            let mut mac = [0; 16];
            mac.copy_from_slice(
                &value[offset + packet_len as usize - 16..offset + packet_len as usize],
            );

            packets.push(EncryptionPacket {
                len: packet_len,
                pubkey,
                nonce,
                keys,
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
