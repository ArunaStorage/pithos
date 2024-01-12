use crate::crypt4gh::error::Crypt4GHError;
use byteorder::{LittleEndian, ReadBytesExt};
use chacha20poly1305::aead::generic_array::sequence::GenericSequence;
use chacha20poly1305::aead::{Aead, Key};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use crypto_kx::{Keypair, PublicKey, SecretKey};
use rand_core::OsRng;
use std::io::{Cursor, Read};
use tokio::io::AsyncReadExt;

const CRYPT4GH_HEADER_MAGIC: [u8; 8] = [0x63, 0x72, 0x79, 0x70, 0x74, 0x34, 0x67, 0x68]; // "crypt4gh"
const CRYPT4GH_HEADER_VERSION: u32 = 1;

#[repr(C)]
struct Crypt4GHHeader {
    magic: [u8; 8],    // Magic string to identify Crypt4GH format
    version: u32,      // Version of the format currently le 1
    packet_count: u32, // Size of the encrypted header
    header_packets: Vec<HeaderPacket>,
}

#[repr(C)]
struct HeaderPacket {
    length: u32,              // Length of the packet
    encryption_method: u32,   // Currently only 0 (Chacha20-Poly1305)
    writers_pubkey: [u8; 32], // Writer's public key
    nonce: [u8; 12],          // Nonce for encryption
    packet_data: PacketData,  // Encryption or editlist packet
    mac: [u8; 16],            // Message Authentication Code (MAC)
}

pub enum PacketData {
    Encrypted(Vec<u8>),
    Decrypted(Vec<Packet>),
}

pub enum Packet {
    Encryption(EncryptionPacket),
    EditList(EditListPacket),
}

#[repr(C)]
pub struct EncryptionPacket {
    packet_type: u32,         // 0 (Encryption)
    encryption_method: u32,   // 0 (Chacha20-Poly1305)
    encryption_key: [u8; 32], // 32 bytes encryption key
}

#[repr(C)]
pub struct EditListPacket {
    packet_type: u32, // 1
    num_length: u32,  // Number of edits
    edits: Vec<u64>,  // List of edits
}

impl TryFrom<&[u8]> for Crypt4GHHeader {
    type Error = Crypt4GHError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let mut header = Crypt4GHHeader {
            magic: [0; 8],
            version: 0,
            packet_count: 0,
            header_packets: Vec::new(),
        };
        let mut cursor = Cursor::new(bytes);
        cursor
            .read_exact(&mut header.magic)
            .map_err(|_| Crypt4GHError::FromBytesError("magic bytes".to_string()))?;
        if header.magic != CRYPT4GH_HEADER_MAGIC {
            return Err(Crypt4GHError::InvalidSpec("magic bytes".to_string()));
        }
        header.version = cursor
            .read_u32::<LittleEndian>()
            .map_err(|_| Crypt4GHError::FromBytesError("version".to_string()))?;
        if header.version != CRYPT4GH_HEADER_VERSION {
            return Err(Crypt4GHError::InvalidSpec("version".to_string()));
        }
        header.packet_count = cursor
            .read_u32::<LittleEndian>()
            .map_err(|_| Crypt4GHError::FromBytesError("header size".to_string()))?;
        while cursor.position() < header.packet_count as u64 {
            let len = cursor
                .read_u32::<LittleEndian>()
                .map_err(|_| Crypt4GHError::FromBytesError("packet length".to_string()))?;
            let mut buf = vec![0; len as usize];
            cursor
                .read_exact(&mut buf)
                .map_err(|_| Crypt4GHError::FromBytesError("packet data".to_string()))?;
            header
                .header_packets
                .push(HeaderPacket::from_buf(&mut buf, len as usize)?);
        }
        Ok(header)
    }
}

impl TryInto<Vec<u8>> for Crypt4GHHeader {
    type Error = Crypt4GHError;
    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.magic);
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&self.packet_count.to_le_bytes());
        for packet in self.header_packets {
            bytes.extend_from_slice(&packet.length.to_le_bytes());
            bytes.extend_from_slice(&packet.encryption_method.to_le_bytes());
            bytes.extend_from_slice(&packet.writers_pubkey);
            bytes.extend_from_slice(&packet.nonce);
            match packet.packet_data {
                PacketData::Encrypted(enc_data) => {
                    bytes.extend_from_slice(&enc_data);
                }
                PacketData::Decrypted(dec_data) => {
                    Crypt4GHError::InvalidSpec("packet data is not encrypted".to_string());
                }
            }
            bytes.extend_from_slice(&packet.mac);
        }
        Ok(bytes)
    }
}

impl HeaderPacket {
    pub fn new(packets: Vec<Packet>) -> Self {
        HeaderPacket {
            length: 0,
            encryption_method: 0,
            writers_pubkey: [0; 32],
            nonce: [0; 12],
            packet_data: PacketData::Decrypted(packets),
            mac: [0; 16],
        }
    }

    pub fn from_buf(bytes: &mut [u8], len: usize) -> Result<Self, Crypt4GHError> {
        let encryption_method = bytes
            .read_u32::<LittleEndian>()
            .map_err(|_| Crypt4GHError::FromBytesError("encryption method".to_string()))?;
        let mut writers_pubkey = [0; 32];
        bytes
            .read_exact(&mut writers_pubkey)
            .map_err(|_| Crypt4GHError::FromBytesError("writer's public key".to_string()))?;
        let mut nonce = [0; 12];
        bytes
            .read_exact(&mut nonce)
            .map_err(|_| Crypt4GHError::FromBytesError("nonce".to_string()))?;
        let encrypted_packet_data =
            PacketData::Encrypted(bytes[4 + 32 + 12..bytes.len() - 16].to_vec());
        let mac = bytes[bytes.len() - 16..];

        Ok(HeaderPacket {
            length: len.into(),
            encryption_method,
            writers_pubkey,
            nonce,
            packet_data: encrypted_packet_data,
            mac: mac
                .try_into()
                .map_err(|_| Crypt4GHError::FromBytesError("packet mac".to_string()))?,
        })
    }

    pub fn decrypt(&mut self, readers_private_key: SecretKey) -> Result<(), Crypt4GHError> {
        let writers_pub_key = PublicKey::from(self.writers_pubkey);
        let session_key = Keypair::from(readers_private_key)
            .session_keys_from(&writers_pub_key)
            .rx
            .as_ref();
        self.packet_data
            .decrypt(session_key.into(), &self.nonce, &self.mac)?;
        Ok(())
    }

    pub fn encrypt(
        &mut self,
        readers_pubkey: PublicKey,
        writers_private_key: Option<SecretKey>,
    ) -> Result<(), Crypt4GHError> {
        let keypair = match writers_private_key {
            Some(key) => Keypair::from(key),
            None => Keypair::generate(&mut OsRng),
        };
        let session_key = keypair.session_keys_from(&readers_pubkey).tx.as_ref();
        let nonce = Nonce::generate(&mut OsRng);
        self.mac = self.packet_data.encrypt(session_key.into(), nonce.into())?;
        self.writers_pubkey = keypair.public().into();
        self.nonce = nonce.into();
        self.length = (4 + 4 + 32 + 12 + self.packet_data.len() + 16).into();
        Ok(())
    }
}

impl PacketData {
    pub fn decrypt(
        &mut self,
        session_key: &[u8; 32],
        nonce: &[u8; 12],
        mac: &[u8; 16],
    ) -> Result<(), Crypt4GHError> {
        if let Self::Encrypted(enc_data) = &self {
            let decrypted_bytes = ChaCha20Poly1305::new_from_slice(session_key)
                .map_err(|e| {
                    Crypt4GHError::DecryptionError(format!("initialize decryptor: {}", e))
                })?
                .decrypt(nonce.into(), vec![enc_data, mac])
                .map_err(|e| Crypt4GHError::DecryptionFailed)?;

            self = &mut Self::Decrypted(Self::packet_from_bytes(&decrypted_bytes)?);
        } else {
            return Err(Crypt4GHError::DecryptionError(
                "packet data is not encrypted".to_string(),
            ));
        }
        Ok(())
    }

    pub fn encrypt(
        &mut self,
        session_key: &[u8; 32],
        nonce: &[u8; 12],
    ) -> Result<[u8; 16], Crypt4GHError> {
        return if let Self::Decrypted(dec_data) = &self {
            let mut enc_data = Vec::new();
            for packet in dec_data {
                match packet {
                    Packet::Encryption(enc_packet) => {
                        enc_data.extend_from_slice(&enc_packet.packet_type.to_le_bytes());
                        enc_data.extend_from_slice(&enc_packet.encryption_method.to_le_bytes());
                        enc_data.extend_from_slice(&enc_packet.encryption_key);
                    }
                    Packet::EditList(edit_packet) => {
                        enc_data.extend_from_slice(&edit_packet.packet_type.to_le_bytes());
                        enc_data.extend_from_slice(&edit_packet.num_length.to_le_bytes());
                        for edit in &edit_packet.edits {
                            enc_data.extend_from_slice(&edit.to_le_bytes());
                        }
                    }
                }
            }
            ChaCha20Poly1305::new(&Key::from(session_key))
                .encrypt(nonce.into(), enc_data.as_slice())
                .map_err(|e| Crypt4GHError::EncryptionError("encrypt chunk".to_string()))?;
            *self = &mut Self::Encrypted(enc_data[..enc_data.len() - 16].to_vec());
            Ok(enc_data[enc_data.len() - 16..]
                .try_into()
                .map_err(|_| Crypt4GHError::EncryptionError("packet mac".to_string()))?)
        } else {
            Err(Crypt4GHError::EncryptionError(
                "packet data is already encrypted".to_string(),
            ))
        };
    }

    pub fn packet_from_bytes(bytes: &[u8]) -> Result<Vec<Packet>, Crypt4GHError> {
        let mut cursor = Cursor::new(bytes);
        let mut packets = Vec::new();
        let mut found_edit = false;
        while cursor.position() < bytes.len() as u64 {
            let packet_type = cursor
                .read_u32::<LittleEndian>()
                .map_err(|_| Crypt4GHError::FromBytesError("packet type".to_string()))?;

            match packet_type {
                0 => {
                    let encryption_method = cursor.read_u32::<LittleEndian>().map_err(|_| {
                        Crypt4GHError::FromBytesError("encryption method".to_string())
                    })?;
                    if encryption_method != 0 {
                        return Err(Crypt4GHError::InvalidSpec(
                            "unsupported encryption method".to_string(),
                        ));
                    }
                    let mut encryption_key = [0; 32];
                    cursor
                        .read_exact(&mut encryption_key)
                        .map_err(|_| Crypt4GHError::FromBytesError("encryption key".to_string()))?;
                    packets.push(Packet::Encryption(EncryptionPacket {
                        packet_type,
                        encryption_method,
                        encryption_key,
                    }));
                }
                1 => {
                    if found_edit {
                        return Err(Crypt4GHError::InvalidSpec(
                            "multiple edit lists not allowed".to_string(),
                        ));
                    }
                    let num_length = cursor.read_u32::<LittleEndian>().map_err(|_| {
                        Crypt4GHError::FromBytesError("number of edits".to_string())
                    })?;
                    let mut edits = Vec::new();
                    for _ in 0..num_length {
                        edits.push(
                            cursor
                                .read_u64::<LittleEndian>()
                                .map_err(|_| Crypt4GHError::FromBytesError("edit".to_string()))?,
                        );
                    }
                    packets.push(Packet::EditList(EditListPacket {
                        packet_type,
                        num_length,
                        edits,
                    }));
                    found_edit = true;
                }
                _ => {
                    return Err(Crypt4GHError::FromBytesError(
                        "invalid packet type".to_string(),
                    ));
                }
            }
        }
        Ok(packets)
    }
}
