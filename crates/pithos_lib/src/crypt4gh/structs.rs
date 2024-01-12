use std::io::{Cursor, Read};
use byteorder::{LittleEndian, ReadBytesExt};
use crate::crypt4gh::error::Crypt4GHError;

const CRYPT4GH_HEADER_MAGIC: [u8; 8] = [0x63, 0x72, 0x79, 0x70, 0x74, 0x34, 0x67, 0x68]; // "crypt4gh"
const CRYPT4GH_HEADER_VERSION: u32 = 1;

#[repr(C)]
struct Crypt4GHHeader {
    magic: [u8; 8],   // Magic string to identify Crypt4GH format
    version: u32,     // Version of the format currently le 1
    header_size: u32, // Size of the encrypted header
    header_packets: Vec<HeaderPacket>,
}

#[repr(C)]
struct HeaderPacket {
    length: u32,                                // Length of the packet
    encryption_method: u32,                     // Currently only 0 (Chacha20-Poly1305)
    writers_pubkey: [u8; 32],                   // Writer's public key
    nonce: [u8; 12],                            // Nonce for encryption
    encrypted_packet_data: EncryptedPacketData, // Encryption or editlist packet
    mac: [u8; 16],                              // Message Authentication Code (MAC)
}

pub enum EncryptedPacketData {
    Encrypted(Vec<u8>),
    Decrypted(Vec<Packet>),
}

pub enum Packet {
    Encryption(EncryptionPacket),
    EditList(EditListPacket),
}

#[repr(C)]
pub struct EncryptionPacket {
    packet_type: u32,           // 0 (Encryption)
    encryption_method: u32,     // 0 (Chacha20-Poly1305)
    encryption_key: [u8; 32],   // 32 bytes encryption key
}

#[repr(C)]
pub struct EditListPacket {
    packet_type: u32, // 1
    num_length: u32, // Number of edits
    edits: Vec<u64>, // List of edits
}

impl TryFrom<&[u8]> for Crypt4GHHeader {
    type Error = Crypt4GHError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let mut header = Crypt4GHHeader {
            magic: [0; 8],
            version: 0,
            header_size: 0,
            header_packets: Vec::new(),
        };
        let mut cursor = Cursor::new(bytes);
        cursor.read_exact(&mut header.magic).map_err(|_| Crypt4GHError::FromBytesError("magic bytes".to_string()))?;
        if header.magic != CRYPT4GH_HEADER_MAGIC {
            return Err(Crypt4GHError::InvalidSpec("magic bytes".to_string()));
        }
        header.version = cursor.read_u32::<LittleEndian>().map_err(|_| Crypt4GHError::FromBytesError("version".to_string()))?;
        if header.version != CRYPT4GH_HEADER_VERSION {
            return Err(Crypt4GHError::InvalidSpec("version".to_string()));
        }
        header.header_size = cursor.read_u32::<LittleEndian>().map_err(|_| Crypt4GHError::FromBytesError("header size".to_string()))?;
        while cursor.position() < header.header_size as u64 {
            let mut packet = HeaderPacket {
                length: 0,
                encryption_method: 0,
                writers_pubkey: [0; 32],
                nonce: [0; 12],
                encrypted_packet_data: Vec::new(),
                mac: [0; 16],
            };
            packet.length = cursor.read_u32::<LittleEndian>().map_err(|_| Crypt4GHError::FromBytesError("packet length".to_string()))?;;
            packet.encryption_method = cursor.read_u32::<LittleEndian>().map_err(|_| Crypt4GHError::FromBytesError("encryption method".to_string()))?;
            if packet.encryption_method != 0 {
                return Err(Crypt4GHError::InvalidSpec(format!("packet encryption method expected: 0, got: {}", packet.encryption_method)));
            }
            cursor.read_exact(&mut packet.writers_pubkey).map_err(|_| Crypt4GHError::FromBytesError("writer's public key".to_string()))?;
            cursor.read_exact(&mut packet.nonce).map_err(|_| Crypt4GHError::FromBytesError("nonce".to_string()))?;
            let mut encrypted_packet_data = vec![0; packet.length as usize];
            cursor.read_exact(&mut encrypted_packet_data).unwrap();
            packet.encrypted_packet_data = encrypted_packet_data;
            cursor.read_exact(&mut packet.mac).unwrap();
            header.header_packets.push(packet);
        }
        header
    }
}