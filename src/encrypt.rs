use anyhow::anyhow;
use anyhow::Result;
use byteorder::LittleEndian;
use byteorder::WriteBytesExt;
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use sodiumoxide::crypto::aead::chacha20poly1305_ietf;
use sodiumoxide::crypto::aead::chacha20poly1305_ietf::Key;
use sodiumoxide::crypto::aead::chacha20poly1305_ietf::Nonce;

const ENCRYPTION_BLOCK_SIZE: usize = 65_536;
const CIPHER_DIFF: usize = 28;
const CIPHER_SEGMENT_SIZE: usize = ENCRYPTION_BLOCK_SIZE + CIPHER_DIFF;

pub fn calculate_padding(size: usize) -> usize {
    let remainder = size % ENCRYPTION_BLOCK_SIZE;

    if remainder == 0 {
        0
    } else {
        // The minimum padding size is 8 bytes, so if the remainder plus minimum padding is larger than the blocksize
        // -> Add a full 64kB block
        // else return the missing bytes to the next "full" block
        if remainder + 8 > ENCRYPTION_BLOCK_SIZE {
            (ENCRYPTION_BLOCK_SIZE - remainder) + ENCRYPTION_BLOCK_SIZE
        } else {
            ENCRYPTION_BLOCK_SIZE - remainder
        }
    }
}

pub fn create_skippable_padding_frame(size: usize) -> Result<Vec<u8>> {
    if size < 8 {
        return Err(anyhow!("{size} is too small, minimum is 8 bytes"));
    }
    // Add frame_header
    let mut frame = hex::decode("502A4D18")?;
    // 4 Bytes (little-endian) for size
    frame.write_u32::<LittleEndian>(size as u32 - 8)?;
    frame.extend(vec![0; size - 8]);
    Ok(frame)
}

pub fn create_skippable_footer_frame(numbers: Vec<u8>) -> Result<Vec<u8>> {
    // Add frame_header
    let mut frame = hex::decode("502A4D18")?;
    // 4 Bytes (little-endian) for size
    frame.write_u32::<LittleEndian>(0 as u32 - 8)?;
    frame.extend(vec![0; 0 - 8]);
    Ok(frame)
}

pub fn decrypt_chunk(chunk: &[u8], decryption_key: &Key) -> Result<Bytes> {
    let (nonce_slice, data) = chunk.split_at(12);
    let nonce = Nonce::from_slice(nonce_slice).ok_or(anyhow!("unable to read nonce"))?;

    Ok(
        chacha20poly1305_ietf::open(data, None, &nonce, decryption_key)
            .map_err(|_| anyhow!("unable to decrypt part"))?
            .into(),
    )
}

pub fn encrypt_chunk(chunk: &[u8], encryption_key: &Key) -> Result<Bytes> {
    let nonce = Nonce::from_slice(&sodiumoxide::randombytes::randombytes(12))
        .ok_or(anyhow!("Unable to create nonce"))?;
    let mut bytes = BytesMut::new();
    bytes.put(nonce.0.as_ref());
    bytes.put(chacha20poly1305_ietf::seal(chunk, None, &nonce, encryption_key).as_ref());
    Ok(bytes.freeze())
}
