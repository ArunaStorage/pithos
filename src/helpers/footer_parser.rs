use anyhow::anyhow;
use anyhow::Result;
use byteorder::LittleEndian;
use byteorder::ReadBytesExt;
use bytes::Bytes;
use sodiumoxide::crypto::aead::chacha20poly1305_ietf;
use sodiumoxide::crypto::aead::chacha20poly1305_ietf::Key;
use sodiumoxide::crypto::aead::chacha20poly1305_ietf::Nonce;

pub struct FooterParser {
    footer: [u8; 65536 * 2],
    blocklist: Vec<u8>,
    total: u32,
    is_encrypted: bool,
}

#[derive(Eq, PartialEq, PartialOrd, Ord, Clone, Copy, Debug)]
pub struct Range {
    pub from: u64,
    pub to: u64,
}

impl FooterParser {
    pub fn new(footer: &[u8; 65536 * 2]) -> Self {
        FooterParser {
            footer: footer.clone(),
            blocklist: Vec::new(),
            total: 0,
            is_encrypted: false,
        }
    }

    pub fn from_encrypted(
        encrypted_footer: &[u8; (65536 + 28) * 2],
        decryption_key: &[u8],
    ) -> Result<Self> {
        Ok(FooterParser {
            footer: decrypt_chunks(encrypted_footer, decryption_key)?
                .iter()
                .as_slice()
                .try_into()?,
            blocklist: Vec::new(),
            total: 0,
            is_encrypted: true,
        })
    }

    pub fn parse(&mut self) -> Result<()> {
        let mut x = 0;
        if self.footer[0..4] == *hex::decode(format!("522A4D18"))?.as_slice() {
            if self.footer[4..8].as_ref().read_u32::<LittleEndian>()? != 65536 - 8 {
                return Err(anyhow!("Unexpected skippable framesize"));
            };
            self.total = self.footer[8..12].as_ref().read_u32::<LittleEndian>()?;

            while x < 65536 {
                match self.footer[12 + x] {
                    0u8 => {
                        break;
                    }
                    a => self.blocklist.push(a),
                }
            }
            x = 0;

            if self.footer[65536 + 4..65536 + 8]
                .as_ref()
                .read_u32::<LittleEndian>()?
                != 65536 - 8
            {
                return Err(anyhow!("Unexpected skippable framesize"));
            };

            while x < self.footer.len() {
                match self.footer[65536 + x + 12] {
                    0u8 => {
                        break;
                    }
                    a => self.blocklist.push(a),
                }
                x += 1;
            }

            // This is a double_footer
        } else {
            if self.footer[65536..65540] != *hex::decode(format!("512A4D18"))?.as_slice() {
                return Err(anyhow!(
                    "Unexpected slice, does not start with magic number 512A4D18"
                ));
            }
            if self.footer[65536 + 4..65536 + 8]
                .as_ref()
                .read_u32::<LittleEndian>()?
                != 65536 - 8
            {
                dbg!(self.footer[65536 + 4..65536 + 8]
                    .as_ref()
                    .read_u32::<LittleEndian>()?);
                return Err(anyhow!("Unexpected skippable framesize"));
            };

            self.total = self.footer[65536 + 8..65536 + 12]
                .as_ref()
                .read_u32::<LittleEndian>()?;

            while x < self.footer.len() {
                match self.footer[65536 + x + 12] {
                    0u8 => {
                        break;
                    }
                    a => self.blocklist.push(a),
                }
                x += 1;
            }
        }
        Ok(())
    }

    pub fn get_offsets_by_range(&self, range: Range) -> Result<(Range, Range)> {
        let from_chunk = range.from / 5_242_880;
        let to_chunk = range.to / 5_242_880;

        let mut from_block: u64 = 0;
        let mut to_block: u64 = 0;

        if from_chunk > to_chunk {
            return Err(anyhow!("From must be smaller than to"));
        }

        // 0 - 1 - [2 - 3] - 4
        // Want 2, 3

        for (index, block) in self.blocklist.iter().enumerate() {
            if (index as u64) < from_chunk {
                from_block += *block as u64;
            }
            if index as u64 <= to_chunk {
                to_block += *block as u64;
            } else {
                break;
            }
        }

        Ok((
            if self.is_encrypted {
                Range {
                    from: from_block * (65536 + 28),
                    to: to_block * (65536 + 28),
                }
            } else {
                Range {
                    from: from_block * 65536,
                    to: to_block * 65536,
                }
            },
            Range {
                from: range.from % 5_242_880,
                to: range.to % 5_242_880 + (to_chunk - from_chunk) * 5_242_880,
            },
        ))
    }

    pub fn debug(&self) {
        dbg!(&self.blocklist);
        dbg!(&self.total);
    }
}

pub fn decrypt_chunks(chunk: &[u8; (65536 + 28) * 2], decryption_key: &[u8]) -> Result<Bytes> {
    let key = Key::from_slice(decryption_key).ok_or(anyhow!("unable to parse decryption key"))?;

    let first = &chunk[0..65536 + 28];
    let second = &chunk[65536 + 28..];

    let (first_nonce_slice, first_data) = first.split_at(12);
    let (second_nonce_slice, second_data) = second.split_at(12);
    let first_nonce =
        Nonce::from_slice(first_nonce_slice).ok_or(anyhow!("unable to read nonce"))?;
    let second_nonce =
        Nonce::from_slice(second_nonce_slice).ok_or(anyhow!("unable to read nonce"))?;

    let mut first_dec = chacha20poly1305_ietf::open(first_data, None, &first_nonce, &key)
        .map_err(|_| anyhow!("unable to decrypt part"))?;
    first_dec.extend(
        chacha20poly1305_ietf::open(second_data, None, &second_nonce, &key)
            .map_err(|_| anyhow!("unable to decrypt part"))?,
    );
    Ok(first_dec.into())
}
