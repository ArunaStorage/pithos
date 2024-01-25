use crate::structs::BlockList;
use crate::structs::EncryptionMetadata;
use crate::structs::EndOfFileMetadata;
use crate::structs::Flag;
use crate::structs::Keys as EncryptionKeys;
use crate::structs::SemanticMetadata;
use crate::structs::TableOfContents;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Result;
use byteorder::ByteOrder;
use byteorder::LittleEndian;
use bytes::Bytes;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use tracing::debug;
use tracing::error;

pub enum FooterParserState<'a> {
    Empty,
    Raw(&'a [u8]),
    Decoded(Box<Footer>),
}

pub struct FooterParser<'a> {
    state: FooterParserState<'a>,
    keys: Option<Keys>,
}

#[derive(Clone, Debug)]
pub enum EncryptionKeySet {
    None,
    Single([u8; 32]),
    Multiple(Vec<[u8; 32]>),
}

impl Into<Vec<[u8; 32]>> for EncryptionKeySet {
    fn into(self) -> Vec<[u8; 32]> {
        match self {
            EncryptionKeySet::None => vec![],
            EncryptionKeySet::Single(key) => vec![key],
            EncryptionKeySet::Multiple(keys) => keys,
        }
    }
}

#[derive(Debug)]
pub struct Keys {
    data_keys: EncryptionKeySet,
    recipient_keys: EncryptionKeySet,
    range_table_key: EncryptionKeySet,
    semantic_metadata: EncryptionKeySet,
}

impl Keys {
    pub fn add_data_keys(&mut self, mut keys: Vec<[u8; 32]>) {
        match (&mut self.data_keys, keys.len()) {
            (EncryptionKeySet::None, 1) => {
                self.data_keys = EncryptionKeySet::Single(keys[0]);
            }
            (EncryptionKeySet::None, _) => {
                self.data_keys = EncryptionKeySet::Multiple(keys);
            }
            (EncryptionKeySet::Single(key), _) => {
                keys.push(*key);
                self.data_keys = EncryptionKeySet::Multiple(keys);
            }
            (EncryptionKeySet::Multiple(current_keys), _) => {
                current_keys.extend(keys);
            }
        }
    }

    fn add_range_table_key(&mut self, key: [u8; 32]) -> Result<()> {
        match &self.range_table_key {
            EncryptionKeySet::None => {
                self.range_table_key = EncryptionKeySet::Single(key);
            }
            EncryptionKeySet::Single(_) => {
                return Err(anyhow!("Range table key already set"));
            }
            EncryptionKeySet::Multiple(_) => {
                return Err(anyhow!("Range table key already set"));
            }
        }
        Ok(())
    }

    fn add_semantic_metadata_key(&mut self, key: [u8; 32]) -> Result<()> {
        match &self.semantic_metadata {
            EncryptionKeySet::None => {
                self.semantic_metadata = EncryptionKeySet::Single(key);
            }
            EncryptionKeySet::Single(_) => {
                return Err(anyhow!("Semantic metadata key already set"));
            }
            EncryptionKeySet::Multiple(_) => {
                return Err(anyhow!("Semantic metadata key already set"));
            }
        }
        Ok(())
    }

    pub fn add_recepient(&mut self, key: [u8; 32]) {
        match &mut self.recipient_keys {
            EncryptionKeySet::None => {
                self.recipient_keys = EncryptionKeySet::Single(key);
            }
            EncryptionKeySet::Single(_) => {
                self.recipient_keys = EncryptionKeySet::Multiple(vec![key]);
            }
            EncryptionKeySet::Multiple(keys) => {
                keys.push(key);
            }
        }
    }
}

pub struct Footer {
    pub eof_metadata: EndOfFileMetadata,
    pub encryption_metadata: Option<EncryptionMetadata>,
    pub blocklist: Option<BlockList>,
    pub range_table: Option<TableOfContents>,
    pub semantic_metadata: Option<SemanticMetadata>,
}

#[derive(Eq, PartialEq, PartialOrd, Ord, Clone, Copy, Debug)]
pub struct Range {
    pub from: u64,
    pub to: u64,
}

impl FooterParser<'_> {
    #[tracing::instrument(level = "trace", skip(bytes))]
    pub fn new<'a>(bytes: &'a [u8]) -> FooterParser<'a> {
        FooterParser {
            state: FooterParserState::Raw(bytes),
            keys: None,
        }
    }

    #[tracing::instrument(level = "trace", skip(self, keys))]
    pub fn add_keys(&mut self, keys: Vec<[u8; 32]>) {
        if let Some(current_keys) = self.keys.as_mut() {
            current_keys.add_data_keys(keys);
        } else {
            self.keys = Some(Keys {
                data_keys: EncryptionKeySet::Multiple(keys),
                recipient_keys: EncryptionKeySet::None,
                range_table_key: EncryptionKeySet::None,
                semantic_metadata: EncryptionKeySet::None,
            });
        }
    }

    #[tracing::instrument(level = "trace", skip(self, key))]
    pub fn add_recipient_key(&mut self, key: [u8; 32]) {
        if let Some(current_keys) = self.keys.as_mut() {
            current_keys.add_recepient(key);
        } else {
            self.keys = Some(Keys {
                data_keys: EncryptionKeySet::None,
                recipient_keys: EncryptionKeySet::Single(key),
                range_table_key: EncryptionKeySet::None,
                semantic_metadata: EncryptionKeySet::None,
            });
        }
    }

    #[tracing::instrument(err, level = "trace", skip(self))]
    pub fn parse(&mut self) -> Result<()> {
        let eof_md = self.locate_and_parse_eof_md()?;
        let mut start_location = eof_md.eof_metadata_len;
        let encryption_metadata = if eof_md.is_flag_set(Flag::HasEncryptionMetadata) {
            Some(self.parse_encryption_metadata(
                start_location,
                eof_md.encryption_len.ok_or_else(|| {
                    anyhow!("Invalid format, flag set but no encryption md written")
                })?,
            )?)
        } else {
            None
        };
        start_location += eof_md.encryption_len.unwrap_or_default();
        let blocklist = if eof_md.is_flag_set(Flag::HasBlockList) {
            Some(self.parse_blocklist(start_location, eof_md.blocklist_len.unwrap_or_default())?)
        } else {
            None
        };
        start_location += eof_md.blocklist_len.unwrap_or_default();
        let range_table = if eof_md.is_flag_set(Flag::HasRangeTable) {
            let enc_key = if eof_md.is_flag_set(Flag::RangeTableEncrypted) {
                let encryption_key = match self
                    .keys
                    .as_ref()
                    .ok_or_else(|| anyhow!("Range table encrypted but no keys"))?
                    .range_table_key
                {
                    EncryptionKeySet::Single(key) => key,
                    _ => return Err(anyhow!("Range table encrypted but invalid keys")),
                };
                Some(encryption_key)
            } else {
                None
            };
            Some(self.parse_range_table(start_location, eof_md.range_table_len, enc_key)?)
        } else {
            None
        };
        start_location += eof_md.range_table_len;
        let semantic_metadata = if eof_md.is_flag_set(Flag::HasSemanticMetadata) {
            let enc_key = if eof_md.is_flag_set(Flag::SemanticMetadataEncrypted) {
                let encryption_keys = match self
                    .keys
                    .as_ref()
                    .ok_or_else(|| anyhow!("Semantic metadata encrypted but no keys"))?
                    .semantic_metadata
                {
                    EncryptionKeySet::Single(key) => vec![key],
                    EncryptionKeySet::None => self
                        .keys
                        .as_ref()
                        .ok_or_else(|| anyhow!("Semantic metadata encrypted but no keys"))?
                        .data_keys
                        .clone()
                        .into(),
                    EncryptionKeySet::Multiple(ref keys) => keys.clone(),
                    //_ => return Err(anyhow!("Semantic metadata encrypted but invalid keys")),
                };
                Some(encryption_keys)
            } else {
                None
            };
            Some(self.parse_semantic_metadata(
                start_location,
                eof_md.semantic_len.unwrap_or_default(),
                enc_key,
            )?)
        } else {
            None
        };

        self.state = FooterParserState::Decoded(Box::new(Footer {
            eof_metadata: eof_md,
            encryption_metadata,
            blocklist,
            range_table,
            semantic_metadata,
        }));

        Ok(())
    }

    fn locate_and_parse_eof_md(&mut self) -> Result<EndOfFileMetadata> {
        match self.state {
            FooterParserState::Raw(ref mut bytes) => {
                let eof_len = LittleEndian::read_u64(&bytes[bytes.len() - 8..]) as usize;
                let eof_md = EndOfFileMetadata::try_from(&bytes[bytes.len() - eof_len..])?;
                Ok(eof_md)
            }
            FooterParserState::Empty => Err(anyhow!("Empty footer")),
            FooterParserState::Decoded(_) => Err(anyhow!(
                "Footer already decoded, cannot locate end of file metadata"
            )),
        }
    }

    fn parse_semantic_metadata(
        &self,
        end_location: u64,
        len_semantic_metadata: u64,
        enc_key: Option<Vec<[u8; 32]>>,
    ) -> Result<SemanticMetadata> {
        match self.state {
            FooterParserState::Raw(bytes) => {
                let from = bytes.len() - end_location as usize - len_semantic_metadata as usize;
                let to = bytes.len() - end_location as usize;
                if bytes.len() < from {
                    return Err(anyhow!("Invalid format, not enough bytes"));
                }

                Ok(if let Some(keys) = enc_key {
                    debug!(keys = keys.len());
                    for key in keys {
                        let hex_key: String = key.iter().map(|b| format!("{:02x}", b)).collect();
                        debug!(?hex_key);

                        if let Ok(semantic) =
                            SemanticMetadata::from_encrypted(&bytes[from..to], key)
                        {
                            return Ok(semantic);
                        }
                    }
                    return Err(anyhow!("No valid key found"));
                } else {
                    SemanticMetadata::try_from(&bytes[from..to])?
                })
            }
            FooterParserState::Empty => Err(anyhow!("Empty footer")),
            FooterParserState::Decoded(_) => Err(anyhow!(
                "Footer already decoded, cannot locate end of file metadata"
            )),
        }
    }

    fn parse_range_table(
        &self,
        end_location: u64,
        len_range_table: u64,
        enc_key: Option<[u8; 32]>,
    ) -> Result<TableOfContents> {
        match self.state {
            FooterParserState::Raw(bytes) => {
                let from = bytes.len() - end_location as usize - len_range_table as usize;
                let to = bytes.len() - end_location as usize;
                if bytes.len() < from {
                    return Err(anyhow!("Invalid format, not enough bytes"));
                }

                Ok(if let Some(key) = enc_key {
                    TableOfContents::from_encrypted(&bytes[from..to], key)?
                } else {
                    TableOfContents::try_from(&bytes[from..to])?
                })
            }
            FooterParserState::Empty => Err(anyhow!("Empty footer")),
            FooterParserState::Decoded(_) => Err(anyhow!(
                "Footer already decoded, cannot locate end of file metadata"
            )),
        }
    }

    fn parse_blocklist(&self, end_location: u64, len_blocklist: u64) -> Result<BlockList> {
        match self.state {
            FooterParserState::Raw(bytes) => {
                let from = bytes.len() - end_location as usize - len_blocklist as usize;
                let to = bytes.len() - end_location as usize;
                if bytes.len() < from {
                    return Err(anyhow!("Invalid format, not enough bytes"));
                }
                let blocklist = BlockList::try_from(&bytes[from..to])?;
                Ok(blocklist)
            }
            FooterParserState::Empty => Err(anyhow!("Empty footer")),
            FooterParserState::Decoded(_) => Err(anyhow!(
                "Footer already decoded, cannot locate end of file metadata"
            )),
        }
    }

    fn parse_encryption_metadata(
        &mut self,
        len_eof: u64,
        len_enc: u64,
    ) -> Result<EncryptionMetadata> {
        match self.state {
            FooterParserState::Raw(ref mut bytes) => {
                let from = bytes.len() - len_enc as usize - len_eof as usize;
                let to = bytes.len() - len_eof as usize;
                if bytes.len() < from {
                    return Err(anyhow!("Invalid format, not enough bytes"));
                }
                let mut enc_md = EncryptionMetadata::try_from(&bytes[from..to]).unwrap();
                self.handle_encryption_metadata(&mut enc_md)?;
                debug!(?self.keys);
                Ok(enc_md)
            }
            FooterParserState::Empty => Err(anyhow!("Empty footer")),
            FooterParserState::Decoded(_) => Err(anyhow!(
                "Footer already decoded, cannot locate end of file metadata"
            )),
        }
    }

    fn handle_encryption_metadata(&mut self, md: &mut EncryptionMetadata) -> Result<()> {
        if let Some(current_keys) = self.keys.as_mut() {
            match &current_keys.recipient_keys {
                EncryptionKeySet::None => {}
                EncryptionKeySet::Single(key) => {
                    if let Err(e) = md.decrypt(*key) {
                        debug!(?e);
                    }
                }
                EncryptionKeySet::Multiple(keys) => {
                    for key in keys {
                        if let Err(e) = md.decrypt(*key) {
                            debug!(?e);
                        }
                    }
                }
            }
            debug!(packets = md.packets.len());
            for x in &md.packets {
                debug!(?x.keys);
                match x.keys {
                    EncryptionKeys::Decrypted(_) => match x.extract_keys_with_flags()? {
                        (None, None, vec) => {
                            current_keys.add_data_keys(vec);
                        }
                        (Some(range), None, vec) => {
                            current_keys.add_range_table_key(range)?;
                            current_keys.add_data_keys(vec);
                        }
                        (None, Some(semantic), vec) => {
                            current_keys.add_semantic_metadata_key(semantic)?;
                            current_keys.add_data_keys(vec);
                        }
                        (Some(range), Some(semantic), vec) => {
                            current_keys.add_range_table_key(range)?;
                            current_keys.add_semantic_metadata_key(semantic)?;
                            current_keys.add_data_keys(vec);
                        }
                    },
                    _ => continue,
                }
            }
        }
        Ok(())
    }

    pub fn get_eof_metadata(&self) -> Result<EndOfFileMetadata> {
        match self.state {
            FooterParserState::Empty => bail!("Footer is empty"),
            FooterParserState::Raw(_) => bail!("Footer has not yet been parsed"),
            FooterParserState::Decoded(ref footer) => Ok(footer.eof_metadata.clone()),
        }
    }

    pub fn get_semantic_metadata(&self) -> Result<SemanticMetadata> {
        match &self.state {
            FooterParserState::Empty => bail!("Footer is empty"),
            FooterParserState::Raw(_) => bail!("Footer not  "),
            FooterParserState::Decoded(footer) => {
                debug!(?footer.semantic_metadata);
                Ok(footer
                    .semantic_metadata
                    .as_ref()
                    .ok_or_else(|| anyhow!("File does not contain semantic metadata"))?
                    .clone())
            }
        }
    }

    // #[tracing::instrument(level = "trace", skip(self, range))]
    // pub fn get_offsets_by_range(&self, range: Range) -> Result<(Range, Range)> {
    //     let from_chunk = range.from / 5_242_880;
    //     let to_chunk = range.to / 5_242_880;

    //     let mut from_block: u64 = 0;
    //     let mut to_block: u64 = 0;

    //     if from_chunk > to_chunk {
    //         error!(
    //             from_chunk = from_chunk,
    //             to_chunk = to_chunk,
    //             "From must be smaller than to"
    //         );
    //         return Err(anyhow!("From must be smaller than to"));
    //     }

    //     // 0 - 1 - [2 - 3] - 4
    //     // Want 2, 3

    //     for (index, block) in self.blocklist.iter().enumerate() {
    //         if (index as u64) < from_chunk {
    //             from_block += *block as u64;
    //         }
    //         if index as u64 <= to_chunk {
    //             to_block += *block as u64;
    //         } else {
    //             break;
    //         }
    //     }

    //     Ok((
    //         if self.is_encrypted {
    //             Range {
    //                 from: from_block * (65536 + 28),
    //                 to: to_block * (65536 + 28),
    //             }
    //         } else {
    //             Range {
    //                 from: from_block * 65536,
    //                 to: to_block * 65536,
    //             }
    //         },
    //         Range {
    //             from: range.from % 5_242_880,
    //             to: range.to % 5_242_880 + (to_chunk - from_chunk) * 5_242_880,
    //         },
    //     ))
    // }
}

#[tracing::instrument(level = "trace", skip(chunk, decryption_key))]
pub fn decrypt_chunks(chunk: &[u8; (65536 + 28) * 2], decryption_key: &[u8]) -> Result<Bytes> {
    let first = &chunk[0..65536 + 28];
    let second = &chunk[65536 + 28..];

    let (first_nonce_slice, first_data) = first.split_at(12);
    let (second_nonce_slice, second_data) = second.split_at(12);

    let decryptor = ChaCha20Poly1305::new_from_slice(decryption_key).map_err(|e| {
        error!(error = ?e, "Unable to initialize decryptor");
        anyhow!("[FOOTER_PARSER] Unable to initialize decryptor")
    })?;

    let mut first_dec = decryptor
        .decrypt(first_nonce_slice.into(), first_data)
        .unwrap_or(vec![]);

    first_dec.extend(
        decryptor
            .decrypt(second_nonce_slice.into(), second_data)
            .map_err(|e| {
                //error!(error = ?e, data = ?second_data, nonce = ?second_nonce_slice, "Unable to decrypt footer part 2");
                error!(error = ?e, "Unable to decrypt footer part 2");
                anyhow!("[FOOTER_PARSER] unable to decrypt part 2")
            })?,
    );
    Ok(first_dec.into())
}
