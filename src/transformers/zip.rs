use std::mem;

use crate::notifications::Message;
use crate::notifications::Response;
use crate::transformer::FileContext;
use crate::transformer::Transformer;
use crate::transformer::TransformerType;
use anyhow::bail;
use anyhow::Result;
use async_zip::base::write::EntryStreamWriter;
use async_zip::base::write::ZipFileWriter;
use async_zip::Compression;
use async_zip::ZipEntry;
use async_zip::ZipEntryBuilder;
use bytes::BufMut;
use futures::AsyncWriteExt;

pub struct ZipEnc<'a> {
    writer: &'a ZipFileWriter<Vec<u8>>,
    current_file: Option<EntryStreamWriter<'a, Vec<u8>>>,
    finished: bool,
}

impl From<FileContext> for ZipEntry {
    fn from(ctx: FileContext) -> Self {
        ZipEntryBuilder::new(ctx.file_name.into(), Compression::Deflate).build()
    }
}

impl<'a> ZipEnc<'a> {
    pub fn new(writer: &'a ZipFileWriter<Vec<u8>>) -> ZipEnc<'a> {
        ZipEnc {
            writer,
            current_file: None,
            finished: false,
        }
    }
}

#[async_trait::async_trait]
impl<'a> Transformer for ZipEnc<'a> {
    async fn process_bytes(
        &mut self,
        buf: &mut bytes::BytesMut,
        finished: bool,
        should_flush: bool,
    ) -> Result<bool> {
        if let Some(current_file) = &mut self.current_file {
            current_file.write_all(buf).await?;
            if finished && buf.is_empty() {
                current_file.close().await?;
                let data = self.writer.close().await?;
                buf.put(self.writer.close().await?.as_ref());
            }
            return Ok(finished);
        } else {
            return Err(anyhow::anyhow!("No current file"));
        }
    }

    fn get_type(&self) -> TransformerType {
        TransformerType::ZipEncoder
    }

    async fn notify(&mut self, message: &Message) -> Result<Response> {
        if message.target == TransformerType::All {
            if let crate::notifications::MessageData::NextFile(nfile) = &message.data {
                if self.current_file.is_none() {
                    let entry = ZipEntry::from(nfile.context.clone());
                    let new_stream = self.writer.write_entry_stream(entry).await?;
                    mem::replace(&mut self.current_file, Some(new_stream));
                } else {
                    bail!("[TAR] A Header is still present")
                }
                self.finished = false;
            }
        }

        Ok(Response::Ok)
    }
}
