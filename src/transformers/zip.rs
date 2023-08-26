use crate::helpers::write_adapter::WriteAdapter;
use crate::notifications::Message;
use crate::notifications::Response;
use crate::transformer::FileContext;
use crate::transformer::Transformer;
use crate::transformer::TransformerType;
use anyhow::bail;
use anyhow::Result;
use bytes::BufMut;
use bytes::BytesMut;
use std::io::Write;
use std::sync::Arc;
use std::sync::Mutex;
use zip::write::FileOptions;
use zip::ZipWriter;

pub struct ZipEnc {
    writer: zip::ZipWriter<WriteAdapter>,
    write_ref: Arc<Mutex<BytesMut>>,
    current_file: Option<(String, bool, FileOptions)>,
    finished: bool,
}

impl TryFrom<FileContext> for FileOptions {
    type Error = anyhow::Error;

    fn try_from(_: FileContext) -> Result<Self> {
        Ok(FileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .large_file(true))
    }
}

impl ZipEnc {
    pub fn new() -> ZipEnc {
        let write_adapter = WriteAdapter::new();
        let write_ref = write_adapter.get_data();

        ZipEnc {
            writer: ZipWriter::new(write_adapter),
            write_ref,
            current_file: None,
            finished: false,
        }
    }
}

impl Default for ZipEnc {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Transformer for ZipEnc {
    async fn process_bytes(
        &mut self,
        buf: &mut bytes::BytesMut,
        finished: bool,
        should_flush: bool,
    ) -> Result<bool> {
        if should_flush {
            self.writer.write_all(buf)?;
            self.writer.flush()?;
            buf.put(self.write_ref.lock().unwrap().split());
            return Ok(finished);
        }
        if let Some((name, is_dir, context)) = &self.current_file {
            if *is_dir {
                self.writer.add_directory(name.as_str(), *context)?;
            } else {
                self.writer.start_file(name.as_str(), *context)?;
            }
        }

        if !buf.is_empty() {
            self.writer.write_all(buf)?;
        }

        if finished && !self.finished {
            self.writer.finish()?;
            buf.put(self.write_ref.lock().unwrap().split());
            self.finished = true;
        }
        Ok(self.finished)
    }

    fn get_type(&self) -> TransformerType {
        TransformerType::ZipEncoder
    }

    async fn notify(&mut self, message: &Message) -> Result<Response> {
        if message.target == TransformerType::All {
            if let crate::notifications::MessageData::NextFile(nfile) = &message.data {
                if self.current_file.is_none() {
                    self.current_file = Some((
                        nfile.context.get_path(),
                        nfile.context.is_dir,
                        TryInto::<FileOptions>::try_into(nfile.context.clone())?,
                    ));
                } else {
                    bail!("[TAR] A Header is still present")
                }
                self.finished = false;
            }
        }

        Ok(Response::Ok)
    }
}
