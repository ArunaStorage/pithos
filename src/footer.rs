use anyhow::anyhow;
use anyhow::Result;
use async_compression::tokio::write::ZstdEncoder;
use byteorder::LittleEndian;
use byteorder::WriteBytesExt;
use bytes::{Bytes, BytesMut};
use tokio::io::AsyncWriteExt;

use crate::transformer::AddTransformer;
use crate::transformer::Notifications;
use crate::transformer::Transformer;

pub struct FooterGenerator<'a> {
    finished: bool,
    external_info: Option<&'a [u8]>,
    next: Option<Box<dyn Transformer + Send + 'a>>,
}

impl<'a> FooterGenerator<'a> {
    #[allow(dead_code)]
    pub fn new(external_info: Option<&'a [u8]>) -> FooterGenerator<'a> {
        FooterGenerator {
            finished: false,
            external_info,
            next: None,
        }
    }
}

impl<'a> AddTransformer<'a> for FooterGenerator<'a> {
    fn add_transformer(&mut self, t: Box<dyn Transformer + Send + 'a>) {
        self.next = Some(t)
    }
}

#[async_trait::async_trait]
impl Transformer for FooterGenerator<'_> {
    async fn process_bytes(&mut self, buf: &mut bytes::Bytes, finished: bool) -> Result<bool> {
        if buf.len() != 0 && !self.finished && finished {}

        if let Some(next) = &mut self.next {
            next.process_bytes(buf, self.finished && buf.len() == 0 && finished)
                .await
        } else {
            Err(anyhow!(
                "This footer generator is designed to always contain a 'next'"
            ))
        }
    }
    async fn notify(&mut self, notes: &mut Vec<Notifications>) -> Result<()> {
        if let Some(next) = &mut self.next {
            next.notify(notes).await?
        }
        Ok(())
    }
}

fn create_skippable_footer_frame(footer_list: &[u8]) -> Result<Bytes> {
    // Add frame_header
    let mut frame = hex::decode("502A4D18")?;
    // 4 Bytes (little-endian) for size
    WriteBytesExt::write_u32::<LittleEndian>(&mut frame, size as u32 - 8)?;
    frame.extend(vec![0; size - 8]);
    Ok(Bytes::from(frame))
}
