use crate::notifications;
use crate::notifications::Message;
use crate::transformer::Transformer;
use anyhow::anyhow;
use anyhow::Result;
use byteorder::LittleEndian;
use byteorder::WriteBytesExt;
use bytes::BufMut;
use bytes::{Bytes, BytesMut};

pub struct FooterGenerator<'a> {
    finished: bool,
    external_info: BytesMut,
    notifications: Option<bool>,
}

impl<'a> FooterGenerator<'a> {
    #[allow(dead_code)]
    pub fn new(external_info: Option<Vec<u8>>, should_be_notified: bool) -> FooterGenerator<'a> {
        FooterGenerator {
            finished: false,
            external_info: match external_info {
                Some(i) => i.as_slice().into(),
                _ => BytesMut::new(),
            },
            notifications: match should_be_notified {
                true => Some(false),
                _ => None,
            },
        }
    }
}

#[async_trait::async_trait]
impl Transformer for FooterGenerator<'_> {
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut, finished: bool) -> Result<bool> {
        if buf.is_empty() && !self.finished && finished {
            if let Some(a) = self.notifications {
                if !a {
                    return Err(anyhow!("Missing notifications"));
                }
            }
            buf.put(create_skippable_footer_frame(self.external_info.to_vec())?);
            self.finished = true;
        }
        Ok(self.finished)
    }
    async fn notify(&mut self, message: Message) -> Result<()> {
        match message {
            notifications::Message::Footer(d) => {},
            notifications::Message::NextFile(_) => {self.finished = false}
            _ => return Err(()),
        }
        Ok(())
    }
}

fn create_skippable_footer_frame(mut footer_list: Vec<u8>) -> Result<Bytes> {
    // 65_536 framesize minus 12 bytes for header
    // 1. Magic bytes (4)
    // 2. Size (4) -> The number 65536 - 8 bytes for needed skippable frame header
    // 3. BlockTotal -> footer_list.len() + frames
    // Up to 65_536 - 12 footer entries for one frame
    let total: u32 = footer_list.iter().map(|e| *e as u32).sum();

    let frames = if footer_list.len() < (65_536 - 12) {
        1
    } else {
        2
    };
    // Create a frame_header
    let mut frame = hex::decode(format!("5{frames}2A4D18"))?;

    if frames == 1 {
        let target_size = 65_536 - footer_list.len() - 12;
        //
        WriteBytesExt::write_u32::<LittleEndian>(&mut frame, 65_536 - 8)?;
        WriteBytesExt::write_u32::<LittleEndian>(&mut frame, total + frames)?;

        if let Some(e) = footer_list.last_mut() {
            *e += 1
        };
        for size in footer_list {
            WriteBytesExt::write_u8(&mut frame, size)?;
            assert!(size < 84)
        }
        frame.extend(vec![0; target_size]);
        assert!(frame.len() == 65_536);
        Ok(Bytes::from(frame))
    } else {
        // Magic frame "size"
        WriteBytesExt::write_u32::<LittleEndian>(&mut frame, 65_536 - 8)?;
        // Footerlist count
        WriteBytesExt::write_u32::<LittleEndian>(&mut frame, total + frames)?;

        if let Some(e) = footer_list.last_mut() {
            *e += 2
        };
        // Blocklist
        for size in &footer_list[..(65_536 - 12)] {
            WriteBytesExt::write_u8(&mut frame, *size)?;
            assert!(*size < 84)
        }
        assert!(frame.len() == 65_536);
        // Repeat the header
        frame.put(hex::decode(format!("5{frames}2A4D18"))?.as_slice());
        // Magic frame "size"
        WriteBytesExt::write_u32::<LittleEndian>(&mut frame, 65_536 - 8)?;
        // Repeat footerlist count
        WriteBytesExt::write_u32::<LittleEndian>(&mut frame, total + frames)?;

        // Write the whole footerlist
        for size in &footer_list[(65_536 - 12)..] {
            WriteBytesExt::write_u8(&mut frame, *size)?;
            assert!(*size < 84)
        }

        let target_size = footer_list.len() - 12 - 65_536;

        frame.extend(vec![0; target_size]);
        assert!(frame.len() == 65_536 * 2);
        Ok(Bytes::from(frame))
    }
}
