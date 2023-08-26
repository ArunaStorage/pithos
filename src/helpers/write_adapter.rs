use bytes::{BufMut, BytesMut};
use std::{
    io::{Seek, SeekFrom, Write},
    sync::{Arc, Mutex},
};

pub struct WriteAdapter {
    pub data: Arc<Mutex<BytesMut>>,
    pub cursor_pos: u64,
}

impl WriteAdapter {
    pub fn new() -> WriteAdapter {
        WriteAdapter {
            data: Arc::new(Mutex::new(BytesMut::new())),
            cursor_pos: 0,
        }
    }

    pub fn get_data(&self) -> Arc<Mutex<BytesMut>> {
        self.data.clone()
    }
}

impl Write for WriteAdapter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut data = self.data.lock().unwrap();
        self.cursor_pos += buf.len() as u64;
        data.put(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Seek for WriteAdapter {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        match from {
            SeekFrom::Start(pos) => Ok(pos),
            SeekFrom::End(pos) => Ok((self.cursor_pos as i64 - pos) as u64),
            SeekFrom::Current(pos) => Ok((self.cursor_pos as i64 + pos) as u64),
        }
    }
}
