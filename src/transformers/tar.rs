use anyhow::anyhow;
use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;
use tar::Header;
use crate::notifications::Notifications;
use crate::transformer::AddTransformer;
use crate::transformer::Transformer;

pub struct TarEnc<'a> {
    current_header: Option<Header>,
    next_header: Option<Header>,
    file_size: u64,
    size_counter: u64,
    finished: bool,
    next: Option<Box<dyn Transformer + Send + 'a>>,
}



#[derive(Serialize, Deserialize)]
pub struct TarFileInfo {
    path: String,
    size: u64,
}

impl TryFrom<TarFileInfo> for Header {
    type Error = anyhow::Error;

    fn try_from(value: TarFileInfo) -> Result<Self> {
        let mut header = Header::new_ustar();
        header.set_path(value.path)?;
        header.set_size(value.size);
        header.set_cksum();
        Ok(header)
    }
}

impl<'a> TarEnc<'a> {
    pub fn new() -> Result<TarEnc<'a>> {
        Ok(TarEnc {
            current_header: None,
            next_header: None,
            file_size: 0,
            size_counter: 0,
            finished: false,
            next: None,
        })
    }
}

impl<'a> AddTransformer<'a> for TarEnc<'a> {
    fn add_transformer(&mut self, t: Box<dyn Transformer + Send + 'a>) {
        self.next = Some(t)
    }
}

#[async_trait::async_trait]
impl Transformer for TarEnc<'_> {
    async fn process_bytes(&mut self, buf: &mut bytes::Bytes, finished: bool) -> Result<bool> {
        // This is forbidden! A tar transformer needs all information to build a header before data is received.
        if buf.len() != 0 && self.current_header.is_none() {
            return Err(anyhow!(
                "A tar transformer needs all information to build an header before data is received."
            ));
        }

        self.size_counter += buf.len() as u64;
        // Try to write the buf to the "next" in the chain, even if the buf is empty
        if let Some(next) = &mut self.next {
            // Should be called even if bytes.len() == 0 to drive underlying Transformer to completion
            next.process_bytes(
                buf,
                self.finished && buf.is_empty() && finished,
            )
            .await
        } else {
            Err(anyhow!(
                "This tar transformer is designed to always contain a 'next'"
            ))
        }
    }
    async fn notify(&mut self, notes: &mut Vec<Notifications>) -> Result<()> {
        if let Some(next) = &mut self.next {

            let index = notes.iter().position(|x| x.get_recipient() == "TAR_ENC_FILEINFO");
            match index {
                Some(i) => {
                    let note = notes.remove(i);
                    let data = note.get_data();
                    if let Some(info) = data.info {
                        let finfo: TarFileInfo = serde_json::from_slice(&info)?;
                        if self.current_header.is_none() {
                            self.file_size = finfo.size;
                            self.current_header = Some(finfo.try_into()?);
                            self.next_header = None;
                        }else{
                            self.next_header = Some(finfo.try_into()?);
                        }
                    }

                },
                None => {}
            }
            next.notify(notes).await?
        }
        Ok(())
    }
}