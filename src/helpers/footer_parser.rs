use anyhow::anyhow;
use anyhow::Result;
use byteorder::LittleEndian;
use byteorder::ReadBytesExt;

pub struct FooterParser<'a> {
    footer: &'a [u8; 65536 * 2],
    blocklist: Vec<u8>,
    total: u32,
}

impl<'a> FooterParser<'a> {
    pub fn new(footer: &'a [u8; 65536 * 2]) -> Self {
        FooterParser {
            footer,
            blocklist: Vec::new(),
            total: 0,
        }
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
                    0 => {
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
                    0 => {
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
                        println!("War hier");
                        break;
                    }
                    a => {
                        println! {"{:x}", a};
                        self.blocklist.push(a)
                    }
                }
                x += 1;
            }
        }
        Ok(())
    }

    pub fn debug(&self) {
        dbg!(&self.blocklist);
        dbg!(&self.total);
    }
}
