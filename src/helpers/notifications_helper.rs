use crate::transformer::Notifications;
use anyhow::anyhow;
use anyhow::Result;

pub fn parse_compressor_chunks(notes: Vec<Notifications>) -> Result<Vec<u8>> {
    // TODO: filter for the right order
    let mut results = Vec::new();

    for note in notes {
        match note {
            Notifications::Response(data) => {
                if data.recipient.starts_with("COMPRESSOR_CHUNKS") {
                    results.extend(data.info.ok_or(anyhow!("No chunks responded"))?)
                }
            }
            _ => continue,
        }
    }
    Ok(results)
}

pub fn parse_size_from_notifications(notes: Vec<Notifications>, id: usize) -> Result<u64> {
    let mut result = 0;
    for note in notes {
        match note {
            Notifications::Response(data) => {
                if data
                    .recipient
                    .starts_with(format!("SIZE_TAG_{}", id).as_str())
                {
                    result = u64::from_le_bytes(
                        data.info
                            .ok_or(anyhow!("No chunks responded"))?
                            .as_slice()
                            .try_into()?,
                    );
                }
            }
            _ => continue,
        }
    }
    Ok(result)
}
