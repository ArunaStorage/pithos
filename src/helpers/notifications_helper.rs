use crate::transformer::Notifications;

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
