use anyhow::Result;
use readwrite::ArunaReadWriter;
use tokio::fs::File;

mod compressor;
mod encrypt;
mod readwrite;
pub mod transformer;

pub async fn read_file() -> Result<()> {
    let file = File::open("hg381").await?;
    let file2 = File::create("hg381.zstd").await?;

    let mut rw = ArunaReadWriter::new(file, file2).await;
    rw.process().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_with_file() {
        read_file().await.unwrap();
    }
}
