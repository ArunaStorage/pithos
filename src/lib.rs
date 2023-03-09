use anyhow::Result;
use readwrite::ArunaReadWriter;
use tokio::fs::File;

mod compressor;
mod encrypt;
mod readwrite;
pub mod transformer;

pub async fn read_file() -> Result<()> {
    let file = File::open("test.txt").await?;

    let testvec = Vec::with_capacity(1000);

    let mut rw = ArunaReadWriter::new(file, testvec).await;

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
