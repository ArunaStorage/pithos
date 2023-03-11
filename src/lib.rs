use anyhow::Result;
use readwrite::ArunaReadWriter;
use tokio::fs::File;

mod compressor;
mod encrypt;
mod finalizer;
mod readwrite;
pub mod transformer;

pub async fn read_file() -> Result<()> {
    let file = File::open("test.txt").await?;
    let file2 = File::create("tst.cmp").await?;

    let mut rw = ArunaReadWriter::new(file, file2)
        .await
        .add_compressor()
        .await;
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
