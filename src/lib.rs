mod compressor;
mod decompressor;
mod decrypt;
mod encrypt;
mod finalizer;
pub mod readwrite;
pub mod transformer;

#[cfg(test)]
mod tests {
    use crate::compressor::ZstdEnc;
    use crate::decompressor::ZstdDec;
    use crate::decrypt::ChaCha20Dec;
    use crate::encrypt::ChaCha20Enc;
    use crate::readwrite::ArunaReadWriter;
    use tokio::fs::File;

    #[tokio::test]
    async fn test_with_file() {
        let file = File::open("test.txt").await.unwrap();
        let file2 = File::create("tst.cmp").await.unwrap();

        // Create a new ArunaReadWriter
        // Add transformer in reverse order -> from "last" to first
        // input -> 1 -> 2 -> 3 -> output
        // .add(3).add(2).add(1)println!("{}", self.internal_buf.len());
        ArunaReadWriter::new(file, file2)
            .add_transformer(ZstdDec::new()) // Double compression because we can
            .add_transformer(ZstdDec::new()) // Double compression because we can
            .add_transformer(
                ChaCha20Dec::new(b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(
                ChaCha20Dec::new(b"99wj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(
                ChaCha20Enc::new(false, b"99wj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(
                ChaCha20Enc::new(false, b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            ) // Tripple compression because we can
            .add_transformer(ZstdEnc::new(2, false)) // Double compression because we can
            .add_transformer(ZstdEnc::new(1, false))
            .process()
            .await
            .unwrap()
    }
}
