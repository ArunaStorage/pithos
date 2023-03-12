pub mod compressor;
pub mod decompressor;
pub mod decrypt;
pub mod encrypt;
mod finalizer;
pub mod footer;
pub mod helpers;
pub mod readwrite;
pub mod transformer;

#[cfg(test)]
mod tests {
    use crate::compressor::ZstdEnc;
    use crate::decompressor::ZstdDec;
    use crate::decrypt::ChaCha20Dec;
    use crate::encrypt::ChaCha20Enc;
    use crate::footer::FooterGenerator;
    use crate::helpers::footer_parser::FooterParser;
    use crate::readwrite::ArunaReadWriter;
    use tokio::fs::File;
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    #[tokio::test]
    async fn test_with_file() {
        let file = File::open("test.txt").await.unwrap();
        let file2 = File::create("test.txt.out").await.unwrap();

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

    #[tokio::test]
    async fn test_with_vec() {
        let file = b"This is a very very important test".to_vec();
        let mut file2 = Vec::new();

        // Create a new ArunaReadWriter
        // Add transformer in reverse order -> from "last" to first
        // input -> 1 -> 2 -> 3 -> output
        // .add(3).add(2).add(1)println!("{}", self.internal_buf.len());
        ArunaReadWriter::new(file.as_ref(), &mut file2)
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
            .unwrap();

        assert_eq!(file, file2)
    }

    #[tokio::test]
    async fn test_with_file_footer() {
        let file = File::open("test.txt").await.unwrap();
        let file2 = File::create("test.txt.out").await.unwrap();
        ArunaReadWriter::new(file, file2)
            //.add_transformer(ZstdDec::new()) // Double compression because we can
            .add_transformer(
                ChaCha20Dec::new(b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(
                ChaCha20Enc::new(false, b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(FooterGenerator::new(None, true))
            .add_transformer(ZstdEnc::new(1, false))
            .process()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_footer_parsing() {
        let mut file2 = File::open("test.txt.out").await.unwrap();

        file2
            .seek(std::io::SeekFrom::End(-65536 * 2))
            .await
            .unwrap();

        let buf: &mut [u8; 65536 * 2] = &mut [0; 65536 * 2];
        file2.read_exact(buf).await.unwrap();

        let mut fp = FooterParser::new(buf);

        fp.parse().unwrap();
        fp.debug();
    }
}
