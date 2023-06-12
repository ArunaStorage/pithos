pub mod helpers;
pub mod notifications;
pub mod readwrite;
pub mod streamreadwrite;
pub mod transformer;
pub mod transformers;

#[cfg(test)]
mod tests {
    use crate::helpers::footer_parser::{FooterParser, Range};
    use crate::readwrite::ArunaReadWriter;
    use crate::streamreadwrite::ArunaStreamReadWriter;
    use crate::transformer::ReadWriter;
    use crate::transformers::compressor::ZstdEnc;
    use crate::transformers::decompressor::ZstdDec;
    use crate::transformers::decrypt::ChaCha20Dec;
    use crate::transformers::encrypt::ChaCha20Enc;
    use crate::transformers::filter::Filter;
    use crate::transformers::footer::FooterGenerator;
    use bytes::Bytes;
    use tokio::fs::File;
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    #[tokio::test]
    async fn test_with_file() {
        let file = File::open("test.txt").await.unwrap();
        let file2 = File::create("test.txt.out.1").await.unwrap();

        // Create a new ArunaReadWriter
        // Add transformer in reverse order -> from "last" to first
        // input -> 1 -> 2 -> 3 -> output
        // .add(3).add(2).add(1)println!("{}", self.internal_buf.len());
        ArunaReadWriter::new_with_writer(file, file2)
            .add_transformer(ZstdEnc::new(1, false))
            .add_transformer(ZstdEnc::new(2, false)) // Double compression because we can
            .add_transformer(
                ChaCha20Enc::new(false, b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(
                ChaCha20Enc::new(false, b"99wj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(
                ChaCha20Dec::new(b"99wj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(
                ChaCha20Dec::new(b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(ZstdDec::new()) // Double compression because we can
            .add_transformer(ZstdDec::new()) // Double compression because we can
            .process()
            .await
            .unwrap();

        let mut file = File::open("test.txt").await.unwrap();
        let mut file2 = File::open("test.txt.out.1").await.unwrap();
        let mut buf1 = String::new();
        let mut buf2 = String::new();
        file.read_to_string(&mut buf1).await.unwrap();
        file2.read_to_string(&mut buf2).await.unwrap();
        assert!(buf1 == buf2)
    }

    #[tokio::test]
    async fn test_with_vec() {
        let file = b"This is a very very important test".to_vec();
        let mut file2 = Vec::new();

        // Create a new ArunaReadWriter
        // Add transformer in reverse order -> from "last" to first
        // input -> 1 -> 2 -> 3 -> output
        // .add(3).add(2).add(1)println!("{}", self.internal_buf.len());
        ArunaReadWriter::new_with_writer(file.as_ref(), &mut file2)
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

        assert!(file == file2)
    }

    #[tokio::test]
    async fn test_with_file_footer() {
        let file = File::open("test.txt").await.unwrap();
        let file2 = File::create("test.txt.out.2").await.unwrap();
        ArunaReadWriter::new_with_writer(file, file2)
            .add_transformer(ZstdDec::new()) // Double compression because we can
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
            .unwrap();

        let mut file = File::open("test.txt").await.unwrap();
        let mut file2 = File::open("test.txt.out.2").await.unwrap();
        let mut buf1 = String::new();
        let mut buf2 = String::new();
        file.read_to_string(&mut buf1).await.unwrap();
        file2.read_to_string(&mut buf2).await.unwrap();
        assert!(buf1 == buf2)
    }

    #[tokio::test]
    async fn test_footer_parsing() {
        let file = File::open("test.txt").await.unwrap();
        let file2 = File::create("test.txt.out.3").await.unwrap();
        ArunaReadWriter::new_with_writer(file, file2)
            //.add_transformer(ZstdDec::new())
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
            .unwrap();

        let mut file2 = File::open("test.txt.out.3").await.unwrap();

        file2
            .seek(std::io::SeekFrom::End(-65536 * 2))
            .await
            .unwrap();

        let buf: &mut [u8; 65536 * 2] = &mut [0; 65536 * 2];
        file2.read_exact(buf).await.unwrap();

        let mut fp = FooterParser::new(buf);

        fp.parse().unwrap();

        let (a, b) = fp
            .get_offsets_by_range(Range { from: 0, to: 1000 })
            .unwrap();

        assert!(a.to % (65536) == 0);

        assert!(
            a == Range {
                from: 0,
                to: 25 * 65536
            }
        );
        assert!(b == Range { from: 0, to: 1000 })
    }

    #[tokio::test]
    async fn test_footer_parsing_encrypted() {
        let file = File::open("test.txt").await.unwrap();
        let file2 = File::create("test.txt.out.4").await.unwrap();
        ArunaReadWriter::new_with_writer(file, file2)
            .add_transformer(
                ChaCha20Enc::new(false, b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(FooterGenerator::new(None, true))
            .add_transformer(ZstdEnc::new(1, false))
            .process()
            .await
            .unwrap();

        let mut file2 = File::open("test.txt.out.4").await.unwrap();
        file2
            .seek(std::io::SeekFrom::End((-65536 - 28) * 2))
            .await
            .unwrap();

        let buf: &mut [u8; (65536 + 28) * 2] = &mut [0; (65536 + 28) * 2];
        file2.read_exact(buf).await.unwrap();

        let mut fp =
            FooterParser::from_encrypted(buf, b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea").unwrap();
        fp.parse().unwrap();

        let (a, b) = fp
            .get_offsets_by_range(Range { from: 0, to: 1000 })
            .unwrap();

        assert!(a.to % (65536 + 28) == 0);

        assert!(
            a == Range {
                from: 0,
                to: 25 * (65536 + 28)
            }
        );
        assert!(b == Range { from: 0, to: 1000 })
    }

    #[tokio::test]
    async fn test_with_filter() {
        let file = b"This is a very very important test".to_vec();
        let mut file2 = Vec::new();

        // Create a new ArunaReadWriter
        // Add transformer in reverse order -> from "last" to first
        // input -> 1 -> 2 -> 3 -> output
        // .add(3).add(2).add(1)println!("{}", self.internal_buf.len());
        ArunaReadWriter::new_with_writer(file.as_ref(), &mut file2)
            .add_transformer(Filter::new(Range { from: 0, to: 3 }))
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

        println!("{:?}", file2);
        assert_eq!(file2, b"Thi".to_vec());
    }

    #[tokio::test]
    async fn stream_test() {
        let mut file2 = Vec::new();

        use futures::stream;

        let stream = stream::iter(vec![
            Ok(Bytes::from_iter(
                b"This is a very very important test".to_vec(),
            )),
            Ok(Bytes::from(b"This is a very very important test".to_vec())),
        ]);

        // Create a new ArunaReadWriter
        // Add transformer in reverse order -> from "last" to first
        // input -> 1 -> 2 -> 3 -> output
        // .add(3).add(2).add(1)println!("{}", self.internal_buf.len());
        ArunaStreamReadWriter::new_with_writer(stream, &mut file2)
            .add_transformer(Filter::new(Range { from: 0, to: 3 }))
            .add_transformer(ZstdDec::new()) // Double compression because we can
            .add_transformer(ZstdDec::new()) // Double compression because we can
            .add_transformer(
                ChaCha20Dec::new(b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(
                ChaCha20Dec::new(b"99wj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(
                ChaCha20Enc::new(true, b"99wj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            )
            .add_transformer(
                ChaCha20Enc::new(true, b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea".to_vec()).unwrap(),
            ) // Tripple compression because we can
            .add_transformer(ZstdEnc::new(2, false)) // Double compression because we can
            .add_transformer(ZstdEnc::new(1, false))
            .process()
            .await
            .unwrap();

        println!("{:?}", file2);
        assert_eq!(file2, b"Thi".to_vec());
    }

    // #[tokio::test]
    // async fn size_tester() {
    //     let file = File::open("test.txt").await.unwrap();
    //     let file2 = io::sink();
    //     let mut arw = ArunaReadWriter::new_with_writer(file, file2)
    //         .add_transformer(SizeProbe::new())
    //         .add_transformer(ZstdEnc::new(0, false))
    //         .add_transformer(SizeProbe::new());

    //     arw.process().await.unwrap();

    //     let notes = arw.get_notifications().await.unwrap();

    //     let size_1 = parse_size_from_notifications(notes.clone(), 1).unwrap();
    //     let size_2 = parse_size_from_notifications(notes, 2).unwrap();

    //     assert!(
    //         size_1
    //             == File::open("test.txt")
    //                 .await
    //                 .unwrap()
    //                 .metadata()
    //                 .await
    //                 .unwrap()
    //                 .len()
    //     );

    //     assert!(size_1 > size_2)
    // }
}
