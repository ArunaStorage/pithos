mod compressor;
mod encrypt;
mod finalizer;
pub mod readwrite;
pub mod transformer;

#[cfg(test)]
mod tests {
    use crate::compressor::Compressor;
    use crate::readwrite::ArunaReadWriter;
    use tokio::fs::File;

    #[tokio::test]
    async fn test_with_file() {
        let file = File::open("test.txt").await.unwrap();
        let file2 = File::create("tst.cmp").await.unwrap();

        // Create a new ArunaReadWriter
        // Add transformer in reverse order -> from "last" to first
        // input -> 1 -> 2 -> 3 -> output
        // .add(3).add(2).add(1)
        ArunaReadWriter::new(file, file2)
            .add_transformer(Compressor::new(3, true)) // Tripple compression because we can
            .add_transformer(Compressor::new(2, false)) // Double compression because we can
            .add_transformer(Compressor::new(1, false))
            .process()
            .await
            .unwrap()
    }
}
