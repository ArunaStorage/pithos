# ArunaReadWriter

Short guidance for usage of the `ArunaReadWriter` custom component. For the formal file specification click [here](#the-aruna-file-format).

This is the first working generic version of customisable data transformer component for the Aruna Object Storage (AOS).
The idea is simple, you implement these two base traits with your custom data transformation logic:

```rust

pub trait AddTransformer<'a> {
    fn add_transformer(&mut self, t: Box<dyn Transformer + Send + 'a>);
}

#[async_trait::async_trait]
pub trait Transformer {
    async fn process_bytes(&mut self, buf: &mut bytes::Bytes, finished: bool) -> Result<bool>;
    async fn get_info(&mut self, is_last: bool) -> Result<Vec<Stats>>;
}
```

And afterwards the structs implementing `Transformer` + `AddTransformer`  can be registered in the `ArunaReadWriter` to be plugged between the `Read` and `Write` parts of the ReadWriter.

Example:

```rust
        let file = b"This is a very very important test".to_vec();
        let mut file2 = Vec::new();

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
```

This example creates a `Vec<u8>` from a bytes array (implements [AsyncRead](https://docs.rs/tokio/1.26.0/tokio/io/trait.AsyncRead.html)) and sinks it in another `Vec<u8>` (impl [AsynWrite](https://docs.rs/tokio/1.26.0/tokio/io/trait.AsyncWrite.html)). In between, custom data transformations can take place. Please note: the order of execution is reversed from the add_transformer calls, so you have to start with the "last" step and end with the "first". 

The example compresses the vector first double compresses the vector with a custom padded Zstandard compression component and afterwards encrypts the result also two times with ChaCha20-Poly1305. Afterwards all steps are reversed resulting in the original data.

### Notes for own implementations

The `AddTransformer` trait is used to register the transformer and chain it via a dynamic dispatch of multiple `Transformer`. For this your struct should contain a `Option<Box<dyn Transformer + Send + 'a>>` field that is set via `add_transformer`. 

The rest of the main logic is build around, the process_bytes function.

```rust
async fn process_bytes(&mut self, buf: &mut bytes::Bytes, finished: bool) -> Result<bool>;
```

The idea is that your Transformer receives a mutable buffer with bytes that you can transform. If you have transformed (either all or via an internal buffer) the data is transferred to the next transformers `process_bytes` method. To work properly the following rules should be followed:

- The `finished` flag indicates that the previous transformer has finished processing its data. Use this to initiate clean-up logic. Although the previous step might be finished, its internal buffers might still contain data, so wait for the first call that contains a buffer with 0 bytes length after finished was set to `true`.
- `Result<bool>` should only return `Ok(true)` if the next transformer also responds with `Ok(true)` and the current transformer has finished all processing and emptied its buffer. This way the iteration can be stopped by backtracing the `Ok(true)` call from the ultimate writer back to the reader.

# The ARUNA file format

This document contains the formal description for the aruna (`.aruna` equivalent to `.zst.c4gh`) file format. A file format that enables compression and encryption while still maintaining a resonable performant indexing solution for large multi-gigabyte files. Optimized for usage with object storage solutions, like S3.

## Specification

The core of the aruna file format is the combination of GA4GH's [crypt4gh](http://samtools.github.io/hts-specs/crypt4gh.pdf) encryption format with the zstandard compression algorithm ([RFC8878](https://datatracker.ietf.org/doc/rfc8878/)). This is extended by an optional custom footer block containing positional information for decrypting and decompressing blocks within larger files.

### **Structure**

Aruna files consist of three distinct parts. A Header section followed by blocks of compressed and encrypted data and an optional footer section containing indirect index information and block sizes.


#### **Data structure**

For Compression the data SHOULD first be split into raw data chunks with exactly 5 Mib size (except the last one). These chunks MUST be compressed using the zstandard algorithm with a compression level of choice and MAY optionally end with a MAC. Each compressed frame MUST be followed by a `skippable frame` as defined in [RFC8878](https://datatracker.ietf.org/doc/rfc8878/) if the resulting compressed size is not a multiple of 65536 Bytes (64 Kib) and the raw file size was more than 5 Mib. The skippable frame SHOULD use `0x184D2A50` as Magic_Number and SHOULD avoid `0x184D2A51` and `0x184D2A52` to avoid confusion with the custom footer section. A skippable frame MUST be used to align the total compressed size to a multiple of the encryption block size of 65536 Bytes (except for the last block) if more than one chunk exists. Because skippable frames have a minimum size of 8 Bytes they extend the data at worst by `65536 + 7 = 65543 Bytes`. Raw files that are smaller than 5 Mib SHOULD NOT contain any skippable frames and omit any indexing for performance reasons.
 
The resulting blocks consisting of compressed data MUST be encrypted in ChaCha20-Poly1305_ietf encrypted blocks as specified in [RFC7539](https://www.rfc-editor.org/rfc/rfc7539) with 65536 Bytes size, using a securely generated random encryption secret. All blocks SHOULD be preceeded by a per block random generated 12 byte Nonce and end with a 16 byte message authentication code (MAC). This results in a total blocksize of 65562 Bytes. The last encrypted block of the file CAN have a smaller size than this if the file has an uncompressed size of less than 5 Mib.

If the file is larger than 5 Mib the number of blocks that build 5 Mib of raw data SHOULD be summed up resulting in a 1 Byte unsigned integer between 1 and 81 (with last chunk +2 = 83). 81 is the maximum because 5 Mebibytes are exactly 80 x 65536 Bytes chunks and in the worst case with no compression the skippable frame could extend this by a maximum of one block. This index number is stored in the last one or two encrypted blocks of skippable frames in the file as index for fast access of data in order.

#### **Header**

The primary header is identical to the header specified by the crypt4gh standard and contains the block and encryption information for a specific recipient. This header is generated ad-hoc and NOT stored with the data itself to avoid re-encrypting the first section multiple times.

#### **Footer** 

The footer consists of one or two encrypted 65536 Byte sized blocks of skippable frames that contain 1 byte unsigned integers with index information about each block of 5 Mib raw uncompressed data in order. These blocks have the following structure in **little-endian** format.

- `Header` with `Magic_Number` `0x184D2A51` for one block `0x184D2A52` if two blocks are attached. (4 Bytes)
- `Frame_Size` = 65536 as unsigned 32 bit integer
- `Block_Total` = 32 bit unsigned integer with the total number of 64Kib + 28 Byte blocks.
- `Block_List` = The size of each 5 Mib segment in multiples of 64Kib + 28 Byte blocks as unsigned 8 Bit integer in order
- `Padding` = 0x00 Bytes to fill the 64 Kib block.

If the footer contains two blocks (indicated by the Magic_Number `0x184D2A52`) both blocks should repeat the `Header` / `Frame_Size` / `Block_number` sections with the same information.


## Practical guidance

This section contains practical recommendations for building encryption logic that comply with this format. 

### **Compression and Encryption**

- Split the file in 5 Mib chunks
- If this results in only one chunk:
    - compress the whole chunk
    - Split the compressed data in 64Kib sections
    - encrypt the 64 Kib sections with a random nonce
    - concatenate `Nonce` + `Encrypted data` + `MAC` to one block
    - concatenate all blocks in order
- If this results in multiple chunks:
    - compress each chunk
    - calculate the "missing" bytes to fill a 64 Kib section for each chunk with the formular: `Compressed size % 65536` if the `result` is < 8 the skippable chunk will be `result + 64 Kib` otherwise the skippable frame should be of size `result`
    - Create a skippable frame of size `result` with a magic header of `0x184D2A50` to align the result to 64Kib
    - split the resulting compressed section in 64 Kib sections and remember the number of sections
    - encrypt the 64 Kib sections with a random nonce
    - concatenate `Nonce` + `Encrypted data` + `MAC` to one block
    - (if shared) Start with a crypt4gh header containing encryption information
    - concatenate all blocks and all chunks in order 
    - create a skippable frame as described in the [Footer](#footer) section with all remembered number of sections for each compressed chunk
    - append the one or two footers to the file

### **Decryption and Decompression**

This procedure has two options a simple single threaded one and a more parallelizable multi-threaded one. Multi-threading only gives a significant advantage for files that are larger than 10-20 Mib.

 #### **Option A (single-threaded)**:

  - This procedure should work with regular tools for crypt4gh and zstandard.
  - Read the file from the start, obtain encryption information via the header section
  - Decrypt each 64 Kib in order using the encryption key from the header and the prepended 12 Byte Nonce in each Block.
  - The resulting data can be piped directly in the zstd decompressor.
  - All padding information and the footer section should be skipped as skippable frame.
 
 #### **Option B (multi-threaded)**:
 
  - Obtain the content-length of the compressed and encrypted file
  - If the file is significantly smaller than 5 Mib -> Proceed with Option A
  - Read and decrypt the last two encrypted blocks 2x (64 Kib + 28 Bytes) and store them in separate variables.
  - Check the last block for its `Magic_Number`, if it is `0x184D2A51` discard the penultimate block, if the number is `0x184D2A52` begin with the penultimate.
  - Decide how many parallel decryption and decompression threads should be spawned.
  - Read and split the `Block_Total` described in the [Footer](#footer) section roughly in your number of parallel threads. This results in a number of 64 Kib blocks that should be handled by each thread.
  - Start iterating through the `Block_List` section of the Footer and sum up the number of blocks for each entry in the blocklist, remember the **initial block** beginning with 0. If the sum surpasses the determined block count from the previous step spawn a separate thread handling the section from your **initial block** up to the end of the current block. Set the initial block to the beginning of the next block and repeat the process.
    - Each thread gets a "initial" and an "up-to" block index to process
    - These number relate to byte offsets in the file via the formular: `blocknumber * (65536 + 28)`
    - **Example 1**: Handle all blocks from 0 to 222 -> Range: 0 - 14554764 Byte
    - **Example 2**: Handle all blocks from 222 to 444 -> Range: 14554765 (14554764 + 1) - 29109528 Byte
    - Because the data is aligned it can be handled equivalent to **Option A**
- Afterwards concatenate all decrypted / decompressed parts from each thread in the correct order to get the full file.

#### **Option C (specific Range)**:

If you want to get only a specific range from the file the procedure is as follows:

- Get the Footer as described in [Option B](#option-b-multi-threaded), if the file is smaller than 5 Mib decrypt / decompress the whole file and extract the requested range from the resulting raw data.
- Determine the needed sections based on your Range request. The data is compressed in chunks of 5 Mib, so the range must first be converted to an index of 5 Mib Blocks. This can be done by integer dividing the index with 5Mib (5242880)
- Example: Range: Begin: 5242111 - End: 20971320 -> Begin // 5 Mib = 0, End // 5 Mib = 3 -> The 5 Mib blocks with the indizes from 0 up to 3 are needed.
- Iterate the Blocklist from the beginning, sum up all counts up to Begin index in Variable A and sum up the counts from Begin to end index separately in Variable B.
- The resulting variables A and B indicate the the Range of compressed and decrypted bytes that needs to be decrypted and compressed to get all data of the requested Range. The formular to calculate the Ranges is: From: `Variable A * (65536 + 28)` to `Variable A * (65536 + 28) + Variable B * (65536 + 28)` This Range should contain only full encrypted / compressed blocks of 5 Mib size that are needed for the request.
- The blocks can be decrypted and decompressed as in [Option A](#option-a-single-threaded) or [Option B](#option-b-multi-threaded).
- To get the "true" requested range afterwards the first `Begin Range % 5 Mib` Bytes and the last `5 Mib - End Range % 5 Mib` Bytes or must be discarded. This can also be done by first discarding the beginning and afterwards only returning the "size" of the requested range (`Begin Range - End Range`)


## Discussion

The Aruna file format considers multiple aspects like compresion ratio, access speed etc. and tries to create a balanced middle ground that is best suitable for a wide range of filetypes. By utilizing existing standard algorithms and procedures the resulting file is readable by existing tools and does not need specific software to be handled. However the full potential of this file format can only be established with customized software that uses the additional information stored in the skippable frames.





 

