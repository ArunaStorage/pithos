mod io;
mod structs;
mod utils;

use crate::io::utils::{load_private_key_from_env, load_private_key_from_pem};
use anyhow::{anyhow, bail, Result};
use clap::{Parser, Subcommand, ValueEnum};
use futures_util::StreamExt;

use pithos_lib::helpers::footer_parser::{Footer, FooterParser, FooterParserState};
use pithos_lib::helpers::structs::{EncryptionKey, FileContext};
use pithos_lib::pithos::pithoswriter::PithosWriter;
use pithos_lib::pithos::structs::{EndOfFileMetadata, EOF_META_LEN};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use tokio::fs::{read_link, File};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::pin;
use utils::conversion::evaluate_log_level;

#[derive(Clone, ValueEnum)]
enum KeyFormat {
    Openssl,
    Crypt4gh,
    Raw,
}

#[derive(Clone, ValueEnum)]
enum ExportFormat {
    Pithos,
    Crypt4gh,
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Optionally set the log level
    #[arg(long, value_name = "LOG_LEVEL")]
    log_level: Option<String>,

    /// Optionally set the log file
    log_file: Option<PathBuf>,

    /// Subcommands
    #[command(subcommand)]
    command: PithosCommands,
}

#[derive(Subcommand)]
enum PithosCommands {
    /// Create a Pithos file from some input
    Create {
        /// Custom file metadata in JSON format
        #[arg(short, long)]
        metadata: Option<String>,
        /// Custom ranges e.g. 'Tag-Name,0,1234;Tag-Name,1235,2345'
        #[arg(short, long)]
        ranges: Option<String>,
        /// Private key used to create session keys for encryption
        #[arg(long)]
        writer_private_key: Option<PathBuf>, // Env var -> Default file: ~/.pithos/sec_key.pem -> CLI parameter file path
        /// Public keys of recipients
        #[arg(long)]
        reader_public_keys: Option<Vec<PathBuf>>, // Iterate files and parse all keys
        /// Output destination; Default is stdout or ./<filename>.pto (?)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Input files
        #[arg(value_name = "FILES")]
        files: Vec<PathBuf>,
    },
    /// Read pithos file
    Read {
        /// Subcommands
        #[command(subcommand)]
        read_command: ReadCommands,
    },
    /// Create x25519
    CreateKeypair {
        /// Key format; Default is openSSL x25519 pem
        #[arg(short, long)]
        format: Option<KeyFormat>,
        /// Output destination; Default is stdout
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Modify the Pithos footer
    Modify {
        /// Subcommands
        #[command(subcommand)]
        command: Option<ModifyCommands>,
    },
    /// Export a Pithos file into another compatible file format
    Export {
        #[arg(short, long, value_enum)]
        format: Option<ExportFormat>,
        #[arg(long)]
        writer_private_key: Option<String>,
    },
}

#[derive(Subcommand)]
enum ReadCommands {
    /// Read the technical metadata of the file
    Info {
        /// Input file
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
    /// Read the complete file
    All {
        /// Private key for decryption
        #[arg(long)]
        reader_private_key: Option<String>,
        /// Input file
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
    /// Read the data
    Data {
        /// Private key for decryption
        #[arg(long)]
        reader_private_key: Option<String>,
        /// Input file
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
    /// Read the Table of Contents
    ContentList {
        /// Private key for decryption
        #[arg(long)]
        reader_private_key: Option<PathBuf>,

        //ToDo: Filter to display only specific fields of the ToC?
        /// Input file
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
}

#[derive(Subcommand)]
enum ModifyCommands {
    /// Add a reader to the encryption metadata
    AddReader {
        // Private key for decryption and shared key generation
        #[arg(long)]
        writer_private_key: Option<String>,
        // Readers public key for shared key generation
        #[arg(long)]
        reader_public_key: Option<String>,
    },
    /// Set all readers in the encryption metadata
    SetReaders {
        // Private key for decryption and shared key generation
        #[arg(long)]
        writer_private_key: Option<String>,
        // List of public keys for encryption packe generation
        #[arg(long)]
        reader_public_keys: Option<Vec<String>>,
    },
}

#[tracing::instrument(level = "trace", skip())]
#[tokio::main]
async fn main() -> Result<()> {
    // Parse CLI input
    let cli = Cli::parse();

    // Evaluate provided log level
    let log_level = evaluate_log_level(cli.log_level);

    // Initialize logger
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            // Use a more compact, abbreviated log format
            .compact()
            // Set LOG_LEVEL to
            .with_max_level(log_level)
            // Display source code file paths
            .with_file(true)
            // Display source code line numbers
            .with_line_number(true)
            .with_target(false)
            .finish(),
    )?;

    // Execute subcommand
    match &cli.command {
        PithosCommands::Read { read_command } => match read_command {
            ReadCommands::Info { file } => {
                // Open file
                let mut input_file = File::open(file).await?;

                // Read EndOfFileMetadata bytes
                input_file
                    .seek(tokio::io::SeekFrom::Start(
                        input_file.metadata().await?.len() - EOF_META_LEN as u64,
                    ))
                    .await?;
                let mut buf = [0; EOF_META_LEN];
                input_file.read_exact(&mut buf).await?;

                // Try to parse EndOfFileMetadata
                let eof_meta: EndOfFileMetadata = borsh::from_slice(&buf)?;

                println!("{eof_meta}");

                //ToDo: OutputWriter
            }
            ReadCommands::All { .. } => todo!("Read everything and write into output(s)"),
            ReadCommands::Data { .. } => {
                // Open file
                //let mut input_file = File::open(file).await?;

                // Create PithosReader
                //let reader = PithosReader::new_with_writer(input_stream, sink, filecontext, metadata);
            }
            ReadCommands::ContentList {
                reader_private_key,
                file,
            } => {
                // Load readers secret key
                let (sec_key, _) = if let Ok(key) = load_private_key_from_env() {
                    key
                } else if let Ok(key_bytes) =
                    load_private_key_from_pem(&PathBuf::from("~/.pithos/private_key.pem"))
                {
                    key_bytes
                } else if let Some(key_path) = reader_private_key {
                    load_private_key_from_pem(key_path)?
                } else {
                    bail!("No private key provided")
                };

                // Open file
                let mut input_file = File::open(file).await?;
                let file_meta = input_file.metadata().await?;

                let footer_prediction = if file_meta.len() < 65536 * 2 {
                    file_meta.len() // 131072 always fits in i64 ...
                } else {
                    65536 * 2
                };

                // Read footer bytes in FooterParser
                input_file
                    .seek(tokio::io::SeekFrom::End(-(footer_prediction as i64)))
                    .await?;
                let buf = &mut vec![0; footer_prediction as usize]; // Has to be vec as length is defined by dynamic value
                input_file.read_exact(buf).await?;

                let parser = FooterParser::new(buf)?.add_recipient(&sec_key).parse()?;

                // Check if bytes are missing
                if let FooterParserState::Missing(missing_bytes) = parser.state {
                    let _needed_bytes = footer_prediction + missing_bytes as u64;
                    todo!()
                }

                // Parse the footer bytes and display Table of Contents
                let footer: Footer = parser.try_into()?;
                println!("{:#?}", footer.table_of_contents);

                //TODO: Output writer
            }
        },
        PithosCommands::Create {
            metadata: _,
            ranges: _,
            writer_private_key,
            reader_public_keys: _,
            files,
            output,
        } => {
            // Ranges as JSON (or CSV) file or 'Tag1,0,12;Tag2,13,38; ...'
            // Metadata as JSON file or '{"key": "value"}' | validate schema

            // Parse writer key to validate format and generate public key
            // Load readers secret key
            let (_sec_key, pub_key) = if let Ok(key) = load_private_key_from_env() {
                key
            } else if let Ok(key_bytes) =
                load_private_key_from_pem(&PathBuf::from("~/.pithos/private_key.pem"))
            {
                key_bytes
            } else if let Some(key_path) = writer_private_key {
                load_private_key_from_pem(key_path)?
            } else {
                bail!("No private key provided")
            };

            // Generate random symmetric "key" for encryption
            let key: String = thread_rng()
                .sample_iter(&Alphanumeric)
                .take(32)
                .map(char::from)
                .collect::<String>()
                .to_ascii_lowercase();

            // Parse file metadata
            let mut file_ctxs = vec![];
            let mut input_streams = vec![];

            for (i, file_path) in files.iter().enumerate() {
                let input_file = File::open(file_path).await?;
                let file_metadata = input_file.metadata().await?;

                let symlink_target = if file_metadata.file_type().is_symlink() {
                    Some(
                        read_link(file_path)
                            .await?
                            .to_str()
                            .ok_or_else(|| anyhow!("Path to string conversion failed"))?
                            .to_string(),
                    )
                } else {
                    None
                };

                let file_context = FileContext {
                    idx: i,
                    file_path: file_path.to_str().unwrap().to_string(),
                    compressed_size: file_metadata.len(),
                    decompressed_size: file_metadata.len(),
                    uid: Some(file_metadata.uid().into()),
                    gid: Some(file_metadata.gid().into()),
                    mode: Some(file_metadata.mode()),
                    mtime: Some(file_metadata.mtime() as u64),
                    compression: false,
                    chunk_multiplier: None,
                    encryption_key: EncryptionKey::Same(key.as_bytes().to_vec()), // How to know if encryption is wanted?
                    recipients_pubkeys: vec![pub_key.as_slice().try_into()?],
                    is_dir: file_metadata.file_type().is_dir(),
                    symlink_target,
                    expected_sha256: None, //ToDo
                    expected_md5: None,    //ToDo
                    semantic_metadata: None,
                    custom_ranges: None,
                };

                file_ctxs.push(file_context);
                input_streams.push(tokio_util::io::ReaderStream::new(input_file));
            }

            // Send all file data into channel
            let (data_sender, data_receiver) = async_channel::bounded(100); // Channel cap?
            tokio::spawn(async move {
                for mut input_stream in input_streams {
                    while let Some(bytes) = input_stream.next().await {
                        data_sender.send(Ok(bytes?)).await?
                    }
                }
                Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
            });
            pin!(data_receiver);

            // Init default PithosWriter with standard Transformers
            let mut writer = if let Some(output_path) = output {
                PithosWriter::new_multi_with_writer(
                    data_receiver,
                    File::create(output_path).await?,
                    file_ctxs,
                )
                .await?
            } else {
                PithosWriter::new_multi_with_writer(data_receiver, tokio::io::stdout(), file_ctxs)
                    .await?
            };
            writer.process_bytes().await?;
        }
        PithosCommands::CreateKeypair { format, output } => {
            // x25519 openSSL keypair
            // x25519 Crypt4GH keypair
            // GPG (for parsing?)
            // Output format parameter?
            //  - Raw
            //  - Pem
            //  - ?

            // Evaluate output format
            let format = format.as_ref().unwrap_or(&KeyFormat::Openssl);

            // Generate keypair
            let (seckey_bytes, pubkey_bytes) = match format {
                KeyFormat::Openssl => {
                    let openssl_keypair = openssl::pkey::PKey::generate_x25519()?;
                    (
                        openssl_keypair.private_key_to_pem_pkcs8()?,
                        openssl_keypair.public_key_to_pem()?,
                    )
                }
                KeyFormat::Crypt4gh => {
                    unimplemented!("Crypt4GH key generation not yet implemented")
                }
                KeyFormat::Raw => {
                    let openssl_keypair = openssl::pkey::PKey::generate_x25519()?;
                    (
                        openssl_keypair.raw_private_key()?,
                        openssl_keypair.raw_public_key()?,
                    )
                }
            };

            // Write output
            if let Some(dest) = output {
                let mut output_target = File::create(dest).await?;
                output_target.write_all(&seckey_bytes).await?;
                output_target.write_all(&pubkey_bytes).await?;
            } else {
                let mut output_target = tokio::io::stdout();
                output_target.write_all(&seckey_bytes).await?;
                output_target.write_all(&pubkey_bytes).await?;
            }
        }
        PithosCommands::Modify { .. } => {}
        PithosCommands::Export { .. } => {}
    }

    // Continued program logic goes here...
    Ok(())
}
