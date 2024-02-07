mod io;
mod structs;
mod utils;

use crate::io::utils::{load_private_key_from_env, load_private_key_from_pem};
use anyhow::{anyhow, bail, Result};
use chacha20poly1305::aead::OsRng;
use clap::{Parser, Subcommand};
use crypto_kx::Keypair;
use futures_util::StreamExt;
use openssl::pkey::PKey;
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
use tracing::debug;
use utils::conversion::evaluate_log_level;

use crate::utils::conversion::to_hex_string;

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
        /// Metadata in JSON format
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
        #[arg(value_name = "FILE")]
        files: Vec<PathBuf>,
    },
    /// Read pithos file
    Read {
        /// Subcommands
        #[command(subcommand)]
        read_command: ReadCommands,
    },

    /// Create custom transformer order or something like that
    CreateKeypair {
        /// Optionally output destination; Default is stdout
        #[arg(value_name = "OUTPUT")]
        output: Option<PathBuf>,
    },

    /// Modify the Pithos footer
    Modify {
        /// Subcommands
        #[command(subcommand)]
        command: Option<ModifyCommands>,
    },

    /// Export a Pithos into another compatible file format
    Export {
        #[arg(short, long)]
        format: String,
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
    /// Read the range list if present
    RangeList {
        /// Private key for decryption
        #[arg(long)]
        reader_private_key: Option<String>,
        /// Input file
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
    /// Read the semantic metadata if present
    Metadata {
        /// Private key for decryption
        #[arg(long)]
        reader_private_key: Option<PathBuf>,
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
            ReadCommands::RangeList { .. } => todo!(""),
            ReadCommands::Metadata {
                reader_private_key,
                file,
            } => {
                // Load readers secret key
                let (sec_key, _) = if let Ok(key) = load_private_key_from_env() {
                    key
                } else {
                    if let Ok(key_bytes) =
                        load_private_key_from_pem(&PathBuf::from("~/.pithos/private_key.pem"))
                    {
                        key_bytes
                    } else {
                        if let Some(key_path) = reader_private_key {
                            load_private_key_from_pem(key_path)?
                        } else {
                            bail!("No private key provided")
                        }
                    }
                };

                // Open file
                let mut input_file = File::open(file).await?;
                let mut file_meta = input_file.metadata().await?;

                let footer_prediction = if file_meta.len() < 65536 * 2 {
                    file_meta.len() as i64 // 131072 always fits in i64 ...
                } else {
                    65536 * 2
                };

                // Read footer bytes in FooterParser
                input_file
                    .seek(tokio::io::SeekFrom::End(-footer_prediction))
                    .await?;
                let buf: &mut [u8; 65536 * 2] = &mut [0; 65536 * 2]; // ToDo
                input_file.read_exact(buf).await?;

                // Init footer parser with provided private key
                //let mut parser = FooterParser::new(buf);
                //parser.add_recipient_key(sec_key);

                // Parse the footer bytes and display technical metadata info
                //parser.parse()?;
                //serde_json::to_string_pretty(&parser.get_semantic_metadata()?.semantic);
            }
        },
        PithosCommands::Create {
            metadata,
            ranges,
            writer_private_key,
            reader_public_keys,
            files,
            output,
        } => {
            // Ranges as JSON (or CSV) file or 'Tag1,0,12;Tag2,13,38; ...'
            // Metadata as JSON file or '{"key": "value"}' | validate schema

            // Parse writer key to validate format and generate public key
            // Load readers secret key
            let (sec_key, pub_key) = if let Ok(key) = load_private_key_from_env() {
                key
            } else {
                if let Ok(key_bytes) =
                    load_private_key_from_pem(&PathBuf::from("~/.pithos/private_key.pem"))
                {
                    key_bytes
                } else {
                    if let Some(key_path) = writer_private_key {
                        load_private_key_from_pem(key_path)?
                    } else {
                        bail!("No private key provided")
                    }
                }
            };

            //let pub_key = PKey::public_key_from_pem(b"-----BEGIN PUBLIC KEY-----MCowBQYDK2VuAyEAlULMGjfTdkjURUilioyhox1uDbLIY8sUnitB1xwYkV8=-----END PUBLIC KEY-----")?.raw_public_key()?;

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
                    symlink_target: symlink_target,
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
        PithosCommands::CreateKeypair { output } => {
            let keypair = Keypair::generate(&mut OsRng);

            // x25519 keypair
            // GPG (for parsing?)
            // Output format parameter?
            //  - Raw
            //  - Pem
            //  - ?

            let mut target_file = File::create(if let Some(destination) = output {
                destination.clone()
            } else {
                PathBuf::from("./keypair.pem")
            })
            .await
            .unwrap();

            let sec_hex = to_hex_string(keypair.secret().to_bytes().into()).to_ascii_lowercase();
            let sec_out = format!(
                "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
                sec_hex
            );
            debug!("{}", sec_out);

            let pub_hex = to_hex_string(keypair.public().as_ref().into()).to_ascii_lowercase();
            let pub_out = format!(
                "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
                pub_hex
            );
            debug!("{}", pub_out);

            target_file.write_all(sec_out.as_bytes()).await?;
            target_file.write_all(pub_out.as_bytes()).await?;
        }
        PithosCommands::Modify { .. } => {}
        PithosCommands::Export { .. } => {}
    }

    // Continued program logic goes here...
    Ok(())
}
