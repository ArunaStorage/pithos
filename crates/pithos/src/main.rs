mod io;
mod structs;
mod utils;

use anyhow::{anyhow, Result};
use base64::engine::general_purpose;
use base64::Engine;
use chacha20poly1305::aead::OsRng;
use clap::{Parser, Subcommand};
use crypto_kx::{Keypair, SecretKey};
use futures::TryStreamExt;
use pithos_lib::helpers::footer_parser::FooterParser;
use pithos_lib::pithoswriter::PithosWriter;
use pithos_lib::structs::{EndOfFileMetadata, FileContext};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::{os::unix::fs::MetadataExt, path::PathBuf};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt}; // for write_all()
use tracing::debug;
use utils::conversion::evaluate_log_level;
use crate::io::utils::{load_private_key_from_pem, load_private_key_from_string};

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
    command: Option<PithosCommands>,
}

#[derive(Subcommand)]
enum PithosCommands {
    /// Create a Pithos file from some input
    Create {
        #[arg(short, long)]
        metadata: Option<String>,
        #[arg(short, long)]
        ranges: Option<String>,
        #[arg(long)]
        writer_private_key: Option<PathBuf>, // Env var -> Default file: ~/.pithos/sec_key.pem -> CLI parameter file path
        #[arg(long)]
        reader_public_keys: Option<Vec<PathBuf>>, // Iterate files and parse all keys

        /// Input file
        #[arg(value_name = "FILE")]
        file: Vec<PathBuf>,
        /// Output destination; Default is stdout or ./<filename>.pto (?)
        #[arg(value_name = "OUTPUT")]
        output: Option<PathBuf>,
    },
    /// Read pithos file
    Read {
        /// Subcommands
        #[command(subcommand)]
        read_command: ReadCommands,

        /// Input file
        #[arg(value_name = "FILE")]
        file: PathBuf,
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
        command: Option<ModifyCommmands>,
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
    Info {},
    /// Read the complete file
    All {
        /// Private key for decryption
        #[arg(long)]
        reader_private_key: Option<String>,
    },
    /// Read the data
    Data {
        /// Private key for decryption
        #[arg(long)]
        reader_private_key: Option<String>,
    },
    /// Read the range list if present
    RangeList {
        /// Private key for decryption
        #[arg(long)]
        reader_private_key: Option<String>,
    },
    /// Read the semantic metadata if present
    Metadata {
        /// Private key for decryption
        #[arg(long)]
        reader_private_key: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ModifyCommmands {
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
        None => {}
        Some(PithosCommands::Read { read_command, file }) => match read_command {
            ReadCommands::Info {} => {
                // Open file
                let mut input_file = File::open(file).await?;

                // Read last 8 bytes to get EndOfFileMetadata len
                input_file.seek(tokio::io::SeekFrom::End(-8)).await?;
                let mut buf = [0; 8];
                input_file.read_exact(&mut buf).await?;
                let eof_len = i64::from_le_bytes(buf);

                // Read EndOfFileMetadata bytes
                let mut eof_metadata = vec![0; eof_len as usize];
                input_file.seek(tokio::io::SeekFrom::End(-eof_len)).await?;
                input_file.read_exact(&mut eof_metadata).await?;

                // Try to parse EndOfFileMetadata
                let eof_block = EndOfFileMetadata::try_from(eof_metadata.as_slice())?;
                debug!(?eof_block)

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
            ReadCommands::Metadata { reader_private_key } => {

                // Load readers secret key
                let sec_key = if let Some(key) = dotenvy::var("MY_PRIVATE_KEY")? {
                    load_private_key_from_string(key.to_bytes())?
                } else {
                    if let Ok(key_bytes) = load_private_key_from_pem(&PathBuf::from("~/.pithos/sec_key.pem")) {
                        key_bytes
                    } else {
                        if let Some(key_path) = reader_private_key {
                            let sec_key = load_private_key_from_pem(key_path)?;
                            let hex_key: String = sec_key.iter().map(|b| format!("{:02x}", b)).collect();
                            debug!(?hex_key);
                            sec_key
                        } else {
                            vec![] //
                        }
                    }
                };

                // Open file
                let mut input_file = File::open(file).await?;

                let footer_prediction = if input_file.metadata()?.len() < 65536*2 {
                    input_file.metadata()?.len()
                } else {
                    65536*2
                };

                // Read footer bytes in FooterParser
                input_file.seek(tokio::io::SeekFrom::End(-footer_prediction)).await?;
                let buf: &mut [u8; 65536] = &mut [0; 65536]; // ToDo
                input_file.read_exact(buf).await.unwrap();
                let mut parser = FooterParser::new(buf);

                parser.add_recipient_key(sec_key.to_bytes());

                // Parse the footer bytes and display technical metadata info
                parser.parse()?;
                println!("{}", parser.get_eof_metadata()?);
                println!("{}", parser.get_semantic_metadata()?);
            }
        },
        Some(PithosCommands::Create {
            metadata,
            ranges,
            writer_private_key,
            reader_public_keys,
            file,
            output,
        }) => {

            // Ranges as JSON (or CSV) file or 'Tag1,0,12;Tag2,13,38; ...'
            // Metadata as JSON file or '{"key": "value"}' | validate schema

            // Parse writer key to validate format and generate public key
            //ToDo: Support keys in pem format
            //Note: This currently only works for asn.1 formatted x25519 private keys
            let writer_public_key = if let Some(secret_key) = writer_private_key {
                let base64_bytes = secret_key.as_bytes();
                let key_bytes = general_purpose::STANDARD
                    .decode(base64_bytes)
                    .map_err(|e| anyhow!("Base64 decoding failed: {e}"))?;
                let key: [u8; 32] = key_bytes[key_bytes.len() - 32..].try_into()?;

                debug!(writer_private_key = to_hex_string(key.to_vec()));

                let sec_key = SecretKey::from(key);
                Some(*sec_key.public_key().as_ref())
            } else {
                None
            };

            let key: String = thread_rng()
                .sample_iter(&Alphanumeric)
                .take(32)
                .map(char::from)
                .collect::<String>()
                .to_ascii_lowercase();

            // Parse file metadata
            let input_file = File::open(file).await?;
            let file_metadata = input_file.metadata().await?;

            let file_context = FileContext {
                file_name: file.file_name().unwrap().to_str().unwrap().to_string(),
                input_size: file_metadata.len(),
                file_size: file_metadata.len(),
                file_path: Some(file.to_str().unwrap().to_string()),
                uid: Some(file_metadata.uid().into()),
                gid: Some(file_metadata.gid().into()),
                mode: Some(file_metadata.mode()),
                mtime: Some(file_metadata.mtime() as u64),
                compression: false,
                encryption_key: Some(key.as_bytes().to_vec()),
                owners_pubkey: writer_public_key,
                is_dir: file_metadata.file_type().is_dir(),
                is_symlink: file_metadata.file_type().is_symlink(),
                expected_sha1: None, //ToDo
                expected_md5: None,  //ToDo
            };

            // Read file content as stream
            let stream = tokio_util::io::ReaderStream::new(input_file).map_err(|_| {
                Box::<(dyn std::error::Error + Send + Sync + 'static)>::from("a_str_error")
            });

            // Init default PithosWriter with standard Transformers
            let mut writer = if let Some(output_path) = output {
                PithosWriter::new_with_writer(
                    stream,
                    File::create(output_path).await?,
                    file_context,
                    metadata.clone(),
                )
                .await?
            } else {
                PithosWriter::new_with_writer(
                    stream,
                    tokio::io::stdout(),
                    file_context,
                    metadata.clone(),
                )
                .await?
            };

            writer.process_bytes().await?;
        }
        Some(PithosCommands::CreateKeypair { output }) => {
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
                PathBuf::from("./keypair.dude")
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
        Some(PithosCommands::Modify { .. }) => {}
        Some(PithosCommands::Export { .. }) => {}
    }

    // Continued program logic goes here...
    Ok(())
}
