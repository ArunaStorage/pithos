use super::{CdcConfig, ProcessingOptions, WriteOptions};
use crate::crypto::{PrivateKey, PublicKey};
use crate::error::PithosError;

/// Durability requested after a child directory has been flushed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppendDurability {
    /// Flush the terminal directory to the supplied file handle.
    Flush,
    /// Flush the terminal directory and request `sync_all` from the filesystem.
    SyncAll,
}

/// Options for a direct filesystem append.
pub struct AppendOptions {
    pub(crate) sender: PrivateKey,
    pub(crate) recipients: Vec<PublicKey>,
    pub(crate) cdc: CdcConfig,
    pub(crate) durability: AppendDurability,
    pub(crate) processing: ProcessingOptions,
}

impl AppendOptions {
    pub fn new(sender: PrivateKey, recipients: Vec<PublicKey>) -> Self {
        Self {
            sender,
            recipients,
            cdc: CdcConfig::default(),
            durability: AppendDurability::Flush,
            processing: ProcessingOptions::append_default(),
        }
    }

    pub fn with_cdc(mut self, cdc: CdcConfig) -> Self {
        self.cdc = cdc;
        self
    }

    pub fn with_durability(mut self, durability: AppendDurability) -> Self {
        self.durability = durability;
        self
    }

    pub(crate) fn validate_recipients(&self) -> Result<(), PithosError> {
        WriteOptions::new(self.sender.duplicate(), self.recipients.clone()).validate()
    }
}

/// Measurements collected while validating and extending an archive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppendObservation {
    pub source_read_count: u64,
    pub source_read_bytes: u64,
    pub base_archive_bytes: u64,
    pub final_archive_bytes: u64,
}
