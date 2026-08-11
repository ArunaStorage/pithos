use crate::archive::types::FileId;
use crate::crypto::{BlockKey, FileKey};
use crate::error::PithosError;
use std::collections::BTreeMap;

/// Recovered file secrets have one crate-private owner and never enter an index.
pub(crate) struct ResolvedAccess {
    keys: BTreeMap<FileId, FileKey>,
    block_keys: BTreeMap<FileId, BTreeMap<crate::archive::types::BlockHash, BlockKey>>,
    provenance: BTreeMap<FileId, AccessProvenance>,
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct AccessProvenance {
    pub(crate) segment: usize,
    pub(crate) recovery_order: usize,
    pub(crate) access_key: usize,
    pub(crate) sender_section: usize,
    pub(crate) recipient_section: usize,
}

impl ResolvedAccess {
    pub(crate) fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
            block_keys: BTreeMap::new(),
            provenance: BTreeMap::new(),
        }
    }

    pub(crate) fn insert(
        &mut self,
        id: FileId,
        key: &[u8; 32],
        provenance: AccessProvenance,
    ) -> Result<(), PithosError> {
        match self.keys.get(&id) {
            Some(existing) if existing.expose_for_protocol() != key => {
                Err(PithosError::ConflictingRecoveredFileKey)
            }
            Some(_) => {
                if provenance < self.provenance[&id] {
                    self.provenance.insert(id, provenance);
                }
                Ok(())
            }
            None => {
                self.keys.insert(id, FileKey::from_protocol(key));
                self.provenance.insert(id, provenance);
                Ok(())
            }
        }
    }

    pub(crate) fn key(&self, id: FileId) -> Option<&FileKey> {
        self.keys.get(&id)
    }

    pub(crate) fn provenance(&self, id: FileId) -> Option<AccessProvenance> {
        self.provenance.get(&id).copied()
    }

    pub(crate) fn with_file_key<T>(
        &self,
        id: FileId,
        operation: impl FnOnce(&FileKey) -> T,
    ) -> Option<T> {
        self.keys.get(&id).map(operation)
    }

    pub(crate) fn insert_block_keys<'a>(
        &mut self,
        id: FileId,
        entries: impl IntoIterator<Item = (crate::archive::types::BlockHash, &'a [u8; 32])>,
    ) {
        self.block_keys.insert(
            id,
            entries
                .into_iter()
                .map(|(hash, key)| (hash, BlockKey::from_protocol(key)))
                .collect(),
        );
    }

    pub(crate) fn block_key(
        &self,
        id: FileId,
        hash: crate::archive::types::BlockHash,
    ) -> Option<&BlockKey> {
        self.block_keys.get(&id).and_then(|keys| keys.get(&hash))
    }
}
