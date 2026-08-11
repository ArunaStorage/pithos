use crate::error::PithosError;
use crate::format::entries::WireEntries;
use crate::format::wire::{BlockDataState, Directory, EncryptionSection, FileEntry, FileType};

impl Directory {
    pub(crate) fn new(
        parent_directory_offset: Option<(u64, u64)>,
        files: WireEntries,
        encryption: indexmap::IndexMap<[u8; 32], EncryptionSection>,
    ) -> Self {
        Self {
            identifier: *b"PITHOSDR",
            parent_directory_offset,
            files,
            blocks: indexmap::IndexMap::new(),
            relations: vec![
                (0, "Describes".into()),
                (1, "Annotates".into()),
                (2, "Derived_From".into()),
                (3, "Source_Of".into()),
                (4, "Previous_Version".into()),
                (5, "Next_Version".into()),
                (6, "Part_of".into()),
                (7, "Contains".into()),
                (8, "Input_To".into()),
                (9, "Output_From".into()),
            ],
            encryption,
            dir_len: 0,
            crc32: 0,
        }
    }

    pub(crate) fn validate_references_and_accessible_blocks_with(
        &self,
        has_entry: impl Fn(u64) -> bool,
        has_relationship: impl Fn(u64) -> bool,
        block_size: impl Fn([u8; 32]) -> Option<u64>,
    ) -> Result<(), PithosError> {
        let relationship_ids = self
            .relations
            .iter()
            .map(|(id, _)| *id)
            .collect::<std::collections::HashSet<_>>();
        for (_, _, file) in self.files.iter() {
            for reference in &file.references {
                if !relationship_ids.contains(&reference.relationship)
                    && !has_relationship(reference.relationship)
                {
                    return Err(PithosError::UnknownRelationshipId(reference.relationship));
                }
                if !has_entry(reference.target_file_id) {
                    return Err(PithosError::MissingReferenceTarget(
                        reference.target_file_id,
                    ));
                }
            }
            if !matches!(file.file_type, FileType::Data | FileType::Metadata) {
                continue;
            }
            if let BlockDataState::Decrypted(references) = &file.block_data {
                crate::format::wire::validate_unique_block_references(references)?;
                let actual = references.iter().try_fold(0u64, |total, (hash, _)| {
                    let original_size =
                        block_size(*hash).ok_or(PithosError::MissingBlockDescriptor)?;
                    total.checked_add(original_size).ok_or({
                        PithosError::AccessibleFileSizeMismatch {
                            expected: file.file_size,
                            actual: u64::MAX,
                        }
                    })
                })?;
                if actual != file.file_size {
                    return Err(PithosError::AccessibleFileSizeMismatch {
                        expected: file.file_size,
                        actual,
                    });
                }
            }
        }
        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub fn next_free_file_index(&self) -> Result<u64, PithosError> {
        self.files
            .next_free_id(self.parent_directory_offset.is_some())
    }

    #[tracing::instrument(level = "trace", skip(self, file_id))]
    pub fn get_file_by_id(&self, file_id: u64) -> Option<&FileEntry> {
        self.files.get_by_id(file_id)
    }
}
