use crate::archive::index::ArchiveIndex;
use crate::archive::types::{BlockDescriptor, BlockHash, ContentState, Entry, FileId, ReadRange};
use crate::error::PithosError;
use std::ops::Range;

/// A block must be completely verified before its `output` slice is released.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PlannedBlock {
    pub(crate) hash: BlockHash,
    pub(crate) descriptor: BlockDescriptor,
    pub(crate) output: Range<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReadPlan {
    pub(crate) file_size: u64,
    pub(crate) blocks: Vec<PlannedBlock>,
}

pub(crate) fn full_file_plan(index: &ArchiveIndex, id: FileId) -> Result<ReadPlan, PithosError> {
    let content = content_entry(index, id)?;
    let range = ReadRange::new(0..content.size, content.size)?;
    range_plan(index, id, range)
}

pub(crate) fn range_plan(
    index: &ArchiveIndex,
    id: FileId,
    range: ReadRange,
) -> Result<ReadPlan, PithosError> {
    let content = content_entry(index, id)?;
    let ContentState::Available(references) = &content.content else {
        return Err(PithosError::ContentUnavailable);
    };
    let mut blocks = Vec::new();
    let mut cursor = 0u64;
    for hash in references.iter() {
        let descriptor = index
            .descriptor(hash)
            .ok_or(PithosError::MissingBlockDescriptor)?;
        let end = cursor.checked_add(descriptor.original_size).ok_or(
            PithosError::AccessibleFileSizeMismatch {
                expected: content.size,
                actual: u64::MAX,
            },
        )?;
        if end > range.start() && cursor < range.end() {
            let output_start = range.start().saturating_sub(cursor);
            let output_end = range.end().min(end) - cursor;
            blocks.push(PlannedBlock {
                hash,
                descriptor: descriptor.clone(),
                output: usize::try_from(output_start).map_err(|_| {
                    PithosError::InvalidDirectoryRange {
                        operation: "convert range index",
                    }
                })?..usize::try_from(output_end).map_err(|_| {
                    PithosError::InvalidDirectoryRange {
                        operation: "convert range index",
                    }
                })?,
            });
        }
        cursor = end;
    }
    Ok(ReadPlan {
        file_size: content.size,
        blocks,
    })
}

fn content_entry(
    index: &ArchiveIndex,
    id: FileId,
) -> Result<&crate::archive::types::ContentEntry, PithosError> {
    index
        .entry(id)
        .and_then(|entry| match &entry.entry {
            Entry::File(content) | Entry::Metadata(content) => Some(content),
            Entry::Directory(_) | Entry::Symlink { .. } => None,
        })
        .ok_or_else(|| {
            PithosError::InvalidBlockDataState("only data/metadata entries have content".into())
        })
}
