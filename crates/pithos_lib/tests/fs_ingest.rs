use pithos_lib::archive::{
    AccessKeys, Archive, ArchiveWriter, EntryKind, OpenOptions, ProcessingOptions, WriteOptions,
};
use pithos_lib::crypto::PrivateKey;
use pithos_lib::error::PithosError;
use pithos_lib::fs::FsError;
use pithos_lib::fs::ingest::build_input_manifest;
use pithos_lib::source::MemorySource;
use std::fs;
use std::path::Path;

fn write_manifest(manifest: &pithos_lib::fs::ingest::InputManifest) -> Archive<MemorySource> {
    let sender = PrivateKey::generate();
    let recipient = sender.public_key();
    let mut writer = ArchiveWriter::create(
        Vec::new(),
        WriteOptions::new(sender.duplicate(), vec![recipient]),
    )
    .unwrap();
    manifest
        .ingest(&mut writer, ProcessingOptions::default())
        .unwrap();
    Archive::open(
        MemorySource::new(writer.finish().unwrap()),
        OpenOptions::default().with_access_keys(AccessKeys::new().with_key(sender)),
    )
    .unwrap()
}

#[test]
fn manifest_ingests_files_directories_and_safe_symlinks() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    fs::create_dir_all(source.join("nested")).unwrap();
    fs::write(source.join("nested/file.txt"), b"content").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("file.txt", source.join("nested/link")).unwrap();

    let archive = write_manifest(&build_input_manifest(&[source]).unwrap());
    assert!(matches!(
        archive.entry("nested").unwrap().unwrap().kind,
        EntryKind::Directory
    ));
    assert!(matches!(
        archive.entry("nested/file.txt").unwrap().unwrap().kind,
        EntryKind::File { size: 7, .. }
    ));
    #[cfg(unix)]
    assert!(matches!(
        archive.entry("nested/link").unwrap().unwrap().kind,
        EntryKind::Symlink { ref target } if target == "file.txt"
    ));
}

#[cfg(unix)]
#[test]
fn manifest_rejects_unsafe_and_non_utf8_symlink_targets() {
    use std::os::unix::ffi::OsStringExt;

    let temporary = tempfile::tempdir().unwrap();
    let absolute = temporary.path().join("absolute");
    std::os::unix::fs::symlink("/outside", &absolute).unwrap();
    assert!(matches!(
        build_input_manifest(&[absolute]),
        Err(FsError::Core {
            source: PithosError::InvalidSymlinkTarget { .. },
            ..
        })
    ));

    let escaping = temporary.path().join("escaping");
    std::os::unix::fs::symlink("../outside", &escaping).unwrap();
    assert!(matches!(
        build_input_manifest(&[escaping]),
        Err(FsError::Core {
            source: PithosError::InvalidSymlinkTarget { .. },
            ..
        })
    ));

    let non_utf8 = temporary.path().join("non-utf8-target");
    std::os::unix::fs::symlink(
        Path::new(&std::ffi::OsString::from_vec(b"bad\xff".to_vec())),
        &non_utf8,
    )
    .unwrap();
    assert!(matches!(
        build_input_manifest(&[non_utf8]),
        Err(FsError::InvalidUtf8Path { .. })
    ));
}

#[cfg(unix)]
#[test]
fn manifest_rejects_non_utf8_archive_paths() {
    use std::os::unix::ffi::OsStringExt;

    let temporary = tempfile::tempdir().unwrap();
    let input = temporary
        .path()
        .join(std::ffi::OsString::from_vec(b"input-\xff".to_vec()));
    fs::write(&input, b"content").unwrap();
    assert!(matches!(
        build_input_manifest(&[input]),
        Err(FsError::InvalidUtf8Path { .. })
    ));
}

#[test]
fn manifest_rejects_duplicate_and_conflicting_archive_paths() {
    let temporary = tempfile::tempdir().unwrap();
    let left = temporary.path().join("left");
    let right = temporary.path().join("right");
    fs::create_dir_all(&left).unwrap();
    fs::create_dir_all(&right).unwrap();
    let duplicate_left = left.join("same");
    let duplicate_right = right.join("same");
    fs::write(&duplicate_left, b"left").unwrap();
    fs::write(&duplicate_right, b"right").unwrap();
    assert!(matches!(
        build_input_manifest(&[duplicate_left, duplicate_right]),
        Err(FsError::Core {
            source: PithosError::PathOccupied(_),
            ..
        })
    ));

    let file = left.join("node");
    fs::write(&file, b"file").unwrap();
    fs::create_dir_all(right.join("node")).unwrap();
    fs::write(right.join("node/child"), b"child").unwrap();
    assert!(matches!(
        build_input_manifest(&[file, right]),
        Err(FsError::Core {
            source: PithosError::InvalidArchivePath { .. },
            ..
        })
    ));
}

#[test]
fn manifest_rejects_missing_input_and_retains_preflight_opened_files() {
    let temporary = tempfile::tempdir().unwrap();
    assert!(matches!(
        build_input_manifest(&[temporary.path().join("missing")]),
        Err(FsError::Host { .. })
    ));

    let first = temporary.path().join("first");
    let second = temporary.path().join("second");
    fs::write(&first, b"first").unwrap();
    fs::write(&second, b"second").unwrap();
    let manifest = build_input_manifest(&[first, second.clone()]).unwrap();
    fs::remove_file(second).unwrap();

    let sender = PrivateKey::generate();
    let recipient = sender.public_key();
    let mut writer = ArchiveWriter::create(
        Vec::new(),
        WriteOptions::new(sender.duplicate(), vec![recipient]),
    )
    .unwrap();
    manifest
        .ingest(&mut writer, ProcessingOptions::default())
        .unwrap();
    let archive = Archive::open(
        MemorySource::new(writer.finish().unwrap()),
        OpenOptions::default().with_access_keys(AccessKeys::new().with_key(sender)),
    )
    .unwrap();
    assert!(archive.entry("first").unwrap().is_some());
    let mut contents = Vec::new();
    archive.copy_to("second", &mut contents).unwrap();
    assert_eq!(contents, b"second");
}

#[test]
fn wide_directory_ingestion_and_archive_traversal_complete() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    fs::create_dir(&source).unwrap();
    for index in 0..1_000 {
        fs::write(source.join(format!("entry-{index:04}")), b"content").unwrap();
    }

    let archive = write_manifest(&build_input_manifest(&[source]).unwrap());

    assert_eq!(archive.entries().len(), 1_000);
    assert!(archive.entry("entry-0000").unwrap().is_some());
    assert!(archive.entry("entry-0999").unwrap().is_some());
}
