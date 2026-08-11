use pithos_lib::archive::{
    AccessKeys, Archive, ArchivePath, ArchiveWriter, EntryMetadata, OpenOptions, ProcessingOptions,
    WriteOptions,
};
use pithos_lib::crypto::PrivateKey;
use pithos_lib::fs::ingest::{InputManifest, build_input_manifest};
use pithos_lib::fs::{FsError, extract};
use pithos_lib::source::MemorySource;
use std::fs::{self, File, FileTimes};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{Duration, SystemTime};

fn write_manifest(manifest: &InputManifest) -> Archive<MemorySource> {
    let sender = PrivateKey::generate();
    let mut writer = ArchiveWriter::create(
        Vec::new(),
        WriteOptions::new(sender.duplicate(), vec![sender.public_key()]),
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
fn ingestion_records_only_linux_permission_bits() {
    let temporary = tempfile::tempdir().unwrap();
    let input = temporary.path().join("mode.bin");
    fs::write(&input, b"mode").unwrap();
    fs::set_permissions(&input, fs::Permissions::from_mode(0o640)).unwrap();

    let archive = write_manifest(&build_input_manifest(&[input]).unwrap());
    let entry = archive.entry("mode.bin").unwrap().unwrap();

    assert_eq!(entry.permissions, 0o640);
}

#[test]
fn ingestion_normalizes_pre_epoch_timestamps_to_zero() {
    let temporary = tempfile::tempdir().unwrap();
    let input = temporary.path().join("pre-epoch.bin");
    fs::write(&input, b"timestamp").unwrap();
    File::options()
        .write(true)
        .open(&input)
        .unwrap()
        .set_times(FileTimes::new().set_modified(SystemTime::UNIX_EPOCH - Duration::from_secs(1)))
        .unwrap();

    let archive = write_manifest(&build_input_manifest(&[input]).unwrap());
    let entry = archive.entry("pre-epoch.bin").unwrap().unwrap();

    assert_eq!(entry.modified, 0);
}

#[test]
fn ingestion_rejects_unix_sockets_with_typed_path_context() {
    let temporary = tempfile::tempdir().unwrap();
    let socket = temporary.path().join("input.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();

    let error = match build_input_manifest(std::slice::from_ref(&socket)) {
        Ok(_) => panic!("socket ingestion unexpectedly succeeded"),
        Err(error) => error,
    };

    let error = (&error as &(dyn std::error::Error + 'static))
        .downcast_ref::<FsError>()
        .expect("filesystem operations must return FsError directly");
    assert!(matches!(
        error,
        FsError::UnsupportedEntry { path, kind }
            if path == &socket && *kind == "socket"
    ));
}

#[test]
fn ingestion_rejects_fifos_with_typed_path_context() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let fifo = source.join("input.fifo");
    fs::create_dir(&source).unwrap();
    rustix::fs::mkfifoat(rustix::fs::CWD, &fifo, rustix::fs::Mode::RWXU).unwrap();

    let error = match build_input_manifest(&[source]) {
        Ok(_) => panic!("FIFO ingestion unexpectedly succeeded"),
        Err(error) => error,
    };
    let error = (&error as &(dyn std::error::Error + 'static))
        .downcast_ref::<FsError>()
        .expect("filesystem operations must return FsError directly");
    assert!(matches!(
        error,
        FsError::UnsupportedEntry { path, kind }
            if path == &fifo && *kind == "FIFO"
    ));
}

#[test]
fn extraction_preserves_files_directories_and_contained_dangling_symlinks() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    fs::create_dir_all(source.join("nested")).unwrap();
    fs::write(source.join("payload.bin"), b"payload").unwrap();
    std::os::unix::fs::symlink("../payload.bin", source.join("nested/live")).unwrap();
    std::os::unix::fs::symlink("../missing.bin", source.join("nested/dangling")).unwrap();
    let archive = write_manifest(&build_input_manifest(&[source]).unwrap());
    let output = temporary.path().join("output");

    for path in ["nested", "payload.bin", "nested/live", "nested/dangling"] {
        extract(&archive, path, &output).unwrap();
    }

    assert!(
        fs::symlink_metadata(output.join("nested"))
            .unwrap()
            .is_dir()
    );
    assert_eq!(fs::read(output.join("payload.bin")).unwrap(), b"payload");
    assert_eq!(
        fs::read_link(output.join("nested/live")).unwrap(),
        Path::new("../payload.bin")
    );
    assert_eq!(
        fs::read_link(output.join("nested/dangling")).unwrap(),
        Path::new("../missing.bin")
    );
    assert!(fs::metadata(output.join("nested/dangling")).is_err());
    assert!(!output.join("missing.bin").exists());
}

#[test]
fn extraction_uses_host_defaults_instead_of_archived_mode_and_timestamps() {
    let sender = PrivateKey::generate();
    let mut writer = ArchiveWriter::create(
        Vec::new(),
        WriteOptions::new(sender.duplicate(), vec![sender.public_key()]),
    )
    .unwrap();
    writer
        .add_file(
            ArchivePath::new("data.bin").unwrap(),
            EntryMetadata::new(1, 1, 0o111),
            ProcessingOptions::default(),
            Some(7),
            std::io::Cursor::new(b"content"),
        )
        .unwrap();
    let archive = Archive::open(
        MemorySource::new(writer.finish().unwrap()),
        OpenOptions::default().with_access_keys(AccessKeys::new().with_key(sender)),
    )
    .unwrap();
    let temporary = tempfile::tempdir().unwrap();

    extract(&archive, "data.bin", temporary.path()).unwrap();

    let output = temporary.path().join("data.bin");
    assert_eq!(fs::read(&output).unwrap(), b"content");
    let metadata = fs::metadata(output).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o111, 0);
    assert!(
        metadata
            .modified()
            .unwrap()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            > 1
    );
}

#[test]
fn extraction_rejects_a_symlink_in_the_destination_root_path() {
    let temporary = tempfile::tempdir().unwrap();
    let input = temporary.path().join("payload.bin");
    fs::write(&input, b"payload").unwrap();
    let archive = write_manifest(&build_input_manifest(&[input]).unwrap());
    let outside = temporary.path().join("outside");
    fs::create_dir(&outside).unwrap();
    let redirect = temporary.path().join("redirect");
    std::os::unix::fs::symlink(&outside, &redirect).unwrap();
    let destination = redirect.join("created-through-link");

    assert!(extract(&archive, "payload.bin", &destination).is_err());
    assert!(!outside.join("created-through-link").exists());
}
