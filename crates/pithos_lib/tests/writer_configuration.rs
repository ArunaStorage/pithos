mod common;

use common::writer::options;
use pithos_lib::archive::{ArchiveWriter, CdcConfig, WriteOptions};
use pithos_lib::crypto::PrivateKey;
use pithos_lib::error::PithosError;

#[test]
fn creation_rejects_empty_recipients_without_losing_sink() {
    let sender = PrivateKey::generate();
    let error = match ArchiveWriter::create(Vec::new(), WriteOptions::new(sender, Vec::new())) {
        Ok(_) => panic!("empty recipients must be rejected"),
        Err(error) => error,
    };
    assert!(matches!(
        error.error(),
        PithosError::WriterRequiresRecipient
    ));
    assert!(error.into_incomplete().is_empty());
}

#[test]
fn invalid_cdc_is_rejected_before_writer_creation() {
    assert!(matches!(
        CdcConfig::new(32, 16, 64),
        Err(PithosError::InvalidCdcConfig { .. })
    ));
    for (min, avg, max) in [(63, 256, 1024), (64, 255, 1024), (64, 256, 1023)] {
        assert!(matches!(
            CdcConfig::new(min, avg, max),
            Err(PithosError::InvalidCdcConfig { .. })
        ));
    }
}

#[test]
fn cdc_accepts_every_fastcdc_boundary_and_rejects_outside_values_without_panicking() {
    use fastcdc::v2020::{
        AVERAGE_MAX, AVERAGE_MIN, MAXIMUM_MAX, MAXIMUM_MIN, MINIMUM_MAX, MINIMUM_MIN,
    };

    assert!(CdcConfig::new(MINIMUM_MIN, AVERAGE_MIN, MAXIMUM_MIN).is_ok());
    assert!(CdcConfig::new(MINIMUM_MAX, AVERAGE_MAX, MAXIMUM_MAX).is_ok());
    for (min, avg, max) in [
        (MINIMUM_MIN - 1, AVERAGE_MIN, MAXIMUM_MIN),
        (MINIMUM_MAX + 1, AVERAGE_MAX, MAXIMUM_MAX),
        (MINIMUM_MIN, AVERAGE_MIN - 1, MAXIMUM_MIN),
        (MINIMUM_MIN, AVERAGE_MAX + 1, MAXIMUM_MAX),
        (MINIMUM_MIN, AVERAGE_MIN, MAXIMUM_MIN - 1),
        (MINIMUM_MIN, AVERAGE_MIN, MAXIMUM_MAX + 1),
    ] {
        assert!(matches!(
            CdcConfig::new(min, avg, max),
            Err(PithosError::InvalidCdcConfig { .. })
        ));
    }
}

#[test]
fn duplicate_recipients_are_rejected_before_header_output() {
    let sender = PrivateKey::generate();
    let recipient = sender.public_key();
    let error = match ArchiveWriter::create(
        Vec::new(),
        WriteOptions::new(sender, vec![recipient, recipient]),
    ) {
        Ok(_) => panic!("duplicate recipients must be rejected"),
        Err(error) => error,
    };
    assert!(matches!(error.error(), PithosError::DuplicateRecipientKey));
    assert!(error.into_incomplete().is_empty());
}

#[test]
fn finish_writes_one_header_and_one_terminal_directory_for_empty_archive() {
    let bytes = ArchiveWriter::create(Vec::new(), options())
        .unwrap()
        .finish()
        .unwrap();
    assert_eq!(&bytes[..4], b"PITH");
    assert_eq!(
        bytes
            .windows(8)
            .filter(|window| *window == b"PITHOSDR")
            .count(),
        1
    );
}

#[test]
fn open_writer_cannot_be_recovered_as_incomplete() {
    let writer = ArchiveWriter::create(Vec::new(), options()).unwrap();
    assert!(writer.into_incomplete().is_err());
}
