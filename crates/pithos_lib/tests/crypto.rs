use pithos_lib::crypto::{
    CryptoError, generate_private_key, parse_private_pem, parse_public_pem, serialize_public_pem,
};
use pkcs8::{Document, LineEnding};

#[test]
fn curated_pem_api_preserves_fixture_bytes_and_redacts_private_debug() {
    let private_pem = std::fs::read("tests/data/keys/sender_private.pem").unwrap();
    let private = parse_private_pem(&private_pem).unwrap();
    assert_eq!(&*private.to_private_pem_bytes().unwrap(), &private_pem);
    assert!(!format!("{private:?}").contains("0f"));

    let public_pem = std::fs::read("tests/data/keys/sender_public.pem").unwrap();
    let public = parse_public_pem(&public_pem).unwrap();
    assert_eq!(serialize_public_pem(&public).unwrap(), public_pem);
    assert_eq!(
        private.public_key().to_public_pem_bytes().unwrap(),
        public_pem
    );
}

#[test]
fn generated_private_keys_are_owned_and_have_public_identities() {
    let first = generate_private_key();
    let second = generate_private_key();
    assert_ne!(
        first.public_key().to_public_pem_bytes().unwrap(),
        second.public_key().to_public_pem_bytes().unwrap()
    );
}

#[test]
fn malformed_pem_is_rejected_by_both_curated_parsers() {
    let malformed = b"this is not valid PEM data";
    assert!(matches!(
        parse_private_pem(malformed),
        Err(CryptoError::InvalidKeyDocument)
    ));
    assert!(matches!(
        parse_public_pem(malformed),
        Err(CryptoError::InvalidKeyDocument)
    ));
}

#[test]
fn invalid_utf8_private_pem_is_rejected() {
    assert!(matches!(
        parse_private_pem(&[0xff, 0xfe, 0xfd]),
        Err(CryptoError::InvalidKeyDocument)
    ));
}

#[test]
fn non_contributory_x25519_public_keys_are_rejected_at_every_public_boundary() {
    let public_pem = std::fs::read_to_string("tests/data/keys/sender_public.pem").unwrap();
    let (_, document) = Document::from_pem(&public_pem).unwrap();
    let mut der = document.as_bytes().to_vec();
    der[12..].fill(0);
    let document = Document::try_from(der.as_slice()).unwrap();
    let zero_public_pem = document.to_pem("PUBLIC KEY", LineEnding::LF).unwrap();

    assert!(parse_public_pem(zero_public_pem.as_bytes()).is_err());
}
