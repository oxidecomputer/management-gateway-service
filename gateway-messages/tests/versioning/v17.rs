use super::assert_serialized;
use gateway_messages::SerializedSize;
use gateway_messages::SpResponse;
use gateway_messages::UpdateError;

#[test]
fn error_enums() {
    let mut out = [0; SpResponse::MAX_SIZE];

    let response: [UpdateError; 5] = [
        UpdateError::InvalidArchive,
        UpdateError::ImageMismatch,
        UpdateError::SignatureNotValidated,
        UpdateError::VersionNotSupported,
        UpdateError::RollbackProtection,
    ];
    let expected = vec![30, 31, 32, 33, 34];
    assert_serialized(&mut out, &expected, &response);
}
