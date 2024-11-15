// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The tests in this module check that the serialized form of messages from MGS
//! protocol version 4 have not changed.
//!
//! If a test in this module fails, _do not change the test_! This means you
//! have changed, deleted, or reordered an existing message type or enum
//! variant, and you should revert that change. This will remain true until we
//! bump the `version::MIN` to a value higher than 4, at which point these tests
//! can be removed as we will stop supporting v4.

use super::assert_serialized;
use gateway_messages::RotError;
use gateway_messages::SpError;
use gateway_messages::SpResponse;
use gateway_messages::SpiError;
use gateway_messages::SprocketsError;
use gateway_messages::SprotProtocolError;
use gateway_messages::UpdateError;

// Test SprotProtocolError
#[test]
fn sprot_errors() {
    for (error, serialized) in [
        (SprotProtocolError::InvalidCrc, &[0_u8] as &[_]),
        (SprotProtocolError::FlowError, &[1]),
        (SprotProtocolError::UnsupportedProtocol, &[2]),
        (SprotProtocolError::BadMessageType, &[3]),
        (SprotProtocolError::BadMessageLength, &[4]),
        (SprotProtocolError::CannotAssertCSn, &[5]),
        (SprotProtocolError::Timeout, &[6]),
        (SprotProtocolError::Deserialization, &[7]),
        (SprotProtocolError::RotIrqRemainsAsserted, &[8]),
        (SprotProtocolError::UnexpectedResponse, &[9]),
        (SprotProtocolError::BadUpdateStatus, &[10]),
        (SprotProtocolError::TaskRestarted, &[11]),
        (
            SprotProtocolError::Unknown(0xABCDEFAB),
            // little endian
            &[12, 0xAB, 0xEF, 0xCD, 0xAB],
        ),
    ] {
        // Test SpError variants encoded in an SpResponse
        let response = SpResponse::Error(SpError::Sprot(error));
        let mut expected = vec![17, 29];
        expected.extend_from_slice(serialized);
        assert_serialized(&expected, &response);

        // Test RotError variants
        let response = RotError::Sprot(error);
        let mut expected = vec![1];
        expected.extend_from_slice(serialized);
        assert_serialized(&expected, &response);
    }
}

// Test SpiError
#[test]
fn spi_error() {
    for (error, serialized) in [
        (SpiError::BadTransferSize, &[0_u8] as &[_]),
        (SpiError::TaskRestarted, &[1]),
        (SpiError::NothingToRelease, &[2]),
        (SpiError::BadDevice, &[3]),
        (
            SpiError::Unknown(0xABCDEFAB),
            // little endian
            &[4, 0xAB, 0xEF, 0xCD, 0xAB],
        ),
    ] {
        // Test SpError variants encoded in an SpResponse
        let response = SpResponse::Error(SpError::Spi(error));
        let mut expected = vec![17, 30];
        expected.extend_from_slice(serialized);
        assert_serialized(&expected, &response);

        // Test RotError variants
        let response = RotError::Spi(error);
        let mut expected = vec![2];
        expected.extend_from_slice(serialized);
        assert_serialized(&expected, &response);
    }
}

// Test SprocketsError
#[test]
fn sprockets_error() {
    for (error, serialized) in [
        (SprocketsError::BadEncoding, &[0_u8] as &[_]),
        (SprocketsError::UnsupportedVersion, &[1]),
        (
            SprocketsError::Unknown(0xABCDEFAB),
            // little endian
            &[2, 0xAB, 0xEF, 0xCD, 0xAB],
        ),
    ] {
        // Test SpError variants encoded in an SpResponse
        let response = SpResponse::Error(SpError::Sprockets(error));
        let mut expected = vec![17, 31];
        expected.extend_from_slice(serialized);
        assert_serialized(&expected, &response);

        // Test RotError variants
        let response = RotError::Sprockets(error);
        let mut expected = vec![3];
        expected.extend_from_slice(serialized);
        assert_serialized(&expected, &response);
    }
}

// Test UpdateError
#[test]
fn update_error() {
    for (error, serialized) in [
        (UpdateError::BadLength, &[0_u8] as &[_]),
        (UpdateError::UpdateInProgress, &[1]),
        (UpdateError::OutOfBounds, &[2]),
        (UpdateError::EccDoubleErr, &[3]),
        (UpdateError::EccSingleErr, &[4]),
        (UpdateError::SecureErr, &[5]),
        (UpdateError::ReadProtErr, &[6]),
        (UpdateError::WriteEraseErr, &[7]),
        (UpdateError::InconsistencyErr, &[8]),
        (UpdateError::StrobeErr, &[9]),
        (UpdateError::ProgSeqErr, &[10]),
        (UpdateError::WriteProtErr, &[11]),
        (UpdateError::BadImageType, &[12]),
        (UpdateError::UpdateAlreadyFinished, &[13]),
        (UpdateError::UpdateNotStarted, &[14]),
        (UpdateError::RunningImage, &[15]),
        (UpdateError::FlashError, &[16]),
        (UpdateError::FlashIllegalRead, &[17]),
        (UpdateError::FlashReadFail, &[18]),
        (UpdateError::MissingHeaderBlock, &[19]),
        (UpdateError::InvalidHeaderBlock, &[20]),
        (UpdateError::ImageBoardMismatch, &[21]),
        (UpdateError::ImageBoardUnknown, &[22]),
        (UpdateError::TaskRestarted, &[23]),
        (UpdateError::NotImplemented, &[24]),
        (
            UpdateError::Unknown(0xABCDEFAB),
            // little endian
            &[25, 0xAB, 0xEF, 0xCD, 0xAB],
        ),
    ] {
        // Test SpError variants encoded in an SpResponse
        let response = SpResponse::Error(SpError::Update(error));
        let mut expected = vec![17, 32];
        expected.extend_from_slice(serialized);
        assert_serialized(&expected, &response);

        // Test RotError variants
        let response = RotError::Update(error);
        let mut expected = vec![4];
        expected.extend_from_slice(serialized);
        assert_serialized(&expected, &response);
    }
}
