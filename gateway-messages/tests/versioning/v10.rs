// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The tests in this module check that the serialized form of messages from MGS
//! protocol version 10 have not changed.
//!
//! If a test in this module fails, _do not change the test_! This means you
//! have changed, deleted, or reordered an existing message type or enum
//! variant, and you should revert that change. This will remain true until we
//! bump the `version::MIN` to a value higher than 10, at which point these tests
//! can be removed as we will stop supporting v10.

use super::assert_serialized;
use gateway_messages::MgsRequest;
use gateway_messages::RotError;
use gateway_messages::SerializedSize;
use gateway_messages::SpError;
use gateway_messages::SpResponse;
use gateway_messages::SprotProtocolError;

// Test SprotProtocolError
#[test]
fn sprot_protocol_errors() {
    let mut out = [0; MgsRequest::MAX_SIZE];

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
        (SprotProtocolError::Desynchronized, &[13]),
    ] {
        // Test SpError variants encoded in an SpResponse
        let response = SpResponse::Error(SpError::Sprot(error));
        let mut expected = vec![17, 29];
        expected.extend_from_slice(serialized);
        assert_serialized(&mut out, &expected, &response);

        // Test RotError variants
        let response = RotError::Sprot(error);
        let mut expected = vec![1];
        expected.extend_from_slice(serialized);
        assert_serialized(&mut out, &expected, &response);
    }
}
