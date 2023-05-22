// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The tests in this module check that the serialized form of messages from MGS
//! protocol version 7 have not changed.
//!
//! If a test in this module fails, _do not change the test_! This means you
//! have changed, deleted, or reordered an existing message type or enum
//! variant, and you should revert that change. This will remain true until we
//! bump the `version::MIN` to a value higher than 6, at which point these tests
//! can be removed as we will stop supporting v6.

use super::assert_serialized;
use gateway_messages::RotError;
use gateway_messages::SerializedSize;
use gateway_messages::SpResponse;
use gateway_messages::SpiError;
use gateway_messages::SprocketsError;
use gateway_messages::SprotProtocolError;
use gateway_messages::UpdateError;
use gateway_messages::UpdateId;
use gateway_messages::UpdateStatus;

#[test]
fn sp_response() {
    let mut out = [0; SpResponse::MAX_SIZE];

    // The full set of nested error serialization was tested back in v4; we'll
    // just repeat a few of those here.
    for (rot_error, serialized) in [
        (
            RotError::MessageError { code: 0x01020304 },
            &[0_u8, 4, 3, 2, 1] as &[_],
        ),
        (RotError::Sprot(SprotProtocolError::InvalidCrc), &[1, 0]),
        (RotError::Spi(SpiError::TaskRestarted), &[2, 1]),
        (
            RotError::Sprockets(SprocketsError::Unknown(0x05060708)),
            &[3, 2, 8, 7, 6, 5],
        ),
        (RotError::Update(UpdateError::RunningImage), &[4, 15]),
    ] {
        let update_id = [
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa,
            0xfb, 0xfc, 0xfd, 0xfe, 0xff,
        ];
        let status = UpdateStatus::RotError {
            id: UpdateId(update_id),
            error: rot_error,
        };
        let response = SpResponse::UpdateStatus(status);
        let mut expected = vec![
            8, // SpResponse::UpdateStatus
            7, // UpdateStatus::RotError
        ];
        expected.extend_from_slice(&update_id);
        expected.extend_from_slice(serialized);
        assert_serialized(&mut out, &expected, &response);
    }
}
