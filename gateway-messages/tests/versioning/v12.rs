// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The tests in this module check that the serialized form of messages from MGS
//! protocol version 12 have not changed.
//!
//! If a test in this module fails, _do not change the test_! This means you
//! have changed, deleted, or reordered an existing message type or enum
//! variant, and you should revert that change. This will remain true until we
//! bump the `version::MIN` to a value higher than 11, at which point these
//! tests can be removed as we will stop supporting v11.

use super::assert_serialized;
use gateway_messages::MgsRequest;
use gateway_messages::RotError;
use gateway_messages::SerializedSize;
use gateway_messages::SpError;
use gateway_messages::SpResponse;
use gateway_messages::WatchdogError;

#[test]
fn sp_response() {
    let mut out = [0; SpResponse::MAX_SIZE];

    let response = SpResponse::DisableSpSlotWatchdogAck;
    let expected = [42];
    assert_serialized(&mut out, &expected, &response);
}

#[test]
fn host_request() {
    let mut out = [0; MgsRequest::MAX_SIZE];
    let request = MgsRequest::ResetWithWatchdog { time_ms: 0x12345 };
    let expected = [
        42, // tag
        0x45, 0x23, 0x01, 0x00, // time_ms
    ];
    assert_serialized(&mut out, &expected, &request);

    let request = MgsRequest::DisableSpSlotWatchdog;
    let expected = [
        43, // tag
    ];
    assert_serialized(&mut out, &expected, &request);
}

#[test]
fn watchdog_error() {
    let mut out = [0; SpResponse::MAX_SIZE];

    for err in [WatchdogError::SpCtrl, WatchdogError::NoCompletedUpdate] {
        // using a match to force exhaustive checking here
        let serialized = match err {
            WatchdogError::SpCtrl => [17, 35, 0],
            WatchdogError::NoCompletedUpdate => [17, 35, 1],
        };
        let response = SpResponse::Error(SpError::Watchdog(err));
        assert_serialized(&mut out, &serialized, &response);
    }
}

#[test]
fn rot_watchdog_error() {
    let mut out = [0; RotError::MAX_SIZE];

    let err = WatchdogError::SpCtrl;
    // using a match to force exhaustive checking here
    let serialized = match err {
        WatchdogError::SpCtrl => [5, 0],
        WatchdogError::NoCompletedUpdate => [5, 1],
    };
    // TODO do we need both SpError::Watchdog and RotError::Watchdog?
    let response = RotError::Watchdog(err);
    assert_serialized(&mut out, &serialized, &response);
}