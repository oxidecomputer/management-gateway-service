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
use gateway_messages::RotWatchdogError;
use gateway_messages::SerializedSize;
use gateway_messages::SpComponent;
use gateway_messages::SpError;
use gateway_messages::SpResponse;
use gateway_messages::WatchdogError;

#[test]
fn sp_response() {
    let mut out = [0; SpResponse::MAX_SIZE];

    let response = SpResponse::DisableComponentWatchdogAck;
    let expected = [42];
    assert_serialized(&mut out, &expected, &response);

    let response = SpResponse::ComponentWatchdogSupportedAck;
    let expected = [43];
    assert_serialized(&mut out, &expected, &response);
}

#[test]
fn host_request() {
    let mut out = [0; MgsRequest::MAX_SIZE];
    let request = MgsRequest::ResetComponentTriggerWithWatchdog {
        component: SpComponent::SP_ITSELF,
        time_ms: 0x12345,
    };
    let expected = [
        42, // tag
        b's', b'p', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // component
        0x45, 0x23, 0x01, 0x00, // time_ms
    ];
    assert_serialized(&mut out, &expected, &request);

    let request = MgsRequest::DisableComponentWatchdog {
        component: SpComponent::SP_ITSELF,
    };
    let expected = [
        43, // tag
        b's', b'p', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    assert_serialized(&mut out, &expected, &request);

    let request = MgsRequest::ComponentWatchdogSupported {
        component: SpComponent::SP_ITSELF,
    };
    let expected = [
        44, // tag
        b's', b'p', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    assert_serialized(&mut out, &expected, &request);
}

#[test]
fn watchdog_error() {
    let mut out = [0; SpResponse::MAX_SIZE];

    for err in [
        WatchdogError::NoCompletedUpdate,
        WatchdogError::Rot(RotWatchdogError::DongleDetected),
        WatchdogError::Rot(RotWatchdogError::Other(123)),
    ] {
        // using a match to force exhaustive checking here
        let serialized = match err {
            WatchdogError::NoCompletedUpdate => [17, 35, 0].as_slice(),
            WatchdogError::Rot(RotWatchdogError::DongleDetected) => {
                &[17, 35, 1, 0]
            }
            WatchdogError::Rot(RotWatchdogError::Other(..)) => {
                &[17, 35, 1, 1, 123, 0, 0, 0]
            }
        };
        let response = SpResponse::Error(SpError::Watchdog(err));
        assert_serialized(&mut out, serialized, &response);
    }
}
