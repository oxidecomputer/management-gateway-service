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
use gateway_messages::SerializedSize;
use gateway_messages::SpResponse;
use gateway_messages::SpSlotId;
use gateway_messages::WatchdogId;

#[test]
fn sp_response() {
    let mut out = [0; SpResponse::MAX_SIZE];
    let response = SpResponse::EnableSpSlotWatchdogAck;
    let expected = [42];
    assert_serialized(&mut out, &expected, &response);

    let response = SpResponse::DisableSpSlotWatchdogAck;
    let expected = [43];
    assert_serialized(&mut out, &expected, &response);
}

#[test]
fn host_request() {
    let mut out = [0; MgsRequest::MAX_SIZE];
    let request = MgsRequest::EnableSpSlotWatchdog {
        revert_to_slot: SpSlotId::A,
        time_ms: 0x12345,
        id: WatchdogId([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
    };
    let expected = [
        42, // tag
        0,  // slot ID
        0x45, 0x23, 0x01, 0x00, // time_ms
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, // id
    ];
    assert_serialized(&mut out, &expected, &request);
}

#[test]
fn sp_slot_id() {
    let mut out = [0; SpSlotId::MAX_SIZE];

    for slot in [SpSlotId::A, SpSlotId::B] {
        // using a match to force exhaustive checking here
        let serialized = match slot {
            SpSlotId::A => [0],
            SpSlotId::B => [1],
        };
        assert_serialized(&mut out, &serialized, &slot);
    }
}
