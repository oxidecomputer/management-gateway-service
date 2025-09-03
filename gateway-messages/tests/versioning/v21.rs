// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! The tests in this module check that the serialized form of messages from MGS
//! protocol version 2 have not changed.
//!
//! If a test in this module fails, _do not change the test_! This means you
//! have changed, deleted, or reordered an existing message type or enum
//! variant, and you should revert that change. This will remain true until we
//! bump the `version::MIN` to a value higher than 2, at which point these tests
//! can be removed as we will stop supporting v2.

use gateway_messages::MgsRequest;
use gateway_messages::SpComponent;
use gateway_messages::SpResponse;
use gateway_messages::UpdateError;

use super::assert_serialized;

#[test]
fn mgs_request() {
    let request = MgsRequest::ComponentCancelPendingActiveSlot {
        component: SpComponent::ROT,
        slot: 0x0102,
        persist: true,
    };
    #[rustfmt::skip]
    let expected = &[
        50, // ComponentCancelPendingActiveSlot
        b'r', b'o', b't', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // ROT
        2, 1, // slot
        1, // persist = true
    ];
    assert_serialized(expected, &request);
}

#[test]
fn sp_response() {
    let response = SpResponse::ComponentCancelPendingActiveSlotAck;
    let expected = &[52];
    assert_serialized(expected, &response);
}

#[test]
fn error_enums() {
    let response: [UpdateError; 2] =
        [UpdateError::AlreadyPending, UpdateError::NonePending];
    let expected = vec![35, 36];
    assert_serialized(&expected, &response);
}
