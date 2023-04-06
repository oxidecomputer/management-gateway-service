// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! The tests in this module check that the serialized form of messages from MGS
//! protocol version 3 have not changed.
//!
//! If a test in this module fails, _do not change the test_! This means you
//! have changed, deleted, or reordered an existing message type or enum
//! variant, and you should revert that change. This will remain true until we
//! bump the `version::MIN` to a value higher than 3, at which point these tests
//! can be removed as we will stop supporting v3.

use gateway_messages::ComponentAction;
use gateway_messages::LedComponentAction;
use gateway_messages::MgsRequest;
use gateway_messages::SerializedSize;
use gateway_messages::SpComponent;
use gateway_messages::SpResponse;

use super::assert_serialized;

// This test covers the ComponentAction message added in v3.
#[test]
fn mgs_request() {
    let mut out = [0; MgsRequest::MAX_SIZE];

    let request = MgsRequest::ComponentAction {
        component: SpComponent::SYSTEM_LED,
        action: ComponentAction::Led(LedComponentAction::TurnOn),
    };
    let expected = b"\x24system-led\0\0\0\0\0\0\0\0";
    assert_serialized(&mut out, expected, &request);

    let request = MgsRequest::ComponentAction {
        component: SpComponent::SYSTEM_LED,
        action: ComponentAction::Led(LedComponentAction::TurnOff),
    };
    let expected = b"\x24system-led\0\0\0\0\0\0\0\x01";
    assert_serialized(&mut out, expected, &request);

    let request = MgsRequest::ComponentAction {
        component: SpComponent::SYSTEM_LED,
        action: ComponentAction::Led(LedComponentAction::Blink),
    };
    let expected = b"\x24system-led\0\0\0\0\0\0\0\x02";
    assert_serialized(&mut out, expected, &request);
}

#[test]
fn sp_response() {
    let mut out = [0; SpResponse::MAX_SIZE];
    let response = SpResponse::ComponentActionAck;
    let expected = &[36];
    assert_serialized(&mut out, expected, &response);
}
