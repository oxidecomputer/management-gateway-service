// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! This source file is named after the protocol version being tested,
//! e.g. v01.rs implements tests for protocol version 1.
//! The tested protocol version is represented by "$VERSION" below.
//!
//! The tests in this module check that the serialized form of messages from MGS
//! protocol version $VERSION have not changed.
//!
//! If a test in this module fails, _do not change the test_! This means you
//! have changed, deleted, or reordered an existing message type or enum
//! variant, and you should revert that change. This will remain true until we
//! bump the `version::MIN` to a value higher than $VERSION, at which point these
//! tests can be removed as we will stop supporting $VERSION.

use super::assert_serialized;
use gateway_messages::ComponentAction;
use gateway_messages::ComponentActionResponse;
use gateway_messages::MonorailComponentAction;
use gateway_messages::MonorailComponentActionResponse;
use gateway_messages::MonorailError;
use gateway_messages::SpError;
use gateway_messages::SpResponse;
use gateway_messages::UnlockChallenge;
use gateway_messages::UnlockResponse;

#[test]
fn monorail_component_action() {
    let action =
        ComponentAction::Monorail(MonorailComponentAction::RequestChallenge);
    let expected = vec![
        1, // Monorail
        0, // RequestChallenge
    ];
    assert_serialized(&expected, &action);

    let action = ComponentAction::Monorail(MonorailComponentAction::Unlock {
        challenge: UnlockChallenge::Trivial { timestamp: 0x1234 },
        response: UnlockResponse::Trivial { timestamp: 0x4567 },
        time_sec: 0x1234,
    });
    let expected = vec![
        1, // ComponentAction::Monorail
        1, // MonorailComponentAction::Unlock
        0, // UnlockChallenge::Trivial
        0x34, 0x12, 0, 0, 0, 0, 0, 0, // timestamp
        0, // UnlockResponse::Trivial
        0x67, 0x45, 0, 0, 0, 0, 0, 0, // timestamp
        0x34, 0x12, 0, 0, // time_s
    ];
    assert_serialized(&expected, &action);

    let action = ComponentAction::Monorail(MonorailComponentAction::Lock);
    let expected = vec![
        1, // Monorail
        2, // Lock
    ];
    assert_serialized(&expected, &action);
}
#[test]
fn component_action_response() {
    let r = SpResponse::ComponentAction(ComponentActionResponse::Ack);
    let expected = vec![
        46, // ComponentAction
        0,  // Ack
    ];
    assert_serialized(&expected, &r);

    let r = SpResponse::ComponentAction(ComponentActionResponse::Monorail(
        MonorailComponentActionResponse::RequestChallenge(
            UnlockChallenge::Trivial { timestamp: 0x4455 },
        ),
    ));
    let expected = vec![
        46, // ComponentAction
        1,  // Ack
        0,  // RequestChallenge
        0,  // Trivial
        0x55, 0x44, 0, 0, 0, 0, 0, 0, // timestamp
    ];
    assert_serialized(&expected, &r);
}

#[test]
fn monorail_error() {
    for (i, e) in [
        MonorailError::UnlockAuthFailed,
        MonorailError::UnlockFailed,
        MonorailError::LockFailed,
        MonorailError::ManagementNetworkLocked,
        MonorailError::InvalidVLAN,
        MonorailError::GetChallengeFailed,
        MonorailError::TimeIsTooLong,
        MonorailError::ChallengeExpired,
        MonorailError::AlreadyTrusted,
    ]
    .iter()
    .enumerate()
    {
        let err = SpError::Monorail(*e);

        let expected = vec![
            36,      // Monorail
            i as u8, // error code
        ];
        assert_serialized(&expected, &err);
    }
}
