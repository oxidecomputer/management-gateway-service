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
use gateway_messages::EcdsaSha2Nistp256Challenge;
use gateway_messages::MonorailComponentAction;
use gateway_messages::MonorailComponentActionResponse;
use gateway_messages::SerializedSize;
use gateway_messages::SpResponse;
use gateway_messages::UnlockChallenge;
use gateway_messages::UnlockResponse;

#[test]
fn monorail_component_action() {
    let mut out = [0; ComponentAction::MAX_SIZE];
    let action =
        ComponentAction::Monorail(MonorailComponentAction::RequestChallenge);
    let expected = vec![
        1, // Monorail
        0, // RequestChallenge
    ];
    assert_serialized(&mut out, &expected, &action);

    #[rustfmt::skip]
    let action = ComponentAction::Monorail(MonorailComponentAction::Unlock {
        challenge: UnlockChallenge::EcdsaSha2Nistp256(
           EcdsaSha2Nistp256Challenge {
                hw_id: [
                    8, 8, 9, 0, 3, 3, 3, 3,
                    1, 1, 1, 1, 2, 2, 2, 2,
                    5, 5, 5, 5, 5, 6, 7, 8,
                    6, 6, 6, 6, 6, 7, 8, 9,
                ],
                sw_id: [8, 8, 9, 0],
                time: [0, 0, 0, 0, 1, 2, 3, 4],
                nonce: [
                    1, 2, 3, 4, 5, 6, 7, 8,
                    1, 2, 3, 4, 5, 6, 7, 8,
                    1, 2, 3, 4, 5, 6, 7, 8,
                    1, 2, 3, 4, 5, 6, 7, 8,
                ],
            }
        ),
        response: UnlockResponse::EcdsaSha2Nistp256 {
            key: [
                123,
                1, 1, 1, 1, 1, 1, 1, 1,
                2, 2, 2, 2, 2, 2, 2, 2,
                3, 3, 3, 3, 3, 3, 3, 3,
                4, 4, 4, 4, 4, 4, 4, 4,
                5, 5, 5, 5, 5, 5, 5, 5,
                6, 6, 6, 6, 6, 6, 6, 6,
                7, 7, 7, 7, 7, 7, 7, 7,
                8, 8, 8, 8, 8, 8, 8, 8,
            ],
            signer_nonce: [1, 2, 3, 4, 5, 6, 7, 8],
            signature: [
                8, 8, 8, 8, 8, 8, 8, 8,
                7, 7, 7, 7, 7, 7, 7, 7,
                6, 6, 6, 6, 6, 6, 6, 6,
                5, 5, 5, 5, 5, 5, 5, 5,
                4, 4, 4, 4, 4, 4, 4, 4,
                3, 3, 3, 3, 3, 3, 3, 3,
                2, 2, 2, 2, 2, 2, 2, 2,
                1, 1, 1, 1, 1, 1, 1, 1,
            ],
        },
        time_sec: 0x1234,
    });
    #[rustfmt::skip]
    let expected = vec![
        1, // ComponentAction::Monorail
        1, // MonorailComponentAction::Unlock
        1, // UnlockChallenge::EcdsaSha2Nistp256
        8, 8, 9, 0, 3, 3, 3, 3, // hw_id
        1, 1, 1, 1, 2, 2, 2, 2,
        5, 5, 5, 5, 5, 6, 7, 8,
        6, 6, 6, 6, 6, 7, 8, 9,
        8, 8, 9, 0, // sw_id
        0, 0, 0, 0, 1, 2, 3, 4, // time
        1, 2, 3, 4, 5, 6, 7, 8, // nonce
        1, 2, 3, 4, 5, 6, 7, 8,
        1, 2, 3, 4, 5, 6, 7, 8,
        1, 2, 3, 4, 5, 6, 7, 8,

        1, // UnlockResponse::EcdsaSha2Nistp256
        123, // key
        1, 1, 1, 1, 1, 1, 1, 1,
        2, 2, 2, 2, 2, 2, 2, 2,
        3, 3, 3, 3, 3, 3, 3, 3,
        4, 4, 4, 4, 4, 4, 4, 4,
        5, 5, 5, 5, 5, 5, 5, 5,
        6, 6, 6, 6, 6, 6, 6, 6,
        7, 7, 7, 7, 7, 7, 7, 7,
        8, 8, 8, 8, 8, 8, 8, 8,

        // signer_nonce
        1, 2, 3, 4, 5, 6, 7, 8,

        8, 8, 8, 8, 8, 8, 8, 8, // signature
        7, 7, 7, 7, 7, 7, 7, 7,
        6, 6, 6, 6, 6, 6, 6, 6,
        5, 5, 5, 5, 5, 5, 5, 5,
        4, 4, 4, 4, 4, 4, 4, 4,
        3, 3, 3, 3, 3, 3, 3, 3,
        2, 2, 2, 2, 2, 2, 2, 2,
        1, 1, 1, 1, 1, 1, 1, 1,

        0x34, 0x12, 0, 0, // time_s
    ];
    assert_serialized(&mut out, &expected, &action);
}
#[test]
fn component_action_response() {
    let mut out = [0; SpResponse::MAX_SIZE];

    #[rustfmt::skip]
    let r = SpResponse::ComponentAction(ComponentActionResponse::Monorail(
        MonorailComponentActionResponse::RequestChallenge(
            UnlockChallenge::EcdsaSha2Nistp256(
                EcdsaSha2Nistp256Challenge {
                    hw_id: [
                        8, 8, 9, 0, 3, 3, 3, 3,
                        1, 1, 1, 1, 2, 2, 2, 2,
                        5, 5, 5, 5, 5, 6, 7, 8,
                        6, 6, 6, 6, 6, 7, 8, 9,
                    ],
                    sw_id: [8, 8, 9, 0],
                    time: [0, 0, 0, 0, 1, 2, 3, 4],
                    nonce: [
                        1, 2, 3, 4, 5, 6, 7, 8,
                        1, 2, 3, 4, 5, 6, 7, 8,
                        1, 2, 3, 4, 5, 6, 7, 8,
                        1, 2, 3, 4, 5, 6, 7, 8,
                    ],
                }
            )
        )
    ));
    #[rustfmt::skip]
    let expected = vec![
        46, // ComponentAction
        1,  // Ack
        0,  // RequestChallenge
        1,  // EcdsaSha2Nistp256
        8, 8, 9, 0, 3, 3, 3, 3, // hw_id
        1, 1, 1, 1, 2, 2, 2, 2,
        5, 5, 5, 5, 5, 6, 7, 8,
        6, 6, 6, 6, 6, 7, 8, 9,
        8, 8, 9, 0, // sw_id
        0, 0, 0, 0, 1, 2, 3, 4, // time
        1, 2, 3, 4, 5, 6, 7, 8, // nonce
        1, 2, 3, 4, 5, 6, 7, 8,
        1, 2, 3, 4, 5, 6, 7, 8,
        1, 2, 3, 4, 5, 6, 7, 8,
    ];
    assert_serialized(&mut out, &expected, &r);
}
