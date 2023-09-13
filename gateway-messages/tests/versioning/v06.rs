// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The tests in this module check that the serialized form of messages from MGS
//! protocol version 6 have not changed.
//!
//! If a test in this module fails, _do not change the test_! This means you
//! have changed, deleted, or reordered an existing message type or enum
//! variant, and you should revert that change. This will remain true until we
//! bump the `version::MIN` to a value higher than 6, at which point these tests
//! can be removed as we will stop supporting v6.

use super::assert_serialized;
use gateway_messages::RotError;
use gateway_messages::RotSlotId;
use gateway_messages::RotStateV2;
use gateway_messages::SerializedSize;
use gateway_messages::SpError;
use gateway_messages::SpResponse;
use gateway_messages::SpStateV2;
use gateway_messages::UpdateError;

#[test]
fn sp_response() {
    let mut out = [0; SpResponse::MAX_SIZE];

    let rot = RotStateV2 {
        active: RotSlotId::A,
        persistent_boot_preference: RotSlotId::A,
        pending_persistent_boot_preference: Some(RotSlotId::B),
        transient_boot_preference: None,
        slot_a_sha3_256_digest: Some([0u8; 32]),
        slot_b_sha3_256_digest: Some([0u8; 32]),
    };

    let response = SpResponse::SpStateV2(SpStateV2 {
        hubris_archive_id: [1, 2, 3, 4, 5, 6, 7, 8],
        serial_number: [
            9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
            26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        ],
        model: [
            41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
            58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72,
        ],
        revision: 0xf0f1f2f3,
        base_mac_address: [73, 74, 75, 76, 77, 78],
        power_state: gateway_messages::PowerState::A0,
        rot: Ok(rot),
    });

    #[rustfmt::skip]
    let expected = vec![
        37, // SpState
        1, 2, 3, 4, 5, 6, 7, 8, // hubris_archive_id

        9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
        39, 40, // serial_number

        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55,
        56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70,
        71, 72, // model

        0xf3, 0xf2, 0xf1, 0xf0, // revision
        73, 74, 75, 76, 77, 78, // base_mac_address
        0, // power_state

        // rot
        0, // Ok
        0, // active
        0, // peristent_boot_preference
        1,1, // pending_persistent_boot_preference
        0, // transient_persistent_boot_preference
        1, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0, // slot_a_sha3_256_digest
        1, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0, // slot_b_sha3_256_digest
    ];

    assert_serialized(&mut out, &expected, &response);
}

#[test]
fn update_error() {
    // This variant was added in v6
    let mut out = [0; SpResponse::MAX_SIZE];
    let response =
        SpResponse::Error(SpError::Update(UpdateError::MissingHandoffData));
    let expected = vec![17, 32, 26];
    assert_serialized(&mut out, &expected, &response);

    // Test RotError variants
    let mut out = [0; RotError::MAX_SIZE];
    let response = RotError::Update(UpdateError::MissingHandoffData);
    let expected = vec![4, 26];
    assert_serialized(&mut out, &expected, &response);
}
