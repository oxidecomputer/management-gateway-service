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
use gateway_messages::Fwid;
use gateway_messages::ImageError;
use gateway_messages::MgsRequest;
use gateway_messages::RotBootInfo;
use gateway_messages::RotSlotId;
use gateway_messages::RotStateV3;
use gateway_messages::SpResponse;
use gateway_messages::SpStateV3;
use gateway_messages::UpdateError;

#[test]
fn sp_response() {
    let response = SpResponse::SpStateV3(SpStateV3 {
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
    });

    #[rustfmt::skip]
    let expected = vec![
        44, // SpStateV3
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
    ];

    assert_serialized(&expected, &response);
}

#[test]
fn host_request() {
    let request = MgsRequest::VersionedRotBootInfo { version: 3 };

    #[rustfmt::skip]
    let expected = vec![
        45, // VersionedRotBootInfo
        3, // version
    ];

    assert_serialized(&expected, &request);
}

#[test]
fn rot_boot_info_v3() {
    let response = SpResponse::RotBootInfo(RotBootInfo::V3(RotStateV3 {
        active: RotSlotId::A,
        persistent_boot_preference: RotSlotId::A,
        pending_persistent_boot_preference: Some(RotSlotId::B),
        transient_boot_preference: None,
        slot_a_fwid: Fwid::Sha3_256([11u8; 32]),
        slot_b_fwid: Fwid::Sha3_256([22u8; 32]),
        stage0_fwid: Fwid::Sha3_256([33u8; 32]),
        stage0next_fwid: Fwid::Sha3_256([44u8; 32]),
        slot_a_status: Ok(()),
        slot_b_status: Err(ImageError::Signature),
        stage0_status: Ok(()),
        stage0next_status: Err(ImageError::FirstPageErased),
    }));

    #[rustfmt::skip]
    let expected =  vec![
        45, 2, // SpResponse::RotBootInfo(RotBootInfo::V3(RotStateV3 {
        0, // active: RotSlotId::A
        0, // persistent_boot_preference: RotSlotId::A
        1, 1, // pending_persistent_boot_preference: Some(RotSlotId::B)
        0, // transient_boot_preference: None
        0, // slot_a_fwid: Fwid::Sha3_256([11u8;32])
        11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
        11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
        0, // slot_b_fwid: Fwid::Sha3_256([22u8;32])
        22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22,
        22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22,
        0, // stage0_fwid: Fwid::Sha3_256([33u8;32])
        33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33,
        33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33, 33,
        0, // stage0next_fwid: Fwid::Sha3_256([44u8;32])
        44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44,
        44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44,
        0, // slot_a_status: Ok(())
        1, 12, // slot_b_status: Err(ImageError::Signature)
        0, // stage0_status: Ok(())
        1, 1 // stage0next_status: Err(ImageError::FirstPageErased)
    ];

    assert_serialized(&expected, &response);
}

#[test]
fn error_enums() {
    let response: [ImageError; 13] = [
        ImageError::Unchecked,
        ImageError::FirstPageErased,
        ImageError::PartiallyProgrammed,
        ImageError::InvalidLength,
        ImageError::HeaderNotProgrammed,
        ImageError::BootloaderTooSmall,
        ImageError::BadMagic,
        ImageError::HeaderImageSize,
        ImageError::UnalignedLength,
        ImageError::UnsupportedType,
        ImageError::ResetVectorNotThumb2,
        ImageError::ResetVector,
        ImageError::Signature,
    ];
    let expected = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    assert_serialized(&expected, &response);

    let response: [UpdateError; 3] = [
        UpdateError::BlockOutOfOrder,
        UpdateError::InvalidComponent,
        UpdateError::InvalidSlotIdForOperation,
    ];
    let expected = vec![27, 28, 29];
    assert_serialized(&expected, &response);
}
