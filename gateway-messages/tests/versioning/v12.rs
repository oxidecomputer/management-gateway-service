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
use gateway_messages::Fwid;
use gateway_messages::ImageError;
use gateway_messages::MgsRequest;
use gateway_messages::RotBootInfo;
use gateway_messages::RotSlotId;
use gateway_messages::RotStateV3;
use gateway_messages::RotWatchdogError;
use gateway_messages::SerializedSize;
use gateway_messages::SpComponent;
use gateway_messages::SpError;
use gateway_messages::SpResponse;
use gateway_messages::WatchdogError;

use gateway_messages::SpStateV3;

#[test]
fn sp_response() {
    let mut out = [0; SpResponse::MAX_SIZE];

    let response = SpResponse::DisableComponentWatchdogAck;
    let expected = [42];
    assert_serialized(&mut out, &expected, &response);

    let response = SpResponse::ComponentWatchdogSupportedAck;
    let expected = [43];
    assert_serialized(&mut out, &expected, &response);

    let mut out = [0; SpResponse::MAX_SIZE];
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

    let mut out = [0; MgsRequest::MAX_SIZE];
    let request = MgsRequest::VersionedRotBootInfo { version: 3 };

    #[rustfmt::skip]
    let expected = vec![
        45, // VersionedRotBootInfo
        3, // version
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

#[test]
fn rot_boot_info_v3() {
    let mut out = [0; SpResponse::MAX_SIZE];

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

    assert_serialized(&mut out, &expected, &response);
}
