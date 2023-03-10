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

use gateway_messages::ignition::TransceiverSelect;
use gateway_messages::BadRequestReason;
use gateway_messages::ComponentUpdatePrepare;
use gateway_messages::Header;
use gateway_messages::IgnitionCommand;
use gateway_messages::Message;
use gateway_messages::MessageKind;
use gateway_messages::MgsError;
use gateway_messages::MgsRequest;
use gateway_messages::MgsResponse;
use gateway_messages::PowerState;
use gateway_messages::SerializedSize;
use gateway_messages::SpComponent;
use gateway_messages::SpRequest;
use gateway_messages::SpResponse;
use gateway_messages::SpUpdatePrepare;
use gateway_messages::StartupOptions;
use gateway_messages::UpdateChunk;
use gateway_messages::UpdateId;
use serde::Serialize;

fn assert_serialized(out: &mut [u8], expected: &[u8], item: &impl Serialize) {
    let n = gateway_messages::serialize(out, item).unwrap();
    assert_eq!(expected, &out[..n]);
}

// This test covers the high-level `Message`, `Header`, and `MessageKind` types.
// It does not cover all possible request/response variants that live inside
// `MessageKind` (but does pick simple ones to have concrete values). Those
// variants are covered in additional tests below.
#[test]
fn message() {
    let mut out = [0; Message::MAX_SIZE];
    let header = Header { version: 2, message_id: 0x01020304 };

    #[rustfmt::skip]
    let expected = &[
        // Header
        2, 0, 0, 0, // version 2
        4, 3, 2, 1, // message_id 0x01020304

        // Kind
        0, // MgsRequest
        0, // Discover
    ];
    let message =
        Message { header, kind: MessageKind::MgsRequest(MgsRequest::Discover) };
    assert_serialized(&mut out, expected, &message);

    #[rustfmt::skip]
    let expected = &[
        // Header
        2, 0, 0, 0, // version 2
        4, 3, 2, 1, // message_id 0x01020304

        // Kind
        1, // MgsResponse
        0, // Error
        0, // BadRequest
        1, // WrongDirection
    ];
    let message = Message {
        header,
        kind: MessageKind::MgsResponse(MgsResponse::Error(
            MgsError::BadRequest(BadRequestReason::WrongDirection),
        )),
    };
    assert_serialized(&mut out, expected, &message);

    #[rustfmt::skip]
    let expected = &[
        // Header
        2, 0, 0, 0, // version 2
        4, 3, 2, 1, // message_id 0x01020304

        // Kind
        2, // SpRequest
        0, // SerialConsole
        b'a', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // component "a"
        8, 7, 6, 5, 4, 3, 2, 1, // offset 0x0102030405060708
    ];
    let message = Message {
        header,
        kind: MessageKind::SpRequest(SpRequest::SerialConsole {
            component: SpComponent::try_from("a").unwrap(),
            offset: 0x0102_0304_0506_0708,
        }),
    };
    assert_serialized(&mut out, expected, &message);

    #[rustfmt::skip]
    let expected = &[
        // Header
        2, 0, 0, 0, // version 2
        4, 3, 2, 1, // message_id 0x01020304

        // Kind
        3, // SpResponse
        5, // SpUpdatePrepareAck
    ];
    let message = Message {
        header,
        kind: MessageKind::SpResponse(SpResponse::SpUpdatePrepareAck),
    };
    assert_serialized(&mut out, expected, &message);
}

#[test]
fn mgs_request() {
    let mut out = [0; MgsRequest::MAX_SIZE];

    let request = MgsRequest::Discover;
    let expected = &[0];
    assert_serialized(&mut out, expected, &request);

    let request = MgsRequest::IgnitionState { target: 7 };
    let expected = &[1, 7];
    assert_serialized(&mut out, expected, &request);

    let request = MgsRequest::BulkIgnitionState { offset: 0x01020304 };
    let expected = &[2, 4, 3, 2, 1];
    assert_serialized(&mut out, expected, &request);

    for (command, command_val) in [
        (IgnitionCommand::PowerOn, 0),
        (IgnitionCommand::PowerOff, 1),
        (IgnitionCommand::PowerReset, 2),
    ] {
        let request = MgsRequest::IgnitionCommand { target: 7, command };
        let expected = &[3, 7, command_val];
        assert_serialized(&mut out, expected, &request);
    }

    let request = MgsRequest::SpState;
    let expected = &[4];
    assert_serialized(&mut out, expected, &request);

    let request = MgsRequest::SerialConsoleAttach(SpComponent::SP_ITSELF);
    let expected = &[5, b's', b'p', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_serialized(&mut out, expected, &request);

    let request =
        MgsRequest::SerialConsoleWrite { offset: 0x0102_0304_0506_0708 };
    let expected = &[6, 8, 7, 6, 5, 4, 3, 2, 1];
    assert_serialized(&mut out, expected, &request);

    let request = MgsRequest::SerialConsoleDetach;
    let expected = &[7];
    assert_serialized(&mut out, expected, &request);

    let request = MgsRequest::SpUpdatePrepare(SpUpdatePrepare {
        id: UpdateId([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
        aux_flash_size: 0x0a0b0c0d,
        aux_flash_chck: [
            101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113,
            114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126,
            127, 128, 129, 130, 131, 132,
        ],
        sp_image_size: 0xf0f1f2f3,
    });
    #[rustfmt::skip]
    let expected = &[
        8, // SpUpdatePrepare
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, // id
        0xd, 0xc, 0xb, 0xa, // aux_flash_size

        // aux_flash_chck
        101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113,
        114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126,
        127, 128, 129, 130, 131, 132,

        0xf3, 0xf2, 0xf1, 0xf0, // sp_image_size
    ];
    assert_serialized(&mut out, expected, &request);

    let request = MgsRequest::ComponentUpdatePrepare(ComponentUpdatePrepare {
        component: SpComponent::SP_ITSELF,
        id: UpdateId([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
        slot: 0x0102,
        total_size: 0x03040506,
    });
    #[rustfmt::skip]
    let expected = &[
        9, // ComponentUpdatePrepare
        b's', b'p', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // SP_ITSELF
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, // id
        2, 1, // slot
        6, 5, 4, 3, // total_size
    ];
    assert_serialized(&mut out, expected, &request);

    let request = MgsRequest::UpdateChunk(UpdateChunk {
        component: SpComponent::SP_ITSELF,
        id: UpdateId([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
        offset: 0x03040506,
    });
    #[rustfmt::skip]
    let expected = &[
        10, // UpdateChunk
        b's', b'p', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // SP_ITSELF
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, // id
        6, 5, 4, 3, // offset
    ];
    assert_serialized(&mut out, expected, &request);

    let request = MgsRequest::UpdateStatus(SpComponent::SP_ITSELF);
    let expected = &[11, b's', b'p', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_serialized(&mut out, expected, &request);

    let request = MgsRequest::UpdateAbort {
        component: SpComponent::SP_ITSELF,
        id: UpdateId([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
    };
    #[rustfmt::skip]
    let expected = &[
        12, // UpdateAbort
        b's', b'p', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // SP_ITSELF
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, // id
    ];
    assert_serialized(&mut out, expected, &request);

    let request = MgsRequest::GetPowerState;
    let expected = &[13];
    assert_serialized(&mut out, expected, &request);

    for (state, state_val) in
        [(PowerState::A0, 0), (PowerState::A1, 1), (PowerState::A2, 2)]
    {
        let request = MgsRequest::SetPowerState(state);
        let expected = &[14, state_val];
        assert_serialized(&mut out, expected, &request);
    }

    let request = MgsRequest::ResetPrepare;
    let expected = &[15];
    assert_serialized(&mut out, expected, &request);

    let request = MgsRequest::ResetTrigger;
    let expected = &[16];
    assert_serialized(&mut out, expected, &request);

    let request = MgsRequest::Inventory { device_index: 0x01020304 };
    let expected = &[17, 4, 3, 2, 1];
    assert_serialized(&mut out, expected, &request);

    let request = MgsRequest::GetStartupOptions;
    let expected = &[18];
    assert_serialized(&mut out, expected, &request);

    let options = StartupOptions::PHASE2_RECOVERY_MODE
        | StartupOptions::STARTUP_KBM
        | StartupOptions::STARTUP_KMDB
        | StartupOptions::STARTUP_BOOT_RAMDISK
        | StartupOptions::STARTUP_VERBOSE;
    assert_eq!(options.bits(), 0x0000_0000_0000_0153);
    let request = MgsRequest::SetStartupOptions(options);
    let expected = &[19, 0x53, 0x01, 0, 0, 0, 0, 0, 0];
    assert_serialized(&mut out, expected, &request);

    let request = MgsRequest::ComponentDetails {
        component: SpComponent::SP_ITSELF,
        offset: 0x03040506,
    };
    #[rustfmt::skip]
    let expected = &[
        20, // ComponentDetails
        b's', b'p', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // SP_ITSELF
        6, 5, 4, 3, // offset
    ];
    assert_serialized(&mut out, expected, &request);

    let request = MgsRequest::IgnitionLinkEvents { target: 7 };
    let expected = &[21, 7];
    assert_serialized(&mut out, expected, &request);

    let request = MgsRequest::BulkIgnitionLinkEvents { offset: 0x01020304 };
    let expected = &[22, 4, 3, 2, 1];
    assert_serialized(&mut out, expected, &request);

    for (target, target_val, xvr_select, xvr_select_val) in [
        (None, &[0_u8] as &[u8], None, &[0_u8] as &[u8]),
        (Some(7), &[1, 7], Some(TransceiverSelect::Controller), &[1, 0]),
        (None, &[0], Some(TransceiverSelect::TargetLink0), &[1, 1]),
        (Some(9), &[1, 9], Some(TransceiverSelect::TargetLink1), &[1, 2]),
    ] {
        let request = MgsRequest::ClearIgnitionLinkEvents {
            target,
            transceiver_select: xvr_select,
        };
        let mut expected = vec![23];
        expected.extend_from_slice(target_val);
        expected.extend_from_slice(xvr_select_val);
        assert_serialized(&mut out, &expected, &request);
    }

    let request = MgsRequest::ComponentClearStatus(SpComponent::SP_ITSELF);
    #[rustfmt::skip]
    let expected = &[
        24, // ComponentClearStatus
        b's', b'p', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // SP_ITSELF
    ];
    assert_serialized(&mut out, expected, &request);

    let request = MgsRequest::ComponentGetActiveSlot(SpComponent::SP_ITSELF);
    #[rustfmt::skip]
    let expected = &[
        25, // ComponentGetActiveSlot
        b's', b'p', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // SP_ITSELF
    ];
    assert_serialized(&mut out, expected, &request);

    let request = MgsRequest::ComponentSetActiveSlot {
        component: SpComponent::SP_ITSELF,
        slot: 0x0102,
    };
    #[rustfmt::skip]
    let expected = &[
        26, // ComponentSetActiveSlot
        b's', b'p', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // SP_ITSELF
        2, 1, // slot
    ];
    assert_serialized(&mut out, expected, &request);

    let request = MgsRequest::SerialConsoleBreak;
    let expected = &[27];
    assert_serialized(&mut out, expected, &request);

    let request = MgsRequest::SendHostNmi;
    let expected = &[28];
    assert_serialized(&mut out, expected, &request);

    let request = MgsRequest::SetIpccKeyLookupValue { key: 7 };
    let expected = &[29, 7];
    assert_serialized(&mut out, expected, &request);

    let request = MgsRequest::ComponentSetAndPersistActiveSlot {
        component: SpComponent::SP_ITSELF,
        slot: 0x0102,
    };
    #[rustfmt::skip]
    let expected = &[
        30, // ComponentSetAndPersistActiveSlot
        b's', b'p', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // SP_ITSELF
        2, 1, // slot
    ];
    assert_serialized(&mut out, expected, &request);

    let request = MgsRequest::ReadCaboose { key: [1, 2, 3, 4] };
    let expected = &[31, 1, 2, 3, 4];
    assert_serialized(&mut out, expected, &request);
}

#[test]
fn mgs_response() {
    let mut out = [0; MgsResponse::MAX_SIZE];

    let response = MgsResponse::Error(MgsError::BadRequest(
        BadRequestReason::WrongVersion { sp: 0x01020304, request: 0x05060708 },
    ));
    let expected = &[0, 0, 0, 4, 3, 2, 1, 8, 7, 6, 5];
    assert_serialized(&mut out, expected, &response);

    let response = MgsResponse::Error(MgsError::BadRequest(
        BadRequestReason::WrongDirection,
    ));
    let expected = &[0, 0, 1];
    assert_serialized(&mut out, expected, &response);

    let response = MgsResponse::Error(MgsError::BadRequest(
        BadRequestReason::UnexpectedTrailingData,
    ));
    let expected = &[0, 0, 2];
    assert_serialized(&mut out, expected, &response);

    let response = MgsResponse::Error(MgsError::BadRequest(
        BadRequestReason::DeserializationError,
    ));
    let expected = &[0, 0, 3];
    assert_serialized(&mut out, expected, &response);

    let response = MgsResponse::Error(MgsError::HostPhase2Unavailable {
        hash: [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
            20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
        ],
    });
    let expected = &[
        0, 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
        19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
    ];
    assert_serialized(&mut out, expected, &response);

    let response = MgsResponse::Error(MgsError::HostPhase2ImageBadOffset {
        hash: [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
            20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
        ],
        offset: 0xa0a1_a2a3_a4a5_a6a7,
    });
    let expected = &[
        0, 2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
        19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 0xa7, 0xa6,
        0xa5, 0xa4, 0xa3, 0xa2, 0xa1, 0xa0,
    ];
    assert_serialized(&mut out, expected, &response);

    let response = MgsResponse::HostPhase2Data {
        hash: [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
            20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
        ],
        offset: 0xa0a1_a2a3_a4a5_a6a7,
    };
    let expected = &[
        1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
        20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 0xa7, 0xa6, 0xa5,
        0xa4, 0xa3, 0xa2, 0xa1, 0xa0,
    ];
    assert_serialized(&mut out, expected, &response);
}
