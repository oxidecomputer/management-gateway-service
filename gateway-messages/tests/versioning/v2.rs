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

use gateway_messages::ignition::IgnitionError;
use gateway_messages::ignition::LinkEvents;
use gateway_messages::ignition::ReceiverStatus;
use gateway_messages::ignition::SystemFaults;
use gateway_messages::ignition::SystemPowerState;
use gateway_messages::ignition::SystemType;
use gateway_messages::ignition::TargetState;
use gateway_messages::ignition::TransceiverEvents;
use gateway_messages::ignition::TransceiverSelect;
use gateway_messages::BadRequestReason;
use gateway_messages::ComponentUpdatePrepare;
use gateway_messages::DiscoverResponse;
use gateway_messages::Header;
use gateway_messages::IgnitionCommand;
use gateway_messages::IgnitionState;
use gateway_messages::ImageVersion;
use gateway_messages::IpccKeyLookupValueError;
use gateway_messages::Message;
use gateway_messages::MessageKind;
use gateway_messages::MgsError;
use gateway_messages::MgsRequest;
use gateway_messages::MgsResponse;
use gateway_messages::PowerState;
use gateway_messages::RotBootState;
use gateway_messages::RotImageDetails;
use gateway_messages::RotSlot;
use gateway_messages::RotState;
use gateway_messages::RotUpdateDetails;
use gateway_messages::SerializedSize;
use gateway_messages::SlotId;
use gateway_messages::SpComponent;
use gateway_messages::SpError;
use gateway_messages::SpPort;
use gateway_messages::SpRequest;
use gateway_messages::SpResponse;
use gateway_messages::SpStateV1;
use gateway_messages::SpUpdatePrepare;
use gateway_messages::StartupOptions;
use gateway_messages::SwitchDuration;
use gateway_messages::TlvPage;
use gateway_messages::UpdateChunk;
use gateway_messages::UpdateId;
use gateway_messages::UpdateInProgressStatus;
use gateway_messages::UpdatePreparationProgress;
use gateway_messages::UpdatePreparationStatus;
use gateway_messages::UpdateStatus;

use super::assert_serialized;

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

    let request = MgsRequest::SerialConsoleKeepAlive;
    let expected = &[32];
    assert_serialized(&mut out, expected, &request);

    let request =
        MgsRequest::ResetComponentPrepare { component: SpComponent::SP_ITSELF };
    let expected = &[33, 115, 112, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_serialized(&mut out, expected, &request);

    let request =
        MgsRequest::ResetComponentTrigger { component: SpComponent::SP_ITSELF };
    let expected = &[34, 115, 112, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_serialized(&mut out, expected, &request);

    let request = MgsRequest::SwitchDefaultImage {
        component: SpComponent::ROT,
        slot: SlotId::A,
        duration: SwitchDuration::Forever,
    };
    let expected =
        &[35, 114, 111, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
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

#[test]
fn sp_request() {
    let mut out = [0; SpRequest::MAX_SIZE];

    let request = SpRequest::SerialConsole {
        component: SpComponent::SP_ITSELF,
        offset: 0x0102_0304_0506_0708,
    };
    #[rustfmt::skip]
    let expected = &[
        0, // SerialConsole
        b's', b'p', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // SP_ITSELF
        8, 7, 6, 5, 4, 3, 2, 1, // offset
    ];
    assert_serialized(&mut out, expected, &request);

    let request = SpRequest::HostPhase2Data {
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
    assert_serialized(&mut out, expected, &request);
}

#[test]
fn sp_response() {
    let mut out = [0; SpResponse::MAX_SIZE];

    let response =
        SpResponse::Discover(DiscoverResponse { sp_port: SpPort::One });
    let expected = &[0, 1];
    assert_serialized(&mut out, expected, &response);

    let response =
        SpResponse::Discover(DiscoverResponse { sp_port: SpPort::Two });
    let expected = &[0, 2];
    assert_serialized(&mut out, expected, &response);

    let response = SpResponse::IgnitionState(IgnitionState {
        receiver: ReceiverStatus {
            aligned: true,
            locked: true,
            polarity_inverted: true,
        },
        target: None,
    });
    let expected = &[1, 1, 1, 1, 0];
    assert_serialized(&mut out, expected, &response);

    for (system_type, system_type_val) in [
        (SystemType::Gimlet, &[0_u8] as &[_]),
        (SystemType::Sidecar, &[1]),
        (SystemType::Psc, &[2]),
        (SystemType::Unknown(0xa0a1), &[3, 0xa1, 0xa0]),
    ] {
        for (power_state, power_state_val) in [
            (SystemPowerState::Off, 0),
            (SystemPowerState::On, 1),
            (SystemPowerState::Aborted, 2),
            (SystemPowerState::PoweringOff, 3),
            (SystemPowerState::PoweringOn, 4),
        ] {
            let response = SpResponse::IgnitionState(IgnitionState {
                receiver: ReceiverStatus {
                    aligned: false,
                    locked: false,
                    polarity_inverted: false,
                },
                target: Some(TargetState {
                    system_type,
                    power_state,
                    power_reset_in_progress: true,
                    faults: SystemFaults {
                        power_a3: true,
                        power_a2: false,
                        sp: true,
                        rot: true,
                    },
                    controller0_present: false,
                    controller1_present: true,
                    link0_receiver_status: ReceiverStatus {
                        aligned: true,
                        locked: false,
                        polarity_inverted: false,
                    },
                    link1_receiver_status: ReceiverStatus {
                        aligned: false,
                        locked: true,
                        polarity_inverted: true,
                    },
                }),
            });
            #[rustfmt::skip]
            let mut expected = vec![
                1, // IgnitionState
                0, 0, 0, // receiver bools
                1, // Some(_)
            ];
            expected.extend_from_slice(system_type_val);
            expected.push(power_state_val);
            #[rustfmt::skip]
            expected.extend_from_slice(&[
                1, // power_reset_in_progress
                1, 0, 1, 1, // faults
                0, 1, // controllerN_present
                1, 0, 0, // link0_receiver_status
                0, 1, 1, // link1_receiver_status
            ]);
            assert_serialized(&mut out, &expected, &response);
        }
    }

    let response = SpResponse::BulkIgnitionState(TlvPage {
        offset: 0x01020304,
        total: 0x05060708,
    });
    let expected = &[2, 4, 3, 2, 1, 8, 7, 6, 5];
    assert_serialized(&mut out, expected, &response);

    let response = SpResponse::IgnitionCommandAck;
    let expected = &[3];
    assert_serialized(&mut out, expected, &response);

    for (rot, rot_val) in [
        (
            Ok(RotState {
                rot_updates: RotUpdateDetails {
                    boot_state: RotBootState {
                        active: RotSlot::A,
                        slot_a: None,
                        slot_b: None,
                    },
                },
            }),
            &[0_u8, 0, 0, 0] as &[_],
        ),
        (
            Ok(RotState {
                rot_updates: RotUpdateDetails {
                    boot_state: RotBootState {
                        active: RotSlot::B,
                        slot_a: Some(RotImageDetails {
                            digest: [
                                100, 101, 102, 103, 104, 105, 106, 107, 108,
                                109, 110, 111, 112, 113, 114, 115, 116, 117,
                                118, 119, 120, 121, 122, 123, 124, 125, 126,
                                127, 128, 129, 130, 131,
                            ],
                            version: ImageVersion {
                                epoch: 0xa0a1a2a3,
                                version: 0xa4a5a6a7,
                            },
                        }),
                        slot_b: None,
                    },
                },
            }),
            &[
                0, 1, 1, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110,
                111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122,
                123, 124, 125, 126, 127, 128, 129, 130, 131, 0xa3, 0xa2, 0xa1,
                0xa0, 0xa7, 0xa6, 0xa5, 0xa4, 0,
            ],
        ),
        (
            Ok(RotState {
                rot_updates: RotUpdateDetails {
                    boot_state: RotBootState {
                        active: RotSlot::A,
                        slot_a: None,
                        slot_b: Some(RotImageDetails {
                            digest: [
                                100, 101, 102, 103, 104, 105, 106, 107, 108,
                                109, 110, 111, 112, 113, 114, 115, 116, 117,
                                118, 119, 120, 121, 122, 123, 124, 125, 126,
                                127, 128, 129, 130, 131,
                            ],
                            version: ImageVersion {
                                epoch: 0xa0a1a2a3,
                                version: 0xa4a5a6a7,
                            },
                        }),
                    },
                },
            }),
            &[
                0, 0, 0, 1, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109,
                110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121,
                122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 0xa3, 0xa2,
                0xa1, 0xa0, 0xa7, 0xa6, 0xa5, 0xa4,
            ],
        ),
    ] {
        for (power_state, power_state_val) in
            [(PowerState::A0, 0), (PowerState::A1, 1), (PowerState::A2, 2)]
        {
            let response = SpResponse::SpState(SpStateV1 {
                hubris_archive_id: [1, 2, 3, 4, 5, 6, 7, 8],
                serial_number: [
                    9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                    24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
                    39, 40,
                ],
                model: [
                    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55,
                    56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70,
                    71, 72,
                ],
                revision: 0xf0f1f2f3,
                base_mac_address: [73, 74, 75, 76, 77, 78],
                version: ImageVersion {
                    epoch: 0xf4f5f6f7,
                    version: 0xf8f9fafb,
                },
                power_state,
                rot,
            });
            #[rustfmt::skip]
            let mut expected = vec![
                4, // SpState
                1, 2, 3, 4, 5, 6, 7, 8, // hubris_archive_id

                9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
                39, 40, // serial_number

                41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55,
                56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70,
                71, 72, // model

                0xf3, 0xf2, 0xf1, 0xf0, // revision
                73, 74, 75, 76, 77, 78, // base_mac_address
                0xf7, 0xf6, 0xf5, 0xf4, // epoch
                0xfb, 0xfa, 0xf9, 0xf8, // version
            ];
            expected.push(power_state_val);
            expected.extend_from_slice(rot_val);
            assert_serialized(&mut out, &expected, &response);
        }
    }

    let response = SpResponse::SpUpdatePrepareAck;
    let expected = &[5];
    assert_serialized(&mut out, expected, &response);

    let response = SpResponse::ComponentUpdatePrepareAck;
    let expected = &[6];
    assert_serialized(&mut out, expected, &response);

    let response = SpResponse::UpdateChunkAck;
    let expected = &[7];
    assert_serialized(&mut out, expected, &response);

    for (status, status_val) in [
        (UpdateStatus::None, &[0_u8] as &[_]),
        (
            UpdateStatus::Preparing(UpdatePreparationStatus {
                id: UpdateId([
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                ]),
                progress: None,
            }),
            &[1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0],
        ),
        (
            UpdateStatus::Preparing(UpdatePreparationStatus {
                id: UpdateId([
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                ]),
                progress: Some(UpdatePreparationProgress {
                    current: 0x80818283,
                    total: 0x84858687,
                }),
            }),
            &[
                1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 1,
                0x83, 0x82, 0x81, 0x80, 0x87, 0x86, 0x85, 0x84,
            ],
        ),
        (
            UpdateStatus::SpUpdateAuxFlashChckScan {
                id: UpdateId([
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                ]),
                found_match: false,
                total_size: 0x80818283,
            },
            &[
                2, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0,
                0x83, 0x82, 0x81, 0x80,
            ],
        ),
        (
            UpdateStatus::InProgress(UpdateInProgressStatus {
                id: UpdateId([
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                ]),
                bytes_received: 0x84858687,
                total_size: 0x80818283,
            }),
            &[
                3, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0x87,
                0x86, 0x85, 0x84, 0x83, 0x82, 0x81, 0x80,
            ],
        ),
        (
            UpdateStatus::Complete(UpdateId([
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            ])),
            &[4, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        ),
        (
            UpdateStatus::Aborted(UpdateId([
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            ])),
            &[5, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        ),
        (
            UpdateStatus::Failed {
                id: UpdateId([
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                ]),
                code: 0x80818283,
            },
            &[
                6, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0x83,
                0x82, 0x81, 0x80,
            ],
        ),
    ] {
        let response = SpResponse::UpdateStatus(status);
        let mut expected = vec![8];
        expected.extend_from_slice(status_val);
        assert_serialized(&mut out, &expected, &response);
    }

    let response = SpResponse::UpdateAbortAck;
    let expected = &[9];
    assert_serialized(&mut out, expected, &response);

    let response = SpResponse::SerialConsoleAttachAck;
    let expected = &[10];
    assert_serialized(&mut out, expected, &response);

    let response = SpResponse::SerialConsoleWriteAck {
        furthest_ingested_offset: 0x0102_0304_0506_0708,
    };
    let expected = &[11, 8, 7, 6, 5, 4, 3, 2, 1];
    assert_serialized(&mut out, expected, &response);

    let response = SpResponse::SerialConsoleDetachAck;
    let expected = &[12];
    assert_serialized(&mut out, expected, &response);

    for (power_state, power_state_val) in
        [(PowerState::A0, 0), (PowerState::A1, 1), (PowerState::A2, 2)]
    {
        let response = SpResponse::PowerState(power_state);
        let expected = &[13, power_state_val];
        assert_serialized(&mut out, expected, &response);
    }

    let response = SpResponse::SetPowerStateAck;
    let expected = &[14];
    assert_serialized(&mut out, expected, &response);

    let response = SpResponse::ResetPrepareAck;
    let expected = &[15];
    assert_serialized(&mut out, expected, &response);

    let response = SpResponse::Inventory(TlvPage {
        offset: 0x01020304,
        total: 0x05060708,
    });
    let expected = &[16, 4, 3, 2, 1, 8, 7, 6, 5];
    assert_serialized(&mut out, expected, &response);

    for (error, error_val) in [
        (SpError::Busy, &[0_u8] as &[_]),
        (
            SpError::BadRequest(BadRequestReason::WrongVersion {
                sp: 0x01020304,
                request: 0x05060708,
            }),
            &[1, 0, 4, 3, 2, 1, 8, 7, 6, 5],
        ),
        (SpError::BadRequest(BadRequestReason::WrongDirection), &[1, 1]),
        (
            SpError::BadRequest(BadRequestReason::UnexpectedTrailingData),
            &[1, 2],
        ),
        (SpError::BadRequest(BadRequestReason::DeserializationError), &[1, 3]),
        (SpError::RequestUnsupportedForSp, &[2]),
        (SpError::RequestUnsupportedForComponent, &[3]),
        (SpError::Ignition(IgnitionError::FpgaError), &[4, 0]),
        (SpError::Ignition(IgnitionError::InvalidPort), &[4, 1]),
        (SpError::Ignition(IgnitionError::InvalidValue), &[4, 2]),
        (SpError::Ignition(IgnitionError::NoTargetPresent), &[4, 3]),
        (SpError::Ignition(IgnitionError::RequestInProgress), &[4, 4]),
        (SpError::Ignition(IgnitionError::RequestDiscarded), &[4, 5]),
        (
            SpError::Ignition(IgnitionError::Other(0x01020304)),
            &[4, 6, 4, 3, 2, 1],
        ),
        (SpError::SerialConsoleNotAttached, &[5]),
        (SpError::SerialConsoleAlreadyAttached, &[6]),
        (
            SpError::OtherComponentUpdateInProgress(SpComponent::SP_ITSELF),
            &[7, b's', b'p', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ),
        (SpError::UpdateNotPrepared, &[8]),
        (
            SpError::InvalidUpdateId {
                sp_update_id: UpdateId([
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                ]),
            },
            &[9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        ),
        (SpError::UpdateInProgress(UpdateStatus::None), &[10, 0]),
        // Other UpdateStatus variant encodings are already covered by the tests
        // on SpResponse::UpdateStatus above
        (SpError::InvalidUpdateChunk, &[11]),
        (SpError::UpdateFailed(0x01020304), &[12, 4, 3, 2, 1]),
        (SpError::UpdateSlotBusy, &[13]),
        (SpError::PowerStateError(0x01020304), &[14, 4, 3, 2, 1]),
        (SpError::ResetTriggerWithoutPrepare, &[15]),
        (SpError::InvalidSlotForComponent, &[16]),
        (SpError::ComponentOperationFailed(0x01020304), &[17, 4, 3, 2, 1]),
        (SpError::UpdateIsTooLarge, &[18]),
        (
            SpError::SetIpccKeyLookupValueFailed(
                IpccKeyLookupValueError::InvalidKey,
            ),
            &[19, 0],
        ),
        (
            SpError::SetIpccKeyLookupValueFailed(
                IpccKeyLookupValueError::ValueTooLong { max_len: 0x0304 },
            ),
            &[19, 1, 4, 3],
        ),
        (SpError::NoCaboose, &[20]),
        (SpError::NoSuchCabooseKey([1, 2, 3, 4]), &[21, 1, 2, 3, 4]),
        (SpError::CabooseValueOverflow(0x01020304), &[22, 4, 3, 2, 1]),
        (SpError::CabooseReadError, &[23]),
        (SpError::BadCabooseChecksum, &[24]),
        (SpError::ImageBoardUnknown, &[25]),
        (SpError::ImageBoardMismatch, &[26]),
        (SpError::ResetComponentTriggerWithoutPrepare, &[27]),
        (SpError::SwitchDefaultImageError(0x04030201), &[28, 1, 2, 3, 4]),
    ] {
        let response = SpResponse::Error(error);
        let mut expected = vec![17];
        expected.extend_from_slice(error_val);
        assert_serialized(&mut out, &expected, &response);
    }

    let options = StartupOptions::PHASE2_RECOVERY_MODE
        | StartupOptions::STARTUP_KBM
        | StartupOptions::STARTUP_KMDB
        | StartupOptions::STARTUP_BOOT_RAMDISK
        | StartupOptions::STARTUP_VERBOSE;
    assert_eq!(options.bits(), 0x0000_0000_0000_0153);
    let response = SpResponse::StartupOptions(options);
    let expected = &[18, 0x53, 0x01, 0, 0, 0, 0, 0, 0];
    assert_serialized(&mut out, expected, &response);

    let response = SpResponse::SetStartupOptionsAck;
    let expected = &[19];
    assert_serialized(&mut out, expected, &response);

    let response = SpResponse::ComponentDetails(TlvPage {
        offset: 0x01020304,
        total: 0x05060708,
    });
    let expected = &[20, 4, 3, 2, 1, 8, 7, 6, 5];
    assert_serialized(&mut out, expected, &response);

    let response = SpResponse::IgnitionLinkEvents(LinkEvents {
        controller: TransceiverEvents {
            encoding_error: true,
            decoding_error: false,
            ordered_set_invalid: true,
            message_version_invalid: false,
            message_type_invalid: true,
            message_checksum_invalid: false,
        },
        target_link0: TransceiverEvents {
            encoding_error: true,
            decoding_error: true,
            ordered_set_invalid: true,
            message_version_invalid: false,
            message_type_invalid: false,
            message_checksum_invalid: false,
        },
        target_link1: TransceiverEvents {
            encoding_error: false,
            decoding_error: true,
            ordered_set_invalid: false,
            message_version_invalid: true,
            message_type_invalid: false,
            message_checksum_invalid: true,
        },
    });
    let expected = &[21, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1];
    assert_serialized(&mut out, expected, &response);

    let response = SpResponse::BulkIgnitionLinkEvents(TlvPage {
        offset: 0x01020304,
        total: 0x05060708,
    });
    let expected = &[22, 4, 3, 2, 1, 8, 7, 6, 5];
    assert_serialized(&mut out, expected, &response);

    let response = SpResponse::ClearIgnitionLinkEventsAck;
    let expected = &[23];
    assert_serialized(&mut out, expected, &response);

    let response = SpResponse::ComponentClearStatusAck;
    let expected = &[24];
    assert_serialized(&mut out, expected, &response);

    let response = SpResponse::ComponentActiveSlot(0x0102);
    let expected = &[25, 2, 1];
    assert_serialized(&mut out, expected, &response);

    let response = SpResponse::ComponentSetActiveSlotAck;
    let expected = &[26];
    assert_serialized(&mut out, expected, &response);

    let response = SpResponse::SerialConsoleBreakAck;
    let expected = &[27];
    assert_serialized(&mut out, expected, &response);

    let response = SpResponse::SendHostNmiAck;
    let expected = &[28];
    assert_serialized(&mut out, expected, &response);

    let response = SpResponse::SetIpccKeyLookupValueAck;
    let expected = &[29];
    assert_serialized(&mut out, expected, &response);

    let response = SpResponse::ComponentSetAndPersistActiveSlotAck;
    let expected = &[30];
    assert_serialized(&mut out, expected, &response);

    let response = SpResponse::CabooseValue;
    let expected = &[31];
    assert_serialized(&mut out, expected, &response);

    let response = SpResponse::SerialConsoleKeepAliveAck;
    let expected = &[32];
    assert_serialized(&mut out, expected, &response);

    let response = SpResponse::ResetComponentPrepareAck;
    let expected = &[33];
    assert_serialized(&mut out, expected, &response);

    let response = SpResponse::ResetComponentTriggerAck;
    let expected = &[34];
    assert_serialized(&mut out, expected, &response);

    let response = SpResponse::SwitchDefaultImageAck;
    let expected = &[35];
    assert_serialized(&mut out, expected, &response);
}
