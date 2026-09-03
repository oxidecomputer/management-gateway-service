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
//! bump the `version::MIN` to a value higher than $VERSION, at which point
//! these tests can be removed as we will stop supporting $VERSION.

use std::iter::repeat_n;

use gateway_messages::vpd::{
    PmbusVpd, SledFanTrayVpd, SmbusBlock, Tmp11xVpd, Vpd,
};
use gateway_messages::{MgsRequest, SpComponent, SpResponse};

use super::assert_serialized;

fn smbus_block(value: &[u8]) -> SmbusBlock {
    let mut block = SmbusBlock::UNSUPPORTED;
    block
        .read_into(|buffer| {
            buffer[..value.len()].copy_from_slice(value);
            Ok::<_, core::convert::Infallible>(Some(value.len()))
        })
        .unwrap();
    block
}

#[test]
fn component_get_vpd_request() {
    let request = MgsRequest::ComponentGetVpd {
        component: SpComponent::try_from("power").unwrap(),
    };
    let mut expected = vec![
        55, // ComponentGetVpd
    ];
    expected.extend_from_slice(b"power");
    expected.extend(repeat_n(0, 11));
    assert_serialized(&expected, &request);
}

#[test]
fn component_vpd_response() {
    assert_serialized(&[57], &SpResponse::ComponentVpd);
}

#[test]
fn pmbus_vpd() {
    const MFR_ID: &[u8] = b"Eliza's Discount Power Supplies";
    const MFR_LOCATION: &[u8] = b"\0Anytown,\0USA";
    const MFR_DATE: &[u8] = b"January 1st, 1970";
    const MFR_SERIAL: &[u8] = &[1, 2, 3, 4];
    const IC_DEVICE_ID: &[u8] = &[0xff, 0, 0x80];

    let vpd = Vpd::Pmbus(PmbusVpd {
        mfr_id: smbus_block(MFR_ID),
        mfr_model: smbus_block(&[0x55; 32]),
        mfr_revision: SmbusBlock::UNSUPPORTED,
        mfr_location: smbus_block(MFR_LOCATION),
        mfr_date: smbus_block(MFR_DATE),
        mfr_serial: smbus_block(MFR_SERIAL),
        ic_device_id: smbus_block(IC_DEVICE_ID),
        ic_device_rev: SmbusBlock::UNSUPPORTED,
    });

    let mut expected = vec![
        0, // Vpd::Pmbus
        1,
        MFR_ID.len() as u8, // Some(MFR_ID)
    ];
    expected.extend_from_slice(MFR_ID);
    expected.extend(repeat_n(0, 32 - MFR_ID.len()));

    expected.extend_from_slice(&[
        1, 32, // Some(MFR_MODEL)
    ]);
    expected.extend(repeat_n(0x55, 32));

    expected.push(0); // None (MFR_REVISION)
    expected.extend(repeat_n(0, 32));

    expected.extend_from_slice(&[
        1,
        MFR_LOCATION.len() as u8, // Some(MFR_LOCATION)
    ]);
    expected.extend_from_slice(MFR_LOCATION);
    expected.extend(repeat_n(0, 32 - MFR_LOCATION.len()));

    expected.extend_from_slice(&[
        1,
        MFR_DATE.len() as u8, // Some(MFR_DATE)
    ]);
    expected.extend_from_slice(MFR_DATE);
    expected.extend(repeat_n(0, 32 - MFR_DATE.len()));

    expected.extend_from_slice(&[
        1,
        MFR_SERIAL.len() as u8, // Some(MFR_SERIAL)
    ]);
    expected.extend_from_slice(MFR_SERIAL);
    expected.extend(repeat_n(0, 32 - MFR_SERIAL.len()));

    expected.extend_from_slice(&[
        1,
        IC_DEVICE_ID.len() as u8, // Some(IC_DEVICE_ID)
    ]);
    expected.extend_from_slice(IC_DEVICE_ID);
    expected.extend(repeat_n(0, 32 - IC_DEVICE_ID.len()));

    expected.push(0); // None (IC_DEVICE_REV)
    expected.extend(repeat_n(0, 32));

    assert_serialized(&expected, &vpd);
}

#[test]
fn oxide_barcode_vpd() {
    const BARCODE: &str = "0XV2:913-000000:003:BRM41210001";

    let vpd = Vpd::Barcode(BARCODE.try_into().unwrap());
    let mut expected = vec![
        1, // Vpd::Barcode
    ];
    expected.extend_from_slice(BARCODE.as_bytes());
    expected.extend(repeat_n(0, 128 - BARCODE.len()));
    assert_serialized(&expected, &vpd);
}

#[test]
fn mpn1_barcode_vpd() {
    const BARCODE: &str = "MPN1:Joe's Stuff:Thingy 2000:420:555-5555";

    let vpd = Vpd::Barcode(BARCODE.try_into().unwrap());
    let mut expected = vec![
        1, // Vpd::Barcode
    ];
    expected.extend_from_slice(BARCODE.as_bytes());
    expected.extend(repeat_n(0, 128 - BARCODE.len()));
    assert_serialized(&expected, &vpd);
}

#[test]
fn fan_assembly_vpd() {
    const ASSEMBLY: &str = "0XV2:913-000000:003:BRM41210001";
    const FAN_0: &str = "MPN1:Eliza's Fans:bcantrill#1fan:01:12345";
    const FAN_1: &str = "0XV2:913-00005:001:BRM41210002";
    const FAN_2: &str = "0XV2:913-00005:002:BRM41210003";

    let vpd = Vpd::SledFanTray(SledFanTrayVpd {
        identity: ASSEMBLY.try_into().unwrap(),
        vpd_board_identity: ASSEMBLY.try_into().unwrap(),
        fans: [
            FAN_0.try_into().unwrap(),
            FAN_1.try_into().unwrap(),
            FAN_2.try_into().unwrap(),
        ],
    });

    let mut expected = vec![
        2, // Vpd::FanAssembly
    ];
    for barcode in [ASSEMBLY, ASSEMBLY, FAN_0, FAN_1, FAN_2] {
        expected.extend_from_slice(barcode.as_bytes());
        expected.extend(repeat_n(0, 128 - barcode.len()));
    }
    assert_serialized(&expected, &vpd);
}

#[test]
fn tmp117_vpd() {
    let vpd = Vpd::Tmp11x(Tmp11xVpd {
        id: 0x117,
        eeprom1: 1,
        eeprom2: 2,
        eeprom3: 3,
    });
    #[rustfmt::skip]
    let expected = &[
        3,          // Vpd::Tmp117
        0x17, 0x01, // id
        0x01, 0x00, // eeprom1
        0x02, 0x00, // eeprom2
        0x03, 0x00, // eeprom3
    ];
    assert_serialized(expected, &vpd);
}
