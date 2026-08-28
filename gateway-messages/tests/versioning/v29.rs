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
    Barcode, FanAssemblyIdentity, Mpn1Identity, OxideIdentity, PmbusVpd,
    SmbusBlock, Tmp117Identity, Vpd,
};
use gateway_messages::{MgsRequest, SpComponent, SpResponse};

use super::assert_serialized;

fn oxide_identity(
    model: &str,
    revision: u32,
    serial_number: &str,
) -> OxideIdentity {
    OxideIdentity {
        serial_number: serial_number.try_into().unwrap(),
        model: model.try_into().unwrap(),
        revision,
    }
}

fn mpn1_identity(serial_number: &str) -> Mpn1Identity {
    Mpn1Identity {
        manufacturer: "manufacturer".try_into().unwrap(),
        model: "model".try_into().unwrap(),
        revision: "revision".try_into().unwrap(),
        serial_number: serial_number.try_into().unwrap(),
    }
}

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
    const MODEL: &[u8] = b"913-000000";
    const SERIAL: &[u8] = b"BRM41210001";

    let vpd = Vpd::OxideBarcode(oxide_identity("913-000000", 3, "BRM41210001"));
    let mut expected = vec![
        1, // Vpd::OxideBarcode
    ];
    expected.extend_from_slice(SERIAL);
    expected.extend(repeat_n(0, 32 - SERIAL.len()));
    expected.extend_from_slice(MODEL);
    expected.extend(repeat_n(0, 32 - MODEL.len()));
    expected.extend_from_slice(&3_u32.to_le_bytes());
    assert_serialized(&expected, &vpd);
}

#[test]
fn mpn1_barcode_vpd() {
    const MANUFACTURER: &[u8] = b"manufacturer";
    const MODEL: &[u8] = b"model";
    const REVISION: &[u8] = b"revision";
    const SERIAL: &[u8] = b"mpn1-serial";

    let vpd = Vpd::Mpn1Barcode(mpn1_identity("mpn1-serial"));
    let mut expected = vec![
        2, // Vpd::Mpn1Barcode
    ];
    for value in [MANUFACTURER, MODEL, REVISION, SERIAL] {
        expected.extend_from_slice(value);
        expected.extend(repeat_n(0, 32 - value.len()));
    }
    assert_serialized(&expected, &vpd);
}

#[test]
fn fan_assembly_vpd() {
    const ASSEMBLY_MODEL: &[u8] = b"913-000000";
    const ASSEMBLY_SERIAL: &[u8] = b"BRM41210001";
    const FAN_MODEL: &[u8] = b"913-00005";
    const FAN_1_SERIAL: &[u8] = b"BRM41210002";
    const FAN_2_SERIAL: &[u8] = b"BRM41210003";
    const MPN1_SERIAL: &[u8] = b"mpn1-serial";

    let assembly = oxide_identity("913-000000", 3, "BRM41210001");
    let vpd = Vpd::FanAssembly(FanAssemblyIdentity {
        identity: assembly.clone(),
        vpd_board_identity: assembly,
        fans: [
            Barcode::Mpn1(mpn1_identity("mpn1-serial")),
            Barcode::Oxide(oxide_identity("913-00005", 1, "BRM41210002")),
            Barcode::Oxide(oxide_identity("913-00005", 2, "BRM41210003")),
        ],
    });

    let mut expected = vec![
        3, // Vpd::FanAssembly
    ];

    // Fan assembly identity.
    expected.extend_from_slice(ASSEMBLY_SERIAL);
    expected.extend(repeat_n(0, 32 - ASSEMBLY_SERIAL.len()));
    expected.extend_from_slice(ASSEMBLY_MODEL);
    expected.extend(repeat_n(0, 32 - ASSEMBLY_MODEL.len()));
    expected.extend_from_slice(&3_u32.to_le_bytes());

    // VPD board identity.
    expected.extend_from_slice(ASSEMBLY_SERIAL);
    expected.extend(repeat_n(0, 32 - ASSEMBLY_SERIAL.len()));
    expected.extend_from_slice(ASSEMBLY_MODEL);
    expected.extend(repeat_n(0, 32 - ASSEMBLY_MODEL.len()));
    expected.extend_from_slice(&3_u32.to_le_bytes());

    // Fan 0: Barcode::Mpn1.
    expected.push(1);
    for value in
        [&b"manufacturer"[..], &b"model"[..], &b"revision"[..], MPN1_SERIAL]
    {
        expected.extend_from_slice(value);
        expected.extend(repeat_n(0, 32 - value.len()));
    }

    // Fan 1: Barcode::Oxide.
    expected.push(0);
    expected.extend_from_slice(FAN_1_SERIAL);
    expected.extend(repeat_n(0, 32 - FAN_1_SERIAL.len()));
    expected.extend_from_slice(FAN_MODEL);
    expected.extend(repeat_n(0, 32 - FAN_MODEL.len()));
    expected.extend_from_slice(&1_u32.to_le_bytes());

    // Fan 2: Barcode::Oxide.
    expected.push(0);
    expected.extend_from_slice(FAN_2_SERIAL);
    expected.extend(repeat_n(0, 32 - FAN_2_SERIAL.len()));
    expected.extend_from_slice(FAN_MODEL);
    expected.extend(repeat_n(0, 32 - FAN_MODEL.len()));
    expected.extend_from_slice(&2_u32.to_le_bytes());

    assert_serialized(&expected, &vpd);
}

#[test]
fn tmp117_vpd() {
    let vpd = Vpd::Tmp117(Tmp117Identity {
        id: 0x117,
        eeprom1: 1,
        eeprom2: 2,
        eeprom3: 3,
    });
    #[rustfmt::skip]
    let expected = &[
        4,          // Vpd::Tmp117
        0x17, 0x01, // id
        0x01, 0x00, // eeprom1
        0x02, 0x00, // eeprom2
        0x03, 0x00, // eeprom3
    ];
    assert_serialized(expected, &vpd);
}
