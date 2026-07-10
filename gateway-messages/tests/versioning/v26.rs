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

use gateway_messages::{
    MgsRequest, PmbusStatus, PmbusStatusReadError, PmbusStatusResponse,
    PowerRailName, SpResponse,
};

use super::assert_serialized;

const NAME: &str = "VDD_TOASTER";
const RAIL: PowerRailName = PowerRailName::from_const(NAME);

#[test]
fn get_pmbus_status_request() {
    assert_eq!(PowerRailName::MAX_NAME_LENGTH, 32);

    let request = MgsRequest::GetPmbusStatus(RAIL);
    let mut expected = vec![];
    expected.push(51);
    expected.extend(NAME.as_bytes());
    expected.extend(repeat_n(0, PowerRailName::MAX_NAME_LENGTH - NAME.len()));
    assert_serialized(&expected, &request);
}

#[test]
fn get_pmbus_status_response() {
    let response = SpResponse::PmbusStatus(PmbusStatusResponse {
        rail: RAIL,
        status: PmbusStatus {
            status_word: 0x1234,
            status_vout: Ok(0x56),
            status_iout: Ok(0x78),
            status_temperature: Ok(0x9A),
            status_cml: Ok(0xBC),
            status_other: Ok(0xDE),
            status_input: Ok(0xF0),
            status_mfr_specific: Err(PmbusStatusReadError::Unsupported),
            status_fans_1_2: Err(PmbusStatusReadError::DriverReadFailed {
                retry_hint: false,
                raw_response_code: 0xE1,
            }),
            status_fans_3_4: Err(PmbusStatusReadError::DriverReadFailed {
                retry_hint: true,
                raw_response_code: 0xD2,
            }),
        },
    });
    #[rustfmt::skip]
    let expected = &[
        // PmbusStatus
        0x35,
        // VDD_TOASTER
        0x56, 0x44, 0x44, 0x5f, 0x54, 0x4f, 0x41, 0x53, 0x54, 0x45, 0x52,
        // \0 x 21
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // 0x1234
        0x34, 0x12,
        // Ok(0x56)
        0x00, 0x56,
        // Ok(0x78)
        0x00, 0x78,
        // Ok(0x9a)
        0x00, 0x9a,
        // Ok(0xbc)
        0x00, 0xbc,
        // Ok(0xde)
        0x00, 0xde,
        // Ok(0xf0)
        0x00, 0xf0,
        // Err(Unsupported)
        0x01, 0x01,
        // Err(DriverReadFailed { false, 0xe1 })
        0x01, 0x00, 0x00, 0xe1,
        // Err(DriverReadFailed { true, 0xd2 })
        0x01, 0x00, 0x01, 0xd2,
    ];
    assert_serialized(expected, &response);
}
