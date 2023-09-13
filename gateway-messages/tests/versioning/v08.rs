// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The tests in this module check that the serialized form of messages from MGS
//! protocol version 8 have not changed.
//!
//! If a test in this module fails, _do not change the test_! This means you
//! have changed, deleted, or reordered an existing message type or enum
//! variant, and you should revert that change. This will remain true until we
//! bump the `version::MIN` to a value higher than 8, at which point these tests
//! can be removed as we will stop supporting v8.

use super::assert_serialized;
use gateway_messages::MgsRequest;
use gateway_messages::SensorDataMissing;
use gateway_messages::SensorReading;
use gateway_messages::SensorRequest;
use gateway_messages::SensorRequestKind;
use gateway_messages::SensorResponse;
use gateway_messages::SerializedSize;
use gateway_messages::SpResponse;

#[test]
fn sp_response() {
    let mut out = [0; SpResponse::MAX_SIZE];
    for (response, serialized) in [
        (
            SensorResponse::LastReading(SensorReading {
                value: Ok(1.0),
                timestamp: 0x5566,
            }),
            &[0u8, 0, 0, 0, 0x80, 0x3f, 0x66, 0x55, 0, 0, 0, 0, 0, 0] as &[_],
        ),
        (
            SensorResponse::LastData { value: 1.0, timestamp: 0x5566 },
            &[1, 0, 0, 0x80, 0x3f, 0x66, 0x55, 0, 0, 0, 0, 0, 0],
        ),
        (
            SensorResponse::LastError {
                value: SensorDataMissing::DeviceOff,
                timestamp: 0x5566,
            },
            &[2, 0, 0x66, 0x55, 0, 0, 0, 0, 0, 0],
        ),
        (SensorResponse::ErrorCount(0x12345678), &[3, 0x78, 0x56, 0x34, 0x12]),
    ] {
        let response = SpResponse::ReadSensor(response);
        let mut expected = vec![
            38, // SpResponse::ReadSensor
        ];
        expected.extend_from_slice(serialized);
        assert_serialized(&mut out, &expected, &response);
    }

    let response = SpResponse::CurrentTime(0x1234);
    let expected = [39, 0x34, 0x12, 0, 0, 0, 0, 0, 0];
    assert_serialized(&mut out, &expected, &response);
}

#[test]
fn host_request() {
    let mut out = [0; MgsRequest::MAX_SIZE];
    for (kind, serialized) in [
        (SensorRequestKind::LastReading, &[0, 0x34, 0x12, 0, 0]),
        (SensorRequestKind::LastData, &[1, 0x34, 0x12, 0, 0]),
        (SensorRequestKind::LastError, &[2, 0x34, 0x12, 0, 0]),
        (SensorRequestKind::ErrorCount, &[3, 0x34, 0x12, 0, 0]),
    ] {
        let request =
            MgsRequest::ReadSensor(SensorRequest { kind, id: 0x1234 });
        let mut expected = vec![
            38, // MgsRequest::ReadSensor
        ];
        expected.extend_from_slice(serialized);
        assert_serialized(&mut out, &expected, &request);
    }

    let request = MgsRequest::CurrentTime;
    let expected = vec![
        39, // MgsRequest::CurrentTime
    ];
    assert_serialized(&mut out, &expected, &request);
}

#[test]
fn sensor_data_missing() {
    let mut out = [0; SensorDataMissing::MAX_SIZE];

    assert_serialized(&mut out, &[0], &SensorDataMissing::DeviceOff);
    assert_serialized(&mut out, &[1], &SensorDataMissing::DeviceError);
    assert_serialized(&mut out, &[2], &SensorDataMissing::DeviceNotPresent);
    assert_serialized(&mut out, &[3], &SensorDataMissing::DeviceUnavailable);
    assert_serialized(&mut out, &[4], &SensorDataMissing::DeviceTimeout);
}
