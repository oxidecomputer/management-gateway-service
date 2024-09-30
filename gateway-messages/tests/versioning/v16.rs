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
use gateway_messages::measurement::MeasurementKind;
use gateway_messages::SerializedSize;
use gateway_messages::SpResponse;

#[test]
fn measurement_kinds() {
    let mut out = [0; SpResponse::MAX_SIZE];

    for (kind, serialized) in [
        (MeasurementKind::Temperature, &[0]),
        (MeasurementKind::Power, &[1]),
        (MeasurementKind::Current, &[2]),
        (MeasurementKind::Voltage, &[3]),
        (MeasurementKind::InputCurrent, &[4]),
        (MeasurementKind::InputVoltage, &[5]),
        (MeasurementKind::Speed, &[6]),
        (MeasurementKind::CpuTctl, &[7]),
    ] {
        assert_serialized(&mut out, serialized, &kind);
    }
}
