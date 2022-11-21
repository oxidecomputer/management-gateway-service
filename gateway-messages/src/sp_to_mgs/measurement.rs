// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use hubpack::SerializedSize;
use serde::Deserialize;
use serde::Serialize;

use crate::tlv;

/// `Measurement` includes a `name` field; on the SP, this is a `&'static str`
/// (embedded at build time), and in MGS it's a `String` (deserialized from the
/// SP message).
///
/// This struct does not implement `Serialize`/`Deserialize`; it is serialized
/// as a [`tlv`] triple with the value bing a [`MeasurementHeader`] followed by
/// the name.
#[derive(Debug, Clone)]
pub struct Measurement {
    #[cfg(feature = "std")]
    pub name: String,
    #[cfg(not(feature = "std"))]
    pub name: &'static str,
    pub kind: MeasurementKind,
    pub value: Result<f32, MeasurementError>,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, SerializedSize)]
pub struct MeasurementHeader {
    pub name_length: u32,
    pub kind: MeasurementKind,
    pub value: Result<f32, MeasurementError>,
}

impl From<&'_ Measurement> for MeasurementHeader {
    fn from(m: &Measurement) -> Self {
        Self { name_length: m.name.len() as u32, kind: m.kind, value: m.value }
    }
}

impl MeasurementHeader {
    pub const TAG: tlv::Tag = tlv::Tag(*b"MEA0");
}

#[derive(
    Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize, SerializedSize,
)]
pub enum MeasurementError {
    InvalidSensor,
    NoReading,
    NotPresent,
    DeviceError,
    DeviceUnavailable,
    DeviceTimeout,
    DeviceOff,
}

#[derive(
    Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, SerializedSize,
)]
pub enum MeasurementKind {
    Temperature,
    Power,
    Current,
    Voltage,
    Speed,
}
