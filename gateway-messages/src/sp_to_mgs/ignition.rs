// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Types describing ignition state; see RFD 141.

use core::fmt;
use hubpack::SerializedSize;
use serde::Deserialize;
use serde::Serialize;

use crate::tlv;

// Confirm our expectation that for our current product (35 ports), we can fit
// the full bulk ignition state into a single UDP packet.
static_assertions::const_assert!(
    IgnitionState::MAX_SIZE * 35 <= crate::MIN_TRAILING_DATA_LEN
);

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub enum IgnitionError {
    FpgaError,
    InvalidPort,
    InvalidValue,
    NoTargetPresent,
    RequestInProgress,
    RequestDiscarded,
    Other(u32),
}

impl fmt::Display for IgnitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            IgnitionError::FpgaError => "fpga communication error",
            IgnitionError::InvalidPort => "invalid target",
            IgnitionError::InvalidValue => "invalid value",
            IgnitionError::NoTargetPresent => "no target present",
            IgnitionError::RequestInProgress => "request in progress",
            IgnitionError::RequestDiscarded => "request discarded",
            IgnitionError::Other(code) => {
                return write!(f, "other (code = {code})");
            }
        };
        write!(f, "{s}")
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct IgnitionState {
    pub receiver_status: ReceiverStatus,
    pub target: Option<Target>,
}

impl IgnitionState {
    pub const TAG: tlv::Tag = tlv::Tag(*b"IGN0");
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct ReceiverStatus {
    pub aligned: bool,
    pub locked: bool,
    pub polarity_inverted: bool,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct Target {
    pub system_type: SystemType,
    pub power_state: SystemPowerState,
    pub power_reset_in_progress: bool,
    pub faults: SystemFaults,
    pub controller0_present: bool,
    pub controller1_present: bool,
    pub link0_receiver_status: ReceiverStatus,
    pub link1_receiver_status: ReceiverStatus,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub enum SystemPowerState {
    Off,
    On,
    Aborted,
    PoweringOff,
    PoweringOn,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct SystemFaults {
    pub power_a3: bool,
    pub power_a2: bool,
    pub sp: bool,
    pub rot: bool,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub enum SystemType {
    // TODO do we want these specific names or generic ones? MGS proper can also
    // translate before going out to the control plane, potentially.
    Gimlet,
    Sidecar,
    Psc,
    Unknown(u16),
}

impl From<u16> for SystemType {
    fn from(val: u16) -> Self {
        match val {
            raw_system_type::GIMLET => Self::Gimlet,
            raw_system_type::SIDECAR => Self::Sidecar,
            raw_system_type::PSC => Self::Psc,
            _ => Self::Unknown(val),
        }
    }
}

// Constant values from RFD 141.
mod raw_system_type {
    pub(super) const GIMLET: u16 = 0b0000_0000_0001_0001;
    pub(super) const SIDECAR: u16 = 0b0000_0000_0001_0010;
    pub(super) const PSC: u16 = 0b0000_0000_0001_0011;
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct LinkEvents {
    pub controller: TransceiverEvents,
    pub target_link0: TransceiverEvents,
    pub target_link1: TransceiverEvents,
}

impl LinkEvents {
    pub const TAG: tlv::Tag = tlv::Tag(*b"ILE0");
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub enum TransceiverSelect {
    Controller,
    TargetLink0,
    TargetLink1,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct TransceiverEvents {
    pub encoding_error: bool,
    pub decoding_error: bool,
    pub ordered_set_invalid: bool,
    pub message_version_invalid: bool,
    pub message_type_invalid: bool,
    pub message_checksum_invalid: bool,
}
