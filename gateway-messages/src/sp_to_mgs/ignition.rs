// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Types describing ignition state; see RFD 141.

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
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    SerializedSize,
    Serialize,
    Deserialize,
)]
pub struct IgnitionState {
    pub receiver_status: ReceiverStatus,
    pub target: Option<Target>,
}

impl IgnitionState {
    pub const TAG: tlv::Tag = tlv::Tag(*b"IGN0");
}

#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    SerializedSize,
    Serialize,
    Deserialize,
)]
pub struct ReceiverStatus {
    pub aligned: bool,
    pub locked: bool,
    pub polarity_inverted: bool,
}

#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    SerializedSize,
    Serialize,
    Deserialize,
)]
pub struct Target {
    pub system_type: SystemType,
    pub controller0_present: bool,
    pub controller1_present: bool,
    pub system_power_abort: bool,
    pub faults: SystemFaults,
    pub system_power_off_in_progress: bool,
    pub system_power_on_in_progress: bool,
    pub system_power_reset_in_progress: bool,
    pub link0_receiver_status: ReceiverStatus,
    pub link1_receiver_status: ReceiverStatus,
}

#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    SerializedSize,
    Serialize,
    Deserialize,
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
    Gimlet,
    Sidecar,
    Psc,
    Unknown(u16),
}

impl Default for SystemType {
    fn default() -> Self {
        Self::Unknown(0)
    }
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
