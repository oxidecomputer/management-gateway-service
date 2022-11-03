// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Types for messages sent from SPs to MGS.

use crate::tlv;
use crate::BadRequestReason;
use crate::PowerState;
use crate::SpComponent;
use crate::UpdateId;
use bitflags::bitflags;
use core::fmt;
use hubpack::SerializedSize;
use serde::Deserialize;
use serde::Serialize;
use serde_repr::Deserialize_repr;
use serde_repr::Serialize_repr;

#[derive(
    Debug, Clone, Copy, SerializedSize, Serialize, Deserialize, PartialEq, Eq,
)]
pub enum SpRequest {
    /// Data traveling from an SP-attached component (in practice, a CPU) on the
    /// component's serial console.
    ///
    /// Note that SP -> MGS serial console messages are currently _not_
    /// acknowledged or retried; they are purely "fire and forget" from the SP's
    /// point of view. Once it sends data in a packet, it discards it from its
    /// local buffer.
    SerialConsole {
        component: SpComponent,
        /// Offset of the first byte in this packet's data starting from 0 when
        /// the serial console session was attached.
        offset: u64,
    },
}

#[derive(
    Debug, Clone, Copy, SerializedSize, Serialize, Deserialize, PartialEq, Eq,
)]
pub enum SpResponse {
    Discover(DiscoverResponse),
    IgnitionState(IgnitionState),
    BulkIgnitionState(BulkIgnitionState),
    IgnitionCommandAck,
    SpState(SpState),
    SpUpdatePrepareAck,
    ComponentUpdatePrepareAck,
    UpdateChunkAck,
    UpdateStatus(UpdateStatus),
    UpdateAbortAck,
    SerialConsoleAttachAck,
    SerialConsoleWriteAck {
        furthest_ingested_offset: u64,
    },
    SerialConsoleDetachAck,
    PowerState(PowerState),
    SetPowerStateAck,
    ResetPrepareAck,
    // There is intentionally no `ResetTriggerAck` response; the expected
    // "response" to `ResetTrigger` is an SP reset, which won't allow for
    // acks to be sent.
    /// An `Inventory` response is followed by a TLV-encoded set of device
    /// descriptions. See TODO FIXME for details.
    Inventory(DeviceInventoryPage),
    Error(SpError),
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
pub struct IgnitionState {
    pub id: u16,
    pub flags: IgnitionFlags,
}

impl IgnitionState {
    pub fn is_powered_on(self) -> bool {
        self.flags.intersects(IgnitionFlags::POWER)
    }
}

bitflags! {
    #[derive(Default, SerializedSize, Serialize, Deserialize)]
    pub struct IgnitionFlags: u8 {
        // RFD 142, 5.2.4 status bits
        const POWER = 0b0000_0001;
        const CTRL_DETECT_0 = 0b0000_0010;
        const CTRL_DETECT_1 = 0b0000_0100;
        // const RESERVED_3 = 0b0000_1000;

        // RFD 142, 5.2.3 fault signals
        const FLT_A3 = 0b0001_0000;
        const FLT_A2 = 0b0010_0000;
        const FLT_ROT = 0b0100_0000;
        const FLT_SP = 0b1000_0000;
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct BulkIgnitionState {
    /// Ignition state for each target.
    ///
    /// TODO The ignition target is implicitly the array index; is that
    /// reasonable or should we specify target indices explicitly?
    #[serde(with = "serde_big_array::BigArray")]
    pub targets: [IgnitionState; Self::MAX_IGNITION_TARGETS],
}

impl BulkIgnitionState {
    // TODO-cleanup Is it okay to hard code this number to what we know the
    // value is for the initial rack? For now assuming yes, and any changes in
    // future products could use a different message.
    pub const MAX_IGNITION_TARGETS: usize = 36;
}

/// Identifier for one of of an SP's KSZ8463 management-network-facing ports.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    Serialize_repr,
    Deserialize_repr,
    SerializedSize,
)]
#[repr(u8)]
pub enum SpPort {
    One = 1,
    Two = 2,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct DiscoverResponse {
    /// Which SP port received the `Discover` request.
    pub sp_port: SpPort,
}

// TODO how is this reported? Same/different for components?
pub type SerialNumber = [u8; 16];

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct SpState {
    pub serial_number: SerialNumber,
    pub version: u32,
}

/// Metadata describing the set of device descriptions present in this response.
///
/// Followed by trailing data containing a sequence of [`tlv`]-encoded
/// [`DeviceDescriptionHeader`]s and their associated data.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, SerializedSize,
)]
pub struct DeviceInventoryPage {
    /// First device index present in this response.
    pub device_index: u32,
    /// Total number of devices present on the SP.
    pub total_devices: u32,
}

/// Header for the description of a single device.
///
/// Always packed into a [`tlv`] triple containing:
///
/// ```text
/// [
///     DeviceDescriptionHeader::TAG
///     | length
///     | hubpack-serialized DeviceDescriptionHeader
///     | device
///     | description
/// ]
/// ```
///
/// where `device` and `description` are UTF8 strings whose lengths are included
/// in the `DeviceDescriptionHeader`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, SerializedSize,
)]
pub struct DeviceDescriptionHeader {
    pub component: SpComponent,
    pub device_len: u32,
    pub description_len: u32,
    pub capabilities: DeviceCapabilities,
    pub presence: DevicePresence,
}

impl DeviceDescriptionHeader {
    pub const TAG: tlv::Tag = tlv::Tag(*b"DSC0");
}

bitflags! {
    #[derive(Default, SerializedSize, Serialize, Deserialize)]
    pub struct DeviceCapabilities: u32 {
        const UPDATEABLE = 1 << 0;
        const HAS_MEASUREMENT_CHANNELS = 1 << 1;
        const HAS_SERIAL_CONSOLE = 1 << 2;
        // MGS has a placeholder API for powering off an individual component;
        // do we want to keep that? If so, add a bit for "can be powered on and
        // off".
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, SerializedSize,
)]
pub enum DevicePresence {
    Present,
    NotPresent,
    Failed,
    Unavailable,
    Timeout,
    Error,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub enum UpdateStatus {
    /// The SP has no update status.
    None,
    /// Returned when the SP is still preparing to apply the update with the
    /// given ID (e.g., erasing a target flash slot).
    Preparing(UpdatePreparationStatus),
    /// Special status only applicable to SP updates: the SP has finished
    /// scanning its auxiliary flash slots, and we now know whether we need to
    /// send the aux flash image.
    ///
    /// This state is only applicable to (a) the `SP_ITSELF` component when (b)
    /// the update preparation message sent by MGS indicates an aux flash image
    /// is present.
    SpUpdateAuxFlashChckScan {
        id: UpdateId,
        /// If true, MGS will not send the aux flash image and will only send
        /// the SP image.
        found_match: bool,
        /// Total size of the update to be applied.
        ///
        /// This is not directly relevant to this state, but is used by MGS to
        /// convert this state (which only it knows about) into an `InProgress`
        /// state to return to its callers.
        total_size: u32,
    },
    /// Returned when an update is currently in progress.
    InProgress(UpdateInProgressStatus),
    /// Returned when an update has completed.
    ///
    /// The SP has no concept of time, so we cannot indicate how recently this
    /// update completed. The SP will continue to return this status until a new
    /// update starts (or the status is reset some other way, such as an SP
    /// reboot).
    Complete(UpdateId),
    /// Returned when an update has been aborted.
    ///
    /// The SP has no concept of time, so we cannot indicate how recently this
    /// abort happened. The SP will continue to return this status until a new
    /// update starts (or the status is reset some other way, such as an SP
    /// reboot).
    Aborted(UpdateId),
    /// Returned when an update has failed on the SP.
    ///
    /// The SP has no concept of time, so we cannot indicate how recently this
    /// abort happened. The SP will continue to return this status until a new
    /// update starts (or the status is reset some other way, such as an SP
    /// reboot).
    Failed { id: UpdateId, code: u32 },
}

/// Current state when the SP is preparing to apply an update.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct UpdatePreparationStatus {
    pub id: UpdateId,
    pub progress: Option<UpdatePreparationProgress>,
}

/// Current progress of preparing for an update.
///
/// The initial values reported by the SP should have `current=0` and `total`
/// defined in some SP-specific unit. `current` should advance toward `total`;
/// once `current == total` preparation is complete, and the SP should return
/// `UpdateStatus::InProgress` instead.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct UpdatePreparationProgress {
    pub current: u32,
    pub total: u32,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct UpdateInProgressStatus {
    pub id: UpdateId,
    pub bytes_received: u32,
    pub total_size: u32,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub enum SpError {
    /// The SP is busy; retry the request mometarily.
    ///
    /// E.g., the request requires communicating on a USART whose FIFO is
    /// currently full.
    Busy,
    /// The request from MGS was invalid.
    BadRequest(BadRequestReason),
    /// The [`RequestKind`] is not supported by the receiving SP; e.g., asking an
    /// SP without an attached ignition controller for ignition state.
    RequestUnsupportedForSp,
    /// The [`RequestKind`] is not supported by the receiving component of the
    /// SP; e.g., asking for the serial console of a component that does not
    /// have one.
    RequestUnsupportedForComponent,
    /// The specified ignition target does not exist.
    IgnitionTargetDoesNotExist(u8),
    /// Cannot write to the serial console because it is not attached.
    SerialConsoleNotAttached,
    /// Cannot attach to the serial console because another MGS instance is
    /// already attached.
    SerialConsoleAlreadyAttached,
    /// An update cannot be started while another component is being updated.
    OtherComponentUpdateInProgress(SpComponent),
    /// An update has not been prepared yet.
    UpdateNotPrepared,
    /// An update-related message arrived at the SP, but its update ID does not
    /// match the update ID the SP is currently processing.
    InvalidUpdateId { sp_update_id: UpdateId },
    /// An update is already in progress with the specified amount of data
    /// already provided. MGS should resume the update at that offset.
    UpdateInProgress(UpdateStatus),
    /// Received an invalid update chunk; the in-progress update must be
    /// aborted and restarted.
    InvalidUpdateChunk,
    /// An update operation failed with the associated code.
    UpdateFailed(u32),
    /// An update is not possible at this time (e.g., the target slot is locked
    /// by another device).
    UpdateSlotBusy,
    /// An error occurred getting or setting the power state.
    PowerStateError(u32),
    /// Received a `ResetTrigger` request without first receiving a
    /// `ResetPrepare` request. This can be used to detect a successful
    /// reset.
    ResetTriggerWithoutPrepare,
    /// Request mentioned a slot number for a component that does not have that
    /// slot.
    InvalidSlotForComponent,
}

impl fmt::Display for SpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy => {
                write!(f, "SP busy")
            }
            Self::BadRequest(reason) => {
                write!(f, "bad request: {reason:?}")
            }
            Self::RequestUnsupportedForSp => {
                write!(f, "unsupported request for this SP")
            }
            Self::RequestUnsupportedForComponent => {
                write!(f, "unsupported request for this SP component")
            }
            Self::IgnitionTargetDoesNotExist(target) => {
                write!(f, "nonexistent ignition target {}", target)
            }
            Self::SerialConsoleNotAttached => {
                write!(f, "serial console is not attached")
            }
            Self::SerialConsoleAlreadyAttached => {
                write!(f, "serial console already attached")
            }
            Self::OtherComponentUpdateInProgress(component) => {
                write!(f, "another component is being updated {component:?}")
            }
            Self::UpdateNotPrepared => {
                write!(f, "SP has not received update prepare request")
            }
            Self::InvalidUpdateId { sp_update_id } => {
                write!(
                    f,
                    "bad update ID (update already in progress, ID {:#04x?})",
                    sp_update_id.0
                )
            }
            Self::UpdateInProgress(status) => {
                write!(f, "update still in progress ({status:?})")
            }
            Self::UpdateSlotBusy => {
                write!(f, "update currently unavailable (slot busy)")
            }
            Self::InvalidUpdateChunk => {
                write!(f, "invalid update chunk")
            }
            Self::UpdateFailed(code) => {
                write!(f, "update failed (code {})", code)
            }
            Self::PowerStateError(code) => {
                write!(f, "power state error (code {}))", code)
            }
            Self::ResetTriggerWithoutPrepare => {
                write!(f, "sys reset trigger requested without a preceding sys reset prepare")
            }
            Self::InvalidSlotForComponent => {
                write!(f, "invalid slot number for component")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SpError {}
