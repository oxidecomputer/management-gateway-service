// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Types for messages sent from SPs to MGS.

use crate::tlv;
use crate::BadRequestReason;
use crate::PowerState;
use crate::SpComponent;
use crate::StartupOptions;
use crate::UpdateId;
use bitflags::bitflags;
use core::fmt;
use hubpack::SerializedSize;
use serde::Deserialize;
use serde::Serialize;
use serde_repr::Deserialize_repr;
use serde_repr::Serialize_repr;

pub mod ignition;
pub mod measurement;
pub mod monorail_port_status;

pub use ignition::IgnitionState;
pub use measurement::Measurement;

use ignition::IgnitionError;
use measurement::MeasurementHeader;
use monorail_port_status::{PortStatus, PortStatusError};

use ignition::LinkEvents;

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
    /// Request a single packet-worth of a host phase 2 image (identified by
    /// `hash`) starting at `offset`.
    HostPhase2Data { hash: [u8; 32], offset: u64 },
}

#[derive(
    Debug, Clone, Copy, SerializedSize, Serialize, Deserialize, PartialEq, Eq,
)]
pub enum SpResponse {
    Discover(DiscoverResponse),
    IgnitionState(IgnitionState),
    /// `BulkIgnitionState` is followed by a TLV-encoded set of
    /// [`ignition::IgnitionState`]s.
    BulkIgnitionState(TlvPage),
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
    /// An `Inventory` response is followed by a TLV-encoded set of
    /// [`DeviceDescriptionHeader`]s.
    Inventory(TlvPage),
    Error(SpError),
    StartupOptions(StartupOptions),
    SetStartupOptionsAck,
    /// A `ComponentDetails` response is followed by a TLV-encoded set of
    /// informational structures (see [`ComponentDetails`]).
    ComponentDetails(TlvPage),
    IgnitionLinkEvents(LinkEvents),
    /// A `BulkIgnitionLinkEvents` response is followed by a TLV-encoded set of
    /// [`ignition::LinkEvents`]s.
    BulkIgnitionLinkEvents(TlvPage),
    ClearIgnitionLinkEventsAck,
    ComponentClearStatusAck,
    ComponentActiveSlot(u16),
    ComponentSetActiveSlotAck,
    SerialConsoleBreakAck,
    SendHostNmiAck,
    SetIpccKeyLookupValueAck,
    ComponentSetAndPersistActiveSlotAck,

    /// The packet contains trailing caboose data
    CabooseValue,

    SerialConsoleKeepAliveAck,
    ResetComponentPrepareAck,
    ResetComponentTriggerAck,
    SwitchDefaultImageAck,
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

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct ImageVersion {
    pub epoch: u32,
    pub version: u32,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct SpState {
    pub hubris_archive_id: [u8; 8],
    // Serial and revision are only 11 bytes in practice; we have plenty of room
    // so we'll leave the fields wider in case we grow it in the future. The
    // values are 0-padded.
    pub serial_number: [u8; 32],
    pub model: [u8; 32],
    pub revision: u32,
    pub base_mac_address: [u8; 6],
    pub version: ImageVersion,
    pub power_state: PowerState,
    pub rot: Result<RotState, RotError>,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub enum RotSlot {
    A,
    B,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, SerializedSize,
)]
pub struct RotImageDetails {
    pub digest: [u8; 32],
    pub version: ImageVersion,
}

/// The boot time details dumped by Stage0 into Hubris on the RoT
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct RotBootState {
    pub active: RotSlot,
    pub slot_a: Option<RotImageDetails>,
    pub slot_b: Option<RotImageDetails>,
}

// TODO(AJS): Fill in with runtime state - i.e. updates that have completed before an RoT reset
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct RotUpdateDetails {
    pub boot_state: RotBootState,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct RotState {
    pub rot_updates: RotUpdateDetails,
}

/// Metadata describing a single page (out of a larger list) of TLV-encoded
/// structures returned by the SP.
///
/// Always followed by trailing data containing a sequence of [`tlv`]-encoded
/// structures (e.g., [`DeviceDescriptionHeader`], [`ComponentDetails`]).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, SerializedSize,
)]
pub struct TlvPage {
    /// First encoded structure present in this packet.
    pub offset: u32,
    /// Total number of structures in this data set.
    pub total: u32,
}

/// Types of component details that can be included in the TLV-encoded data of
/// an [`SpResponse::ComponentDetails(_)`] message.
///
/// Note that `ComponentDetails` itself does not implement the relevant serde
/// serialization traits; it only serves as an organizing collection of the
/// possible types contained in a component details message. Each TLV-encoded
/// struct corresponds to one of these cases.
#[derive(Debug, Clone)]
pub enum ComponentDetails {
    PortStatus(Result<PortStatus, PortStatusError>),
    Measurement(Measurement),
}

impl ComponentDetails {
    pub fn tag(&self) -> tlv::Tag {
        match self {
            ComponentDetails::PortStatus(_) => PortStatus::TAG,
            ComponentDetails::Measurement(_) => MeasurementHeader::TAG,
        }
    }

    pub fn serialize(&self, buf: &mut [u8]) -> hubpack::error::Result<usize> {
        match self {
            ComponentDetails::PortStatus(p) => hubpack::serialize(buf, p),
            ComponentDetails::Measurement(m) => {
                let header = MeasurementHeader::from(m);

                // Serialize the header...
                let n = hubpack::serialize(buf, &header)?;
                let buf = &mut buf[n..];

                // ... then append the name if we have room.
                if buf.len() < m.name.len() {
                    Err(hubpack::error::Error::Overrun)
                } else {
                    buf[..m.name.len()].copy_from_slice(m.name.as_bytes());
                    Ok(n + m.name.len())
                }
            }
        }
    }
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
    /// An ignition-related error.
    Ignition(IgnitionError),
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
    InvalidUpdateId {
        sp_update_id: UpdateId,
    },
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
    /// The requested operation on the component failed with the associated
    /// code.
    ComponentOperationFailed(u32),
    /// The update exceeds our slot capacity
    UpdateIsTooLarge,
    /// Setting requested IPCC key/value failed.
    SetIpccKeyLookupValueFailed(IpccKeyLookupValueError),
    /// The image does not have a caboose
    NoCaboose,
    /// The given key is not available in the caboose
    NoSuchCabooseKey([u8; 4]),
    /// The given caboose value would overflow the trailing packet data
    CabooseValueOverflow(u32),
    CabooseReadError,
    BadCabooseChecksum,
    /// The new image does not have a caboose with the `BORD` key
    ImageBoardUnknown,
    /// The new image has a `BORD` key that does not match the current image
    ImageBoardMismatch,
    /// Received a `ResetComponentTrigger` request without first receiving a
    /// `ResetComponentPrepare` request. This can be used to detect a successful
    /// reset on the SP_ITSELF. Not used for the ROT where the SP observes
    /// the RoT reset and can report success.
    ResetComponentTriggerWithoutPrepare,
    /// There will be policy violations for some requests:
    ///   - No image in SlotId (what suitability checks are needed?)
    ///   - Lower epoch than current in SlotId
    SwitchDefaultImageError(u32),
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
            Self::Ignition(err) => {
                write!(f, "ignition error: {err}")
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
            Self::ComponentOperationFailed(code) => {
                write!(f, "component operation failed (code {code})")
            }
            Self::UpdateIsTooLarge => {
                write!(f, "update is too large")
            }
            Self::SetIpccKeyLookupValueFailed(err) => {
                write!(f, "failed to set IPCC key/value: {err}")
            }
            Self::NoCaboose => {
                write!(f, "the image does not include a caboose")
            }
            Self::NoSuchCabooseKey(key) => {
                write!(f, "the image caboose does not contain ").and_then(
                    |_| match core::str::from_utf8(key) {
                        Ok(s) => write!(f, "'{s}'"),
                        Err(_) => write!(f, "{key:#x?}"),
                    },
                )
            }
            Self::CabooseValueOverflow(size) => {
                write!(
                    f,
                    "caboose value is too large to fit in a packet \
                     ({size} bytes)"
                )
            }
            Self::CabooseReadError => {
                write!(f, "failed to read data from the caboose")
            }
            Self::BadCabooseChecksum => {
                write!(f, "a data checksum in the caboose is invalid")
            }
            Self::ImageBoardUnknown => {
                write!(f, "could not find the board in the image cabose")
            }
            Self::ImageBoardMismatch => {
                write!(f, "the image has a board that doesn't match the current image")
            }
            Self::ResetComponentTriggerWithoutPrepare => {
                write!(f, "reset component trigger requested without a preceding reset component prepare")
            }
            Self::SwitchDefaultImageError(code) => {
                write!(f, "switch default image failed with code {code}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SpError {}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub enum IpccKeyLookupValueError {
    InvalidKey,
    ValueTooLong { max_len: u16 },
}

impl fmt::Display for IpccKeyLookupValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpccKeyLookupValueError::InvalidKey => write!(f, "invalid key"),
            IpccKeyLookupValueError::ValueTooLong { max_len } => {
                write!(f, "value too long (limit: {max_len})")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IpccKeyLookupValueError {}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub enum RotError {
    MessageError { code: u32 },
}

impl fmt::Display for RotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MessageError { code } => {
                write!(f, "SP/RoT messaging error: {code}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RotError {}
