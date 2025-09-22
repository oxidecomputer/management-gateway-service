// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Types for messages sent from SPs to MGS.

use crate::tlv;
use crate::BadRequestReason;
use crate::PowerState;
use crate::RotResponse;
use crate::RotSlotId;
use crate::SensorResponse;
use crate::SpComponent;
use crate::StartupOptions;
use crate::UnlockChallenge;
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
    Debug,
    Clone,
    Copy,
    SerializedSize,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    strum_macros::VariantNames,
)]
#[strum(serialize_all = "snake_case")]
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
    Debug,
    Clone,
    Copy,
    PartialEq,
    SerializedSize,
    Serialize,
    Deserialize,
    strum_macros::IntoStaticStr,
    strum_macros::VariantNames,
)]
#[strum(serialize_all = "snake_case")]
pub enum SpResponse {
    Discover(DiscoverResponse),
    IgnitionState(IgnitionState),
    /// `BulkIgnitionState` is followed by a TLV-encoded set of
    /// [`ignition::IgnitionState`]s.
    BulkIgnitionState(TlvPage),
    IgnitionCommandAck,
    SpState(SpStateV1),
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
    /// Indicates that a `SetPowerState` request was performed successfully
    /// and resulted in a power state transition.
    ///
    /// If the SP is already in the desired power state, the
    /// [`Self::PowerStateUnchanged`] response is returned instead.
    ///
    /// **Note**: Prior to v18, this message was named `SetPowerStateAck`, but
    /// it was only sent when a power state change occurred (so its semantic
    /// meaning has remained the same). In v17 and earlier, a
    /// [`SpError::SeqError`] message was sent in the case where no power state
    /// transition occurred, instead of a `PowerStateUnchanged` message.
    PowerStateSet,
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
    ComponentActionAck,

    SpStateV2(SpStateV2),
    ReadSensor(SensorResponse),
    CurrentTime(u64),
    ReadRot(RotResponse),
    /// The packet contains trailing lock information
    VpdLockState,

    DisableComponentWatchdogAck,
    ComponentWatchdogSupportedAck,

    SpStateV3(SpStateV3),
    RotBootInfo(RotBootInfo),

    /// Response to a data-bearing component action
    ComponentAction(ComponentActionResponse),

    /// Response to a dump request
    ///
    /// The packet may contain trailing dump data
    Dump(DumpResponse),

    /// Response to a `SetPowerState` request indicating that the system was
    /// already in the desired power state and no transition occurred.
    PowerStateUnchanged,

    /// Packet contains the host flash data
    ReadHostFlash,

    /// Started a hash of a flash bank
    StartHostFlashHashAck,

    /// sha2-256 hash of a flash bank
    HostFlashHash([u8; 32]),

    /// Cancel a pending slot activation
    ComponentCancelPendingActiveSlotAck,
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
    Debug, Copy, Clone, PartialEq, Eq, Deserialize, Serialize, SerializedSize,
)]
pub enum ImageError {
    /// Image has not been sanity checked (internal use)
    Unchecked = 1,
    /// First page of image is erased.
    FirstPageErased,
    /// Some pages in the image are erased.
    PartiallyProgrammed,
    /// The NXP image offset + length caused a wrapping add.
    InvalidLength,
    /// The header flash page is erased.
    HeaderNotProgrammed,
    /// A bootloader image is too short.
    BootloaderTooSmall,
    /// A required ImageHeader is missing.
    BadMagic,
    /// The image size in ImageHeader is unreasonable.
    HeaderImageSize,
    /// total_image_length in ImageHeader is not properly aligned.
    UnalignedLength,
    /// Some NXP image types are not supported.
    UnsupportedType,
    /// Wrong format reset vector.
    ResetVectorNotThumb2,
    /// Reset vector points outside of image execution range.
    ResetVector,
    /// Signature check on image failed.
    Signature,
}

/// This is quasi-deprecated in that it will only be returned by SPs with images
/// older than the  introduction of `SpStateV2`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct SpStateV1 {
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
pub struct SpStateV2 {
    pub hubris_archive_id: [u8; 8],
    // Serial and revision are only 11 bytes in practice; we have plenty of room
    // so we'll leave the fields wider in case we grow it in the future. The
    // values are 0-padded.
    pub serial_number: [u8; 32],
    pub model: [u8; 32],
    pub revision: u32,
    pub base_mac_address: [u8; 6],
    pub power_state: PowerState,
    pub rot: Result<RotStateV2, RotError>,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct SpStateV3 {
    pub hubris_archive_id: [u8; 8],
    // Serial and revision are only 11 bytes in practice; we have plenty of room
    // so we'll leave the fields wider in case we grow it in the future. The
    // values are 0-padded.
    pub serial_number: [u8; 32],
    pub model: [u8; 32],
    pub revision: u32,
    pub base_mac_address: [u8; 6],
    pub power_state: PowerState,
}

type Digest256 = [u8; 32];

trait HexDisplayableArray {
    // fn display(&self) -> fmt::Display;
    fn display(&self) -> HexStringDisplay<'_>;
}

impl HexDisplayableArray for Digest256 {
    fn display(&self) -> HexStringDisplay<'_> {
        HexStringDisplay(&self[..])
    }
}

struct HexStringDisplay<'a>(&'a [u8]);

impl<'a> fmt::Display for HexStringDisplay<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"")?;
        for b in self.0.iter() {
            write!(f, "{:02x}", b)?;
        }
        write!(f, "\"")?;
        Ok(())
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, SerializedSize,
)]
pub struct RotImageDetails {
    pub digest: Digest256,
    pub version: ImageVersion,
}

impl RotImageDetails {
    pub fn display(&self) -> RotImageDetailsDisplay<'_> {
        RotImageDetailsDisplay(self)
    }
}

/// This class exists for faux-mgs to nicely display the Firmware ID (FWID).
#[derive(Clone, Debug)]
#[must_use = "this struct does nothing unless displayed"]
pub struct RotImageDetailsDisplay<'a>(pub &'a RotImageDetails);

impl<'a> fmt::Display for RotImageDetailsDisplay<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.0;
        writeln!(f, "digest: {}, ", s.digest.display())?;
        writeln!(f, "version: {:?}, ", s.version)?;
        Ok(())
    }
}

/// The boot time details dumped by Stage0 into Hubris on the RoT
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct RotBootState {
    pub active: RotSlotId,
    pub slot_a: Option<RotImageDetails>,
    pub slot_b: Option<RotImageDetails>,
}

impl RotBootState {
    pub fn display(&self) -> RotBootStateDisplay<'_> {
        RotBootStateDisplay(self)
    }
}

/// This class exists for faux-mgs to nicely display the Firmware ID (FWID).
#[derive(Clone, Debug)]
#[must_use = "this struct does nothing unless displayed"]
pub struct RotBootStateDisplay<'a>(pub &'a RotBootState);

impl<'a> fmt::Display for RotBootStateDisplay<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.0;
        writeln!(f, "active: {:?}, ", s.active)?;
        write!(f, "slot_a: ")?;
        match s.slot_a {
            Some(details) => {
                writeln!(
                    f,
                    "Some(RotImageDetails{{ {} }}),",
                    &RotImageDetailsDisplay(&details)
                )?;
            }
            None => writeln!(f, "None,")?,
        };
        write!(f, "slot_b: ")?;
        match s.slot_b {
            Some(details) => {
                writeln!(
                    f,
                    "Some(RotImageDetails{{ {} }}),",
                    &RotImageDetailsDisplay(&details)
                )?;
            }
            None => writeln!(f, "None,")?,
        };
        Ok(())
    }
}

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

impl RotState {
    pub fn display(&self) -> RotStateDisplay<'_> {
        RotStateDisplay(self)
    }
}

/// This class exists for faux-mgs to nicely display the Firmware ID (FWID).
#[derive(Clone, Debug)]
#[must_use = "this struct does nothing unless displayed"]
pub struct RotStateDisplay<'a>(pub &'a RotState);

impl<'a> fmt::Display for RotStateDisplay<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.0.rot_updates.boot_state;
        writeln!(
            f,
            "RotState {{ rot_updates: RotUpdateDetails {{ boot_state: RotBootState {{ {} }} }} }}",
            &RotBootStateDisplay(&s)
        )?;
        Ok(())
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct RotStateV2 {
    /// The slot of the currently running image
    pub active: RotSlotId,
    /// The persistent boot preference written into the current authoritative
    /// CFPA page (ping or pong).
    pub persistent_boot_preference: RotSlotId,
    /// The persistent boot preference written into the CFPA scratch page that
    /// will become the persistent boot preference in the authoritative CFPA
    /// page upon reboot, unless CFPA update of the authoritative page fails for
    /// some reason.
    pub pending_persistent_boot_preference: Option<RotSlotId>,
    /// Override persistent preference selection for a single boot
    ///
    /// This is a magic ram value that is cleared by bootleby
    pub transient_boot_preference: Option<RotSlotId>,
    /// Sha3-256 Digest of Slot A in Flash
    pub slot_a_sha3_256_digest: Option<[u8; 32]>,
    /// Sha3-256 Digest of Slot B in Flash
    pub slot_b_sha3_256_digest: Option<[u8; 32]>,
}

impl RotStateV2 {
    pub fn display(&self) -> RotStateV2Display<'_> {
        RotStateV2Display(self)
    }
}

/// This class exists for faux-mgs to nicely display the Firmware ID (FWID).
#[derive(Clone, Debug)]
#[must_use = "this struct does nothing unless displayed"]
pub struct RotStateV2Display<'a>(pub &'a RotStateV2);

impl<'a> fmt::Display for RotStateV2Display<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.0;
        writeln!(f, "RotStateV2 {{")?;
        writeln!(f, "active: {:?}, ", s.active)?;
        writeln!(
            f,
            "persistent_boot_preference: {:?}, ",
            s.persistent_boot_preference
        )?;
        writeln!(
            f,
            "pending_persistent_boot_preference: {:?}, ",
            s.pending_persistent_boot_preference
        )?;
        writeln!(
            f,
            "transient_boot_preference: {:?}, ",
            s.transient_boot_preference
        )?;
        write!(f, "slot_a_sha3_256_digest: ")?;
        match s.slot_a_sha3_256_digest {
            Some(digest) => {
                writeln!(f, "Some({}), ", digest.display())?;
            }
            None => writeln!(f, "None, ")?,
        };
        write!(f, "slot_b_sha3_256_digest: ")?;
        match s.slot_b_sha3_256_digest {
            Some(digest) => {
                writeln!(f, "Some({}), ", digest.display())?;
            }
            None => writeln!(f, "None, ")?,
        };
        writeln!(f, "}}")?;
        Ok(())
    }
}

impl fmt::Display for RotStateV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", &RotStateV2Display(self))?;
        Ok(())
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub enum Fwid {
    Sha3_256(Digest256),
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct RotStateV3 {
    /// The slot of the currently running image
    pub active: RotSlotId,
    /// The persistent boot preference written into the current authoritative
    /// CFPA page (ping or pong).
    pub persistent_boot_preference: RotSlotId,
    /// The persistent boot preference written into the CFPA scratch page that
    /// will become the persistent boot preference in the authoritative CFPA
    /// page upon reboot, unless CFPA update of the authoritative page fails for
    /// some reason.
    pub pending_persistent_boot_preference: Option<RotSlotId>,
    /// Override persistent preference selection for a single boot
    ///
    /// This corresponds to a magic ram value that is cleared by bootleby
    pub transient_boot_preference: Option<RotSlotId>,
    /// Sha3-256 Digest of Slot A in Flash
    pub slot_a_fwid: Fwid,
    /// Sha3-256 Digest of Slot B in Flash
    pub slot_b_fwid: Fwid,
    /// Sha3-256 Digest of Bootloader in Flash at boot time
    pub stage0_fwid: Fwid,
    /// Sha3-256 Digest of Staged Bootloader in Flash at boot time
    pub stage0next_fwid: Fwid,

    /// Flash Slot A status at last RoT reset
    pub slot_a_status: Result<(), ImageError>,
    /// Slot B status at last RoT reset
    pub slot_b_status: Result<(), ImageError>,
    /// Stage0 (bootloader) status at last RoT reset
    pub stage0_status: Result<(), ImageError>,
    /// Stage0Next status at last RoT reset
    pub stage0next_status: Result<(), ImageError>,
}

impl RotStateV3 {
    pub fn display(&self) -> RotStateV3Display<'_> {
        RotStateV3Display(self)
    }
}

#[derive(Clone, Debug)]
#[must_use = "this struct does nothing unless displayed"]
pub struct RotStateV3Display<'a>(pub &'a RotStateV3);

impl<'a> fmt::Display for RotStateV3Display<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.0;
        writeln!(f, "RotStateV3 {{")?;
        writeln!(f, "active: {:?}, ", s.active)?;
        writeln!(
            f,
            "persistent_boot_preference: {:?}, ",
            s.persistent_boot_preference
        )?;
        writeln!(
            f,
            "pending_persistent_boot_preference: {:?}, ",
            s.pending_persistent_boot_preference
        )?;
        writeln!(
            f,
            "transient_boot_preference: {:?}, ",
            s.transient_boot_preference
        )?;
        match s.slot_a_fwid {
            Fwid::Sha3_256(digest) => writeln!(
                f,
                "slot_a_fwid: Fwid::Sha3_256({}), ",
                digest.display()
            )?,
        }
        match s.slot_b_fwid {
            Fwid::Sha3_256(digest) => writeln!(
                f,
                "slot_b_fwid: Fwid::Sha3_256({}), ",
                digest.display()
            )?,
        }
        match s.stage0_fwid {
            Fwid::Sha3_256(digest) => writeln!(
                f,
                "stage0_fwid: Fwid::Sha3_256({}), ",
                digest.display()
            )?,
        }
        match s.stage0next_fwid {
            Fwid::Sha3_256(digest) => writeln!(
                f,
                "stage0next_fwid: Fwid::Sha3_256({}), ",
                digest.display()
            )?,
        }
        writeln!(f, "slot_a_status: {:?}, ", s.slot_a_status)?;
        writeln!(f, "slot_b_status: {:?}, ", s.slot_b_status)?;
        writeln!(f, "stage0_status: {:?}, ", s.stage0_status)?;
        writeln!(f, "stage0next_status: {:?} ", s.stage0next_status)?;
        write!(f, "}}")?;
        Ok(())
    }
}

/// `rot_boot_info` and versioned_rot_boot_info` are used to
/// implement backward/forward compatible Hubris update flows.
///
/// The end goal is to flush out old images from the customer base
/// and spares so that the older APIs can be deprecated and removed.
///
/// A to-be-implemented rollback-protection feature will keep old
/// versions from being reintroduced.
/// [Issue 222](https://github.com/oxidecomputer/management-gateway-service/issues/222)
///
/// Until then, the management-gateway-service needs to continue to
/// handle old versions of SP and RoT firmware update flows.
///
/// MGS will always need to handle SP and RoT version skew during update as
/// well as being exposed to spares loaded with SP and RoT images that are
/// newer than the running MGS version.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub enum RotBootInfo {
    V1(RotState),
    V2(RotStateV2),
    V3(RotStateV3),
}

impl RotBootInfo {
    /// update HIGHEST_KNOWN_VERSION when the next RotBootInfo variant is added.
    pub const HIGHEST_KNOWN_VERSION: u8 = 3;

    pub fn display(&self) -> RotBootInfoDisplay<'_> {
        RotBootInfoDisplay(self)
    }
}

#[derive(Clone, Debug)]
#[must_use = "this struct does nothing unless displayed"]
pub struct RotBootInfoDisplay<'a>(pub &'a RotBootInfo);

impl<'a> fmt::Display for RotBootInfoDisplay<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, " RotBootInfo {{")?;
        match self.0 {
            RotBootInfo::V1(rotstate) => {
                write!(f, " V1({})", &RotStateDisplay(rotstate))?;
            }
            // Use a helper on V2 to display a human readable FWID
            RotBootInfo::V2(rotstate) => {
                write!(f, " V2({})", &RotStateV2Display(rotstate))?;
            }
            // Use helper on V3 to display a human readable FWID
            RotBootInfo::V3(rotstate) => {
                write!(f, " V3({})", &RotStateV3Display(rotstate))?;
            }
        }
        writeln!(f, "}}")?;
        Ok(())
    }
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

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub enum ComponentActionResponse {
    Ack,
    Monorail(MonorailComponentActionResponse),
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub enum DumpResponse {
    TaskDumpCount(u32),
    TaskDumpReadStarted(DumpTask),

    /// This variant is usually followed by compressed data
    ///
    /// `None` indicates the end of the task dump
    TaskDumpRead(Option<DumpSegment>),
}

/// Morally equivalent to `humpty::DumpTask`
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct DumpTask {
    pub task: u16,
    pub time: u64,
    pub compression: DumpCompression,
}

/// Compression type used for dump data
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub enum DumpCompression {
    /// LZSS parameters which are hard-coded in `humpty::DumpLzss`
    ///
    /// This is `lzss::Lzss<6, 4, 0x20, { 1 << 6 }, { 2 << 6 }>;`
    Lzss,
}

/// Morally equivalent to `humpty::DumpSegmentData`
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct DumpSegment {
    /// Memory address for this chunk of data
    pub address: u32,

    /// Compressed data length
    ///
    /// This must match the length of trailing data in the packet
    pub compressed_length: u16,

    /// Original data length
    ///
    /// This must match the data length after decompressing
    pub uncompressed_length: u16,

    /// Sequence number to detect dropped or duplicate packets
    pub seq: u32,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub enum MonorailComponentActionResponse {
    RequestChallenge(UnlockChallenge),
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

#[derive(
    Default,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    SerializedSize,
    Serialize,
    Deserialize,
)]
#[repr(transparent)]
pub struct DeviceCapabilities(u32);

bitflags! {
    impl DeviceCapabilities: u32 {
        const UPDATEABLE = 1 << 0;
        const HAS_MEASUREMENT_CHANNELS = 1 << 1;
        const HAS_SERIAL_CONSOLE = 1 << 2;
        const IS_LED = 1 << 3;
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
    /// Returned when an update to the RoT has failed.
    ///
    /// The SP has no concept of time, so we cannot indicate how recently this
    /// abort happened. The SP will continue to return this status until a new
    /// update starts (or the status is reset some other way, such as an SP
    /// reboot).
    RotError { id: UpdateId, error: RotError },
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

/// Represents the result of a successful [`SetPowerState`] request.
/// [`SetPowerState`]: crate::MgsRequest::SetPowerState
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PowerStateTransition {
    Changed,
    Unchanged,
}

impl From<PowerStateTransition> for SpResponse {
    fn from(transition: PowerStateTransition) -> Self {
        match transition {
            PowerStateTransition::Changed => SpResponse::PowerStateSet,
            PowerStateTransition::Unchanged => SpResponse::PowerStateUnchanged,
        }
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    SerializedSize,
    Serialize,
    Deserialize,
    strum_macros::VariantNames,
)]
#[strum(serialize_all = "snake_case")]
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

    // --------------------------------------
    // *** That new hotness below here ***
    // --------------------------------------
    //
    // New nested variants, one for each hubris API are below We will likely
    // create a new Error variant so we can deprecate some of redundant
    // variants above.
    Sprot(SprotProtocolError),
    Spi(SpiError),
    Sprockets(SprocketsError),
    Update(UpdateError),
    Sensor(SensorError),
    Vpd(VpdError),
    Watchdog(WatchdogError),
    Monorail(MonorailError),
    Dump(DumpError),
    Hf(HfError),
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
                write!(f, "could not find the board in the image caboose")
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
            Self::Sprot(e) => write!(f, "sprot: {}", e),
            Self::Spi(e) => write!(f, "spi: {}", e),
            Self::Sprockets(e) => write!(f, "sprockets: {}", e),
            Self::Update(e) => write!(f, "update: {}", e),
            Self::Sensor(e) => write!(f, "sensor: {}", e),
            Self::Vpd(e) => write!(f, "vpd: {}", e),
            Self::Watchdog(e) => write!(f, "watchdog: {}", e),
            Self::Monorail(e) => write!(f, "monorail: {}", e),
            Self::Dump(e) => write!(f, "dump: {}", e),
            Self::Hf(e) => write!(f, "hf: {}", e),
        }
    }
}

// This is necessarily sparse for now. It's likely we'll clean up the sprockets
// errors. These are ones that are capable of being reported by Sprot now.
#[derive(
    Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize, SerializedSize,
)]
pub enum SprocketsError {
    BadEncoding,
    UnsupportedVersion,

    // When the type in hubris has been updated, but MGS does not yet know
    // this type. The meaning of the error code here should be found in the
    // `From<HubrisType> for MgsType` implementation in the hubris code.
    Unknown(u32),
}

impl fmt::Display for SprocketsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadEncoding => write!(f, "deserialization error"),
            Self::UnsupportedVersion => write!(f, "unsupported version"),
            Self::Unknown(code) => write!(f, "unknown error (code {})", code),
        }
    }
}

#[derive(
    Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize, SerializedSize,
)]
pub enum UpdateError {
    BadLength,
    UpdateInProgress,
    OutOfBounds,
    EccDoubleErr,
    EccSingleErr,
    SecureErr,   // If we get this something has gone very wrong
    ReadProtErr, // If we get this something has gone very wrong
    WriteEraseErr,
    InconsistencyErr,
    StrobeErr,
    ProgSeqErr,
    WriteProtErr,
    BadImageType,
    UpdateAlreadyFinished,
    UpdateNotStarted,
    RunningImage,
    FlashError,
    FlashIllegalRead,
    FlashReadFail,
    MissingHeaderBlock,
    InvalidHeaderBlock,

    // Caboose checks
    ImageBoardMismatch,
    ImageBoardUnknown,

    TaskRestarted,

    NotImplemented,

    // When the type in hubris has been updated, but MGS does not yet know
    // this type. The meaning of the error code here should be found in the
    // `From<HubrisType> for MgsType` implementation in the hubris code.
    Unknown(u32),

    MissingHandoffData,
    BlockOutOfOrder,
    InvalidComponent,
    InvalidSlotIdForOperation,
    InvalidArchive,
    ImageMismatch,
    SignatureNotValidated,
    VersionNotSupported,
    InvalidPreferredSlotId,
}

impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadLength => write!(f, "block sized incorrectly"),
            Self::UpdateInProgress => write!(f, "update in progress"),
            Self::OutOfBounds => write!(f, "out of bounds"),
            Self::EccDoubleErr => write!(f, "ECC double error"),
            Self::EccSingleErr => write!(f, "ECC single error"),
            Self::SecureErr => {
                write!(f, "secure mode error (failed to update CFPA)")
            }
            Self::ReadProtErr => write!(f, "read protection error"),
            Self::WriteEraseErr => write!(f, "write erase error"),
            Self::InconsistencyErr => write!(f, "inconsistency error"),
            Self::StrobeErr => write!(f, "strobe error"),
            Self::ProgSeqErr => write!(f, "programming sequence error"),
            Self::WriteProtErr => write!(f, "write protection error"),
            Self::BadImageType => write!(f, "bad image type"),
            Self::UpdateAlreadyFinished => write!(f, "update already finished"),
            Self::UpdateNotStarted => write!(f, "update not started"),
            Self::RunningImage => {
                write!(f, "attempted to update running image")
            }
            Self::FlashError => write!(f, "flash error"),
            Self::FlashIllegalRead => write!(f, "illegal flash read"),
            Self::FlashReadFail => write!(f, "failed to read flash"),
            Self::MissingHeaderBlock => write!(f, "missing header block"),
            Self::InvalidHeaderBlock => write!(f, "invalid header block"),
            Self::ImageBoardMismatch => write!(f, "image does not match board"),
            Self::ImageBoardUnknown => write!(f, "image missing board details"),
            Self::TaskRestarted => write!(f, "hubris task restarted"),
            Self::NotImplemented => write!(f, "not implemented"),
            Self::Unknown(code) => write!(f, "unknown error (code {})", code),
            Self::MissingHandoffData => {
                write!(f, "boot data not handed off to hubris kernel")
            }
            Self::BlockOutOfOrder => {
                write!(f, "update blocks delivered out of order")
            }
            Self::InvalidSlotIdForOperation => {
                write!(f, "specified SlotId is not supported for operation")
            }
            Self::InvalidArchive => {
                write!(f, "invalid archive")
            }
            Self::ImageMismatch => {
                write!(f, "image does not match")
            }
            Self::SignatureNotValidated => {
                write!(f, "image not present or signature not valid")
            }
            Self::VersionNotSupported => {
                write!(f, "RoT boot info version is not supported")
            }
            Self::InvalidComponent => {
                write!(f, "invalid component for operation")
            }
            Self::InvalidPreferredSlotId => {
                write!(
                    f,
                    "updating a bootloader preferred slot is not permitted"
                )
            }
        }
    }
}

/// SPI specific errors for the SPI link used between the SP and RoT
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub enum SpiError {
    /// Transfer size is 0 or exceeds maximum
    BadTransferSize,

    /// Server restarted
    TaskRestarted,

    /// Release without successful Lock
    NothingToRelease,

    /// Attempt to operate device N when there is no device N, or an attempt to
    /// operate on _any other_ device when you've locked the controller to one.
    ///
    /// This is almost certainly a programming error on the client side.
    BadDevice,

    // When the type in hubris has been updated, but MGS does not yet know
    // this type. The meaning of the error code here should be found in the
    // `From<HubrisType> for MgsType` implementation in the hubris code.
    Unknown(u32),
}

impl fmt::Display for SpiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadTransferSize => write!(f, "bad transfer size"),
            Self::TaskRestarted => write!(f, "hubris task restarted"),
            Self::NothingToRelease => write!(f, "nothing to release"),
            Self::BadDevice => write!(f, "bad device"),
            Self::Unknown(code) => write!(f, "unknown error (code {})", code),
        }
    }
}

/// Sprot protocol specific errors
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub enum SprotProtocolError {
    /// CRC check failed.
    InvalidCrc,
    /// FIFO overflow/underflow
    FlowError,
    /// Unsupported protocol version
    UnsupportedProtocol,
    /// Unknown message
    BadMessageType,
    /// Transfer size is outside of maximum and minimum lenghts for message type.
    BadMessageLength,
    /// We cannot assert chip select
    CannotAssertCSn,
    /// The request timed out
    Timeout,
    /// Hubpack error
    Deserialization,
    /// The RoT has not de-asserted ROT_IRQ
    RotIrqRemainsAsserted,
    /// An unexpected response was received.
    /// This should basically be impossible. We only include it so we can
    /// return this error when unpacking a RspBody in idol calls.
    UnexpectedResponse,
    /// Failed to load update status
    BadUpdateStatus,
    /// Used for mapping From<idol_runtime::ServerDeath>
    TaskRestarted,
    /// When the type in hubris has been updated, but MGS does not yet know
    /// this type. The meaning of the error code here should be found in the
    /// `From<HubrisType> for MgsType` implementation in the hubris code.
    Unknown(u32),
    /// The SP and RoT did not agree on whether the SP is sending a request or
    /// waiting for a reply
    Desynchronized,
}

impl fmt::Display for SprotProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCrc => write!(f, "CRC check failed"),
            Self::FlowError => write!(f, "spi rx error"),
            Self::UnsupportedProtocol => {
                write!(f, "unsupported protocol version")
            }
            Self::BadMessageType => write!(f, "unknown message"),
            Self::BadMessageLength => write!(f, "invalid message length"),
            Self::CannotAssertCSn => write!(f, "failed to assert chip select"),
            Self::Timeout => write!(f, "timeout"),
            Self::Deserialization => write!(f, "failed to deserialize message"),
            Self::RotIrqRemainsAsserted => {
                write!(f, "RoT has failed to deassert ROT_IRQ")
            }
            Self::UnexpectedResponse => {
                write!(f, "RoT response did not match the SP request")
            }
            Self::BadUpdateStatus => write!(f, "failed to load update status"),
            Self::TaskRestarted => write!(f, "hubris task restarted"),
            Self::Unknown(code) => write!(f, "unknown error (code {})", code),
            Self::Desynchronized => write!(f, "SP and RoT are desynchronized"),
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

    // --------------------------------------
    // *** That new hotness below here ***
    // --------------------------------------
    //
    // New nested variants, one for each hubris API are below We will likely
    // create a new Error variant so we can deprecate some of redundant
    // variants above.
    Sprot(SprotProtocolError),
    Spi(SpiError),
    Sprockets(SprocketsError),
    Update(UpdateError),
    Watchdog(WatchdogError),
}

impl fmt::Display for RotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MessageError { code } => {
                write!(f, "SP/RoT messaging error: {code}")
            }
            Self::Sprot(e) => write!(f, "sprot: {}", e),
            Self::Spi(e) => write!(f, "spi: {}", e),
            Self::Sprockets(e) => write!(f, "sprockets: {}", e),
            Self::Update(e) => write!(f, "update: {}", e),
            Self::Watchdog(e) => write!(f, "watchdog: {}", e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RotError {}

/// Sensor errors encountered during a read
///
/// This value is wrapped by [`SpError`]; note that it is distinct from
/// [`crate::SensorDataMissing`]!
#[derive(
    Debug, Clone, Copy, PartialEq, SerializedSize, Serialize, Deserialize,
)]
pub enum SensorError {
    InvalidSensor,
    NoReading,
}

impl fmt::Display for SensorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSensor => write!(f, "sensor ID is invalid"),
            Self::NoReading => write!(f, "reading is not present"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SensorError {}

/// VPD errors encountered while reading
///
/// This value is wrapped by [`SpError`]
#[derive(
    Debug, Clone, Copy, PartialEq, SerializedSize, Serialize, Deserialize,
)]
pub enum VpdError {
    InvalidDevice,
    NotPresent,
    DeviceError,
    Unavailable,
    DeviceTimeout,
    DeviceOff,
    BadAddress,
    BadBuffer,
    BadRead,
    BadWrite,
    BadLock,
    NotImplemented,
    IsLocked,
    PartiallyLocked,
    AlreadyLocked,
    TaskRestarted,
}

impl fmt::Display for VpdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDevice => write!(f, "device index is invalid"),
            Self::NotPresent => write!(f, "device is not present"),
            Self::DeviceError => write!(f, "error with VPD device"),
            Self::Unavailable => write!(f, "vpd device is unavailable"),
            Self::DeviceTimeout => write!(f, "vpd device timed out"),
            Self::DeviceOff => write!(f, "vpd device is off"),
            Self::BadAddress => write!(f, "bad address"),
            Self::BadBuffer => write!(f, "bad buffer"),
            Self::BadRead => write!(f, "bad read"),
            Self::BadWrite => write!(f, "bad write"),
            Self::BadLock => write!(f, "lock failed"),
            Self::NotImplemented => {
                write!(f, "Feature is not implemented/compiled out")
            }
            Self::IsLocked => write!(f, "VPD is locked, cannot write"),
            Self::PartiallyLocked => write!(f, "VPD is partially locked"),
            Self::AlreadyLocked => {
                write!(f, "VPD is already locked, cannot lock again")
            }
            Self::TaskRestarted => write!(f, "task restarted"),
        }
    }
}

/// Watchdog errors encountered configuring the SP-RoT watchdog
///
/// This value is wrapped by [`SpError`]
#[derive(
    Debug, Clone, Copy, Eq, PartialEq, SerializedSize, Serialize, Deserialize,
)]
pub enum WatchdogError {
    /// There is not a complete SP update in place
    NoCompletedUpdate,
    /// RoT returned an error
    Rot(RotWatchdogError),
}

/// Watchdog errors encountered on the RoT side of the link
///
/// This value is wrapped by [`SpError`]
#[derive(
    Debug, Clone, Copy, Eq, PartialEq, SerializedSize, Serialize, Deserialize,
)]
pub enum RotWatchdogError {
    /// The programming dongle is plugged in
    DongleDetected,

    /// Raw error code
    Other(u32),
}

impl fmt::Display for WatchdogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCompletedUpdate => {
                write!(f, "the SP does not have a completed update")
            }
            Self::Rot(r) => write!(f, "RoT error: {r}"),
        }
    }
}

impl fmt::Display for RotWatchdogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DongleDetected => {
                write!(f, "the SP programming dongle is connected")
            }
            Self::Other(r) => write!(f, "unknown error: {r}"),
        }
    }
}

/// Errors encountered interacting with the Monorail switch
///
/// This value is wrapped by [`SpError`]
#[derive(
    Debug, Clone, Copy, Eq, PartialEq, SerializedSize, Serialize, Deserialize,
)]
pub enum MonorailError {
    UnlockAuthFailed,
    UnlockFailed,
    LockFailed,
    ManagementNetworkLocked,
    InvalidVLAN,
    GetChallengeFailed,
    TimeIsTooLong,
    ChallengeExpired,
    AlreadyTrusted,
}

impl fmt::Display for MonorailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::UnlockAuthFailed => "failed to unlock (bad authentication)",
            Self::UnlockFailed => "failed to unlock (internal error)",
            Self::LockFailed => "failed to lock (internal error)",
            Self::ManagementNetworkLocked => "management network is locked",
            Self::InvalidVLAN => "received invalid VLAN tag",
            Self::GetChallengeFailed => "could not create challenge",
            Self::TimeIsTooLong => "unlock time is too long",
            Self::ChallengeExpired => "challenge has expired",
            Self::AlreadyTrusted => "the source port is already trusted",
        };
        write!(f, "{s}")
    }
}

/// Errors encountered interacting with the dump agent
///
/// This value is wrapped by [`SpError`]
#[derive(
    Debug, Clone, Copy, Eq, PartialEq, SerializedSize, Serialize, Deserialize,
)]
pub enum DumpError {
    BadArea,
    BadIndex,
    NoDumpTaskHeader,
    CorruptTaskHeader,
    BadKey,
    ReadFailed,
    NoLongerValid,
    SegmentTooLong,
    BadSequenceNumber,
}

impl fmt::Display for DumpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::BadArea => "could not read area header",
            Self::BadIndex => "could not find dump by index",
            Self::NoDumpTaskHeader => "could not read dump task header",
            Self::CorruptTaskHeader => "task header has invalid magic bytes",
            Self::BadKey => "invalid key",
            Self::ReadFailed => "read failed",
            Self::NoLongerValid => "the dump region has been cleared",
            Self::SegmentTooLong => "data segment cannot fit in packet data",
            Self::BadSequenceNumber => "sequence number is invalid",
        };
        write!(f, "{s}")
    }
}

/// Errors encountered when reading host flash. This isn't all the possible
/// host flash errors but enough of the ones we should see commonly
///
/// This value is wrapped by [`SpError`]
#[derive(
    Debug, Clone, Copy, Eq, PartialEq, SerializedSize, Serialize, Deserialize,
)]
pub enum HfError {
    NotMuxedToSp,
    BadAddress,
    QspiTimeout,
    QspiTransferError,
    HashUncalculated,
    RecalculateHash,
    HashInProgress,
}

impl fmt::Display for HfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::NotMuxedToSp => "Host flash not muxed to SP",
            Self::BadAddress => "Bad host flash address",
            Self::QspiTimeout => "Host QSPI timeout",
            Self::QspiTransferError => {
                "Host QSPI Transfer Error (check address)"
            }
            Self::HashUncalculated => "No hash calculated for slot",
            Self::RecalculateHash => "Slot requires hash recalculation",
            Self::HashInProgress => "Hash calcuation in progress",
        };
        write!(f, "{s}")
    }
}
