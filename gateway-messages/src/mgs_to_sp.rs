// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Types for messages sent from MGS to SPs.

use crate::ignition::TransceiverSelect;
use crate::BadRequestReason;
use crate::PowerState;
use crate::RotRequest;
use crate::RotSlotId;
use crate::SensorRequest;
use crate::SpComponent;
use crate::SwitchDuration;
use crate::UpdateId;
use hubpack::SerializedSize;
use serde::Deserialize;
use serde::Serialize;

#[derive(
    Debug, Clone, Copy, SerializedSize, Serialize, Deserialize, PartialEq, Eq,
)]
pub enum MgsRequest {
    Discover,
    IgnitionState {
        target: u8,
    },
    BulkIgnitionState {
        offset: u32,
    },
    IgnitionCommand {
        target: u8,
        command: IgnitionCommand,
    },
    SpState,
    SerialConsoleAttach(SpComponent),
    /// `SerialConsoleWrite` always includes trailing raw data.
    SerialConsoleWrite {
        /// Offset of the first byte of this packet, starting from 0 when this
        /// serial console session was attached.
        offset: u64,
    },
    SerialConsoleDetach,
    SpUpdatePrepare(SpUpdatePrepare),
    ComponentUpdatePrepare(ComponentUpdatePrepare),
    /// `UpdateChunk` always includes trailing raw data.
    UpdateChunk(UpdateChunk),
    UpdateStatus(SpComponent),
    UpdateAbort {
        component: SpComponent,
        id: UpdateId,
    },
    GetPowerState,
    SetPowerState(PowerState),
    ResetPrepare,
    ResetTrigger,
    /// Get the device inventory of the SP, starting with `device_index`.
    Inventory {
        device_index: u32,
    },
    GetStartupOptions,
    SetStartupOptions(StartupOptions),
    /// Get detailed status information for a component, starting with `offset`
    /// if the component has multiple status information items.
    ComponentDetails {
        component: SpComponent,
        offset: u32,
    },
    /// Get ignition link events for a single target.
    IgnitionLinkEvents {
        target: u8,
    },
    /// Get ignition link events for all targets, starting at `offset`.
    BulkIgnitionLinkEvents {
        offset: u32,
    },
    /// If `target` is `None`, clear events on all targets (potentially
    /// restricted by `transceiver_select`).
    ///
    /// If `transceiver_select` is none, clear events on all transceivers
    /// (potentially restricted by `target`).
    ClearIgnitionLinkEvents {
        target: Option<u8>,
        transceiver_select: Option<TransceiverSelect>,
    },
    /// Clear any clearable state (e.g., event counters) on a component.
    ComponentClearStatus(SpComponent),
    /// For components with multiple slots (e.g., host boot flash), get the
    /// currently-active slot.
    ComponentGetActiveSlot(SpComponent),
    /// For components with multiple slots (e.g., host boot flash), set the
    /// currently-active slot.
    ///
    /// The effect/timing of setting the active slot is component-defined; e.g.,
    /// it make not take effect until the component or SP is next booted.
    ComponentSetActiveSlot {
        component: SpComponent,
        slot: u16,
    },
    /// Send a break on the host serial console
    SerialConsoleBreak,
    /// Send an NMI to the host by toggling a GPIO
    SendHostNmi,
    /// Set the value for an IPCC `KeyLookup` request across the host/SP control
    /// uart.
    ///
    /// The value is appended as trailing data. We currently assume that the max
    /// length for any value fits into the trailing data of a single packet.
    SetIpccKeyLookupValue {
        key: u8,
    },

    /// For components with multiple slots (e.g., host boot flash), set the
    /// currently-active slot and persist it to non-volatile memory.
    ///
    /// The effect/timing of setting the active slot is component-defined; e.g.,
    /// it make not take effect until the component or SP is next booted.
    // TODO: combine this with `ComponentSetActiveSlot` with `persist: bool` on
    // the next version bump.
    ComponentSetAndPersistActiveSlot {
        component: SpComponent,
        slot: u16,
    },

    /// Reads a value from the caboose
    ///
    /// The resulting value is serialized in the trailer of the packet
    ReadCaboose {
        key: [u8; 4],
    },

    SerialConsoleKeepAlive,

    /// Reset a specific component
    /// SP_ITSELF and ROT are supported
    ResetComponentPrepare {
        component: SpComponent,
    },
    ResetComponentTrigger {
        component: SpComponent,
    },

    /// Change boot image selection on reset or power-on.
    SwitchDefaultImage {
        component: SpComponent,
        slot: RotSlotId,
        duration: SwitchDuration,
    },

    ComponentAction {
        component: SpComponent,
        action: ComponentAction,
    },

    /// Reads a value from the caboose of the selected component
    ///
    /// The resulting value is serialized in the trailer of the packet
    ReadComponentCaboose {
        component: SpComponent,
        slot: u16,
        key: [u8; 4],
    },

    /// Issues a sensor read request
    ReadSensor(SensorRequest),

    /// Requests the target's current time (usually milliseconds since boot)
    CurrentTime,

    /// Issues a sensor read request
    ReadRot(RotRequest),

    /// Dump information about the lock state of the VPD (Vital Product Data)
    /// The values are serialized in the trailer of the packet
    VpdLockState,

    /// Read RoT boot state at the highest version not to exceed specified version.
    VersionedRotBootInfo {
        version: u8,
    },
}

#[derive(
    Debug, Clone, Copy, SerializedSize, Serialize, Deserialize, PartialEq, Eq,
)]
pub enum MgsResponse {
    Error(MgsError),
    /// Sent in response to an `SpRequest::HostPhase2Data` request. Followed by
    /// trailing data consisting of a chunk of the requested host phase 2 image
    /// starting at `offset`.
    HostPhase2Data {
        hash: [u8; 32],
        offset: u64,
    },
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub enum MgsError {
    /// The request from the SP was invalid.
    BadRequest(BadRequestReason),
    /// The requested host phase 2 image is not available.
    HostPhase2Unavailable { hash: [u8; 32] },
    /// The requested host phase 2 offset is beyond the end of the image.
    HostPhase2ImageBadOffset { hash: [u8; 32], offset: u64 },
}

#[derive(
    Debug, Clone, Copy, SerializedSize, Serialize, Deserialize, PartialEq, Eq,
)]
pub enum IgnitionCommand {
    PowerOn,
    PowerOff,
    PowerReset,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct SpUpdatePrepare {
    pub id: UpdateId,
    /// If this update includes an aux flash image, this size will be nonzero.
    pub aux_flash_size: u32,
    /// If this update includes an aux flash image, this check value is used by
    /// the SP do determine whether it already has this aux flash image in one
    /// of its slots.
    pub aux_flash_chck: [u8; 32],
    /// Size of the SP image in bytes.
    pub sp_image_size: u32,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct ComponentUpdatePrepare {
    pub component: SpComponent,
    pub id: UpdateId,
    /// The number of available slots depends on `component`; passing an invalid
    /// slot number will result in a [`ResponseError::InvalidSlotForComponent`].
    pub slot: u16,
    pub total_size: u32,
    // TODO auth info? checksum/digest?
    // TODO should we inline the first chunk?
}

#[derive(
    Copy, Clone, Serialize, SerializedSize, Deserialize, PartialEq, Eq, Debug,
)]
pub enum ComponentAction {
    Led(LedComponentAction),
}

/// Actions for LED components, i.e. components with `IS_LED` set
#[derive(
    Copy, Clone, Serialize, SerializedSize, Deserialize, PartialEq, Eq, Debug,
)]
pub enum LedComponentAction {
    TurnOn,
    TurnOff,
    Blink,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct UpdateChunk {
    pub component: SpComponent,
    pub id: UpdateId,
    /// Offset in bytes of this chunk from the beginning of the update data.
    pub offset: u32,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, SerializedSize,
)]
#[repr(transparent)]
pub struct StartupOptions(u64);

bitflags::bitflags! {
    impl StartupOptions: u64 {
        const PHASE2_RECOVERY_MODE = 1 << 0;
        const STARTUP_KBM = 1 << 1;
        const STARTUP_BOOTRD = 1 << 2;
        const STARTUP_PROM = 1 << 3;
        const STARTUP_KMDB = 1 << 4;
        const STARTUP_KMDB_BOOT = 1 << 5;
        const STARTUP_BOOT_RAMDISK = 1 << 6;
        const STARTUP_BOOT_NET = 1 << 7;
        const STARTUP_VERBOSE = 1 << 8;
    }
}
