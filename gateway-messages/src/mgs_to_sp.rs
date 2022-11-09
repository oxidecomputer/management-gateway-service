// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Types for messages sent from MGS to SPs.

use crate::BadRequestReason;
use crate::PowerState;
use crate::SpComponent;
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
    BulkIgnitionState,
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
}

#[derive(
    Debug, Clone, Copy, SerializedSize, Serialize, Deserialize, PartialEq, Eq,
)]
pub enum MgsResponse {
    Error(MgsError),
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub enum MgsError {
    /// The request from the SP was invalid.
    BadRequest(BadRequestReason),
}

#[derive(
    Debug, Clone, Copy, SerializedSize, Serialize, Deserialize, PartialEq, Eq,
)]
pub enum IgnitionCommand {
    PowerOn,
    PowerOff,
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
    Debug, Clone, Copy, PartialEq, Eq, SerializedSize, Serialize, Deserialize,
)]
pub struct UpdateChunk {
    pub component: SpComponent,
    pub id: UpdateId,
    /// Offset in bytes of this chunk from the beginning of the update data.
    pub offset: u32,
}
