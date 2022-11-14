// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Types for sidecar SP reporting VSC7448 port status.

use crate::tlv;
use hubpack::SerializedSize;
use serde::Deserialize;
use serde::Serialize;

#[derive(Copy, Clone, Debug, Serialize, Deserialize, SerializedSize)]
pub struct PortStatusError {
    pub port: u32,
    pub code: PortStatusErrorCode,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, SerializedSize)]
pub enum PortStatusErrorCode {
    Unconfigured,
    Other(u32),
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, SerializedSize)]
pub struct PortStatus {
    pub port: u32,
    pub cfg: PortConfig,
    pub link_status: LinkStatus,
    pub phy_status: Option<PhyStatus>,
    pub counters: PortCounters,
}

impl PortStatus {
    pub const TAG: tlv::Tag = tlv::Tag(*b"VSC0");
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, SerializedSize)]
pub struct PortConfig {
    pub mode: PortMode,
    pub dev: (PortDev, u8),
    pub serdes: (PortSerdes, u8),
}

#[derive(
    Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, SerializedSize,
)]
pub enum PortDev {
    Dev1g,
    Dev2g5,
    Dev10g,
}

#[derive(
    Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, SerializedSize,
)]
pub enum PortSerdes {
    Serdes1g,
    Serdes6g,
    Serdes10g,
}

#[derive(
    Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, SerializedSize,
)]
pub enum Speed {
    Speed100M,
    Speed1G,
    Speed10G,
}

#[derive(
    Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, SerializedSize,
)]
pub enum PortMode {
    Sfi,
    BaseKr,
    Sgmii(Speed),
    Qsgmii(Speed),
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, SerializedSize)]
pub struct PacketCount {
    pub multicast: u32,
    pub unicast: u32,
    pub broadcast: u32,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, SerializedSize)]
pub struct PortCounters {
    pub rx: PacketCount,
    pub tx: PacketCount,
}

#[derive(
    Copy, Clone, Debug, Serialize, Deserialize, SerializedSize, Eq, PartialEq,
)]
pub enum LinkStatus {
    Error,
    Down,
    Up,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, SerializedSize)]
pub struct PhyStatus {
    pub ty: PhyType,
    pub mac_link_up: LinkStatus,
    pub media_link_up: LinkStatus,
}

#[derive(
    Copy, Clone, Debug, Serialize, Deserialize, SerializedSize, Eq, PartialEq,
)]
pub enum PhyType {
    Vsc8504,
    Vsc8522,
    Vsc8552,
    Vsc8562,
}
