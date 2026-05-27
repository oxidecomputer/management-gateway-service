// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Types for sidecar SP reporting Monorail port status.

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

#[cfg(feature = "std")]
impl std::fmt::Display for Speed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Speed::Speed100M => "100M",
            Speed::Speed1G => "1G",
            Speed::Speed10G => "10G",
        };
        write!(f, "{s}")
    }
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

#[cfg(feature = "std")]
impl std::fmt::Display for PortMode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PortMode::Sfi => write!(f, "SFI"),
            PortMode::BaseKr => write!(f, "10GBASE-KR"),
            PortMode::Sgmii(speed) => write!(f, "{speed} SGMII"),
            PortMode::Qsgmii(speed) => write!(f, "{speed} QSGMII"),
        }
    }
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
    pub link_down_sticky: bool,
    pub phy_link_down_sticky: bool,
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

#[cfg(feature = "std")]
impl std::fmt::Display for PhyType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            PhyType::Vsc8504 => "VSC8504",
            PhyType::Vsc8522 => "VSC8522",
            PhyType::Vsc8552 => "VSC8552",
            PhyType::Vsc8562 => "VSC8562",
        };
        write!(f, "{s}")
    }
}
