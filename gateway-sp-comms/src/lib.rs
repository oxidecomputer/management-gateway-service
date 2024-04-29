// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

// The `usdt` crate may require features depending on the compiler version.
#![cfg_attr(usdt_need_asm, feature(asm))]
#![cfg_attr(usdt_need_asm_sym, feature(asm_sym))]

//! This crate provides UDP-based communication to the `control-plane-agent`
//! task of an SP.

mod host_phase2;
mod scope_id_cache;
mod shared_socket;
mod single_sp;
mod sp_response_expect;

use std::net::Ipv6Addr;
use std::net::SocketAddrV6;

pub use usdt::register_probes;

pub mod error;

pub use gateway_messages;
pub use gateway_messages::SpComponent;
pub use gateway_messages::SpStateV1;
pub use gateway_messages::SpStateV2;
pub use gateway_messages::SpStateV3;
pub use host_phase2::HostPhase2ImageError;
pub use host_phase2::HostPhase2Provider;
pub use host_phase2::InMemoryHostPhase2Provider;
pub use shared_socket::BindError;
pub use shared_socket::SharedSocket;
pub use single_sp::AttachedSerialConsole;
pub use single_sp::AttachedSerialConsoleRecv;
pub use single_sp::AttachedSerialConsoleSend;
pub use single_sp::SingleSp;
pub use single_sp::SpComponentDetails;
pub use single_sp::SpDevice;
pub use single_sp::SpInventory;

const SP_TO_MGS_MULTICAST_ADDR: Ipv6Addr =
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0x1de, 1);
const MGS_TO_SP_MULTICAST_ADDR: Ipv6Addr =
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0x1de, 2);

pub const SP_PORT: u16 = 11111;
pub const MGS_PORT: u16 = 22222;

/// Default address to discover an SP via UDP multicast.
pub fn default_discovery_addr() -> SocketAddrV6 {
    SocketAddrV6::new(MGS_TO_SP_MULTICAST_ADDR, SP_PORT, 0, 0)
}

/// Configuration of a single port of the management network switch.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct SwitchPortConfig {
    /// Discovery address used to find the SP connected to this port.
    #[serde(default = "default_discovery_addr")]
    pub discovery_addr: SocketAddrV6,

    /// Name of the interface for this switch port. The interface should be
    /// bound to the correct VLAN tag for this port per RFD 250.
    pub interface: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum VersionedSpState {
    V1(SpStateV1),
    V2(SpStateV2),
    V3(SpStateV3),
}
