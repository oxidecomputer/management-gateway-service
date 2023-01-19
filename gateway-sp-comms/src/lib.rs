// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

// Required nightly features for `usdt`
#![cfg_attr(target_os = "macos", feature(asm_sym))]

//! This crate provides UDP-based communication to the `control-plane-agent`
//! task of an SP.

mod host_phase2;
mod hubris_archive;
mod scope_id_cache;
mod single_sp;
mod sp_response_ext;

use std::net::Ipv6Addr;
use std::net::SocketAddrV6;

pub use usdt::register_probes;

pub mod error;

pub use gateway_messages;
pub use host_phase2::HostPhase2ImageError;
pub use host_phase2::HostPhase2Provider;
pub use host_phase2::InMemoryHostPhase2Provider;
pub use single_sp::AttachedSerialConsole;
pub use single_sp::AttachedSerialConsoleRecv;
pub use single_sp::AttachedSerialConsoleSend;
pub use single_sp::SingleSp;
pub use single_sp::SpDevice;
pub use single_sp::SpInventory;

const SP_TO_MGS_MULTICAST_ADDR: Ipv6Addr =
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0x1de, 1);
const MGS_TO_SP_MULTICAST_ADDR: Ipv6Addr =
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0x1de, 2);

const SP_PORT: u16 = 11111;
const MGS_PORT: u16 = 22222;

/// Default address to discover an SP via UDP multicast.
pub fn default_discovery_addr() -> SocketAddrV6 {
    SocketAddrV6::new(MGS_TO_SP_MULTICAST_ADDR, SP_PORT, 0, 0)
}

/// Default address to use when binding our local socket.
pub fn default_listen_addr() -> SocketAddrV6 {
    SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, MGS_PORT, 0, 0)
}

/// Configuration of a single port of the management network switch.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct SwitchPortConfig {
    /// Address to bind our listening socket for this switch port.
    #[serde(default = "default_listen_addr")]
    pub listen_addr: SocketAddrV6,

    /// Discovery address used to find the SP connected to this port.
    #[serde(default = "default_discovery_addr")]
    pub discovery_addr: SocketAddrV6,

    /// Name of the interface for this switch port. The interface should be
    /// bound to the correct VLAN tag for this port per RFD 250.
    ///
    /// This field is optional to allow for test / CI setups where we're binding
    /// to localhost (and don't know the name of the loopback interface, since
    /// it may vary based on our host OS); if it is not supplied, `listen_addr`
    /// and `discovery_addr` will be used without a `scope_id`.
    #[serde(default)]
    pub interface: Option<String>,
}
