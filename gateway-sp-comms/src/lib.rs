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

pub const SP_PORT: u16 = 11111;
pub const MGS_PORT: u16 = 22222;

/// Default address to discover an SP via UDP multicast.
pub fn default_discovery_addr() -> SocketAddrV6 {
    SocketAddrV6::new(MGS_TO_SP_MULTICAST_ADDR, SP_PORT, 0, 0)
}

/// Configuration of a single port of the management network switch.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct SwitchPortConfig {
    /// Configuration for binding our listening UDP socket.
    pub listen: SwitchPortListenConfig,

    /// Discovery address used to find the SP connected to this port.
    #[serde(default = "default_discovery_addr")]
    pub discovery_addr: SocketAddrV6,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum SwitchPortListenConfig {
    /// Listen on the specified interface's first IPv6 address, and use its
    /// scope ID for any packets sent.
    ///
    /// This variant should be used by `faux-mgs` and real MGS in non-test,
    /// non-CI situations where we know the interface name (either from the user
    /// or from a set configuration) used to communicate on this port.
    Interface {
        /// Name of the interface (e.g., `eth0`) on which we can communicate on
        /// this switch port.
        name: String,

        /// Port we should use when binding our UDP socket.
        ///
        /// If not provided, defaults to [`MGS_PORT`].
        port: Option<u16>,
    },

    /// Listen on an explicit address.
    ///
    /// This variant should be used by test / CI setups where we want to listen
    /// on an address like `::1`.
    Address(SocketAddrV6),
}
