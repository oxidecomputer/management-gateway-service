// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

// Required nightly features for `usdt`
#![cfg_attr(target_os = "macos", feature(asm_sym))]

//! This crate provides UDP-based communication across the Oxide management
//! switch to a collection of SPs.
//!
//! The primary entry point is [`Communicator`].

mod communicator;
mod hubris_archive;
mod management_switch;
mod single_sp;
mod timeout;

use std::net::Ipv6Addr;
use std::net::SocketAddrV6;

pub use usdt::register_probes;

pub mod error;

pub use communicator::Communicator;
pub use communicator::FuturesUnorderedImpl;
pub use management_switch::LocationConfig;
pub use management_switch::LocationDeterminationConfig;
pub use management_switch::SpIdentifier;
pub use management_switch::SpType;
pub use management_switch::SwitchConfig;
pub use management_switch::SwitchPortConfig;
pub use management_switch::SwitchPortDescription;
pub use single_sp::AttachedSerialConsole;
pub use single_sp::AttachedSerialConsoleRecv;
pub use single_sp::AttachedSerialConsoleSend;
pub use single_sp::SingleSp;
pub use single_sp::SpDevice;
pub use single_sp::SpInventory;
pub use timeout::Elapsed;
pub use timeout::Timeout;

const DISCOVERY_MULTICAST_ADDR: Ipv6Addr =
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
const SP_MGS_PORT: u16 = 11111;

/// Default address to discover an SP via UDP multicast.
pub fn default_discovery_addr() -> SocketAddrV6 {
    SocketAddrV6::new(DISCOVERY_MULTICAST_ADDR, SP_MGS_PORT, 0, 0)
}

/// Default address to use when binding our local socket.
pub fn default_listen_addr() -> SocketAddrV6 {
    // TODO: Currently the SP never tries to discover MGS, only MGS discovers
    // SP, which means only SPs need to be listening on known ports. Can we bind
    // the same port on all the vlan interfaces so in the future SPs could
    // discover MGS if needed?
    SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)
}
