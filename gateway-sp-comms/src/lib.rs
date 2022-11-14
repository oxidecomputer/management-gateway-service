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
mod sp_response_ext;
mod timeout;

use std::net::Ipv6Addr;
use std::net::SocketAddrV6;

pub use usdt::register_probes;

pub mod error;

pub use communicator::Communicator;
pub use communicator::FuturesUnorderedImpl;
pub use gateway_messages;
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
pub use single_sp::HostPhase2Provider;
pub use single_sp::SingleSp;
pub use single_sp::SpDevice;
pub use single_sp::SpInventory;
pub use timeout::Elapsed;
pub use timeout::Timeout;

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
