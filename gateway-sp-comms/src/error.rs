// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

use gateway_messages::tlv;
use gateway_messages::SpError;
use slog_error_chain::SlogInlineError;
use std::io;
use std::net::Ipv6Addr;
use std::net::SocketAddrV6;
use thiserror::Error;

pub use crate::scope_id_cache::InterfaceError;
use crate::shared_socket::SingleSpHandleError;

#[derive(Debug, Clone, Error, SlogInlineError)]
pub enum HostPhase2Error {
    #[error("host image with hash {hash} unavailable")]
    NoImage { hash: String },
    #[error("invalid offset for host image {hash}: {offset}")]
    BadOffset { hash: String, offset: u64 },
    #[error(
        "error getting data for host image {hash} at offset {offset}: {err}"
    )]
    Other { hash: String, offset: u64, err: String },
}

#[derive(Debug, Error, SlogInlineError)]
pub enum CommunicationError {
    #[error(transparent)]
    InterfaceError(#[from] InterfaceError),
    #[error("scope ID of interface {interface} changing too frequently")]
    ScopeIdChangingFrequently { interface: String },
    #[error("failed to join multicast group {group} on {interface}: {err}")]
    JoinMulticast { group: Ipv6Addr, interface: String, err: io::Error },
    #[error("failed to send UDP packet to {addr} on {interface}: {err}")]
    UdpSendTo { addr: SocketAddrV6, interface: String, err: io::Error },
    #[error("failed to recv UDP packet: {0}")]
    UdpRecv(io::Error),
    #[error("no SP discovered")]
    NoSpDiscovered,
    #[error("failed to deserialize SP message from {peer}: {err}")]
    Deserialize { peer: SocketAddrV6, err: gateway_messages::HubpackError },
    #[error("RPC call failed (gave up after {0} attempts)")]
    ExhaustedNumAttempts(usize),
    #[error("bogus SP response type: expected {expected:?} but got {got:?}")]
    BadResponseType { expected: &'static str, got: &'static str },
    #[error("Error response from SP")]
    SpError(#[from] SpError),
    #[error("Bogus serial console state; detach and reattach")]
    BogusSerialConsoleState,
    #[error("Protocol version mismatch: SP version {sp}, MGS version {mgs}")]
    VersionMismatch { sp: u32, mgs: u32 },
    #[error("failed to deserialize TLV value for tag {tag:?}: {err}")]
    TlvDeserialize { tag: tlv::Tag, err: gateway_messages::HubpackError },
    #[error("failed to decode TLV triple")]
    TlvDecode(#[from] tlv::DecodeError),
    #[error("invalid pagination: {reason}")]
    TlvPagination { reason: &'static str },
    #[error("IPCC key lookup value too large")]
    IpccKeyLookupValueTooLarge,
    #[error("Packet included unexpected trailing data: {0:x?}")]
    UnexpectedTrailingData(Vec<u8>),
    #[error("Trailing data is wrong length: expected {expected}, got {got}")]
    BadTrailingDataSize { expected: usize, got: usize },
}

impl From<SingleSpHandleError> for CommunicationError {
    fn from(err: SingleSpHandleError) -> Self {
        match err {
            SingleSpHandleError::JoinMulticast { group, interface, err } => {
                Self::JoinMulticast { group, interface, err }
            }
            SingleSpHandleError::ScopeIdChangingFrequently { interface } => {
                Self::ScopeIdChangingFrequently { interface }
            }
            SingleSpHandleError::SendTo { addr, interface, err } => {
                Self::UdpSendTo { addr, interface, err }
            }
            SingleSpHandleError::InterfaceError(err) => Self::from(err),
        }
    }
}

#[derive(Debug, Error, SlogInlineError)]
pub enum UpdateError {
    #[error("update image cannot be empty")]
    ImageEmpty,
    #[error("update image is too large")]
    ImageTooLarge,
    #[error("hubris archive error")]
    HubtoolsError(#[from] hubtools::Error),
    #[error("error reading caboose in hubris archive")]
    CabooseError(#[from] hubtools::CabooseError),
    #[error("board mismatch: SP is {sp} but archive is for {archive}")]
    BoardMismatch { sp: String, archive: String },
    #[error("RoT slot mismatch: target slot {slot} cannot be written with {image_name:?} image")]
    RotSlotMismatch { slot: u16, image_name: String },
    #[error("error reading aux flash image: {0:?}")]
    TlvcError(tlvc::TlvcReadError<std::convert::Infallible>),
    #[error("corrupt aux flash image: {0}")]
    CorruptTlvc(String),
    #[error("failed to send update message to SP")]
    Communication(#[from] CommunicationError),
    #[error("invalid zip archive")]
    InvalidArchive,
    #[error("invalid slot ID for operation")]
    InvalidSlotIdForOperation,
    #[error("invalid component for device")]
    InvalidComponent,
}
