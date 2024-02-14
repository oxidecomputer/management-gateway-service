// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! MGS communications share a single UDP socket that distinguishes which SP
//! it's talking to based on the scope ID of the packet.
//!
//! SPs are logically identified by interface names, and scope IDs are mapped to
//! those interface names.

use fxhash::FxHashMap;
use gateway_messages::version;
use gateway_messages::Header;
use gateway_messages::Message;
use gateway_messages::MessageKind;
use gateway_messages::MgsError;
use gateway_messages::MgsResponse;
use gateway_messages::SpComponent;
use gateway_messages::SpRequest;
use gateway_messages::SpResponse;
use slog::debug;
use slog::error;
use slog::o;
use slog::warn;
use slog::Logger;
use slog_error_chain::SlogInlineError;
use std::collections::hash_map;
use std::io;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV6;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::error::HostPhase2Error;
use crate::scope_id_cache::InterfaceError;
use crate::scope_id_cache::Name;
use crate::scope_id_cache::ScopeIdCache;
use crate::single_sp::HostPhase2Request;
use crate::HostPhase2Provider;
use crate::SP_TO_MGS_MULTICAST_ADDR;

#[derive(Debug, Error, SlogInlineError)]
#[error("failed to bind to {addr})")]
pub struct BindError {
    pub addr: SocketAddrV6,
    #[source]
    pub err: io::Error,
}

/// `SharedSocket` wraps a single UDP socket and allows multiple
/// [`SingleSp`](crate::SingleSp) handles to use it, assuming each is assigned
/// to a different underlying network interface.
///
/// This is designed to match the way management network VLAN interfaces are set
/// up inside the switch zone: all interfaces are VLANs that sit on top of
/// `tfportCPU0`, and they all share the _same_ IPv6 link-local address. This
/// prevents MGS from opening a listening socket on the same port for every
/// management network interface: listening ports must be unique by `(address,
/// port)`.
///
/// Instead, MGS can open a single `SharedSocket` and then create a `SingleSp`
/// handle for each VLAN interface. When creating a `SingleSp` from a
/// `SharedSocket`, an interface name must be specified, and only one `SingleSp`
/// handle is allowed per interface. Each `SingleSp` can send data on the shared
/// socket directly, but receives are handled by `SharedSocket`. When a
/// `SharedSocket` is created, it spawns a background tokio task that receives
/// messages from SPs and checks the scope ID (i.e., the interface that received
/// the packet). If it matches an interface that has a `SingleSp` handler, the
/// message is forwarded to that `SingleSp` instance via a tokio channel;
/// otherwise, the packet is discarded.
#[derive(Debug)]
pub struct SharedSocket {
    socket: SendOnlyUdpSocket,
    scope_id_cache: Arc<ScopeIdCache>,
    single_sp_handlers:
        Arc<Mutex<FxHashMap<Name, mpsc::Sender<SingleSpMessage>>>>,
    recv_handler_task: JoinHandle<()>,
    log: Logger,
}

impl Drop for SharedSocket {
    fn drop(&mut self) {
        self.recv_handler_task.abort();
    }
}

impl SharedSocket {
    /// Construct a `SharedSocket` by binding to a specified interface.
    pub async fn bind<T: HostPhase2Provider>(
        port: u16,
        host_phase2_provider: Arc<T>,
        log: Logger,
    ) -> Result<Self, BindError> {
        let addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0);
        let socket = UdpSocket::bind(addr)
            .await
            .map_err(|err| BindError { addr, err })?;

        Self::new(socket, host_phase2_provider, log)
    }

    /// Construct a `SharedSocket` from an already-bound socket.
    ///
    /// This method is intended primarily for test and CI environments where we
    /// want to bind to a specific address instead of `::`.
    pub fn from_socket<T: HostPhase2Provider>(
        socket: UdpSocket,
        host_phase2_provider: Arc<T>,
        log: Logger,
    ) -> Result<Self, BindError> {
        Self::new(socket, host_phase2_provider, log)
    }

    fn new<T: HostPhase2Provider>(
        socket: UdpSocket,
        host_phase2_provider: Arc<T>,
        log: Logger,
    ) -> Result<Self, BindError> {
        let socket = Arc::new(socket);
        let scope_id_cache = Arc::default();
        let single_sp_handlers = Arc::default();

        let recv_handler = RecvHandler {
            socket: Arc::clone(&socket),
            scope_id_cache: Arc::clone(&scope_id_cache),
            single_sp_handlers: Arc::clone(&single_sp_handlers),
            host_phase2_provider,
            log: log.clone(),
        };

        let recv_handler_task = tokio::spawn(recv_handler.run());

        Ok(Self {
            socket: SendOnlyUdpSocket::from(socket),
            scope_id_cache,
            single_sp_handlers,
            recv_handler_task,
            log,
        })
    }

    /// Create a handle for communicating with a single SP on the given
    /// interface.
    ///
    /// # Panics
    ///
    /// Panics if a handle for `interface` has already been created. This
    /// function should be called once for each interface of interest.
    pub(crate) async fn single_sp_handler(
        &self,
        interface: &str,
        mut discovery_addr: SocketAddrV6,
    ) -> SingleSpHandle {
        // We need to pick a queue depth for incoming packets that we forward to
        // the handle we're about to return. If that handle stops pulling
        // packets from the channel (or gets behind), we will start dropping
        // them. We want this to be effectively unbounded assuming a
        // well-behaved handler, so we'll set it to something relatively large.
        const HANDLER_CHANNEL_DEPTH: usize = 1024;

        // Ensure `discovery_addr` has scope ID 0, which will force a refresh
        // the first time a client tries to `send()` on it. This allows us to
        // delay any errors resolving the interface until this handler is
        // actually _used_ instead of _created_.
        discovery_addr.set_scope_id(0);

        let (tx, recv) = mpsc::channel(HANDLER_CHANNEL_DEPTH);
        let interface = Name::from(interface);

        // Insert our handler into our interface -> handler map, or panic if
        // `interface` is a duplicate.
        {
            let mut single_sp_handlers = self.single_sp_handlers.lock().await;

            match single_sp_handlers.entry(interface.clone()) {
                hash_map::Entry::Occupied(_) => {
                    panic!("single_sp_handler called with duplicate interface {interface:?}");
                }
                hash_map::Entry::Vacant(slot) => {
                    slot.insert(tx);
                }
            }
        }

        let interface_string = interface.to_string();
        SingleSpHandle {
            socket: self.socket.clone(),
            interface,
            scope_id_cache: Arc::clone(&self.scope_id_cache),
            discovery_addr,
            recv,
            log: self.log.new(o!("interface" => interface_string)),
        }
    }
}

#[derive(Debug, Error, SlogInlineError)]
pub(crate) enum SingleSpHandleError {
    #[error("failed to join multicast group {group} on {interface}")]
    JoinMulticast {
        group: Ipv6Addr,
        interface: String,
        #[source]
        err: io::Error,
    },

    #[error("send_to({addr:}) on {interface} failed")]
    SendTo {
        addr: SocketAddrV6,
        interface: String,
        #[source]
        err: io::Error,
    },

    #[error("scope ID of interface {interface} changing too frequently")]
    ScopeIdChangingFrequently { interface: String },

    #[error("cannot determine scope ID for interface")]
    InterfaceError(#[from] InterfaceError),
}

pub(crate) struct SingleSpHandle {
    socket: SendOnlyUdpSocket,
    interface: Name,
    scope_id_cache: Arc<ScopeIdCache>,
    discovery_addr: SocketAddrV6,
    recv: mpsc::Receiver<SingleSpMessage>,
    log: Logger,
}

impl SingleSpHandle {
    pub(crate) fn interface(&self) -> &str {
        &self.interface
    }

    pub(crate) fn log(&self) -> &Logger {
        &self.log
    }

    pub(crate) fn discovery_addr(&self) -> SocketAddrV6 {
        self.discovery_addr
    }

    /// Attempt to refresh our scope ID, returning `true` if it changed.
    async fn refresh_scope_id(&mut self) -> Result<bool, SingleSpHandleError> {
        let old_scope_id = self.discovery_addr.scope_id();
        let new_scope_id =
            self.scope_id_cache.refresh_by_name(&self.interface).await?;

        if new_scope_id == old_scope_id {
            return Ok(false);
        }

        // Scope ID changed; if we had a nonzero scope ID, we'd previously
        // joined the SP_TO_MGS multicast group on it; now leave it.
        if old_scope_id != 0 {
            if let Err(err) = self
                .socket
                .leave_multicast_v6(&SP_TO_MGS_MULTICAST_ADDR, old_scope_id)
            {
                // This presumably isn't fatal, because `old_scope_id` almost
                // certainly references an interface that no longer exists; just
                // log a warning and move on.
                warn!(
                    self.log, "failed to leave multicast group";
                    "group" => %SP_TO_MGS_MULTICAST_ADDR,
                    "interface" => self.interface(),
                    "scope_id" => old_scope_id,
                    "err" => %err,
                );
            }
        }

        // Join the same multicast group on our new scope ID.
        self.socket
            .join_multicast_v6(&SP_TO_MGS_MULTICAST_ADDR, new_scope_id)
            .map_err(|err| SingleSpHandleError::JoinMulticast {
                group: SP_TO_MGS_MULTICAST_ADDR,
                interface: self.interface.to_string(),
                err,
            })?;

        self.discovery_addr.set_scope_id(new_scope_id);
        debug!(
            self.log, "refreshed scope ID for SP interface";
            "interface" => self.interface(),
            "discovery_addr" => %self.discovery_addr(),
        );
        Ok(true)
    }

    pub(crate) async fn send(
        &mut self,
        data: &[u8],
    ) -> Result<(), SingleSpHandleError> {
        // We typically expect the loop below to _not_ loop; i.e., sends will
        // either succeed (in which case we're done, successfully) or fail but
        // our scope ID doesn't change (in which case we're done,
        // unsuccessfully). If we fail and our scope ID has changed, we'll
        // iterate, and this is the cap on the maximum number of scope ID
        // refreshes we're willing to try. The only way we could iterate more
        // than once is if some other part of the system is (quickly) destroying
        // and recreating the interface we're using, but if that's happening,
        // it's better for us to error out than stay stuck in an infinite loop
        // retrying with new scope IDs each time.
        const MAX_SCOPE_ID_REFRESHES: usize = 5;

        // Is this the first time we're being used? Update our scope ID.
        if self.discovery_addr.scope_id() == 0 {
            self.refresh_scope_id().await?;
        }

        for _ in 0..MAX_SCOPE_ID_REFRESHES {
            let err = match self.socket.send_to(data, self.discovery_addr).await
            {
                Ok(n) => {
                    // We should never be asked to send more data than will fit
                    // in one send; assert we didn't send an incomplete packet.
                    assert_eq!(n, data.len(), "UDP send_to incomplete");
                    return Ok(());
                }
                Err(err) => err,
            };

            // UDP send failures are relatively rare; a likely case is that the
            // interface we're using has been deleted (and hopefully
            // recreated!). If we fail to send, we will try evicting our cached
            // scope ID to see if it's changed; if it hasn't, return the send
            // error.
            if self.refresh_scope_id().await? {
                continue;
            } else {
                return Err(SingleSpHandleError::SendTo {
                    addr: self.discovery_addr,
                    interface: self.interface.to_string(),
                    err,
                });
            }
        }

        Err(SingleSpHandleError::ScopeIdChangingFrequently {
            interface: self.interface.to_string(),
        })
    }

    pub(crate) async fn recv(&mut self) -> SingleSpMessage {
        // If `recv()` returns `None`, the `RecvHandler` task associated with
        // the shared socket we're using has panicked; we'll propagate that
        // panic.
        self.recv.recv().await.expect("recv() task died")
    }
}

// Trivial wrapper around `UdpSocket` that only exposes `send`: in our
// `SingleSpHandle`, we want to allow direct sends but _not_ recvs, so we
// use this type to keep ourselves honest.
use send_only::SendOnlyUdpSocket;
mod send_only {
    use std::io;
    use std::net::Ipv6Addr;
    use std::net::SocketAddrV6;
    use std::sync::Arc;
    use tokio::net::UdpSocket;

    #[derive(Debug, Clone)]
    pub(super) struct SendOnlyUdpSocket(Arc<UdpSocket>);

    impl From<Arc<UdpSocket>> for SendOnlyUdpSocket {
        fn from(socket: Arc<UdpSocket>) -> Self {
            Self(socket)
        }
    }

    impl SendOnlyUdpSocket {
        pub(super) async fn send_to(
            &self,
            buf: &[u8],
            addr: SocketAddrV6,
        ) -> Result<usize, io::Error> {
            self.0.send_to(buf, addr).await
        }

        pub(super) fn join_multicast_v6(
            &self,
            maddr: &Ipv6Addr,
            interface: u32,
        ) -> Result<(), io::Error> {
            self.0.join_multicast_v6(maddr, interface)
        }

        pub(super) fn leave_multicast_v6(
            &self,
            maddr: &Ipv6Addr,
            interface: u32,
        ) -> Result<(), io::Error> {
            self.0.leave_multicast_v6(maddr, interface)
        }
    }
}

#[derive(Debug, Error, SlogInlineError)]
enum RecvError {
    #[error("failed to deserialize message header")]
    DeserializeHeader(#[source] hubpack::Error),
    #[error("failed to deserialize message body")]
    DeserializeBody(#[source] hubpack::Error),
    #[error("version mismatch (expected {expected}, SP sent {sp})")]
    VersionMismatch { expected: u32, sp: u32 },
    #[error("invalid message kind ({0})")]
    InvalidMessageKind(&'static str),
    #[error("could not find interface from scope ID of {addr}: {err}")]
    InterfaceForScopeId { addr: SocketAddrV6, err: InterfaceError },
    #[error("discarding packet from interface {interface:?}: no handler")]
    NoHandler { interface: String },
    #[error("discarding message from interface {interface:?}: handler busy")]
    HandlerBusy { interface: String },
}

// When we receive a packet that needs to be handled by a `SingleSp` instance,
// we look up the `SingleSp` instance by the scope ID of the source of the
// packet then send it an instance of this enum to handle.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum SingleSpMessage {
    HostPhase2Request(HostPhase2Request),
    SerialConsole {
        component: SpComponent,
        offset: u64,
        data: Vec<u8>,
    },
    SpResponse {
        peer: SocketAddrV6,
        header: Header,
        response: SpResponse,
        data: Vec<u8>,
    },
}

struct RecvHandler<T> {
    socket: Arc<UdpSocket>,
    scope_id_cache: Arc<ScopeIdCache>,
    single_sp_handlers:
        Arc<Mutex<FxHashMap<Name, mpsc::Sender<SingleSpMessage>>>>,
    host_phase2_provider: Arc<T>,
    log: Logger,
}

impl<T: HostPhase2Provider> RecvHandler<T> {
    async fn run(self) {
        let mut buf = [0; gateway_messages::MAX_SERIALIZED_SIZE];
        loop {
            let (n, peer) = match self.socket.recv_from(&mut buf).await {
                Ok((n, SocketAddr::V6(addr))) => (n, addr),
                // We only use IPv6; we can't receive from an IPv4 peer.
                Ok((_, SocketAddr::V4(_))) => unreachable!(),
                Err(err) => {
                    // Failing to recv _probably_ means our socket is
                    // irrecoverably broken, but there isn't much we can do
                    // about that from here. We'll sleep to avoid spamming the
                    // logs, but someone will have to notice we're dead and
                    // restart us.
                    error!(
                        self.log, "failed to recv on shared MGS socket";
                        "err" => %err,
                    );
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            // Before doing anything else, check our peer's scope ID: If we
            // don't have a `SingleSp` handler for the interface identified by
            // that scope ID, discard this packet.
            let peer_interface = match self
                .scope_id_cache
                .index_to_name(peer.scope_id())
                .await
            {
                Ok(name) => name,
                Err(err) => {
                    warn!(
                        self.log,
                        "failed to look up interface for peer; discarding packet";
                        "peer" => %peer,
                        err,
                    );
                    continue;
                }
            };
            if !self
                .single_sp_handlers
                .lock()
                .await
                .contains_key(&peer_interface)
            {
                warn!(
                    self.log, "discarding packet from unknown interface";
                    "interface" => peer_interface.to_string(),
                );
                continue;
            }

            let data = &buf[..n];
            let (header, kind, trailing_data) = match self.parse_message(data) {
                Ok((header, kind, data)) => (header, kind, data),
                Err(err) => {
                    warn!(
                        self.log, "failed to parse incoming packet";
                        "data" => ?data,
                        "peer" => %peer,
                        err,
                    );
                    continue;
                }
            };

            let message = Message { header, kind };
            if let Err(err) =
                self.handle_message(&message, trailing_data, peer).await
            {
                warn!(
                    self.log, "failed to handle incoming message";
                    "message" => ?Message { header, kind },
                    "peer" => %peer,
                    err,
                );
                continue;
            }
        }
    }

    fn parse_message<'a>(
        &self,
        data: &'a [u8],
    ) -> Result<(Header, MessageKind, &'a [u8]), RecvError> {
        // Peel off the header first to check the version.
        let (header, remaining) = gateway_messages::deserialize::<Header>(data)
            .map_err(RecvError::DeserializeHeader)?;
        if header.version < version::MIN {
            return Err(RecvError::VersionMismatch {
                expected: version::CURRENT,
                sp: header.version,
            });
        }

        // Parse the remainder.
        let (kind, sp_trailing_data) =
            match gateway_messages::deserialize::<MessageKind>(remaining) {
                Ok((kind, sp_trailing_data)) => (kind, sp_trailing_data),
                // We failed to deserialize, and the message version is higher
                // than what we know. This almost certainly means they sent a
                // new message we don't understand; return a version mismatch
                // error.
                Err(_) if header.version > version::CURRENT => {
                    return Err(RecvError::VersionMismatch {
                        expected: version::CURRENT,
                        sp: header.version,
                    })
                }
                // We failed to deserialize but the version is in the range we
                // should have understood; return a deserialization error.
                Err(err) => return Err(RecvError::DeserializeBody(err)),
            };

        Ok((header, kind, sp_trailing_data))
    }

    async fn handle_message(
        &self,
        message: &Message,
        sp_trailing_data: &[u8],
        peer: SocketAddrV6,
    ) -> Result<(), RecvError> {
        // Dispatch based on the kind of message. We handle host phase2 requests
        // ourselves; any other SP request or response must be forwarded to a
        // `SingleSp` instance (if one exists for `peer`).
        match &message.kind {
            MessageKind::MgsRequest(_) => {
                Err(RecvError::InvalidMessageKind("MgsRequest"))
            }
            MessageKind::MgsResponse(_) => {
                Err(RecvError::InvalidMessageKind("MgsResponse"))
            }
            &MessageKind::SpRequest(SpRequest::HostPhase2Data {
                hash,
                offset,
            }) => {
                if !sp_trailing_data.is_empty() {
                    warn!(
                        self.log,
                        "ignoring unexpected trailing data";
                        "request" => ?message,
                        "length" => sp_trailing_data.len(),
                    );
                }

                // Spawn the handler for reading and sending host phase2 data
                // onto a background task to avoid blocking additional `recv`s
                // on it. We do not attempt to retry or handle errors in this
                // task; if something goes wrong, the SP will re-request the
                // same block of data.
                tokio::spawn(
                    SendHostPhase2ResponseTask {
                        scope_id_cache: Arc::clone(&self.scope_id_cache),
                        single_sp_handlers: Arc::clone(
                            &self.single_sp_handlers,
                        ),
                        socket: SendOnlyUdpSocket::from(Arc::clone(
                            &self.socket,
                        )),
                        host_phase2_provider: Arc::clone(
                            &self.host_phase2_provider,
                        ),
                        peer,
                        message_id: message.header.message_id,
                        hash,
                        offset,
                        log: self.log.clone(),
                    }
                    .run(),
                );
                Ok(())
            }
            &MessageKind::SpRequest(SpRequest::SerialConsole {
                component,
                offset,
            }) => {
                forward_to_single_sp(
                    &self.scope_id_cache,
                    &self.single_sp_handlers,
                    peer,
                    SingleSpMessage::SerialConsole {
                        component,
                        offset,
                        data: sp_trailing_data.to_vec(),
                    },
                )
                .await
            }
            MessageKind::SpResponse(response) => {
                forward_to_single_sp(
                    &self.scope_id_cache,
                    &self.single_sp_handlers,
                    peer,
                    SingleSpMessage::SpResponse {
                        peer,
                        header: message.header,
                        response: *response,
                        data: sp_trailing_data.to_vec(),
                    },
                )
                .await
            }
        }
    }
}

async fn forward_to_single_sp(
    scope_id_cache: &ScopeIdCache,
    single_sp_handlers: &Mutex<FxHashMap<Name, mpsc::Sender<SingleSpMessage>>>,
    peer: SocketAddrV6,
    message: SingleSpMessage,
) -> Result<(), RecvError> {
    let interface = scope_id_cache
        .index_to_name(peer.scope_id())
        .await
        .map_err(|err| RecvError::InterfaceForScopeId { addr: peer, err })?;

    let mut single_sp_handlers = single_sp_handlers.lock().await;
    let slot = single_sp_handlers.entry(interface.clone());

    let entry = match slot {
        hash_map::Entry::Occupied(entry) => entry,
        hash_map::Entry::Vacant(_) => {
            // This error is _extremely_ unlikely, because we checked
            // immediately after receiving that we have a handler for the
            // scope ID identified by `peer`. It's not impossible, though,
            // if we lose a race and the interface in question is destroyed
            // between our check above and our check now.
            return Err(RecvError::NoHandler {
                interface: interface.to_string(),
            });
        }
    };

    // We are running in the active `recv()` task, and we don't want to
    // allow a sluggish `SingleSp` handler to block us. We use a bounded
    // channel and `try_send`: if there's no room in the channel, we'll log
    // an error and discard the packet.
    match entry.get().try_send(message) {
        Ok(()) => Ok(()),
        Err(TrySendError::Full(_)) => {
            Err(RecvError::HandlerBusy { interface: interface.to_string() })
        }
        Err(TrySendError::Closed(_)) => {
            // The handler is gone; remove it from our map _and_ fail.
            entry.remove();
            Err(RecvError::NoHandler { interface: interface.to_string() })
        }
    }
}

// Struct holding all the arguments needed to respond to an SP's request for
// host phase 2 data and report the request/response back to the relevant single
// SP handler.
struct SendHostPhase2ResponseTask<T> {
    scope_id_cache: Arc<ScopeIdCache>,
    single_sp_handlers:
        Arc<Mutex<FxHashMap<Name, mpsc::Sender<SingleSpMessage>>>>,
    socket: SendOnlyUdpSocket,
    host_phase2_provider: Arc<T>,
    peer: SocketAddrV6,
    message_id: u32,
    hash: [u8; 32],
    offset: u64,
    log: Logger,
}

impl<T: HostPhase2Provider> SendHostPhase2ResponseTask<T> {
    async fn run(self) {
        let hash = self.hash;
        let offset = self.offset;

        // We will optimistically attempt to serialize a successful response
        // directly into an outgoing buffer. If our phase2 data provider cannot
        // give us the data, we'll bail out and reserialize an error response.
        let mut outgoing_buf = [0; gateway_messages::MAX_SERIALIZED_SIZE];

        // Optimistically serialize a success response, so we can fetch host
        // phase 2 data into the remainder of the buffer.
        let mut message = Message {
            header: Header {
                version: version::CURRENT,
                message_id: self.message_id,
            },
            kind: MessageKind::MgsResponse(MgsResponse::HostPhase2Data {
                hash,
                offset,
            }),
        };

        let mut n =
            gateway_messages::serialize(&mut outgoing_buf, &message).unwrap();
        let mut data_sent = None;

        match self
            .host_phase2_provider
            .read_data(hash, offset, &mut outgoing_buf[n..])
            .await
        {
            Ok(m) => {
                data_sent = Some(m as u64);
                n += m;
            }
            Err(err) => {
                warn!(
                    self.log, "cannot fulfill SP request for host phase 2 data";
                    &err,
                );
                let error_kind = match err {
                    HostPhase2Error::NoImage { .. }
                    | HostPhase2Error::Other { .. } => {
                        MgsError::HostPhase2Unavailable { hash }
                    }
                    HostPhase2Error::BadOffset { .. } => {
                        MgsError::HostPhase2ImageBadOffset { hash, offset }
                    }
                };
                message.kind =
                    MessageKind::MgsResponse(MgsResponse::Error(error_kind));

                n = gateway_messages::serialize(&mut outgoing_buf, &message)
                    .unwrap();
            }
        }

        let serialized_message = &outgoing_buf[..n];
        match self.socket.send_to(serialized_message, self.peer).await {
            Ok(_) => {
                if let Some(data_sent) = data_sent {
                    // Notify our handler of this request so it can report
                    // progress to its clients.
                    if let Err(err) = forward_to_single_sp(
                        &self.scope_id_cache,
                        &self.single_sp_handlers,
                        self.peer,
                        SingleSpMessage::HostPhase2Request(HostPhase2Request {
                            hash,
                            offset,
                            data_sent,
                            received: Instant::now(),
                        }),
                    )
                    .await
                    {
                        warn!(
                            self.log,
                            "failed to notify handler of host phase2 request";
                            err,
                        );
                    }
                }
            }
            Err(err) => {
                warn!(
                    self.log,
                    "failed to respond to SP host phase 2 data request";
                    "err" => %err,
                );
            }
        }
    }
}
