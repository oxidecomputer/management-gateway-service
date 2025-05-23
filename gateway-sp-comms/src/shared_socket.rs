// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! MGS communications share a single UDP socket that distinguishes which SP
//! it's talking to based on the scope ID of the packet.
//!
//! SPs are logically identified by interface names, and scope IDs are mapped to
//! those interface names.

use async_trait::async_trait;
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
use std::fmt;
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
use crate::shared_socket;
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
pub struct SharedSocket<T: Send> {
    socket: SendOnlyUdpSocket,
    scope_id_cache: Arc<ScopeIdCache>,
    single_sp_handlers: SpHandlerMap<T>,
    recv_handler_task: JoinHandle<()>,
    log: Logger,
}

// Hand-rolled `Debug` impl as the message type (`T`) needn't be `Debug` for the
// `SharedSocket` to be debug.
impl<T: Send> fmt::Debug for SharedSocket<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Destructure all of `self` here so that adding a new field gets us a
        // compiler error as a reminder to include (or ignore) it.
        let Self {
            socket,
            scope_id_cache,
            single_sp_handlers,
            recv_handler_task,
            log,
        } = self;
        f.debug_struct("SharedSocket")
            .field("socket", socket)
            .field("scope_id_cache", scope_id_cache)
            .field("single_sp_handlers", single_sp_handlers)
            .field("recv_handler_task", recv_handler_task)
            .field("log", log)
            .finish()
    }
}

type SpHandlerMap<M> = Arc<Mutex<FxHashMap<Name, mpsc::Sender<M>>>>;

impl<T: Send> Drop for SharedSocket<T> {
    fn drop(&mut self) {
        self.recv_handler_task.abort();
    }
}

impl<T: Send> SharedSocket<T> {
    /// Construct a `SharedSocket` by binding to a specified interface.
    pub async fn bind(
        port: u16,
        handler: impl RecvHandler<Message = T> + Send + 'static,
        log: Logger,
    ) -> Result<Self, BindError> {
        let addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0);
        let socket = UdpSocket::bind(addr)
            .await
            .map_err(|err| BindError { addr, err })?;

        Self::new(socket, handler, log)
    }

    /// Construct a `SharedSocket` from an already-bound socket.
    ///
    /// This method is intended primarily for test and CI environments where we
    /// want to bind to a specific address instead of `::`.
    pub fn from_socket(
        socket: UdpSocket,
        handler: impl RecvHandler<Message = T> + Send + 'static,
        log: Logger,
    ) -> Result<Self, BindError> {
        Self::new(socket, handler, log)
    }

    fn new(
        socket: UdpSocket,
        handler: impl RecvHandler<Message = T> + Send + 'static,
        log: Logger,
    ) -> Result<Self, BindError> {
        let socket = Arc::new(socket);
        let scope_id_cache = Arc::<ScopeIdCache>::default();
        let single_sp_handlers = SpHandlerMap::<T>::default();
        let recv_handler_task =
            tokio::spawn(handler.run(shared_socket::RecvSocket {
                socket: socket.clone(),
                sps: SpDispatcher {
                    scope_id_cache: scope_id_cache.clone(),
                    single_sp_handlers: single_sp_handlers.clone(),
                },
                log: log.clone(),
            }));

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
    ) -> SingleSpHandle<T> {
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

pub(crate) struct SingleSpHandle<T> {
    socket: SendOnlyUdpSocket,
    interface: Name,
    scope_id_cache: Arc<ScopeIdCache>,
    discovery_addr: SocketAddrV6,
    recv: mpsc::Receiver<T>,
    log: Logger,
}

impl<T> SingleSpHandle<T> {
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

    pub(crate) async fn recv(&mut self) -> Option<T> {
        // If `recv()` returns `None`, the `RecvHandler` task associated with
        // the shared socket we're using has panicked, or we're in Tokio runtime
        // shutdown (where tasks are destroyed in arbitrary order).  Relevant
        // executables are compiled with `panic = abort`, so this is probably
        // the latter; we'll log the error but not panic ourselves (to avoid
        // spurious panics at shutdown).
        let m = self.recv.recv().await;
        if m.is_none() {
            warn!(self.log, "recv() task died; we are hopefully exiting");
        }
        m
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
pub(crate) enum RecvError {
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
pub enum SingleSpMessage {
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

/// A handler for packets received on a [`SharedSocket`].
///
/// Implementations of this trait are responsible for handling packets received
/// on that UDP socket and dispatching messages to `SingleSp` handlers as
/// appropriate.
///
/// The [`RecvHandler::run`] method provides the implementation of the handler
/// task. Typically, it should be a loop, where each iteration calls the
/// [`RecvSocket::recv_packet`] method to receive the next UDP packet, and then
/// figures out what to do with that packet.
#[async_trait]
pub trait RecvHandler {
    /// The type of messages dispatched to `SingleSp` handlers.
    type Message: Send;

    /// Run the receive handler with the provided [`RecvSocket`].
    //
    // This interface is represented as a single `run()` method that implements
    // the entire lifespan of the receive handler task (which is typically a
    // loop). This is in contrast to a trait with a method that's called to
    // handle a single packet on each iteration of the task's run loop. This
    // design is due to the use of `async-trait`: each time an `async fn` on a
    // trait annotated with `#[async_trait]` is called, a new `Pin<Box<dyn
    // Future<...>>>` is created. Allocating a new `Future` for each received
    // packet would be kind of unfortunate, so instead, we allocate only a
    // single future for the entire run loop.
    async fn run(self, socket: RecvSocket<Self::Message>);
}

/// The receiving side of a [`SharedSocket`], containing the socket itself and a
/// [`SpDispatcher`] mapping peer socket addresses to `SingleSp` handler tasks.
///
/// This type is passed into the [`RecvHandler::run`] method when a socket's
/// [`RecvHandler`] task is spawned.
pub struct RecvSocket<T> {
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) log: Logger,
    pub(crate) sps: SpDispatcher<T>,
}

impl<T> RecvSocket<T> {
    /// Receive a packet from the shared UDP socket, returning the data
    /// contained in the packet as a borrowed slice, along with the peer address
    /// of the SP from which the packet was received.
    ///
    /// This method retries until a packet is successfully received from a
    /// recognizable peer interface, discarding any packets sent by unknown
    /// peers.
    pub(crate) async fn recv_packet<'buf>(
        &self,
        buf: &'buf mut [u8],
    ) -> (SocketAddrV6, &'buf [u8]) {
        loop {
            let (n, peer) = match self.socket.recv_from(buf).await {
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
                .sps
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
                .sps
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
            return (peer, data);
        }
    }
}

#[derive(Clone)]
pub struct SpDispatcher<T> {
    pub(crate) scope_id_cache: Arc<ScopeIdCache>,
    pub(crate) single_sp_handlers: SpHandlerMap<T>,
}

impl<T> SpDispatcher<T> {
    /// Forward `message` to the [`SingleSp`] handler for the SP with peer
    /// address `peer`.
    ///
    /// # Returns
    ///
    /// - [`Ok`]`(())` if the message was forwarded to the signle SP handler.
    /// - [`Err`]`(`[`RecvError`]`)` if no handler exists for the provided
    ///   `peer` address, or the handler task's channel is full (indicating that
    ///   the handler is overloaded).
    pub(crate) async fn forward_to_single_sp(
        &self,
        peer: SocketAddrV6,
        message: T,
    ) -> Result<(), RecvError> {
        let interface =
            self.scope_id_cache.index_to_name(peer.scope_id()).await.map_err(
                |err| RecvError::InterfaceForScopeId { addr: peer, err },
            )?;

        let mut single_sp_handlers = self.single_sp_handlers.lock().await;
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
}

#[async_trait]
impl<T: HostPhase2Provider> RecvHandler for ControlPlaneAgentHandler<T> {
    type Message = SingleSpMessage;
    async fn run(self, socket: RecvSocket<Self::Message>) {
        let mut buf = [0; gateway_messages::MAX_SERIALIZED_SIZE];
        loop {
            let (peer, data) = socket.recv_packet(&mut buf).await;
            let (header, kind, trailing_data) = match Self::parse_message(data)
            {
                Ok((header, kind, data)) => (header, kind, data),
                Err(err) => {
                    warn!(
                        socket.log, "failed to parse incoming packet";
                        "data" => ?data,
                        "peer" => %peer,
                        err,
                    );
                    continue;
                }
            };

            let message = Message { header, kind };
            if let Err(err) = self
                .handle_message(&socket, &message, trailing_data, peer)
                .await
            {
                warn!(
                    socket.log, "failed to handle incoming message";
                    "message" => ?Message { header, kind },
                    "peer" => %peer,
                    err,
                );
                continue;
            }
        }
    }
}

#[derive(Debug)]
pub struct ControlPlaneAgentHandler<T> {
    host_phase2_provider: Arc<T>,
}

impl<T: HostPhase2Provider> ControlPlaneAgentHandler<T> {
    pub fn new(host_phase2_provider: &Arc<T>) -> Self {
        Self { host_phase2_provider: host_phase2_provider.clone() }
    }
}

impl<T: HostPhase2Provider> ControlPlaneAgentHandler<T> {
    fn parse_message(
        data: &[u8],
    ) -> Result<(Header, MessageKind, &[u8]), RecvError> {
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
        socket: &RecvSocket<SingleSpMessage>,
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
                        socket.log,
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
                        sps: socket.sps.clone(),
                        socket: SendOnlyUdpSocket::from(Arc::clone(
                            &socket.socket,
                        )),
                        host_phase2_provider: Arc::clone(
                            &self.host_phase2_provider,
                        ),
                        peer,
                        message_id: message.header.message_id,
                        hash,
                        offset,
                        log: socket.log.clone(),
                    }
                    .run(),
                );
                Ok(())
            }
            &MessageKind::SpRequest(SpRequest::SerialConsole {
                component,
                offset,
            }) => {
                socket
                    .sps
                    .forward_to_single_sp(
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
                socket
                    .sps
                    .forward_to_single_sp(
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

// Struct holding all the arguments needed to respond to an SP's request for
// host phase 2 data and report the request/response back to the relevant single
// SP handler.
struct SendHostPhase2ResponseTask<T> {
    sps: SpDispatcher<SingleSpMessage>,
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
                    if let Err(err) = self
                        .sps
                        .forward_to_single_sp(
                            self.peer,
                            SingleSpMessage::HostPhase2Request(
                                HostPhase2Request {
                                    hash,
                                    offset,
                                    data_sent,
                                    received: Instant::now(),
                                },
                            ),
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
