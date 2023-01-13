// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Helper functionality for async startup of a `SingleSp`.

use super::HostPhase2Provider;
use super::Inner;
use super::InnerCommand;
use crate::error::StartupError;
use crate::SwitchPortConfig;
use crate::SwitchPortListenConfig;
use crate::MGS_PORT;
use crate::SP_TO_MGS_MULTICAST_ADDR;
use futures::Future;
use gateway_messages::SpPort;
use once_cell::sync::OnceCell;
use slog::info;
use slog::warn;
use slog::Logger;
use std::net::SocketAddrV6;
use std::thread;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::watch;

// States we can be in to allow immediate creation of a `SingleSp` even though
// it can't immediately communicate on the management network.
#[derive(Debug)]
enum StartupState {
    // We're waiting for our configured network interface to exist.
    WaitingForInterface(String),
    // We're waiting for the result of attempting to bind to our listening
    // interface.
    WaitingToBind(SocketAddrV6),
    // Startup is complete (although not necessarily successful!).
    //
    // TODO We currently treat failure to bind a socket as a terminal error,
    // expecting it to be indicative of a configuration problem we have no
    // recourse to solve. Is that correct, or do we need some way of recovering
    // and retrying the startup process?
    Complete(Result<RunningState, StartupError>),
}

#[derive(Debug, Clone)]
struct RunningState {
    cmds_tx: mpsc::Sender<InnerCommand>,
    sp_addr_rx: watch::Receiver<Option<(SocketAddrV6, SpPort)>>,
}

#[derive(Debug)]
pub(super) struct State {
    startup_rx: watch::Receiver<StartupState>,
    complete: OnceCell<Result<RunningState, StartupError>>,
}

impl State {
    pub(super) fn new<T: HostPhase2Provider>(
        config: SwitchPortConfig,
        max_attempts_per_rpc: usize,
        per_attempt_timeout: Duration,
        host_phase2_provider: T,
        log: Logger,
    ) -> (Self, impl Future<Output = Option<Inner<T>>>) {
        let initial_state = match &config.listen {
            SwitchPortListenConfig::Interface { name, .. } => {
                StartupState::WaitingForInterface(name.clone())
            }
            SwitchPortListenConfig::Address(addr) => {
                StartupState::WaitingToBind(*addr)
            }
        };

        let (startup_tx, startup_rx) = watch::channel(initial_state);

        let startup_fut = async move {
            let listen_addr = match config.listen {
                SwitchPortListenConfig::Interface { name, port } => {
                    let log = log.clone();
                    let addr = tokio::task::spawn_blocking(move || {
                        wait_for_interface_blocking(
                            &name,
                            &log,
                            port.unwrap_or(MGS_PORT),
                        )
                    })
                    .await
                    .unwrap();

                    // Notify any waiters that we've converted the interface
                    // name into a socket address.
                    startup_tx.send_modify(|s| {
                        *s = StartupState::WaitingToBind(addr)
                    });

                    addr
                }
                SwitchPortListenConfig::Address(addr) => addr,
            };
            /*
            // If we've been given the name of an interface, wait for it to
            // exist.
            let listen_addr = match config.interface.as_deref() {
                Some(interface) => {
                    wait_for_interface_addr(interface, &log).await
                }
                None => {
                    // We checked above that if `config.interface` is `None`,
                    // then `config.listen_addr` is `Some(_)`, so we can u
                    //
                },
            };
            */

            let mut discovery_addr = config.discovery_addr;
            discovery_addr.set_scope_id(listen_addr.scope_id());

            /*
            // If we had to do an interface lookup, notify any waiters that
            // we're transitioning to a new state.
            if config.interface.is_some() {
                startup_tx.send_modify(|s| {
                    *s = StartupState::WaitingToBind(listen_addr)
                });
            }
            */

            // Create a socket via `socket2` so we can set `SO_REUSEADDR`, which
            // is necessary because our vlan interfaces all share the same
            // address (even though they have different scope IDs). Getting
            // "address in use" for the same address but a different scope ID
            // might be an illumos bug; if it is and it's fixed, we could remove
            // this in the future and just use `UdpSocket::bind()`.
            //
            // If binding fails, we assume we are misconfigured and will forever
            // return errors from all of our methods.
            info!(log, "binding to {}", listen_addr);
            let socket = match socket2::Socket::new(
                socket2::Domain::IPV6,
                socket2::Type::DGRAM,
                None,
            )
            .and_then(|s| {
                s.set_reuse_address(true)?;
                s.set_nonblocking(true)?;
                s.bind(&listen_addr.into())?;
                Ok(s)
            })
            .map_err(|e| e.to_string())
            .and_then(|s| {
                UdpSocket::from_std(s.into()).map_err(|e| e.to_string())
            }) {
                Ok(socket) => socket,
                Err(err) => {
                    startup_tx.send_modify(|s| {
                        *s = StartupState::Complete(Err(
                            StartupError::UdpBind { addr: listen_addr, err },
                        ));
                    });
                    return None;
                }
            };

            // Join the multicast group SPs use to send us requests.
            if let Err(err) = socket.join_multicast_v6(
                &SP_TO_MGS_MULTICAST_ADDR,
                listen_addr.scope_id(),
            ) {
                startup_tx.send_modify(|s| {
                    *s = StartupState::Complete(Err(
                        StartupError::JoinMulticast {
                            group: SP_TO_MGS_MULTICAST_ADDR,
                            err: err.to_string(),
                        },
                    ));
                });
                return None;
            }

            // Binding succeeded; we have successfully started up and can
            // now construct an `Inner` with which our parent `SingleSp` can
            // communicate.
            //
            // SPs don't support pipelining, so any command we send to
            // `Inner` that involves contacting an SP will effectively block
            // until it completes. We use a more-or-less arbitrary chanel
            // size of 8 here to allow (a) non-SP commands (e.g., detaching
            // the serial console) and (b) a small number of enqueued SP
            // commands to be submitted without blocking the caller.
            let (cmds_tx, cmds_rx) = mpsc::channel(8);
            let (sp_addr_tx, sp_addr_rx) = watch::channel(None);
            startup_tx.send_modify(|s| {
                *s = StartupState::Complete(Ok(RunningState {
                    cmds_tx,
                    sp_addr_rx,
                }));
            });

            Some(Inner::new(
                log,
                socket,
                sp_addr_tx,
                discovery_addr,
                max_attempts_per_rpc,
                per_attempt_timeout,
                cmds_rx,
                host_phase2_provider,
            ))
        };

        (Self { startup_rx, complete: OnceCell::new() }, startup_fut)
    }

    fn check_complete(&self) -> Result<&RunningState, StartupError> {
        // Have we already completed? If so, we have our state saved in
        // `self.complete`.
        if let Some(result) = self.complete.get() {
            return result.as_ref().map_err(Clone::clone);
        }

        match &*self.startup_rx.borrow() {
            StartupState::WaitingForInterface(iface) => {
                Err(StartupError::WaitingForInterface(iface.clone()))
            }
            StartupState::WaitingToBind(addr) => {
                Err(StartupError::WaitingToBind(*addr))
            }
            StartupState::Complete(result) => self
                .complete
                .get_or_init(|| result.clone())
                .as_ref()
                .map_err(Clone::clone),
        }
    }

    pub(super) async fn wait_for_startup_completion(
        &self,
    ) -> Result<(), StartupError> {
        let mut startup_rx = self.startup_rx.clone();
        loop {
            match &*startup_rx.borrow_and_update() {
                StartupState::WaitingForInterface(_)
                | StartupState::WaitingToBind(_) => {}
                StartupState::Complete(result) => {
                    return result.as_ref().map(|_| ()).map_err(Clone::clone)
                }
            }

            // `startup_tx` is never dropped before it sets the state to
            // `Complete(_)`, so we can unwrap here. This is not clear from the
            // `watch::Receiver` docs, which claims this fails if the sender has
            // been dropped: this actually fails if the sender has been dropped
            // _without changing the value_.
            startup_rx.changed().await.unwrap();
        }
    }

    pub(super) fn cmds_tx(
        &self,
    ) -> Result<&mpsc::Sender<InnerCommand>, StartupError> {
        self.check_complete().map(|state| &state.cmds_tx)
    }

    pub(super) fn sp_addr_rx(
        &self,
    ) -> Result<&watch::Receiver<Option<(SocketAddrV6, SpPort)>>, StartupError>
    {
        self.check_complete().map(|state| &state.sp_addr_rx)
    }
}

// Helper wrapper around `getifaddrs()` that retries indefinitely if the
// lookup fails.
//
// NOTE: This is a non-async function that sleeps; it should be spawned onto a
// background task! The `ifaddrs` iterator used internally is not `Send`,
// causing problems with our futures above if we try to use async sleeps.
fn wait_for_interface_blocking(
    interface: &str,
    log: &Logger,
    port: u16,
) -> SocketAddrV6 {
    // We're going to constantly spin waiting for `config.interface` to exist;
    // how long do we sleep between attempts?
    //
    // TODO replace with exponential backoff with a low-ish cap?
    const SLEEP_BETWEEN_RETRY: Duration = Duration::from_secs(5);

    loop {
        let ifaddrs = match nix::ifaddrs::getifaddrs() {
            Ok(ifaddrs) => ifaddrs,
            Err(err) => {
                warn!(
                    log,
                    "getifaddrs() failed; will retry after {:?}",
                    SLEEP_BETWEEN_RETRY;
                    "interface" => interface,
                    "err" => %err,
                );
                thread::sleep(SLEEP_BETWEEN_RETRY);
                continue;
            }
        };

        for ifaddr in ifaddrs {
            if ifaddr.interface_name == interface {
                if let Some(addr) =
                    ifaddr.address.and_then(|s| s.as_sockaddr_in6().copied())
                {
                    let mut addr = SocketAddrV6::new(
                        addr.ip(),
                        port,
                        addr.flowinfo(),
                        addr.scope_id(),
                    );

                    // On Linux, link-local addresses returned from
                    // `getifaddrs()` include a nonzero scope_id, but on illumos
                    // they do not: attempt to look it up.
                    if addr.scope_id() == 0 {
                        if let Ok(id) = nix::net::if_::if_nametoindex(interface)
                        {
                            addr.set_scope_id(id);
                        }
                    }

                    return addr;
                }
            }
        }

        warn!(
            log,
            "did not find an ipv6 address for interface; will retry after {:?}",
            SLEEP_BETWEEN_RETRY;
            "interface" => interface,
        );
        thread::sleep(SLEEP_BETWEEN_RETRY);
    }
}
