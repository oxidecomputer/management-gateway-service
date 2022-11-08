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
use futures::Future;
use gateway_messages::SpPort;
use once_cell::sync::OnceCell;
use slog::info;
use slog::Logger;
use std::net::SocketAddrV6;
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
        let initial_state = if let Some(interface) = config.interface.clone() {
            StartupState::WaitingForInterface(interface)
        } else {
            StartupState::WaitingToBind(config.listen_addr)
        };

        let (startup_tx, startup_rx) = watch::channel(initial_state);

        let startup_fut = async move {
            // If we've been given the name of an interface, wait for it to
            // exist.
            let scope_id = match config.interface.as_deref() {
                Some(interface) => {
                    wait_for_interface_scope_id(interface, &log).await
                }
                None => 0,
            };

            let mut listen_addr = config.listen_addr;
            let mut discovery_addr = config.discovery_addr;
            listen_addr.set_scope_id(scope_id);
            discovery_addr.set_scope_id(scope_id);

            // If we had to do an interface lookup, notify any waiters that
            // we're transitioning to a new state.
            if config.interface.is_some() {
                startup_tx.send_modify(|s| {
                    *s = StartupState::WaitingToBind(listen_addr)
                });
            }

            // Attempt to bind; if this fails, we are misconfigured and will
            // forever return errors from all of our methods.
            let socket = match UdpSocket::bind(listen_addr).await {
                Ok(socket) => socket,
                Err(err) => {
                    startup_tx.send_modify(|s| {
                        *s = StartupState::Complete(Err(
                            StartupError::UdpBind {
                                addr: listen_addr,
                                err: err.to_string(),
                            },
                        ));
                    });
                    return None;
                }
            };

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

// Helper wrapper around `if_nametoindex()` that retries indefinitely if the
// lookup fails.
async fn wait_for_interface_scope_id(interface: &str, log: &Logger) -> u32 {
    // We're going to constantly spin waiting for `config.interface` to exist;
    // how long do we sleep between attempts?
    //
    // TODO replace with exponential backoff with a low-ish cap?
    const SLEEP_BETWEEN_RETRY: Duration = Duration::from_secs(5);

    loop {
        match nix::net::if_::if_nametoindex(interface) {
            Ok(id) => return id,
            Err(err) => {
                // TODO This assumes something else is responsible for
                // creating the interface we're supposed to use; if it needs
                // to be us (or if we need to do extra work to use it) we
                // need to do more here.
                info!(
                    log,
                    "if_nametoindex failed; will retry after {:?}",
                    SLEEP_BETWEEN_RETRY;
                    "interface" => interface,
                    "err" => %err,
                );
                tokio::time::sleep(SLEEP_BETWEEN_RETRY).await;
            }
        }
    }
}
