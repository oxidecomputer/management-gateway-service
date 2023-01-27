// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Interface for communicating with a single SP.

use crate::error::CommunicationError;
use crate::error::UpdateError;
use crate::shared_socket::SingleSpHandle;
use crate::shared_socket::SingleSpHandleError;
use crate::shared_socket::SingleSpMessage;
use crate::sp_response_ext::SpResponseExt;
use crate::SharedSocket;
use crate::SwitchPortConfig;
use async_trait::async_trait;
use backoff::backoff::Backoff;
use gateway_messages::ignition::LinkEvents;
use gateway_messages::ignition::TransceiverSelect;
use gateway_messages::tlv;
use gateway_messages::version;
use gateway_messages::ComponentDetails;
use gateway_messages::DeviceCapabilities;
use gateway_messages::DeviceDescriptionHeader;
use gateway_messages::DevicePresence;
use gateway_messages::Header;
use gateway_messages::IgnitionCommand;
use gateway_messages::IgnitionState;
use gateway_messages::Message;
use gateway_messages::MessageKind;
use gateway_messages::MgsRequest;
use gateway_messages::PowerState;
use gateway_messages::SpComponent;
use gateway_messages::SpError;
use gateway_messages::SpPort;
use gateway_messages::SpRequest;
use gateway_messages::SpResponse;
use gateway_messages::SpState;
use gateway_messages::StartupOptions;
use gateway_messages::TlvPage;
use gateway_messages::UpdateStatus;
use slog::debug;
use slog::error;
use slog::info;
use slog::trace;
use slog::warn;
use slog::Logger;
use std::io::Cursor;
use std::io::Seek;
use std::io::SeekFrom;
use std::net::SocketAddr;
use std::net::SocketAddrV6;
use std::str;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::oneshot;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time;
use tokio::time::timeout;
use tokio::time::Instant;
use uuid::Uuid;

mod update;

use self::update::start_component_update;
use self::update::start_sp_update;
use self::update::update_status;

// Once we've discovered an SP, continue to send discovery packets on this
// interval to detect changes.
//
// TODO-correctness/TODO-security What do we do if the SP address changes?
const DISCOVERY_INTERVAL_IDLE: Duration = Duration::from_secs(60);

// Minor "malicious / misbehaving SP" denial of service protection: When we ask
// the SP for its inventory or details of a component, we get back a response
// indicating the total number of TLV triples the SP will return in response to
// our query. We then repeatedly call the SP to fetch all of those triples
// (getting back multiple triples per call, hopefully, but that's fully in the
// SP's control). The number of triples is a u32; if an SP claimed to have an
// absurdly large number, we'd be stuck fetching that many (and building up a
// Vec of them in memory). We set a "we never expect this many devices" cap
// here; 1024 is over 10x our current gimlet rev-c device inventory count, so
// this should be plenty of buffer. If it needs to increase in the future, that
// will require an MGS update.
const TLV_RPC_TOTAL_ITEMS_DOS_LIMIT: u32 = 1024;

type Result<T, E = CommunicationError> = std::result::Result<T, E>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpInventory {
    pub devices: Vec<SpDevice>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpDevice {
    pub component: SpComponent,
    pub device: String,
    pub description: String,
    pub capabilities: DeviceCapabilities,
    pub presence: DevicePresence,
}

#[derive(Debug, Clone)]
pub struct SpComponentDetails {
    pub entries: Vec<ComponentDetails>,
}

#[derive(Debug)]
pub struct SingleSp {
    interface: String,
    cmds_tx: mpsc::Sender<InnerCommand>,
    sp_addr_rx: watch::Receiver<Option<(SocketAddrV6, SpPort)>>,
    inner_task: JoinHandle<()>,
    log: Logger,
}

impl Drop for SingleSp {
    fn drop(&mut self) {
        self.inner_task.abort();
    }
}

impl SingleSp {
    /// Construct a new `SingleSp` that will periodically attempt to discover an
    /// SP reachable on the port specified by `config`.
    ///
    /// This function returns immediately, but returns an object that is
    /// initially (and possibly always) unusable: until we complete any local
    /// setup for our UDP socket, methods of the returned `SingleSp` will fail.
    /// The local setup includes:
    ///
    /// 1. Waiting for an interface with the name specified by
    ///    `config.interface` to exist (if `config.interface` is `Some(_)`). We
    ///    determine this via `if_nametoindex()`. This step never fails, but
    ///    will block forever waiting for the interface.
    /// 2. Binding a UDP socket to `config.listen_addr` (with a `scope_id`
    ///    determined by the previous step). If this bind fails (e.g., because
    ///    `config.listen_addr` is invalid), the returned `SingleSp` will return
    ///    a "UDP bind failed" error from all methods forever.
    pub async fn new(
        shared_socket: &SharedSocket,
        config: SwitchPortConfig,
        max_attempts_per_rpc: usize,
        per_attempt_timeout: Duration,
    ) -> Self {
        let handle = shared_socket
            .single_sp_handler(&config.interface, config.discovery_addr)
            .await;

        let log = handle.log().clone();

        Self::new_impl(
            handle,
            config.interface,
            max_attempts_per_rpc,
            per_attempt_timeout,
            log,
        )
    }

    /// Create a new `SingleSp` instance specifically for testing (i.e.,
    /// communicating with a simulated SP).
    ///
    /// Unlike [`SingleSp::new()`], this method takes an existing bound
    /// [`UdpSocket`] and the target address of the SP. This allows multiple
    /// `SingleSp`s to exist on the same interface (e.g., the loopback
    /// interface) for testing.
    pub fn new_direct_socket_for_testing(
        socket: UdpSocket,
        discovery_addr: SocketAddrV6,
        max_attempts_per_rpc: usize,
        per_attempt_timeout: Duration,
        log: Logger,
    ) -> Self {
        let wrapper =
            InnerSocketWrapper { socket, discovery_addr, log: log.clone() };

        Self::new_impl(
            wrapper,
            "(direct socket handle)".to_string(),
            max_attempts_per_rpc,
            per_attempt_timeout,
            log,
        )
    }

    // Shared implementation of `new` and `new_direct_socket_for_testing` that
    // doesn't care whether we're using a `SharedSocket` or a
    // `InnerSocketWrapper` (the latter for tests).
    fn new_impl<T: InnerSocket + Send + 'static>(
        socket: T,
        interface: String,
        max_attempts_per_rpc: usize,
        per_attempt_timeout: Duration,
        log: Logger,
    ) -> Self {
        // SPs don't support pipelining, so any command we send to
        // `Inner` that involves contacting an SP will effectively block
        // until it completes. We use a more-or-less arbitrary chanel
        // size of 8 here to allow (a) non-SP commands (e.g., detaching
        // the serial console) and (b) a small number of enqueued SP
        // commands to be submitted without blocking the caller.
        let (cmds_tx, cmds_rx) = mpsc::channel(8);
        let (sp_addr_tx, sp_addr_rx) = watch::channel(None);

        let inner = Inner::new(
            socket,
            sp_addr_tx,
            max_attempts_per_rpc,
            per_attempt_timeout,
            cmds_rx,
        );

        let inner_task = tokio::spawn(inner.run());

        Self { interface, cmds_tx, sp_addr_rx, inner_task, log }
    }

    fn log(&self) -> &Logger {
        &self.log
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Retrieve the [`watch::Receiver`] for notifications of discovery of an
    /// SP's address.
    pub fn sp_addr_watch(
        &self,
    ) -> &watch::Receiver<Option<(SocketAddrV6, SpPort)>> {
        &self.sp_addr_rx
    }

    /// Request the state of an ignition target.
    ///
    /// This will fail if this SP is not connected to an ignition controller.
    pub async fn ignition_state(&self, target: u8) -> Result<IgnitionState> {
        self.rpc(MgsRequest::IgnitionState { target }).await.and_then(
            |(_peer, response, _data)| {
                response.expect_ignition_state().map_err(Into::into)
            },
        )
    }

    /// Request the state of all ignition targets.
    ///
    /// This will fail if this SP is not connected to an ignition controller.
    ///
    /// TODO: This _does not_ return the ignition state for the SP we're
    /// querying (which must be an ignition controller)! If this function
    /// returns successfully, it's on. Is that good enough?
    pub async fn bulk_ignition_state(&self) -> Result<Vec<IgnitionState>> {
        self.get_paginated_tlv_data(BulkIgnitionStateTlvRpc { log: self.log() })
            .await
    }

    /// Request link events for a single ignition target.
    ///
    /// This will fail if this SP is not connected to an ignition controller.
    pub async fn ignition_link_events(&self, target: u8) -> Result<LinkEvents> {
        self.rpc(MgsRequest::IgnitionLinkEvents { target }).await.and_then(
            |(_peer, response, _data)| response.expect_ignition_link_events(),
        )
    }

    /// Request all link events on all ignition targets.
    ///
    /// This will fail if this SP is not connected to an ignition controller.
    ///
    /// TODO: This _does not_ return events for the target on the SP we're
    /// querying (which must be an ignition controller)!
    pub async fn bulk_ignition_link_events(&self) -> Result<Vec<LinkEvents>> {
        self.get_paginated_tlv_data(BulkIgnitionLinkEventsTlvRpc {
            log: self.log(),
        })
        .await
    }

    /// Clear ignition link events.
    ///
    /// If `target` is `None`, ignition events are cleared on all targets
    /// (potentially restricted by `transceiver_select`).
    ///
    /// If `transceiver_select` is `None`, ignition events are cleared for all
    /// transceivers (potentially restricted by `target`).
    ///
    /// This will fail if this SP is not connected to an ignition controller.
    pub async fn clear_ignition_link_events(
        &self,
        target: Option<u8>,
        transceiver_select: Option<TransceiverSelect>,
    ) -> Result<()> {
        self.rpc(MgsRequest::ClearIgnitionLinkEvents {
            target,
            transceiver_select,
        })
        .await
        .and_then(|(_peer, response, _data)| {
            response.expect_clear_ignition_link_events_ack()
        })
    }

    /// Send an ignition command to the given target.
    ///
    /// This will fail if this SP is not connected to an ignition controller.
    pub async fn ignition_command(
        &self,
        target: u8,
        command: IgnitionCommand,
    ) -> Result<()> {
        self.rpc(MgsRequest::IgnitionCommand { target, command })
            .await
            .and_then(|(_peer, response, _data)| {
                response.expect_ignition_command_ack().map_err(Into::into)
            })
    }

    /// Request the state of the SP.
    pub async fn state(&self) -> Result<SpState> {
        self.rpc(MgsRequest::SpState).await.and_then(
            |(_peer, response, _data)| {
                response.expect_sp_state().map_err(Into::into)
            },
        )
    }

    /// Request the inventory of the SP.
    pub async fn inventory(&self) -> Result<SpInventory> {
        let devices = self.get_paginated_tlv_data(InventoryTlvRpc).await?;
        Ok(SpInventory { devices })
    }

    /// Request the detailed status / measurements of a particular component
    /// accessible to the SP.
    pub async fn component_details(
        &self,
        component: SpComponent,
    ) -> Result<SpComponentDetails> {
        let entries = self
            .get_paginated_tlv_data(ComponentDetailsTlvRpc {
                component,
                log: self.log(),
            })
            .await?;

        Ok(SpComponentDetails { entries })
    }

    /// Get the currently-active slot of a particular component.
    pub async fn component_active_slot(
        &self,
        component: SpComponent,
    ) -> Result<u16> {
        self.rpc(MgsRequest::ComponentGetActiveSlot(component)).await.and_then(
            |(_peer, response, _data)| response.expect_component_active_slot(),
        )
    }

    /// Set the currently-active slot of a particular component.
    pub async fn set_component_active_slot(
        &self,
        component: SpComponent,
        slot: u16,
    ) -> Result<()> {
        self.rpc(MgsRequest::ComponentSetActiveSlot { component, slot })
            .await
            .and_then(|(_peer, response, _data)| {
                response.expect_component_set_active_slot_ack()
            })
    }

    /// Request that the status of a component be cleared (e.g., resetting
    /// counters).
    pub async fn component_clear_status(
        &self,
        component: SpComponent,
    ) -> Result<()> {
        self.rpc(MgsRequest::ComponentClearStatus(component)).await.and_then(
            |(_peer, response, _data)| {
                response.expect_component_clear_status_ack()
            },
        )
    }

    async fn get_paginated_tlv_data<T: TlvRpc>(
        &self,
        rpc: T,
    ) -> Result<Vec<T::Item>> {
        // We don't know the total number of entries until we've requested the
        // first page; we'll set this to `Some(_)` in the first iteration of the
        // loop below.
        let mut page0_total = None;
        let mut entries = Vec::new();

        while entries.len() < page0_total.unwrap_or(usize::MAX) {
            // Index of the first entry we want to fetch.
            let offset = entries.len() as u32;

            let (page, data) = self.rpc(rpc.request(offset)).await.and_then(
                |(_peer, response, data)| {
                    let page = rpc.parse_response(response)?;
                    Ok((page, data))
                },
            )?;

            // Double-check the numbers we got were reasonable: did we get the
            // page we asked for, and is the total correct? If this is the first
            // page, "correct" just means "reasonable"; if this is the second or
            // later page, it should match every other page.
            if page.offset != offset {
                return Err(CommunicationError::TlvPagination {
                    reason: "unexpected offset from SP",
                });
            }
            let total = if let Some(n) = page0_total {
                if n != page.total as usize {
                    return Err(CommunicationError::TlvPagination {
                        reason: "total item count changed",
                    });
                }
                n
            } else {
                if page.total > TLV_RPC_TOTAL_ITEMS_DOS_LIMIT {
                    return Err(CommunicationError::TlvPagination {
                        reason: "too many items",
                    });
                }
                let n = page.total as usize;
                entries.reserve_exact(n);
                page0_total = Some(n);
                n
            };

            // Decode the TLV data.
            for result in tlv::decode_iter(&data) {
                // Is the TLV chunk valid?
                let (tag, value) = result?;

                // Are we expecting this chunk?
                if entries.len() >= total {
                    return Err(CommunicationError::TlvPagination {
                        reason:
                            "SP returned more entries than its reported total",
                    });
                }

                // Decode this chunk.
                if let Some(entry) = rpc.parse_tag_value(tag, value)? {
                    entries.push(entry);
                } else {
                    info!(
                        self.log(),
                        "skipping unknown tag {tag:?} while parsing {}",
                        T::LOG_NAME
                    );
                }
            }

            // Did our number of entries change? If not, we're presumably unable
            // to parse the response (unknown TLV tags, perhaps) and won't make
            // forward progress by retrying.
            if entries.len() as u32 == offset && total > 0 {
                return Err(CommunicationError::TlvPagination {
                    reason: "failed to parse any entries from SP response",
                });
            }
        }

        Ok(entries)
    }

    /// Get the current startup options of the target SP.
    ///
    /// Startup options are only meaningful for sleds and will only take effect
    /// the next time the sled starts up.
    pub async fn get_startup_options(&self) -> Result<StartupOptions> {
        self.rpc(MgsRequest::GetStartupOptions).await.and_then(
            |(_peer, response, _data)| {
                response.expect_startup_options().map_err(Into::into)
            },
        )
    }

    /// Set startup options on the target SP.
    ///
    /// Startup options are only meaningful for sleds and will only take effect
    /// the next time the sled starts up.
    pub async fn set_startup_options(
        &self,
        startup_options: StartupOptions,
    ) -> Result<()> {
        self.rpc(MgsRequest::SetStartupOptions(startup_options)).await.and_then(
            |(_peer, response, _data)| {
                response.expect_set_startup_options_ack().map_err(Into::into)
            },
        )
    }

    /// Update a component of the SP (or the SP itself!).
    ///
    /// This function will return before the update is compelte! Once the SP
    /// acknowledges that we want to apply an update, we spawn a background task
    /// to stream the update to the SP and then return. Poll the status of the
    /// update via [`Self::update_status()`].
    pub async fn start_update(
        &self,
        component: SpComponent,
        update_id: Uuid,
        slot: u16,
        image: Vec<u8>,
    ) -> Result<(), UpdateError> {
        if image.is_empty() {
            return Err(UpdateError::ImageEmpty);
        }

        // SP updates are special (`image` is a hubris archive and may include
        // an aux flash image in addition to the SP image).
        if component == SpComponent::SP_ITSELF {
            if slot != 0 {
                // We know the SP only has one possible slot, so fail fast if
                // the caller requested a slot other than 0.
                return Err(UpdateError::Communication(
                    CommunicationError::SpError(
                        SpError::InvalidSlotForComponent,
                    ),
                ));
            }
            start_sp_update(&self.cmds_tx, update_id, image, self.log()).await
        } else {
            start_component_update(
                &self.cmds_tx,
                component,
                update_id,
                slot,
                image,
                self.log(),
            )
            .await
        }
    }

    /// Get the status of any update being applied to the given component.
    pub async fn update_status(
        &self,
        component: SpComponent,
    ) -> Result<UpdateStatus> {
        update_status(&self.cmds_tx, component).await
    }

    /// Abort an in-progress update.
    pub async fn update_abort(
        &self,
        component: SpComponent,
        update_id: Uuid,
    ) -> Result<()> {
        self.rpc(MgsRequest::UpdateAbort { component, id: update_id.into() })
            .await
            .and_then(|(_peer, response, _data)| {
                response.expect_update_abort_ack().map_err(Into::into)
            })
    }

    /// Get the current power state.
    pub async fn power_state(&self) -> Result<PowerState> {
        self.rpc(MgsRequest::GetPowerState).await.and_then(
            |(_peer, response, _data)| {
                response.expect_power_state().map_err(Into::into)
            },
        )
    }

    /// Set the current power state.
    pub async fn set_power_state(&self, power_state: PowerState) -> Result<()> {
        self.rpc(MgsRequest::SetPowerState(power_state)).await.and_then(
            |(_peer, response, _data)| {
                response.expect_set_power_state_ack().map_err(Into::into)
            },
        )
    }

    /// Instruct the SP that a reset trigger will be coming.
    ///
    /// This is part of a two-phase reset process. MGS should set a
    /// `reset_prepare()` followed by `reset_trigger()`. Internally,
    /// `reset_trigger()` continues to send the reset trigger message until the
    /// SP responds with an error that it wasn't expecting it, at which point we
    /// assume a reset has happened. In critical situations (e.g., updates),
    /// callers should verify through a separate channel that the operation they
    /// needed the reset for has happened (e.g., checking the SP's version, in
    /// the case of updates).
    pub async fn reset_prepare(&self) -> Result<()> {
        self.rpc(MgsRequest::ResetPrepare).await.and_then(
            |(_peer, response, _data)| {
                response.expect_sys_reset_prepare_ack().map_err(Into::into)
            },
        )
    }

    /// Instruct the SP to reset.
    ///
    /// Only valid after a successful call to `reset_prepare()`.
    pub async fn reset_trigger(&self) -> Result<()> {
        // Reset trigger should retry until we get back an error indicating the
        // SP wasn't expecting a reset trigger (because it has reset!).
        match self.rpc(MgsRequest::ResetTrigger).await {
            Ok((_peer, response, _data)) => {
                Err(CommunicationError::BadResponseType {
                    expected: "system-reset",
                    got: response.name(),
                })
            }
            Err(CommunicationError::SpError(
                SpError::ResetTriggerWithoutPrepare,
            )) => Ok(()),
            Err(other) => Err(other),
        }
    }

    /// "Attach" to the serial console, setting up a tokio channel for all
    /// incoming serial console packets from the SP.
    pub async fn serial_console_attach(
        &self,
        component: SpComponent,
    ) -> Result<AttachedSerialConsole> {
        let (tx, rx) = oneshot::channel();

        // `Inner::run()` doesn't exit until we are dropped, so unwrapping here
        // only panics if it itself panicked.
        self.cmds_tx
            .send(InnerCommand::SerialConsoleAttach(component, tx))
            .await
            .unwrap();

        let attachment = rx.await.unwrap()?;

        Ok(AttachedSerialConsole {
            key: attachment.key,
            rx: attachment.incoming,
            inner_tx: self.cmds_tx.clone(),
            log: self.log().clone(),
        })
    }

    /// Detach any existing attached serial console connection.
    pub async fn serial_console_detach(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();

        // `Inner::run()` doesn't exit until we are dropped, so unwrapping here
        // only panics if it itself panicked.
        self.cmds_tx
            .send(InnerCommand::SerialConsoleDetach(None, tx))
            .await
            .unwrap();

        rx.await.unwrap()
    }

    pub(crate) async fn rpc(
        &self,
        kind: MgsRequest,
    ) -> Result<(SocketAddrV6, SpResponse, Vec<u8>)> {
        rpc(&self.cmds_tx, kind, None).await.result
    }

    pub async fn send_host_nmi(&self) -> Result<()> {
        self.rpc(MgsRequest::SendHostNmi).await.and_then(
            |(_peer, response, _data)| response.expect_send_host_nmi_ack(),
        )
    }
}

// Helper trait to call a "paginated" (i.e., split across multiple UDP packets)
// endpoint on the SP that returns TLV-encoded data.
trait TlvRpc {
    type Item;

    // A description of this message type used in logs.
    const LOG_NAME: &'static str;

    // Build the appropriate request for the given offset.
    fn request(&self, offset: u32) -> MgsRequest;

    // Parse the SP's response into a description of the page contents.
    fn parse_response(&self, response: SpResponse) -> Result<TlvPage>;

    // Parse a single tag/value pair into an `Item`.
    //
    // If the tag is unknown to the implementor, return `Ok(None)` (and this
    // pair will be skipped by `get_paginated_tlv_data()` above). If the tag is
    // known, return `Ok(Some(_))` if parsing succeeds or `Err(_)` otherwise.
    fn parse_tag_value(
        &self,
        tag: tlv::Tag,
        value: &[u8],
    ) -> Result<Option<Self::Item>>;
}

struct InventoryTlvRpc;

impl TlvRpc for InventoryTlvRpc {
    type Item = SpDevice;

    const LOG_NAME: &'static str = "inventory";

    fn request(&self, offset: u32) -> MgsRequest {
        MgsRequest::Inventory { device_index: offset }
    }

    fn parse_response(&self, response: SpResponse) -> Result<TlvPage> {
        response.expect_inventory()
    }

    fn parse_tag_value(
        &self,
        tag: tlv::Tag,
        value: &[u8],
    ) -> Result<Option<Self::Item>> {
        match tag {
            DeviceDescriptionHeader::TAG => {
                // Peel header out of the value.
                let (header, data) = gateway_messages::deserialize::<
                    DeviceDescriptionHeader,
                >(value)
                .map_err(|err| CommunicationError::TlvDeserialize {
                    tag,
                    err,
                })?;

                // Make sure the data length matches the header's claims.
                let device_len = header.device_len as usize;
                let description_len = header.description_len as usize;
                if data.len() != device_len.saturating_add(description_len) {
                    return Err(CommunicationError::TlvPagination {
                        reason: "inventory data / header length mismatch",
                    });
                }

                // Interpret the data as UTF8.
                let device =
                    str::from_utf8(&data[..device_len]).map_err(|_| {
                        CommunicationError::TlvPagination {
                            reason: "non-UTF8 inventory device",
                        }
                    })?;
                let description =
                    str::from_utf8(&data[device_len..]).map_err(|_| {
                        CommunicationError::TlvPagination {
                            reason: "non-UTF8 inventory description",
                        }
                    })?;

                Ok(Some(SpDevice {
                    component: header.component,
                    device: device.to_string(),
                    description: description.to_string(),
                    capabilities: header.capabilities,
                    presence: header.presence,
                }))
            }
            _ => Ok(None),
        }
    }
}

struct ComponentDetailsTlvRpc<'a> {
    component: SpComponent,
    log: &'a Logger,
}

impl TlvRpc for ComponentDetailsTlvRpc<'_> {
    type Item = ComponentDetails;

    const LOG_NAME: &'static str = "component details";

    fn request(&self, offset: u32) -> MgsRequest {
        MgsRequest::ComponentDetails { component: self.component, offset }
    }

    fn parse_response(&self, response: SpResponse) -> Result<TlvPage> {
        response.expect_component_details()
    }

    fn parse_tag_value(
        &self,
        tag: tlv::Tag,
        value: &[u8],
    ) -> Result<Option<Self::Item>> {
        use gateway_messages::measurement::Measurement;
        use gateway_messages::measurement::MeasurementHeader;
        use gateway_messages::monorail_port_status::PortStatus;
        use gateway_messages::monorail_port_status::PortStatusError;

        match tag {
            PortStatus::TAG => {
                let (result, leftover) = gateway_messages::deserialize::<
                    Result<PortStatus, PortStatusError>,
                >(value)
                .map_err(|err| CommunicationError::TlvDeserialize {
                    tag,
                    err,
                })?;

                if !leftover.is_empty() {
                    info!(
                        self.log,
                        "ignoring unexpected data in PortStatus TLV entry"
                    );
                }

                Ok(Some(ComponentDetails::PortStatus(result)))
            }
            MeasurementHeader::TAG => {
                let (header, leftover) =
                    gateway_messages::deserialize::<MeasurementHeader>(value)
                        .map_err(|err| CommunicationError::TlvDeserialize {
                        tag,
                        err,
                    })?;

                if leftover.len() != header.name_length as usize {
                    return Err(CommunicationError::TlvPagination {
                        reason: "measurement data / header length mismatch",
                    });
                }

                let name = str::from_utf8(leftover).map_err(|_| {
                    CommunicationError::TlvPagination {
                        reason: "non-UTF8 measurement name",
                    }
                })?;

                Ok(Some(ComponentDetails::Measurement(Measurement {
                    name: name.to_string(),
                    kind: header.kind,
                    value: header.value,
                })))
            }
            _ => {
                info!(
                    self.log,
                    "skipping unknown component details tag {tag:?}"
                );
                Ok(None)
            }
        }
    }
}

struct BulkIgnitionStateTlvRpc<'a> {
    log: &'a Logger,
}

impl TlvRpc for BulkIgnitionStateTlvRpc<'_> {
    type Item = IgnitionState;

    const LOG_NAME: &'static str = "ignition state";

    fn request(&self, offset: u32) -> MgsRequest {
        MgsRequest::BulkIgnitionState { offset }
    }

    fn parse_response(&self, response: SpResponse) -> Result<TlvPage> {
        response.expect_bulk_ignition_state()
    }

    fn parse_tag_value(
        &self,
        tag: tlv::Tag,
        value: &[u8],
    ) -> Result<Option<Self::Item>> {
        match tag {
            IgnitionState::TAG => {
                let (state, leftover) =
                    gateway_messages::deserialize::<IgnitionState>(value)
                        .map_err(|err| CommunicationError::TlvDeserialize {
                            tag,
                            err,
                        })?;

                if !leftover.is_empty() {
                    info!(
                        self.log,
                        "ignoring unexpected data in IgnitionState TLV entry"
                    );
                }

                Ok(Some(state))
            }
            _ => {
                info!(self.log, "skipping unknown ignition state tag {tag:?}");
                Ok(None)
            }
        }
    }
}

struct BulkIgnitionLinkEventsTlvRpc<'a> {
    log: &'a Logger,
}

impl TlvRpc for BulkIgnitionLinkEventsTlvRpc<'_> {
    type Item = LinkEvents;

    const LOG_NAME: &'static str = "ignition link events";

    fn request(&self, offset: u32) -> MgsRequest {
        MgsRequest::BulkIgnitionLinkEvents { offset }
    }

    fn parse_response(&self, response: SpResponse) -> Result<TlvPage> {
        response.expect_bulk_ignition_link_events()
    }

    fn parse_tag_value(
        &self,
        tag: tlv::Tag,
        value: &[u8],
    ) -> Result<Option<Self::Item>> {
        match tag {
            LinkEvents::TAG => {
                let (events, leftover) =
                    gateway_messages::deserialize::<LinkEvents>(value)
                        .map_err(|err| CommunicationError::TlvDeserialize {
                            tag,
                            err,
                        })?;

                if !leftover.is_empty() {
                    info!(
                        self.log,
                        "ignoring unexpected data in IgnitionState TLV entry"
                    );
                }

                Ok(Some(events))
            }
            _ => {
                info!(
                    self.log,
                    "skipping unknown ignition link events tag {tag:?}"
                );
                Ok(None)
            }
        }
    }
}

async fn rpc_with_trailing_data(
    inner_tx: &mpsc::Sender<InnerCommand>,
    kind: MgsRequest,
    our_trailing_data: Cursor<Vec<u8>>,
) -> (Result<(SocketAddrV6, SpResponse, Vec<u8>)>, Cursor<Vec<u8>>) {
    let RpcResponse { result, our_trailing_data } =
        rpc(inner_tx, kind, Some(our_trailing_data)).await;

    // We sent `Some(_)` trailing data, so we get `Some(_)` back; unwrap it
    // so our caller can remain ignorant of this detail.
    (result, our_trailing_data.unwrap())
}

async fn rpc(
    inner_tx: &mpsc::Sender<InnerCommand>,
    kind: MgsRequest,
    our_trailing_data: Option<Cursor<Vec<u8>>>,
) -> RpcResponse {
    let (resp_tx, resp_rx) = oneshot::channel();

    // `Inner::run()` doesn't exit as long as `inner_tx` exists, so unwrapping
    // here only panics if it itself panicked.
    inner_tx
        .send(InnerCommand::Rpc(RpcRequest {
            kind,
            our_trailing_data,
            response_tx: resp_tx,
        }))
        .await
        .unwrap();

    resp_rx.await.unwrap()
}

#[derive(Debug)]
pub struct AttachedSerialConsole {
    key: u64,
    rx: mpsc::Receiver<(u64, Vec<u8>)>,
    inner_tx: mpsc::Sender<InnerCommand>,
    log: Logger,
}

impl AttachedSerialConsole {
    pub fn split(
        self,
    ) -> (AttachedSerialConsoleSend, AttachedSerialConsoleRecv) {
        (
            AttachedSerialConsoleSend {
                key: self.key,
                tx_offset: 0,
                inner_tx: self.inner_tx,
            },
            AttachedSerialConsoleRecv {
                rx_offset: 0,
                rx: self.rx,
                log: self.log,
            },
        )
    }
}

#[derive(Debug)]
pub struct AttachedSerialConsoleSend {
    key: u64,
    tx_offset: u64,
    inner_tx: mpsc::Sender<InnerCommand>,
}

impl AttachedSerialConsoleSend {
    /// Write `data` to the serial console of the SP.
    pub async fn write(&mut self, data: Vec<u8>) -> Result<()> {
        let mut data = Cursor::new(data);
        let mut remaining_data = CursorExt::remaining_slice(&data).len();
        while remaining_data > 0 {
            let (result, new_data) = rpc_with_trailing_data(
                &self.inner_tx,
                MgsRequest::SerialConsoleWrite { offset: self.tx_offset },
                data,
            )
            .await;

            let data_sent = (remaining_data
                - CursorExt::remaining_slice(&new_data).len())
                as u64;

            let n = result.and_then(|(_peer, response, _data)| {
                response.expect_serial_console_write_ack().map_err(Into::into)
            })?;

            // Confirm the ack we got back makes sense; its `n` should be in the
            // range `[self.tx_offset..self.tx_offset + data_sent]`.
            if n < self.tx_offset {
                return Err(CommunicationError::BogusSerialConsoleState);
            }
            let bytes_accepted = n - self.tx_offset;
            if bytes_accepted > data_sent {
                return Err(CommunicationError::BogusSerialConsoleState);
            }

            data = new_data;

            // If the SP only accepted part of the data we sent, we need to
            // rewind our cursor and resend what it couldn't accept.
            if bytes_accepted < data_sent {
                let rewind = data_sent - bytes_accepted;
                data.seek(SeekFrom::Current(-(rewind as i64))).unwrap();
            }

            self.tx_offset += bytes_accepted;
            remaining_data = CursorExt::remaining_slice(&data).len();
        }
        Ok(())
    }

    /// Detach this serial console connection.
    pub async fn detach(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();

        self.inner_tx
            .send(InnerCommand::SerialConsoleDetach(Some(self.key), tx))
            .await
            .unwrap();

        rx.await.unwrap()
    }

    pub async fn send_break(&self) -> Result<()> {
        rpc(&self.inner_tx, MgsRequest::SerialConsoleBreak, None)
            .await
            .result
            .and_then(|(_peer, response, _data)| {
                response.expect_serial_console_break_ack()
            })
    }
}

#[derive(Debug)]
pub struct AttachedSerialConsoleRecv {
    rx_offset: u64,
    rx: mpsc::Receiver<(u64, Vec<u8>)>,
    log: Logger,
}

impl AttachedSerialConsoleRecv {
    /// Receive a `SerialConsole` packet from the SP.
    ///
    /// Returns `None` if the underlying channel has been closed (e.g., if the
    /// serial console has been detached).
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        let (offset, data) = self.rx.recv().await?;
        if offset != self.rx_offset {
            warn!(
                self.log,
                "gap in serial console data (dropped packet or buffer overrun)",
            );
        }
        self.rx_offset = offset + data.len() as u64;
        Some(data)
    }
}

// All RPC request/responses are handled by message passing to the `Inner` task
// below. `our_trailing_data` deserves some extra documentation: Some packet types
// (e.g., update chunks) want to send potentially-large binary data. We
// serialize this data with `gateway_messages::serialize_with_trailing_data()`,
// which appends as much data as will fit after the message header, but the
// caller doesn't know how much data that is until serialization happens. To
// handle this, we traffic in `Cursor<Vec<u8>>`s for communicating trailing data
// to `Inner`. If `our_trailing_data` in the `RpcRequest` is `Some(_)`, it will
// always be returned as `Some(_)` in the response as well, and the cursor will
// have been advanced by however much data was packed into the single RPC packet
// exchanged with the SP.
#[derive(Debug)]
struct RpcRequest {
    kind: MgsRequest,
    our_trailing_data: Option<Cursor<Vec<u8>>>,
    response_tx: oneshot::Sender<RpcResponse>,
}

#[derive(Debug)]
struct RpcResponse {
    result: Result<(SocketAddrV6, SpResponse, Vec<u8>)>,
    our_trailing_data: Option<Cursor<Vec<u8>>>,
}

#[derive(Debug)]
struct SerialConsoleAttachment {
    key: u64,
    incoming: mpsc::Receiver<(u64, Vec<u8>)>,
}

#[derive(Debug)]
// `Rpc` is the large variant, which is by far the most common, so silence
// clippy's warning that recommends boxing it.
#[allow(clippy::large_enum_variant)]
enum InnerCommand {
    Rpc(RpcRequest),
    SerialConsoleAttach(
        SpComponent,
        oneshot::Sender<Result<SerialConsoleAttachment>>,
    ),
    // The associated value is the connection key; if `Some(_)`, only detach if
    // the currently-attached key number matches. If `None`, detach any current
    // connection. These correspond to "detach the current session" (performed
    // automatically when a connection is closed) and "force-detach any session"
    // (performed by a user).
    SerialConsoleDetach(Option<u64>, oneshot::Sender<Result<()>>),
}

#[async_trait]
trait InnerSocket {
    fn log(&self) -> &Logger;
    fn discovery_addr(&self) -> SocketAddrV6;
    async fn send(&mut self, data: &[u8]) -> Result<(), SingleSpHandleError>;
    async fn recv(&mut self) -> SingleSpMessage;
}

#[async_trait]
impl InnerSocket for SingleSpHandle {
    fn log(&self) -> &Logger {
        SingleSpHandle::log(self)
    }

    fn discovery_addr(&self) -> SocketAddrV6 {
        SingleSpHandle::discovery_addr(self)
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), SingleSpHandleError> {
        SingleSpHandle::send(self, data).await
    }

    async fn recv(&mut self) -> SingleSpMessage {
        SingleSpHandle::recv(self).await
    }
}

struct InnerSocketWrapper {
    socket: UdpSocket,
    discovery_addr: SocketAddrV6,
    log: Logger,
}

#[async_trait]
impl InnerSocket for InnerSocketWrapper {
    fn log(&self) -> &Logger {
        &self.log
    }

    fn discovery_addr(&self) -> SocketAddrV6 {
        self.discovery_addr
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), SingleSpHandleError> {
        self.socket
            .send_to(data, self.discovery_addr)
            .await
            .map(|n| assert_eq!(n, data.len()))
            .map_err(|err| SingleSpHandleError::SendTo {
                addr: self.discovery_addr,
                interface: "(direct socket handle)".to_string(),
                err,
            })
    }

    // This function is only used if we were created with
    // `new_direct_socket_for_testing()`, so we're a little lazy with error
    // handling. The real `SingleSpHandle` handles errors internally, so this
    // `recv()` is defined as infallible in our trait that wraps both the real
    // handle and this wrapper-for-tests.
    async fn recv(&mut self) -> SingleSpMessage {
        let mut buf = [0; gateway_messages::MAX_SERIALIZED_SIZE];
        loop {
            let (peer, buf) = match self.socket.recv_from(&mut buf).await {
                Ok((n, SocketAddr::V6(peer))) => (peer, &buf[..n]),
                Ok((_, SocketAddr::V4(_))) => unreachable!(),
                Err(err) => {
                    error!(self.log, "failed to recv"; "err" => %err);
                    continue;
                }
            };

            let (message, data) =
                match gateway_messages::deserialize::<Message>(buf) {
                    Ok((message, data)) => (message, data),
                    Err(err) => {
                        error!(
                            self.log, "failed to deserialize packet";
                            "err" => %err,
                        );
                        continue;
                    }
                };

            match &message.kind {
                // TODO: We could handle `HostPhase2Data` requests with some
                // work, but currently we have no simulations / tests that need
                // it, so we omit it for now.
                MessageKind::MgsRequest(_)
                | MessageKind::MgsResponse(_)
                | MessageKind::SpRequest(SpRequest::HostPhase2Data {
                    ..
                }) => {
                    warn!(
                        self.log, "message kind unsupported by test socket";
                        "message" => ?message,
                    );
                    continue;
                }
                &MessageKind::SpRequest(SpRequest::SerialConsole {
                    component,
                    offset,
                }) => {
                    return SingleSpMessage::SerialConsole {
                        component,
                        offset,
                        data: data.to_owned(),
                    };
                }
                MessageKind::SpResponse(response) => {
                    return SingleSpMessage::SpResponse {
                        peer,
                        header: message.header,
                        response: *response,
                        data: data.to_owned(),
                    };
                }
            }
        }
    }
}

struct Inner<T> {
    socket_handle: T,
    sp_addr_tx: watch::Sender<Option<(SocketAddrV6, SpPort)>>,
    max_attempts_per_rpc: usize,
    per_attempt_timeout: Duration,
    serial_console_tx: Option<mpsc::Sender<(u64, Vec<u8>)>>,
    cmds_rx: mpsc::Receiver<InnerCommand>,
    message_id: u32,
    serial_console_connection_key: u64,
}

impl<T: InnerSocket> Inner<T> {
    // This is a private function; squishing the number of arguments down seems
    // like more trouble than it's worth.
    #[allow(clippy::too_many_arguments)]
    fn new(
        socket_handle: T,
        sp_addr_tx: watch::Sender<Option<(SocketAddrV6, SpPort)>>,
        max_attempts_per_rpc: usize,
        per_attempt_timeout: Duration,
        cmds_rx: mpsc::Receiver<InnerCommand>,
    ) -> Self {
        Self {
            socket_handle,
            sp_addr_tx,
            max_attempts_per_rpc,
            per_attempt_timeout,
            serial_console_tx: None,
            cmds_rx,
            message_id: 0,
            serial_console_connection_key: 0,
        }
    }

    fn log(&self) -> &Logger {
        self.socket_handle.log()
    }

    async fn run(mut self) {
        let maybe_known_addr = *self.sp_addr_tx.borrow();
        let mut sp_addr = match maybe_known_addr {
            Some((addr, _port)) => addr,
            None => match self.initial_discovery().await {
                Some(addr) => addr,
                // initial_discovery only returns `None` if `cmds_rx` is closed,
                // which means the `SingleSp` that spawned us is gone.
                None => return,
            },
        };

        info!(
            self.log(),
            "initial discovery complete";
            "addr" => %sp_addr,
        );

        let mut discovery_idle = time::interval_at(
            Instant::now() + DISCOVERY_INTERVAL_IDLE,
            DISCOVERY_INTERVAL_IDLE,
        );

        loop {
            tokio::select! {
                cmd = self.cmds_rx.recv() => {
                    let cmd = match cmd {
                        Some(cmd) => cmd,
                        None => return,
                    };

                    self.handle_command(cmd).await;
                    discovery_idle.reset();
                }

                message = self.socket_handle.recv() => {
                    self.handle_incoming_message(message).await;
                    discovery_idle.reset();
                }

                _ = discovery_idle.tick() => {
                    debug!(
                        self.log(), "attempting SP discovery (idle timeout)";
                        "discovery_addr" => %self.socket_handle.discovery_addr(),
                    );
                    match self.discover().await {
                        Ok(addr) => {
                            if sp_addr == addr {
                                debug!(
                                    self.log(), "discovered same SP";
                                    "addr" => %addr,
                                );
                            } else {
                                warn!(
                                    self.log(), "discovered new SP";
                                    "new_addr" => %addr,
                                    "old_addr" => %sp_addr,
                                );
                                sp_addr = addr;
                            }
                        }
                        Err(err) => {
                            warn!(
                                self.log(), "idle discovery check failed";
                                "err" => %err,
                            );
                        }
                    }
                }
            }
        }
    }

    // Waits until we've discovered an SP for the first time. Only returns none
    // if `cmds_rx` is closed, indicating our corresponding `SingleSp` is gone.
    async fn initial_discovery(&mut self) -> Option<SocketAddrV6> {
        // If discovery fails (typically due to timeout, but also possible due
        // to misconfiguration where we can't send packets at all), how long do
        // we wait before retrying? If failure is due to misconfiguration, we
        // will never succeed.
        const SLEEP_BETWEEN_DISCOVERY_RETRY: Duration = Duration::from_secs(1);

        // We can't do anything useful until we find an SP; loop
        // discovery packets first.
        debug!(
            self.log(), "attempting initial SP discovery";
            "discovery_addr" => %self.socket_handle.discovery_addr(),
        );

        loop {
            match self.discover().await {
                Ok(addr) => return Some(addr),
                Err(err) => {
                    info!(
                        self.log(),
                        "initial discovery failed";
                        "err" => %err,
                        "addr" => %self.socket_handle.discovery_addr(),
                    );
                }
            }

            // Before re-attempting discovery, peel out any pending commands and
            // fail them.
            loop {
                let response_is_ok = match self.cmds_rx.try_recv() {
                    Ok(InnerCommand::Rpc(rpc)) => rpc
                        .response_tx
                        .send(RpcResponse {
                            result: Err(CommunicationError::NoSpDiscovered),
                            our_trailing_data: rpc.our_trailing_data,
                        })
                        .is_ok(),
                    Ok(InnerCommand::SerialConsoleAttach(_, tx)) => {
                        tx.send(Err(CommunicationError::NoSpDiscovered)).is_ok()
                    }
                    Ok(InnerCommand::SerialConsoleDetach(_, tx)) => {
                        tx.send(Err(CommunicationError::NoSpDiscovered)).is_ok()
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => return None,
                };

                if !response_is_ok {
                    warn!(
                        self.log(),
                        "RPC requester disappeared while waiting for response"
                    );
                }
            }

            tokio::time::sleep(SLEEP_BETWEEN_DISCOVERY_RETRY).await;
        }
    }

    async fn discover(&mut self) -> Result<SocketAddrV6> {
        let (addr, response, _data) =
            self.rpc_call(MgsRequest::Discover, None).await?;

        let discovery = response.expect_discover()?;

        // The receiving half of `sp_addr_tx` is held by the `SingleSp` that
        // created us, and it aborts our task when it's dropped. This send
        // therefore can't fail; ignore the returned result.
        let _ = self.sp_addr_tx.send(Some((addr, discovery.sp_port)));

        Ok(addr)
    }

    async fn handle_command(&mut self, command: InnerCommand) {
        match command {
            InnerCommand::Rpc(mut rpc) => {
                let result = self
                    .rpc_call(rpc.kind, rpc.our_trailing_data.as_mut())
                    .await;
                let response = RpcResponse {
                    result,
                    our_trailing_data: rpc.our_trailing_data,
                };

                if rpc.response_tx.send(response).is_err() {
                    warn!(
                        self.log(),
                        "RPC requester disappeared while waiting for response"
                    );
                }
            }
            InnerCommand::SerialConsoleAttach(component, response_tx) => {
                let resp = self.attach_serial_console(component).await;
                response_tx.send(resp).unwrap();
            }
            InnerCommand::SerialConsoleDetach(key, response_tx) => {
                let resp = if key.is_none()
                    || key == Some(self.serial_console_connection_key)
                {
                    self.detach_serial_console().await
                } else {
                    Ok(())
                };
                response_tx.send(resp).unwrap();
            }
        }
    }

    async fn handle_incoming_message(&mut self, message: SingleSpMessage) {
        match message {
            SingleSpMessage::SerialConsole { component, offset, data } => {
                self.forward_serial_console(component, offset, &data);
            }
            SingleSpMessage::SpResponse { header, response, .. } => {
                // Reconstruct the message for logging.
                let message =
                    Message { header, kind: MessageKind::SpResponse(response) };

                warn!(
                    self.log(),
                    "ignoring unexpected RPC response";
                    "message" => ?message,
                );
            }
        }
    }

    async fn rpc_call(
        &mut self,
        kind: MgsRequest,
        our_trailing_data: Option<&mut Cursor<Vec<u8>>>,
    ) -> Result<(SocketAddrV6, SpResponse, Vec<u8>)> {
        // Build and serialize our request once.
        self.message_id += 1;
        let request = Message {
            header: Header {
                version: version::V2,
                message_id: self.message_id,
            },
            kind: MessageKind::MgsRequest(kind),
        };

        let mut outgoing_buf = [0; gateway_messages::MAX_SERIALIZED_SIZE];
        let n = match our_trailing_data {
            Some(data) => {
                let (n, written) =
                    gateway_messages::serialize_with_trailing_data(
                        &mut outgoing_buf,
                        &request,
                        &[CursorExt::remaining_slice(data)],
                    );
                // `data` is an in-memory cursor; seeking can only fail if we
                // provide a bogus offset, so it's safe to unwrap here.
                data.seek(SeekFrom::Current(written as i64)).unwrap();
                n
            }
            None => {
                // We know statically that `outgoing_buf` is large enough to
                // hold any `Request`, which in practice is the only possible
                // serialization error. Therefore, we can `.unwrap()`.
                gateway_messages::serialize(&mut outgoing_buf[..], &request)
                    .unwrap()
            }
        };
        let outgoing_buf = &outgoing_buf[..n];

        for attempt in 1..=self.max_attempts_per_rpc {
            trace!(
                self.log(), "sending request to SP";
                "request" => ?request,
                "attempt" => attempt,
            );

            match self
                .rpc_call_one_attempt(request.header.message_id, outgoing_buf)
                .await?
            {
                Some(result) => return Ok(result),
                None => continue,
            }
        }

        Err(CommunicationError::ExhaustedNumAttempts(self.max_attempts_per_rpc))
    }

    async fn rpc_call_one_attempt(
        &mut self,
        message_id: u32,
        serialized_request: &[u8],
    ) -> Result<Option<(SocketAddrV6, SpResponse, Vec<u8>)>> {
        // We consider an RPC attempt to be our attempt to contact the SP. It's
        // possible for the SP to respond and say it's busy; we shouldn't count
        // that as a failed UDP RPC attempt, so we loop within this "one
        // attempt" function to handle busy SP responses.
        let mut busy_sp_backoff = sp_busy_policy();

        // We usually resend the request in each iteration of the loop below,
        // but we skip that if we receive an out-of-band packet from the SP
        // (e.g., a serial console relay).
        let mut resend_request = true;

        loop {
            if resend_request {
                self.socket_handle.send(serialized_request).await?;
            }

            // Reset our default policy of resending requests if we iterate on
            // this loop.
            resend_request = true;

            let message = match timeout(
                self.per_attempt_timeout,
                self.socket_handle.recv(),
            )
            .await
            {
                Ok(result) => result,
                Err(_elapsed) => return Ok(None),
            };

            let (peer, header, response, sp_trailing_data) = match message {
                SingleSpMessage::SerialConsole { component, offset, data } => {
                    self.forward_serial_console(component, offset, &data);

                    // This is the only case where we want to go straight back
                    // to `recv()` again without resending our request; the SP
                    // might have already sent our response but we got a serial
                    // console packet to handle first.
                    resend_request = false;

                    continue;
                }
                SingleSpMessage::SpResponse {
                    peer,
                    header,
                    response,
                    data,
                } => {
                    if message_id == header.message_id {
                        (peer, header, response, data)
                    } else {
                        debug!(
                            self.log(), "ignoring unexpected response";
                            "id" => header.message_id,
                            "peer" => %peer,
                        );
                        return Ok(None);
                    }
                }
            };

            trace!(
                self.log(), "received response from SP";
                "header" => ?header,
                "response" => ?response,
            );

            match response {
                SpResponse::Error(SpError::Busy) => {
                    // Our SP busy policy never gives up, so we can unwrap.
                    let backoff_sleep = busy_sp_backoff.next_backoff().unwrap();
                    time::sleep(backoff_sleep).await;
                    continue;
                }
                SpResponse::Error(err) => {
                    return Err(err.into());
                }
                _ => {
                    return Ok(Some((
                        peer,
                        response,
                        sp_trailing_data.to_vec(),
                    )))
                }
            }
        }
    }

    fn forward_serial_console(
        &mut self,
        _component: SpComponent,
        offset: u64,
        data: &[u8],
    ) {
        // TODO-cleanup component support for serial console is half baked;
        // should we check here that it matches the attached serial console? For
        // the foreseeable future we only support one component, so we skip that
        // for now.

        if let Some(tx) = self.serial_console_tx.as_ref() {
            match tx.try_send((offset, data.to_vec())) {
                Ok(()) => return,
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.serial_console_tx = None;
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    error!(
                        self.log(),
                        "discarding SP serial console data (buffer full)"
                    );
                    return;
                }
            }
        }
        warn!(self.log(), "discarding SP serial console data (no receiver)");
    }

    async fn attach_serial_console(
        &mut self,
        component: SpComponent,
    ) -> Result<SerialConsoleAttachment> {
        // When a caller attaches to the SP's serial console, we return an
        // `mpsc::Receiver<_>` on which we send any packets received from the
        // SP. We have to pick a depth for that channel, and given we're not
        // able to apply backpressure to the SP / host sending the data, we
        // choose to drop data if the channel fills. We want something large
        // enough that hiccups in the receiver doesn't cause data loss, but
        // small enough that if the receiver stops handling messages we don't
        // eat a bunch of memory buffering up console data. We'll take a WAG and
        // pick a depth of 32 for now.
        const SERIAL_CONSOLE_CHANNEL_DEPTH: usize = 32;

        if self.serial_console_tx.is_some() {
            // Returning an `SpError` here is a little suspect since we didn't
            // actually talk to an SP, but we already know we're attached to it.
            // If we asked it to attach again, it would send back this error.
            return Err(CommunicationError::SpError(
                SpError::SerialConsoleAlreadyAttached,
            ));
        }

        let (_peer, response, _data) = self
            .rpc_call(MgsRequest::SerialConsoleAttach(component), None)
            .await?;
        response.expect_serial_console_attach_ack()?;

        let (tx, rx) = mpsc::channel(SERIAL_CONSOLE_CHANNEL_DEPTH);
        self.serial_console_tx = Some(tx);
        self.serial_console_connection_key += 1;
        Ok(SerialConsoleAttachment {
            key: self.serial_console_connection_key,
            incoming: rx,
        })
    }

    async fn detach_serial_console(&mut self) -> Result<()> {
        let (_peer, response, _data) =
            self.rpc_call(MgsRequest::SerialConsoleDetach, None).await?;
        response.expect_serial_console_detach_ack()?;
        self.serial_console_tx = None;
        Ok(())
    }
}

fn sp_busy_policy() -> backoff::ExponentialBackoff {
    const INITIAL_INTERVAL: Duration = Duration::from_millis(20);
    const MAX_INTERVAL: Duration = Duration::from_millis(1_000);

    backoff::ExponentialBackoff {
        current_interval: INITIAL_INTERVAL,
        initial_interval: INITIAL_INTERVAL,
        multiplier: 2.0,
        max_interval: MAX_INTERVAL,
        max_elapsed_time: None,
        ..Default::default()
    }
}

// Helper trait to provide methods on `io::Cursor` that are currently unstable.
trait CursorExt {
    fn is_empty(&self) -> bool;
    fn remaining_slice(&self) -> &[u8];
}

impl CursorExt for Cursor<Vec<u8>> {
    fn is_empty(&self) -> bool {
        self.position() as usize >= self.get_ref().len()
    }

    fn remaining_slice(&self) -> &[u8] {
        let data = self.get_ref();
        let pos = usize::min(self.position() as usize, data.len());
        &data[pos..]
    }
}

#[usdt::provider(provider = "gateway_sp_comms")]
mod probes {
    fn recv_packet(
        _source: &SocketAddr,
        _data: u64, // TODO actually a `*const u8`, but that isn't allowed by usdt
        _len: u64,
    ) {
    }
}
