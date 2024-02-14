// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Behavior implemented by both real and simulated SPs.

use crate::ignition;
use crate::ignition::LinkEvents;
use crate::tlv;
use crate::version;
use crate::BadRequestReason;
use crate::ComponentAction;
use crate::ComponentDetails;
use crate::ComponentUpdatePrepare;
use crate::DeviceCapabilities;
use crate::DeviceDescriptionHeader;
use crate::DevicePresence;
use crate::DiscoverResponse;
use crate::Header;
use crate::IgnitionCommand;
use crate::IgnitionState;
use crate::Message;
use crate::MessageKind;
use crate::MgsError;
use crate::MgsRequest;
use crate::MgsResponse;
use crate::PowerState;
use crate::RotBootInfo;
use crate::RotRequest;
use crate::RotResponse;
use crate::RotSlotId;
use crate::SensorRequest;
use crate::SensorResponse;
use crate::SerializedSize;
use crate::SpComponent;
use crate::SpError;
use crate::SpPort;
use crate::SpResponse;
use crate::SpStateV2;
use crate::SpUpdatePrepare;
use crate::StartupOptions;
use crate::SwitchDuration;
use crate::TlvPage;
use crate::UpdateChunk;
use crate::UpdateId;
use crate::UpdateStatus;
use crate::ROT_PAGE_SIZE;
use hubpack::error::Error as HubpackError;
use hubpack::error::Result as HubpackResult;

#[cfg(feature = "std")]
use std::net::SocketAddrV6;

#[cfg(not(feature = "std"))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct SocketAddrV6 {
    pub ip: smoltcp::wire::Ipv6Address,
    pub port: u16,
}

/// Description of a device as reported as part of this SP's inventory.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct DeviceDescription<'a> {
    pub component: SpComponent,
    pub device: &'a str,
    pub description: &'a str,
    pub capabilities: DeviceCapabilities,
    pub presence: DevicePresence,
}

impl From<DeviceDescription<'_>> for DeviceDescriptionHeader {
    fn from(dev: DeviceDescription<'_>) -> Self {
        Self {
            component: dev.component,
            device_len: dev.device.len() as u32,
            description_len: dev.description.len() as u32,
            capabilities: dev.capabilities,
            presence: dev.presence,
        }
    }
}

/// An index that [`handle_message`] has bounds-checked; see the comments on the
/// trait methods that accept this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundsChecked(pub u32);

pub trait SpHandler {
    type BulkIgnitionStateIter: Iterator<Item = IgnitionState>;
    type BulkIgnitionLinkEventsIter: Iterator<Item = LinkEvents>;

    fn discover(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
    ) -> Result<DiscoverResponse, SpError>;

    fn num_ignition_ports(&mut self) -> Result<u32, SpError>;

    fn ignition_state(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        target: u8,
    ) -> Result<IgnitionState, SpError>;

    fn bulk_ignition_state(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        offset: u32,
    ) -> Result<Self::BulkIgnitionStateIter, SpError>;

    fn ignition_link_events(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        target: u8,
    ) -> Result<LinkEvents, SpError>;

    fn bulk_ignition_link_events(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        offset: u32,
    ) -> Result<Self::BulkIgnitionLinkEventsIter, SpError>;

    /// If `target` is `None`, clear link events for all targets.
    fn clear_ignition_link_events(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        target: Option<u8>,
        transceiver_select: Option<ignition::TransceiverSelect>,
    ) -> Result<(), SpError>;

    fn ignition_command(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        target: u8,
        command: IgnitionCommand,
    ) -> Result<(), SpError>;

    fn sp_state(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
    ) -> Result<SpStateV2, SpError>;

    fn sp_update_prepare(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        update: SpUpdatePrepare,
    ) -> Result<(), SpError>;

    fn component_update_prepare(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        update: ComponentUpdatePrepare,
    ) -> Result<(), SpError>;

    fn update_chunk(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        chunk: UpdateChunk,
        data: &[u8],
    ) -> Result<(), SpError>;

    fn update_status(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        component: SpComponent,
    ) -> Result<UpdateStatus, SpError>;

    fn update_abort(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        component: SpComponent,
        id: UpdateId,
    ) -> Result<(), SpError>;

    fn power_state(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
    ) -> Result<PowerState, SpError>;

    fn set_power_state(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        power_state: PowerState,
    ) -> Result<(), SpError>;

    fn serial_console_attach(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        component: SpComponent,
    ) -> Result<(), SpError>;

    /// The returned u64 should be the offset we want to receive in the next
    /// call to `serial_console_write()`; i.e., the furthest offset we've
    /// ingested (either by writing to the console or by buffering to write it).
    fn serial_console_write(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        offset: u64,
        data: &[u8],
    ) -> Result<u64, SpError>;

    fn serial_console_detach(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
    ) -> Result<(), SpError>;

    fn serial_console_keepalive(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
    ) -> Result<(), SpError>;

    fn serial_console_break(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
    ) -> Result<(), SpError>;

    /// Number of devices returned in the inventory of this SP.
    fn num_devices(&mut self, sender: SocketAddrV6, port: SpPort) -> u32;

    /// Get the description for the given device.
    ///
    /// This function should never fail, as the device inventory should be
    /// static. Acquiring the presence of a device may fail, but that should be
    /// indicated inline via the returned description's `presence` field.
    ///
    /// When this method is called by `handle_message`, `index` has been bounds
    /// checked and is guaranteed to be in the range `0..num_devices()`.
    ///
    /// # Panics
    ///
    /// Implementors are allowed to panic if `index` is not in range (i.e., is
    /// greater than or equal to the value returned by `num_devices()`).
    fn device_description(
        &mut self,
        index: BoundsChecked,
    ) -> DeviceDescription<'static>;

    /// Number of informational elements returned in the details for the given
    /// component.
    fn num_component_details(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        component: SpComponent,
    ) -> Result<u32, SpError>;

    /// Get detailed information for the given component.
    ///
    /// When this method is called by `handle_message`, `index` has been bounds
    /// checked and is guaranteed to be in the range
    /// `0..num_component_details(_, _, component)`.
    ///
    /// # Panics
    ///
    /// Implementors are allowed to panic if `index` is not in range (i.e., is
    /// greater than or equal to the value returned by `num_component_details()`
    /// for this component).
    fn component_details(
        &mut self,
        component: SpComponent,
        index: BoundsChecked,
    ) -> ComponentDetails;

    fn component_clear_status(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        component: SpComponent,
    ) -> Result<(), SpError>;

    fn component_get_active_slot(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        component: SpComponent,
    ) -> Result<u16, SpError>;

    fn component_set_active_slot(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        component: SpComponent,
        slot: u16,
        persist: bool,
    ) -> Result<(), SpError>;

    fn component_action(
        &mut self,
        sender: SocketAddrV6,
        component: SpComponent,
        action: ComponentAction,
    ) -> Result<(), SpError>;

    fn get_startup_options(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
    ) -> Result<StartupOptions, SpError>;

    fn set_startup_options(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        startup_options: StartupOptions,
    ) -> Result<(), SpError>;

    fn mgs_response_error(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        message_id: u32,
        err: MgsError,
    );

    fn mgs_response_host_phase2_data(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        message_id: u32,
        hash: [u8; 32],
        offset: u64,
        data: &[u8],
    );

    fn send_host_nmi(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
    ) -> Result<(), SpError>;

    fn set_ipcc_key_lookup_value(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        key: u8,
        value: &[u8],
    ) -> Result<(), SpError>;

    fn get_component_caboose_value(
        &mut self,
        component: SpComponent,
        slot: u16,
        key: [u8; 4],
        buf: &mut [u8],
    ) -> Result<usize, SpError>;

    fn reset_component_prepare(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        component: SpComponent,
    ) -> Result<(), SpError>;

    // On success, this method will return unless the reset
    // affects the SP_ITSELF.
    fn reset_component_trigger(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        component: SpComponent,
    ) -> Result<(), SpError>;

    fn read_sensor(
        &mut self,
        request: SensorRequest,
    ) -> Result<SensorResponse, SpError>;

    fn current_time(&mut self) -> Result<u64, SpError>;

    fn read_rot(
        &mut self,
        request: RotRequest,
        buf: &mut [u8],
    ) -> Result<RotResponse, SpError>;

    fn vpd_lock_status_all(&mut self, buf: &mut [u8])
        -> Result<usize, SpError>;

    fn versioned_rot_boot_info(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        version: u8,
    ) -> Result<RotBootInfo, SpError>;
}

/// Handle a single incoming message.
///
/// The incoming message is described by `sender` (the remote address of the
/// sender), `port` (the local port the message arived on), and `data` (the raw
/// message). It will be deserialized, and the appropriate method will be called
/// on `handler` to craft a response.
///
/// If the message warrants a response, the response will then be serialized
/// into `out`, the length of the serialized response is returned. If the
/// message does not warrant a response, `out` remains unchanged and `None` is
/// returned.
pub fn handle_message<H: SpHandler>(
    sender: SocketAddrV6,
    port: SpPort,
    data: &[u8],
    handler: &mut H,
    out: &mut [u8; crate::MAX_SERIALIZED_SIZE],
) -> Option<usize> {
    // If we were able to peel off the header, chain the rest of the data
    // then chain the rest of the data through to the handler.
    let (message_id, response, outgoing_trailing_data) =
        match read_request_header(data) {
            ReadHeaderResult::Ok { header, remaining_data } => {
                let (response, outgoing_trailing_data) = handle_message_impl(
                    sender,
                    port,
                    header,
                    remaining_data,
                    handler,
                    &mut out[Message::MAX_SIZE..],
                )?;
                (header.message_id, response, outgoing_trailing_data)
            }
            ReadHeaderResult::HeaderValidationFailed { header, error } => {
                (header.message_id, SpResponse::Error(error), None)
            }
            ReadHeaderResult::HeaderParsingFailed { error } => {
                // We didn't even get a message_id; make one up.
                (u32::MAX, SpResponse::Error(error), None)
            }
        };

    let response = Message {
        header: Header { version: version::CURRENT, message_id },
        kind: MessageKind::SpResponse(response),
    };

    // We know `response` is well-formed and fits into `out`, so we can unwrap
    // serialization.
    let mut n = match hubpack::serialize(&mut out[..], &response) {
        Ok(n) => n,
        Err(_) => panic!(),
    };

    // Append any outgoing trailing data.
    n += match outgoing_trailing_data {
        Some(OutgoingTrailingData::DeviceInventory {
            device_index,
            total_devices,
        }) => {
            encode_tlv_structs(
                &mut out[n..],
                (device_index..total_devices).map(|i| {
                    let dev = handler.device_description(BoundsChecked(i));
                    (DeviceDescriptionHeader::TAG, move |buf: &mut [u8]| {
                        // Will the serialized description of this device fit?
                        let len = DeviceDescriptionHeader::MAX_SIZE
                            + dev.device.len()
                            + dev.description.len();
                        if len > buf.len() {
                            return Err(HubpackError::Overrun);
                        }

                        let header = DeviceDescriptionHeader::from(dev);

                        // Serialize the header, then pack in the device and
                        // description strings (which we know will fit based on
                        // our length check above).
                        let mut n = hubpack::serialize(buf, &header)?;
                        for s in [dev.device, dev.description] {
                            buf[n..][..s.len()].copy_from_slice(s.as_bytes());
                            n += s.len();
                        }

                        Ok(n)
                    })
                }),
            )
        }
        Some(OutgoingTrailingData::ComponentDetails {
            component,
            offset,
            total,
        }) => encode_tlv_structs(
            &mut out[n..],
            (offset..total).map(|i| {
                let details =
                    handler.component_details(component, BoundsChecked(i));
                (details.tag(), move |buf: &mut [u8]| details.serialize(buf))
            }),
        ),
        Some(OutgoingTrailingData::BulkIgnitionState(iter)) => {
            encode_tlv_structs(
                &mut out[n..],
                iter.map(|state| {
                    (IgnitionState::TAG, move |buf: &mut [u8]| {
                        hubpack::serialize(buf, &state)
                    })
                }),
            )
        }
        Some(OutgoingTrailingData::BulkIgnitionLinkEvents(iter)) => {
            encode_tlv_structs(
                &mut out[n..],
                iter.map(|state| {
                    (LinkEvents::TAG, move |buf: &mut [u8]| {
                        hubpack::serialize(buf, &state)
                    })
                }),
            )
        }
        Some(OutgoingTrailingData::ShiftFromTail(len)) => {
            out.copy_within(Message::MAX_SIZE..Message::MAX_SIZE + len, n);
            len
        }

        None => 0,
    };

    Some(n)
}

/// Given an iterator that produces `(tag, value)` pairs (where `value` is
/// provided as a function that serializes the value into a buffer), pack as
/// many TLV triples from `iter` as we can into `out`.
///
/// Returns the total number of bytes written into `out`.
fn encode_tlv_structs<I, F>(mut out: &mut [u8], iter: I) -> usize
where
    I: Iterator<Item = (tlv::Tag, F)>,
    F: FnOnce(&mut [u8]) -> HubpackResult<usize>,
{
    let mut total_tlv_len = 0;

    for (tag, encode) in iter {
        match tlv::encode(out, tag, encode) {
            Ok(n) => {
                total_tlv_len += n;
                out = &mut out[n..];
            }

            // If either the `encode` closure or the TLV header doesn't fit,
            // we've packed as much as we can into `out` and we're done.
            Err(tlv::EncodeError::Custom(HubpackError::Overrun))
            | Err(tlv::EncodeError::BufferTooSmall) => break,

            // Other hubpack errors are impossible with all serialization types
            // we use.
            Err(tlv::EncodeError::Custom(_)) => panic!(),
        }
    }

    total_tlv_len
}

// We could use a combination of Option/Result/tuples to represent the results
// of `read_request_header()`, but it fundamentally has three possible result
// states, represented here.
enum ReadHeaderResult<'a> {
    // We successfully parsed the header and it appears valid.
    Ok { header: Header, remaining_data: &'a [u8] },
    // We successfully parsed the header, but it is not valid.
    HeaderValidationFailed { header: Header, error: SpError },
    // We failed to parse even a header.
    HeaderParsingFailed { error: SpError },
}

/// Read the request header from the front of `data`, returning the message
/// header and the remainder of the request data on success. On failure, returns
/// an appropriate error message, and possibly a header (if the message was
/// well-formed enough to have one!).
fn read_request_header(data: &[u8]) -> ReadHeaderResult<'_> {
    let (header, remaining_data) = match hubpack::deserialize::<Header>(data) {
        Ok((header, remaining_data)) => (header, remaining_data),
        Err(_) => {
            return ReadHeaderResult::HeaderParsingFailed {
                error: SpError::BadRequest(
                    BadRequestReason::DeserializationError,
                ),
            };
        }
    };

    // Check the message version.
    if header.version >= version::MIN {
        ReadHeaderResult::Ok { header, remaining_data }
    } else {
        ReadHeaderResult::HeaderValidationFailed {
            header,
            error: SpError::BadRequest(BadRequestReason::WrongVersion {
                sp: version::CURRENT,
                request: header.version,
            }),
        }
    }
}

/// Parses the remainder of a message (after the header, which is handled by
/// `read_request_header`), and calls `handler`.
///
/// If the response kind needs to generate trailing data, returns `(_, Some(_)`,
/// and our caller is responsible for handling that generation. Otherwise,
/// returns `(_, None)`.
fn handle_message_impl<H: SpHandler>(
    sender: SocketAddrV6,
    port: SpPort,
    header: Header,
    request_kind_data: &[u8],
    handler: &mut H,
    trailing_tx_buf: &mut [u8],
) -> Option<(SpResponse, Option<OutgoingTrailingData<H>>)> {
    match hubpack::deserialize::<MessageKind>(request_kind_data) {
        Ok((MessageKind::MgsRequest(kind), leftover)) => {
            Some(handle_mgs_request(
                sender,
                port,
                handler,
                kind,
                leftover,
                trailing_tx_buf,
            ))
        }
        Ok((MessageKind::MgsResponse(kind), leftover)) => {
            handle_mgs_response(
                sender,
                port,
                header.message_id,
                handler,
                kind,
                leftover,
            );
            None
        }
        Ok((MessageKind::SpRequest(_) | MessageKind::SpResponse(_), _)) => {
            Some((
                SpResponse::Error(SpError::BadRequest(
                    BadRequestReason::WrongDirection,
                )),
                None,
            ))
        }
        // We failed to deserialize, and the message version is higher than
        // what we know. This almost certainly means they sent a new message we
        // don't understand; send back a version mismatch error.
        Err(_) if header.version > version::CURRENT => Some((
            SpResponse::Error(SpError::BadRequest(
                BadRequestReason::WrongVersion {
                    sp: version::CURRENT,
                    request: header.version,
                },
            )),
            None,
        )),
        // We failed to deserialize even though the message version is in the
        // range we understand; something has gone wrong!
        Err(_) => Some((
            SpResponse::Error(SpError::BadRequest(
                BadRequestReason::DeserializationError,
            )),
            None,
        )),
    }
}

fn handle_mgs_response<H: SpHandler>(
    sender: SocketAddrV6,
    port: SpPort,
    message_id: u32,
    handler: &mut H,
    kind: MgsResponse,
    leftover: &[u8],
) {
    match kind {
        MgsResponse::Error(err) => {
            handler.mgs_response_error(sender, port, message_id, err)
        }
        MgsResponse::HostPhase2Data { hash, offset } => handler
            .mgs_response_host_phase2_data(
                sender, port, message_id, hash, offset, leftover,
            ),
    }
}

fn handle_mgs_request<H: SpHandler>(
    sender: SocketAddrV6,
    port: SpPort,
    handler: &mut H,
    kind: MgsRequest,
    leftover: &[u8],
    trailing_tx_buf: &mut [u8],
) -> (SpResponse, Option<OutgoingTrailingData<H>>) {
    // Do we expect any trailing raw data? Only for specific kinds of messages;
    // if we get any for other messages, bail out.
    let trailing_data = match &kind {
        MgsRequest::UpdateChunk(_)
        | MgsRequest::SerialConsoleWrite { .. }
        | MgsRequest::SetIpccKeyLookupValue { .. }
        | MgsRequest::ReadRot(_) => leftover,
        _ => {
            if !leftover.is_empty() {
                return (
                    SpResponse::Error(SpError::BadRequest(
                        BadRequestReason::UnexpectedTrailingData,
                    )),
                    None,
                );
            }
            &[]
        }
    };

    // Call out to handler to provide response.
    //
    // The vast majority of response kinds do not need to pack additional
    // trailing data in, so instead of having our match return `(result,
    // outgoing_trailing_data)`, we'll use a mutable `outgoing_trailing_data`
    // here that defaults to `None`, and only set it to `Some(_)` in the odd arm
    // that needs it.
    let mut outgoing_trailing_data = None;
    let result = match kind {
        MgsRequest::Discover => {
            handler.discover(sender, port).map(SpResponse::Discover)
        }
        MgsRequest::IgnitionState { target } => handler
            .ignition_state(sender, port, target)
            .map(SpResponse::IgnitionState),
        MgsRequest::BulkIgnitionState { offset } => {
            handler.num_ignition_ports().and_then(|port_count| {
                let offset = u32::min(offset, port_count);
                let iter = handler.bulk_ignition_state(sender, port, offset)?;
                outgoing_trailing_data =
                    Some(OutgoingTrailingData::BulkIgnitionState(iter));
                Ok(SpResponse::BulkIgnitionState(TlvPage {
                    offset,
                    total: port_count,
                }))
            })
        }
        MgsRequest::IgnitionLinkEvents { target } => handler
            .ignition_link_events(sender, port, target)
            .map(SpResponse::IgnitionLinkEvents),
        MgsRequest::BulkIgnitionLinkEvents { offset } => {
            handler.num_ignition_ports().and_then(|port_count| {
                let offset = u32::min(offset, port_count);
                let iter =
                    handler.bulk_ignition_link_events(sender, port, offset)?;
                outgoing_trailing_data =
                    Some(OutgoingTrailingData::BulkIgnitionLinkEvents(iter));
                Ok(SpResponse::BulkIgnitionLinkEvents(TlvPage {
                    offset,
                    total: port_count,
                }))
            })
        }
        MgsRequest::ClearIgnitionLinkEvents { target, transceiver_select } => {
            handler
                .clear_ignition_link_events(
                    sender,
                    port,
                    target,
                    transceiver_select,
                )
                .map(|()| SpResponse::ClearIgnitionLinkEventsAck)
        }
        MgsRequest::IgnitionCommand { target, command } => handler
            .ignition_command(sender, port, target, command)
            .map(|()| SpResponse::IgnitionCommandAck),
        MgsRequest::SpState => {
            handler.sp_state(sender, port).map(SpResponse::SpStateV2)
        }
        MgsRequest::SpUpdatePrepare(update) => handler
            .sp_update_prepare(sender, port, update)
            .map(|()| SpResponse::SpUpdatePrepareAck),
        MgsRequest::ComponentUpdatePrepare(update) => handler
            .component_update_prepare(sender, port, update)
            .map(|()| SpResponse::ComponentUpdatePrepareAck),
        MgsRequest::UpdateChunk(chunk) => handler
            .update_chunk(sender, port, chunk, trailing_data)
            .map(|()| SpResponse::UpdateChunkAck),
        MgsRequest::UpdateStatus(component) => handler
            .update_status(sender, port, component)
            .map(SpResponse::UpdateStatus),
        MgsRequest::UpdateAbort { component, id } => handler
            .update_abort(sender, port, component, id)
            .map(|()| SpResponse::UpdateAbortAck),
        MgsRequest::SerialConsoleAttach(component) => handler
            .serial_console_attach(sender, port, component)
            .map(|()| SpResponse::SerialConsoleAttachAck),
        MgsRequest::SerialConsoleWrite { offset } => handler
            .serial_console_write(sender, port, offset, trailing_data)
            .map(|n| SpResponse::SerialConsoleWriteAck {
                furthest_ingested_offset: n,
            }),
        MgsRequest::SerialConsoleDetach => handler
            .serial_console_detach(sender, port)
            .map(|()| SpResponse::SerialConsoleDetachAck),
        MgsRequest::SerialConsoleKeepAlive => handler
            .serial_console_keepalive(sender, port)
            .map(|()| SpResponse::SerialConsoleKeepAliveAck),
        MgsRequest::SerialConsoleBreak => handler
            .serial_console_break(sender, port)
            .map(|()| SpResponse::SerialConsoleBreakAck),
        MgsRequest::GetPowerState => {
            handler.power_state(sender, port).map(SpResponse::PowerState)
        }
        MgsRequest::SetPowerState(power_state) => handler
            .set_power_state(sender, port, power_state)
            .map(|()| SpResponse::SetPowerStateAck),
        MgsRequest::ResetPrepare => handler
            .reset_component_prepare(sender, port, SpComponent::SP_ITSELF)
            .map(|()| SpResponse::ResetPrepareAck),
        MgsRequest::ResetTrigger => handler
            .reset_component_trigger(sender, port, SpComponent::SP_ITSELF)
            .map(|()| SpResponse::ResetComponentTriggerAck),
        MgsRequest::Inventory { device_index } => {
            let total_devices = handler.num_devices(sender, port);
            // If a caller asks for an index past our end, clamp it.
            let device_index = u32::min(device_index, total_devices);
            // We need to pack TLV-encoded device descriptions as our outgoing
            // trailing data.
            outgoing_trailing_data =
                Some(OutgoingTrailingData::DeviceInventory {
                    device_index,
                    total_devices,
                });
            Ok(SpResponse::Inventory(TlvPage {
                offset: device_index,
                total: total_devices,
            }))
        }
        MgsRequest::GetStartupOptions => handler
            .get_startup_options(sender, port)
            .map(SpResponse::StartupOptions),
        MgsRequest::SetStartupOptions(startup_options) => handler
            .set_startup_options(sender, port, startup_options)
            .map(|()| SpResponse::SetStartupOptionsAck),
        MgsRequest::ComponentDetails { component, offset } => handler
            .num_component_details(sender, port, component)
            .map(|total_items| {
                // If a caller asks for an index past our end, clamp it.
                let offset = u32::min(offset, total_items);
                // We need to pack TLV-encoded component details as our
                // outgoing trailing data.
                outgoing_trailing_data =
                    Some(OutgoingTrailingData::ComponentDetails {
                        component,
                        offset,
                        total: total_items,
                    });
                SpResponse::ComponentDetails(TlvPage {
                    offset,
                    total: total_items,
                })
            }),
        MgsRequest::ComponentClearStatus(component) => handler
            .component_clear_status(sender, port, component)
            .map(|()| SpResponse::ComponentClearStatusAck),
        MgsRequest::ComponentGetActiveSlot(component) => handler
            .component_get_active_slot(sender, port, component)
            .map(SpResponse::ComponentActiveSlot),
        MgsRequest::ComponentSetActiveSlot { component, slot } => handler
            .component_set_active_slot(sender, port, component, slot, false)
            .map(|()| SpResponse::ComponentSetActiveSlotAck),
        MgsRequest::ComponentSetAndPersistActiveSlot { component, slot } => {
            handler
                .component_set_active_slot(sender, port, component, slot, true)
                .map(|()| SpResponse::ComponentSetAndPersistActiveSlotAck)
        }
        MgsRequest::SendHostNmi => handler
            .send_host_nmi(sender, port)
            .map(|()| SpResponse::SendHostNmiAck),
        MgsRequest::SetIpccKeyLookupValue { key } => handler
            .set_ipcc_key_lookup_value(sender, port, key, trailing_data)
            .map(|()| SpResponse::SetIpccKeyLookupValueAck),
        MgsRequest::ResetComponentPrepare { component } => handler
            .reset_component_prepare(sender, port, component)
            .map(|()| SpResponse::ResetComponentPrepareAck),
        MgsRequest::ResetComponentTrigger { component } => {
            // Until further implementations are done, only the RoT
            // will be reset with this message. The SP forwards the reset
            // message, and if successful, will get a timeout response.
            // Layers above here will have to verify that the desired effects
            // have been achieved. SP will see that timeout as success in this
            // case, but it could also be a dropped message.
            // In a case where the SP is reset, not some sub-component, there
            // would be no response.
            handler
                .reset_component_trigger(sender, port, component)
                .map(|()| SpResponse::ResetComponentTriggerAck)
        }
        MgsRequest::SwitchDefaultImage { component, slot, duration } => {
            let slot = match slot {
                RotSlotId::A => 0,
                RotSlotId::B => 1,
            };
            let persist = match duration {
                SwitchDuration::Once => false,
                SwitchDuration::Forever => true,
            };
            handler
                .component_set_active_slot(
                    sender, port, component, slot, persist,
                )
                .map(|()| SpResponse::SwitchDefaultImageAck)
        }
        MgsRequest::ComponentAction { component, action } => handler
            .component_action(sender, component, action)
            .map(|()| SpResponse::ComponentActionAck),
        MgsRequest::ReadCaboose { key }
        | MgsRequest::ReadComponentCaboose { key, .. } => {
            let (component, slot) = if let MgsRequest::ReadComponentCaboose {
                component,
                slot,
                ..
            } = kind
            {
                (component, slot)
            } else {
                (SpComponent::SP_ITSELF, 0)
            };
            let r = handler.get_component_caboose_value(
                component,
                slot,
                key,
                trailing_tx_buf,
            );
            if let Ok(n) = r {
                outgoing_trailing_data =
                    Some(OutgoingTrailingData::ShiftFromTail(n));
            }
            r.map(|_| SpResponse::CabooseValue)
        }
        MgsRequest::ReadSensor(req) => {
            handler.read_sensor(req).map(SpResponse::ReadSensor)
        }
        MgsRequest::ReadRot(req) => {
            let r = handler.read_rot(req, trailing_tx_buf);
            if r.is_ok() {
                outgoing_trailing_data =
                    Some(OutgoingTrailingData::ShiftFromTail(ROT_PAGE_SIZE));
            }
            r.map(SpResponse::ReadRot)
        }
        MgsRequest::CurrentTime => {
            handler.current_time().map(SpResponse::CurrentTime)
        }
        MgsRequest::VpdLockState => {
            let r = handler.vpd_lock_status_all(trailing_tx_buf);

            if let Ok(n) = r {
                outgoing_trailing_data =
                    Some(OutgoingTrailingData::ShiftFromTail(n));
            }
            r.map(|_| SpResponse::VpdLockState)
        }
        MgsRequest::VersionedRotBootInfo { version } => {
            let r = handler.versioned_rot_boot_info(sender, port, version);
            r.map(SpResponse::RotBootInfo)
        }
    };

    let response = match result {
        Ok(response) => response,
        Err(err) => SpResponse::Error(err),
    };

    (response, outgoing_trailing_data)
}

enum OutgoingTrailingData<H: SpHandler> {
    DeviceInventory {
        device_index: u32,
        total_devices: u32,
    },
    ComponentDetails {
        component: SpComponent,
        offset: u32,
        total: u32,
    },
    BulkIgnitionState(H::BulkIgnitionStateIter),
    BulkIgnitionLinkEvents(H::BulkIgnitionLinkEventsIter),

    /// Shift some number of bytes from `tx_buf[Message::MAX_SIZE..]`
    ///
    /// This is useful if you want to read bytes into the transmit buffer as
    /// part of message handling, instead of afterwards (e.g. because the read
    /// is fallible but small)
    ShiftFromTail(usize),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SerializedSize;
    use serde::Serialize;

    struct FakeHandler;

    // Only implements `discover()`; all other methods are left as
    // `unimplemented!()` since no tests are intended to call them.
    impl SpHandler for FakeHandler {
        type BulkIgnitionStateIter = std::iter::Empty<IgnitionState>;
        type BulkIgnitionLinkEventsIter = std::iter::Empty<LinkEvents>;

        fn discover(
            &mut self,
            _sender: SocketAddrV6,
            port: SpPort,
        ) -> Result<DiscoverResponse, SpError> {
            Ok(DiscoverResponse { sp_port: port })
        }

        fn num_ignition_ports(&mut self) -> Result<u32, SpError> {
            unimplemented!()
        }

        fn ignition_state(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _target: u8,
        ) -> Result<IgnitionState, SpError> {
            unimplemented!()
        }

        fn bulk_ignition_state(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _offset: u32,
        ) -> Result<Self::BulkIgnitionStateIter, SpError> {
            unimplemented!()
        }

        fn bulk_ignition_link_events(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _offset: u32,
        ) -> Result<Self::BulkIgnitionLinkEventsIter, SpError> {
            unimplemented!()
        }

        fn ignition_link_events(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _target: u8,
        ) -> Result<LinkEvents, SpError> {
            unimplemented!()
        }

        fn clear_ignition_link_events(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _target: Option<u8>,
            _transceiver_select: Option<ignition::TransceiverSelect>,
        ) -> Result<(), SpError> {
            unimplemented!()
        }

        fn ignition_command(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _target: u8,
            _command: IgnitionCommand,
        ) -> Result<(), SpError> {
            unimplemented!()
        }

        fn sp_state(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
        ) -> Result<SpStateV2, SpError> {
            unimplemented!()
        }

        fn sp_update_prepare(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _update: SpUpdatePrepare,
        ) -> Result<(), SpError> {
            unimplemented!()
        }

        fn component_update_prepare(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _update: ComponentUpdatePrepare,
        ) -> Result<(), SpError> {
            unimplemented!()
        }

        fn update_chunk(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _chunk: UpdateChunk,
            _data: &[u8],
        ) -> Result<(), SpError> {
            unimplemented!()
        }

        fn update_status(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _component: SpComponent,
        ) -> Result<UpdateStatus, SpError> {
            unimplemented!()
        }

        fn update_abort(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _component: SpComponent,
            _id: UpdateId,
        ) -> Result<(), SpError> {
            unimplemented!()
        }

        fn power_state(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
        ) -> Result<PowerState, SpError> {
            unimplemented!()
        }

        fn set_power_state(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _power_state: PowerState,
        ) -> Result<(), SpError> {
            unimplemented!()
        }

        fn serial_console_attach(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _component: SpComponent,
        ) -> Result<(), SpError> {
            unimplemented!()
        }

        fn serial_console_write(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _offset: u64,
            _data: &[u8],
        ) -> Result<u64, SpError> {
            unimplemented!()
        }

        fn serial_console_detach(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
        ) -> Result<(), SpError> {
            unimplemented!()
        }

        fn serial_console_keepalive(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
        ) -> Result<(), SpError> {
            unimplemented!()
        }

        fn serial_console_break(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
        ) -> Result<(), SpError> {
            unimplemented!()
        }

        fn num_devices(&mut self, _sender: SocketAddrV6, _port: SpPort) -> u32 {
            unimplemented!()
        }

        fn device_description(
            &mut self,
            _index: BoundsChecked,
        ) -> DeviceDescription<'static> {
            unimplemented!()
        }

        fn num_component_details(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _component: SpComponent,
        ) -> Result<u32, SpError> {
            unimplemented!()
        }

        fn component_details(
            &mut self,
            _component: SpComponent,
            _index: BoundsChecked,
        ) -> ComponentDetails {
            unimplemented!()
        }

        fn component_clear_status(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _component: SpComponent,
        ) -> Result<(), SpError> {
            unimplemented!()
        }

        fn get_startup_options(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
        ) -> Result<StartupOptions, SpError> {
            unimplemented!()
        }

        fn set_startup_options(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _startup_options: StartupOptions,
        ) -> Result<(), SpError> {
            unimplemented!()
        }

        fn mgs_response_error(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _message_id: u32,
            _err: MgsError,
        ) {
            unimplemented!()
        }

        fn mgs_response_host_phase2_data(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _message_id: u32,
            _hash: [u8; 32],
            _offset: u64,
            _data: &[u8],
        ) {
            unimplemented!()
        }

        fn component_get_active_slot(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _component: SpComponent,
        ) -> Result<u16, SpError> {
            unimplemented!()
        }

        fn component_set_active_slot(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _component: SpComponent,
            _slot: u16,
            _persist: bool,
        ) -> Result<(), SpError> {
            unimplemented!()
        }

        fn component_action(
            &mut self,
            _sender: SocketAddrV6,
            _component: SpComponent,
            _action: ComponentAction,
        ) -> Result<(), SpError> {
            unimplemented!()
        }

        fn send_host_nmi(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
        ) -> Result<(), SpError> {
            unimplemented!()
        }

        fn set_ipcc_key_lookup_value(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _key: u8,
            _value: &[u8],
        ) -> Result<(), SpError> {
            unimplemented!()
        }

        fn reset_component_prepare(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _component: SpComponent,
        ) -> Result<(), SpError> {
            unimplemented!()
        }

        fn reset_component_trigger(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _component: SpComponent,
        ) -> Result<(), SpError> {
            unimplemented!()
        }

        fn get_component_caboose_value(
            &mut self,
            _component: SpComponent,
            _slot: u16,
            _key: [u8; 4],
            _buf: &mut [u8],
        ) -> Result<usize, SpError> {
            unimplemented!()
        }

        fn read_sensor(
            &mut self,
            _r: SensorRequest,
        ) -> Result<SensorResponse, SpError> {
            unimplemented!()
        }

        fn read_rot(
            &mut self,
            _r: RotRequest,
            _buf: &mut [u8],
        ) -> Result<RotResponse, SpError> {
            unimplemented!()
        }

        fn current_time(&mut self) -> Result<u64, SpError> {
            unimplemented!()
        }

        fn vpd_lock_status_all(
            &mut self,
            _buf: &mut [u8],
        ) -> Result<usize, SpError> {
            unimplemented!()
        }

        fn versioned_rot_boot_info(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _version: u8,
        ) -> Result<RotBootInfo, SpError> {
            unimplemented!()
        }
    }

    #[cfg(feature = "std")]
    fn any_socket_addr_v6() -> SocketAddrV6 {
        "[::1]:123".parse().unwrap()
    }

    #[cfg(not(feature = "std"))]
    fn any_socket_addr_v6() -> SocketAddrV6 {
        SocketAddrV6 { ip: smoltcp::wire::Ipv6Address::LOOPBACK, port: 123 }
    }

    fn call_handle_message<Msg>(msg: Msg) -> Message
    where
        Msg: Serialize + SerializedSize,
    {
        let mut req_buf = vec![0; Msg::MAX_SIZE];
        let m = crate::serialize(&mut req_buf, &msg).unwrap();

        let mut buf = [0; crate::MAX_SERIALIZED_SIZE];
        let n = handle_message(
            any_socket_addr_v6(),
            SpPort::One,
            &req_buf[..m],
            &mut FakeHandler,
            &mut buf,
        )
        .unwrap();

        let (resp, _) = crate::deserialize::<Message>(&buf[..n]).unwrap();
        resp
    }

    // Smoke test that a valid request returns an `Ok(_)` response.
    #[test]
    fn handle_valid_request() {
        let req = Message {
            header: Header {
                version: version::CURRENT,
                message_id: 0x01020304,
            },
            kind: MessageKind::MgsRequest(MgsRequest::Discover),
        };

        let resp = call_handle_message(req);

        assert_eq!(
            resp,
            Message {
                header: Header {
                    version: version::CURRENT,
                    message_id: req.header.message_id,
                },
                kind: MessageKind::SpResponse(SpResponse::Discover(
                    DiscoverResponse { sp_port: SpPort::One }
                ))
            }
        );
    }

    #[test]
    fn version_too_low() {
        let req = Message {
            header: Header { version: 1, message_id: 0x01020304 },
            kind: MessageKind::MgsRequest(MgsRequest::Discover),
        };

        let resp = call_handle_message(req);

        assert_eq!(
            resp,
            Message {
                header: Header {
                    version: version::CURRENT,
                    message_id: 0x01020304,
                },
                kind: MessageKind::SpResponse(SpResponse::Error(
                    SpError::BadRequest(BadRequestReason::WrongVersion {
                        sp: version::CURRENT,
                        request: 1,
                    })
                )),
            }
        );
    }

    #[test]
    fn bad_request_header() {
        // Valid request...
        let req = Message {
            header: Header {
                version: version::CURRENT,
                message_id: 0x01020304,
            },
            kind: MessageKind::MgsRequest(MgsRequest::Discover),
        };
        let mut req_buf = vec![0; Message::MAX_SIZE];
        let _ = crate::serialize(&mut req_buf, &req).unwrap();

        let mut buf = [0; crate::MAX_SERIALIZED_SIZE];

        // ... but only the first 3 bytes (incomplete version field)
        let n = handle_message(
            any_socket_addr_v6(),
            SpPort::One,
            &req_buf[..3],
            &mut FakeHandler,
            &mut buf,
        )
        .unwrap();
        let (resp1, _) = crate::deserialize::<Message>(&buf[..n]).unwrap();

        // ... or only the first 7 bytes (incomplete request ID field)
        let n = handle_message(
            any_socket_addr_v6(),
            SpPort::One,
            &req_buf[..7],
            &mut FakeHandler,
            &mut buf,
        )
        .unwrap();
        let (resp2, _) = crate::deserialize::<Message>(&buf[..n]).unwrap();

        assert_eq!(resp1, resp2);
        assert_eq!(
            resp1,
            Message {
                header: Header {
                    version: version::CURRENT,
                    // Header is incomplete, so we don't know the request ID.
                    message_id: 0xffff_ffff,
                },
                kind: MessageKind::SpResponse(SpResponse::Error(
                    SpError::BadRequest(BadRequestReason::DeserializationError)
                )),
            }
        );
    }

    #[test]
    fn bad_request_kind() {
        #[derive(SerializedSize, Serialize)]
        struct FakeRequest {
            version: u32,
            message_id: u32,
            kind: u8,
        }

        let req = FakeRequest {
            version: version::CURRENT,
            message_id: 0x01020304,
            // Hubpack encodes the real `MessageKind` enum using an initial byte
            // to identify the variant; send a byte that is past the end of our
            // enum (assuming we never have 256 cases).
            kind: 0xff,
        };

        let resp = call_handle_message(req);

        assert_eq!(
            resp,
            Message {
                header: Header {
                    version: version::CURRENT,
                    message_id: 0x01020304
                },
                kind: MessageKind::SpResponse(SpResponse::Error(
                    SpError::BadRequest(BadRequestReason::DeserializationError)
                ))
            }
        );
    }
}
