// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Behavior implemented by both real and simulated SPs.

use crate::tlv;
use crate::version;
use crate::BadRequestReason;
use crate::BulkIgnitionState;
use crate::ComponentUpdatePrepare;
use crate::DeviceCapabilities;
use crate::DeviceDescriptionHeader;
use crate::DeviceInventoryPage;
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
use crate::SerializedSize;
use crate::SpComponent;
use crate::SpError;
use crate::SpPort;
use crate::SpResponse;
use crate::SpState;
use crate::SpUpdatePrepare;
use crate::UpdateChunk;
use crate::UpdateId;
use crate::UpdateStatus;
use core::convert::Infallible;

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

pub trait SpHandler {
    fn discover(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
    ) -> Result<DiscoverResponse, SpError>;

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
    ) -> Result<BulkIgnitionState, SpError>;

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
    ) -> Result<SpState, SpError>;

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

    fn reset_prepare(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
    ) -> Result<(), SpError>;

    // On success, this method cannot return (it should perform a reset).
    fn reset_trigger(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
    ) -> Result<Infallible, SpError>;

    /// Number of devices returned in the inventory of this SP.
    fn num_devices(&mut self, sender: SocketAddrV6, port: SpPort) -> u32;

    /// Get the description for the given device.
    ///
    /// This function should never fail, as the device inventory should be
    /// static. Acquiring the presence of a device may fail, but that should be
    /// indicated inline via the returned description's `presence` field.
    ///
    /// # Panics
    ///
    /// Implementors are allowed to panic if `index` is not in range (i.e., is
    /// greater than or equal to the value returned by `num_devices()`).
    fn device_description(&mut self, index: u32) -> DeviceDescription<'_>;

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
}

/// Handle a single incoming message.
///
/// The incoming message is described by `sender` (the remote address of the
/// sender), `port` (the local port the message arived on), and `data` (the raw
/// message). It will be deserialized, and the appropriate method will be called
/// on `handler` to craft a response. The response will then be serialized into
/// `out`, and returned `Ok(n)` value specifies length of the serialized
/// response.
pub fn handle_message<H: SpHandler>(
    sender: SocketAddrV6,
    port: SpPort,
    data: &[u8],
    handler: &mut H,
    out: &mut [u8; crate::MAX_SERIALIZED_SIZE],
) -> usize {
    // Try to peel the header off first, allowing us to check the version and
    // get the request ID (even if we fail to parse the rest of the request).
    let (message_id, result) = read_request_header(data);

    // If we were able to peel off the header, chain the rest of the data
    // then chain the rest of the data through to the handler.
    let maybe_response = match result {
        Ok(request_kind_data) => handle_message_impl(
            sender,
            port,
            message_id,
            request_kind_data,
            handler,
        ),
        Err(err) => Some((SpResponse::Error(err), None)),
    };

    let (response, outgoing_trailing_data) = match maybe_response {
        Some((response, outgoing_trailing_data)) => {
            (response, outgoing_trailing_data)
        }
        None => return 0,
    };

    let response = Message {
        header: Header { version: version::V2, message_id },
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
        }) => encode_device_inventory(
            &mut out[n..],
            device_index,
            total_devices,
            handler,
        ),
        None => 0,
    };

    n
}

/// Pack as many device description TLV triples as we can into `out`, starting
/// at `device_index`.
fn encode_device_inventory<H: SpHandler>(
    mut out: &mut [u8],
    mut device_index: u32,
    total_devices: u32,
    handler: &mut H,
) -> usize {
    let mut total_tlv_len = 0;
    while device_index < total_devices {
        let dev = handler.device_description(device_index);

        // Will the serialized description of this device fit in `out`?
        let len = tlv::tlv_len(
            DeviceDescriptionHeader::MAX_SIZE
                + dev.device.len()
                + dev.description.len(),
        );
        if len > out.len() {
            break;
        }

        // It will fit: serialize and encode it.
        match tlv::encode::<_, Infallible>(
            out,
            DeviceDescriptionHeader::TAG,
            |buf| {
                let header = DeviceDescriptionHeader::from(dev);
                // We know our buffer is large enough from our length check
                // above, so this serialization can't fail.
                let mut n = hubpack::serialize(buf, &header).unwrap();

                // Pack in the device and description
                for s in [dev.device, dev.description] {
                    buf[n..][..s.len()].copy_from_slice(s.as_bytes());
                    n += s.len();
                }

                Ok(n)
            },
        ) {
            Ok(n) => {
                total_tlv_len += n;
                out = &mut out[n..];
            }
            Err(tlv::EncodeError::Custom(infallible)) => {
                // A bit of type system magic here; our custom error type
                // (`Infallible`) cannot be instantiated. We can
                // provide an empty match to teach the type system that an
                // `Infallible` (which can't exist) can this branch is
                // unreachable without needing to explicitly panic.
                match infallible {}
            }
            // We checked the length above; this error isn't possible.
            Err(tlv::EncodeError::BufferTooSmall) => panic!(),
        }

        device_index += 1;
    }

    total_tlv_len
}

/// Read the request header from the front of `data`, returning the message ID
/// we should use in our response (pulled from the header if possible, or a
/// sentinel if not) and either the remainder of the request data or an error.
fn read_request_header(data: &[u8]) -> (u32, Result<&[u8], SpError>) {
    let (header, request_kind_data) = match hubpack::deserialize::<Header>(data)
    {
        Ok((header, request_kind_data)) => (header, request_kind_data),
        Err(_) => {
            return (
                // We don't know the request ID, but need to reply with
                // something - fill in 0xffff_ffff.
                u32::MAX,
                Err(SpError::BadRequest(
                    BadRequestReason::DeserializationError,
                )),
            );
        }
    };

    // Check the message version.
    let result = if header.version == version::V2 {
        Ok(request_kind_data)
    } else {
        Err(SpError::BadRequest(BadRequestReason::WrongVersion {
            sp: version::V2,
            request: header.version,
        }))
    };

    (header.message_id, result)
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
    message_id: u32,
    request_kind_data: &[u8],
    handler: &mut H,
) -> Option<(SpResponse, Option<OutgoingTrailingData>)> {
    match hubpack::deserialize::<MessageKind>(request_kind_data) {
        Ok((MessageKind::MgsRequest(kind), leftover)) => {
            Some(handle_mgs_request(sender, port, handler, kind, leftover))
        }
        Ok((MessageKind::MgsResponse(kind), leftover)) => {
            handle_mgs_response(
                sender, port, message_id, handler, kind, leftover,
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
) -> (SpResponse, Option<OutgoingTrailingData>) {
    // Do we expect any trailing raw data? Only for specific kinds of messages;
    // if we get any for other messages, bail out.
    let trailing_data = match &kind {
        MgsRequest::UpdateChunk(_) | MgsRequest::SerialConsoleWrite { .. } => {
            leftover
        }
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
        MgsRequest::BulkIgnitionState => handler
            .bulk_ignition_state(sender, port)
            .map(SpResponse::BulkIgnitionState),
        MgsRequest::IgnitionCommand { target, command } => handler
            .ignition_command(sender, port, target, command)
            .map(|()| SpResponse::IgnitionCommandAck),
        MgsRequest::SpState => {
            handler.sp_state(sender, port).map(SpResponse::SpState)
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
        MgsRequest::GetPowerState => {
            handler.power_state(sender, port).map(SpResponse::PowerState)
        }
        MgsRequest::SetPowerState(power_state) => handler
            .set_power_state(sender, port, power_state)
            .map(|()| SpResponse::SetPowerStateAck),
        MgsRequest::ResetPrepare => handler
            .reset_prepare(sender, port)
            .map(|()| SpResponse::ResetPrepareAck),
        MgsRequest::ResetTrigger => {
            handler.reset_trigger(sender, port).map(|infallible| {
                // A bit of type system magic here; `reset_trigger`'s
                // success type (`Infallible`) cannot be instantiated. We can
                // provide an empty match to teach the type system that an
                // `Infallible` (which can't exist) can be converted to a
                // `SpResponse` (or any other type!).
                match infallible {}
            })
        }
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
            Ok(SpResponse::Inventory(DeviceInventoryPage {
                device_index,
                total_devices,
            }))
        }
    };

    let response = match result {
        Ok(response) => response,
        Err(err) => SpResponse::Error(err),
    };

    (response, outgoing_trailing_data)
}

enum OutgoingTrailingData {
    DeviceInventory { device_index: u32, total_devices: u32 },
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
        fn discover(
            &mut self,
            _sender: SocketAddrV6,
            port: SpPort,
        ) -> Result<DiscoverResponse, SpError> {
            Ok(DiscoverResponse { sp_port: port })
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
        ) -> Result<BulkIgnitionState, SpError> {
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
        ) -> Result<SpState, SpError> {
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

        fn reset_prepare(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
        ) -> Result<(), SpError> {
            unimplemented!()
        }

        fn reset_trigger(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
        ) -> Result<Infallible, SpError> {
            unimplemented!()
        }

        fn num_devices(&mut self, _sender: SocketAddrV6, _port: SpPort) -> u32 {
            unimplemented!()
        }

        fn device_description(&mut self, _index: u32) -> DeviceDescription<'_> {
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
        );

        let (resp, _) = crate::deserialize::<Message>(&buf[..n]).unwrap();
        resp
    }

    // Smoke test that a valid request returns an `Ok(_)` response.
    #[test]
    fn handle_valid_request() {
        let req = Message {
            header: Header { version: version::V2, message_id: 0x01020304 },
            kind: MessageKind::MgsRequest(MgsRequest::Discover),
        };

        let resp = call_handle_message(req);

        assert_eq!(
            resp,
            Message {
                header: Header {
                    version: version::V2,
                    message_id: req.header.message_id,
                },
                kind: MessageKind::SpResponse(SpResponse::Discover(
                    DiscoverResponse { sp_port: SpPort::One }
                ))
            }
        );
    }

    #[test]
    fn bad_version() {
        let req = Message {
            header: Header { version: 0x0badf00d, message_id: 0x01020304 },
            kind: MessageKind::MgsRequest(MgsRequest::Discover),
        };

        let resp = call_handle_message(req);

        assert_eq!(
            resp,
            Message {
                header: Header { version: version::V2, message_id: 0x01020304 },
                kind: MessageKind::SpResponse(SpResponse::Error(
                    SpError::BadRequest(BadRequestReason::WrongVersion {
                        sp: version::V2,
                        request: 0x0badf00d
                    })
                )),
            }
        );
    }

    #[test]
    fn bad_request_header() {
        // Valid request...
        let req = Message {
            header: Header { version: version::V2, message_id: 0x01020304 },
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
        );
        let (resp1, _) = crate::deserialize::<Message>(&buf[..n]).unwrap();

        // ... or only the first 7 bytes (incomplete request ID field)
        let n = handle_message(
            any_socket_addr_v6(),
            SpPort::One,
            &req_buf[..7],
            &mut FakeHandler,
            &mut buf,
        );
        let (resp2, _) = crate::deserialize::<Message>(&buf[..n]).unwrap();

        assert_eq!(resp1, resp2);
        assert_eq!(
            resp1,
            Message {
                header: Header {
                    version: version::V2,
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
            version: version::V2,
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
                header: Header { version: version::V2, message_id: 0x01020304 },
                kind: MessageKind::SpResponse(SpResponse::Error(
                    SpError::BadRequest(BadRequestReason::DeserializationError)
                ))
            }
        );
    }
}
