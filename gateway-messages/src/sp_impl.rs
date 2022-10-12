// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Behavior implemented by both real and simulated SPs.

use crate::tlv;
use crate::version;
use crate::BadRequestReason;
use crate::BulkIgnitionState;
use crate::ComponentUpdatePrepare;
use crate::DeviceInventoryPage;
use crate::DevicePresence;
use crate::DiscoverResponse;
use crate::IgnitionCommand;
use crate::IgnitionState;
use crate::PowerState;
use crate::RequestHeader;
use crate::RequestKind;
use crate::ResponseError;
use crate::ResponseKind;
use crate::SerializedSize;
use crate::SpComponent;
use crate::SpMessage;
use crate::SpMessageKind;
use crate::SpPort;
use crate::SpState;
use crate::SpUpdatePrepare;
use crate::UpdateChunk;
use crate::UpdateId;
use crate::UpdateStatus;
use core::convert::Infallible;
use core::mem;

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
    pub device: &'a str,
    pub description: &'a str,
    pub num_measurement_channels: u32,
    pub presence: DevicePresence,
}

impl From<DeviceDescription<'_>> for crate::DeviceDescription {
    fn from(dev: DeviceDescription<'_>) -> Self {
        Self {
            device_len: dev.device.len() as u32,
            description_len: dev.description.len() as u32,
            num_measurement_channels: dev.num_measurement_channels,
            presence: dev.presence,
        }
    }
}

pub trait SpHandler {
    fn discover(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
    ) -> Result<DiscoverResponse, ResponseError>;

    fn ignition_state(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        target: u8,
    ) -> Result<IgnitionState, ResponseError>;

    fn bulk_ignition_state(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
    ) -> Result<BulkIgnitionState, ResponseError>;

    fn ignition_command(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        target: u8,
        command: IgnitionCommand,
    ) -> Result<(), ResponseError>;

    fn sp_state(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
    ) -> Result<SpState, ResponseError>;

    fn sp_update_prepare(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        update: SpUpdatePrepare,
    ) -> Result<(), ResponseError>;

    fn component_update_prepare(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        update: ComponentUpdatePrepare,
    ) -> Result<(), ResponseError>;

    fn update_chunk(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        chunk: UpdateChunk,
        data: &[u8],
    ) -> Result<(), ResponseError>;

    fn update_status(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        component: SpComponent,
    ) -> Result<UpdateStatus, ResponseError>;

    fn update_abort(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        component: SpComponent,
        id: UpdateId,
    ) -> Result<(), ResponseError>;

    fn power_state(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
    ) -> Result<PowerState, ResponseError>;

    fn set_power_state(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        power_state: PowerState,
    ) -> Result<(), ResponseError>;

    fn serial_console_attach(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        component: SpComponent,
    ) -> Result<(), ResponseError>;

    /// The returned u64 should be the offset we want to receive in the next
    /// call to `serial_console_write()`; i.e., the furthest offset we've
    /// ingested (either by writing to the console or by buffering to write it).
    fn serial_console_write(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
        offset: u64,
        data: &[u8],
    ) -> Result<u64, ResponseError>;

    fn serial_console_detach(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
    ) -> Result<(), ResponseError>;

    fn reset_prepare(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
    ) -> Result<(), ResponseError>;

    // On success, this method cannot return (it should perform a reset).
    fn reset_trigger(
        &mut self,
        sender: SocketAddrV6,
        port: SpPort,
    ) -> Result<Infallible, ResponseError>;

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
}

/// Unpack the 2-byte length-prefixed trailing data that comes after some
/// packets (e.g., update chunks, serial console).
pub fn unpack_trailing_data(data: &[u8]) -> hubpack::error::Result<&[u8]> {
    if data.len() < mem::size_of::<u16>() {
        return Err(hubpack::error::Error::Truncated);
    }
    let (prefix, data) = data.split_at(mem::size_of::<u16>());
    let len = u16::from_le_bytes([prefix[0], prefix[1]]);
    if data.len() != usize::from(len) {
        return Err(hubpack::error::Error::Invalid);
    }
    Ok(data)
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
    let (request_id, result) = read_request_header(data);

    // If we were able to peel off the header, chain the rest of the data
    // then chain the rest of the data
    // through to the handler.
    let (result, outgoing_trailing_data) = match result {
        Ok(request_kind_data) => {
            handle_message_impl(sender, port, request_kind_data, handler)
        }
        Err(err) => (Err(err), None),
    };

    // We control `SpMessage` and know all cases can successfully serialize
    // into `self.buf`.
    let response = SpMessage {
        version: version::V1,
        kind: SpMessageKind::Response { request_id, result },
    };

    // We know `response` is well-formed and fits into `out` (since it's
    // statically sized for `SpMessage`), so we can unwrap serialization.
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
    use crate::DeviceDescription as DeviceDescriptionHeader;

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
            // We checked the length above; this error isn't possible.
            Err(tlv::EncodeError::BufferTooSmall) => panic!(),
            Err(tlv::EncodeError::Custom(infallible)) => match infallible {},
        }

        device_index += 1;
    }

    total_tlv_len
}

/// Read the request header from the front of `data`, returning the request ID
/// we should use in our response (pulled from the header if possible, or a
/// sentinel if not) and either the remainder of the request data or an error.
fn read_request_header(data: &[u8]) -> (u32, Result<&[u8], ResponseError>) {
    let (header, request_kind_data) =
        match hubpack::deserialize::<RequestHeader>(data) {
            Ok((header, request_kind_data)) => (header, request_kind_data),
            Err(_) => {
                return (
                    // We don't know the request ID, but need to reply with
                    // something - fill in 0xffff_ffff.
                    u32::MAX,
                    Err(ResponseError::BadRequest(
                        BadRequestReason::DeserializationError,
                    )),
                );
            }
        };

    // Check the message version.
    let result = if header.version == version::V1 {
        Ok(request_kind_data)
    } else {
        Err(ResponseError::BadRequest(BadRequestReason::WrongVersion {
            sp: version::V1,
            request: header.version,
        }))
    };

    (header.request_id, result)
}

/// Parses the remainder of a request (after `version` and `request_id`, which
/// are handled by `read_request_header`) and calls `handler`.
///
/// If the response kind needs to generate trailing data, returns `(Ok(_),
/// Some(_)`, and our caller is resposnible for handling that generation.
/// Otherwise, returns `(result, None)`.
fn handle_message_impl<H: SpHandler>(
    sender: SocketAddrV6,
    port: SpPort,
    request_kind_data: &[u8],
    handler: &mut H,
) -> (Result<ResponseKind, ResponseError>, Option<OutgoingTrailingData>) {
    let (kind, leftover) =
        match hubpack::deserialize::<RequestKind>(request_kind_data) {
            Ok((kind, leftover)) => (kind, leftover),
            Err(_) => {
                return (
                    Err(ResponseError::BadRequest(
                        BadRequestReason::DeserializationError,
                    )),
                    None,
                );
            }
        };

    // Do we expect any trailing raw data? Only for specific kinds of messages;
    // if we get any for other messages, bail out.
    let trailing_data = match &kind {
        RequestKind::UpdateChunk(_)
        | RequestKind::SerialConsoleWrite { .. } => {
            match unpack_trailing_data(leftover) {
                Ok(trailing_data) => trailing_data,
                Err(_) => {
                    return (
                        Err(ResponseError::BadRequest(
                            BadRequestReason::DeserializationError,
                        )),
                        None,
                    );
                }
            }
        }
        _ => {
            if !leftover.is_empty() {
                return (
                    Err(ResponseError::BadRequest(
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
        RequestKind::Discover => {
            handler.discover(sender, port).map(ResponseKind::Discover)
        }
        RequestKind::IgnitionState { target } => handler
            .ignition_state(sender, port, target)
            .map(ResponseKind::IgnitionState),
        RequestKind::BulkIgnitionState => handler
            .bulk_ignition_state(sender, port)
            .map(ResponseKind::BulkIgnitionState),
        RequestKind::IgnitionCommand { target, command } => handler
            .ignition_command(sender, port, target, command)
            .map(|()| ResponseKind::IgnitionCommandAck),
        RequestKind::SpState => {
            handler.sp_state(sender, port).map(ResponseKind::SpState)
        }
        RequestKind::SpUpdatePrepare(update) => handler
            .sp_update_prepare(sender, port, update)
            .map(|()| ResponseKind::SpUpdatePrepareAck),
        RequestKind::ComponentUpdatePrepare(update) => handler
            .component_update_prepare(sender, port, update)
            .map(|()| ResponseKind::ComponentUpdatePrepareAck),
        RequestKind::UpdateChunk(chunk) => handler
            .update_chunk(sender, port, chunk, trailing_data)
            .map(|()| ResponseKind::UpdateChunkAck),
        RequestKind::UpdateStatus(component) => handler
            .update_status(sender, port, component)
            .map(ResponseKind::UpdateStatus),
        RequestKind::UpdateAbort { component, id } => handler
            .update_abort(sender, port, component, id)
            .map(|()| ResponseKind::UpdateAbortAck),
        RequestKind::SerialConsoleAttach(component) => handler
            .serial_console_attach(sender, port, component)
            .map(|()| ResponseKind::SerialConsoleAttachAck),
        RequestKind::SerialConsoleWrite { offset } => handler
            .serial_console_write(sender, port, offset, trailing_data)
            .map(|n| ResponseKind::SerialConsoleWriteAck {
                furthest_ingested_offset: n,
            }),
        RequestKind::SerialConsoleDetach => handler
            .serial_console_detach(sender, port)
            .map(|()| ResponseKind::SerialConsoleDetachAck),
        RequestKind::GetPowerState => {
            handler.power_state(sender, port).map(ResponseKind::PowerState)
        }
        RequestKind::SetPowerState(power_state) => handler
            .set_power_state(sender, port, power_state)
            .map(|()| ResponseKind::SetPowerStateAck),
        RequestKind::ResetPrepare => handler
            .reset_prepare(sender, port)
            .map(|()| ResponseKind::ResetPrepareAck),
        RequestKind::ResetTrigger => {
            handler.reset_trigger(sender, port).map(|infallible| {
                // A bit of type system magic here; `reset_trigger`'s
                // success type (`Infallible`) cannot be instantiated. We can
                // provide an empty match to teach the type system that an
                // `Infallible` (which can't exist) can be converted to a
                // `ResponseKind` (or any other type!).
                match infallible {}
            })
        }
        RequestKind::Inventory { device_index } => {
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
            Ok(ResponseKind::Inventory(DeviceInventoryPage {
                device_index,
                total_devices,
            }))
        }
    };

    (result, outgoing_trailing_data)
}

enum OutgoingTrailingData {
    DeviceInventory { device_index: u32, total_devices: u32 },
}

#[cfg(test)]
mod tests {
    use serde::Serialize;

    use super::*;
    use crate::Request;
    use crate::SerializedSize;

    struct FakeHandler;

    // Only implements `discover()`.
    impl SpHandler for FakeHandler {
        fn discover(
            &mut self,
            _sender: SocketAddrV6,
            port: SpPort,
        ) -> Result<DiscoverResponse, ResponseError> {
            Ok(DiscoverResponse { sp_port: port })
        }

        fn ignition_state(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _target: u8,
        ) -> Result<IgnitionState, ResponseError> {
            todo!()
        }

        fn bulk_ignition_state(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
        ) -> Result<BulkIgnitionState, ResponseError> {
            todo!()
        }

        fn ignition_command(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _target: u8,
            _command: IgnitionCommand,
        ) -> Result<(), ResponseError> {
            todo!()
        }

        fn sp_state(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
        ) -> Result<SpState, ResponseError> {
            todo!()
        }

        fn sp_update_prepare(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _update: SpUpdatePrepare,
        ) -> Result<(), ResponseError> {
            todo!()
        }

        fn component_update_prepare(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _update: ComponentUpdatePrepare,
        ) -> Result<(), ResponseError> {
            todo!()
        }

        fn update_chunk(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _chunk: UpdateChunk,
            _data: &[u8],
        ) -> Result<(), ResponseError> {
            todo!()
        }

        fn update_status(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _component: SpComponent,
        ) -> Result<UpdateStatus, ResponseError> {
            todo!()
        }

        fn update_abort(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _component: SpComponent,
            _id: UpdateId,
        ) -> Result<(), ResponseError> {
            todo!()
        }

        fn power_state(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
        ) -> Result<PowerState, ResponseError> {
            todo!()
        }

        fn set_power_state(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _power_state: PowerState,
        ) -> Result<(), ResponseError> {
            todo!()
        }

        fn serial_console_attach(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _component: SpComponent,
        ) -> Result<(), ResponseError> {
            todo!()
        }

        fn serial_console_write(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
            _offset: u64,
            _data: &[u8],
        ) -> Result<u64, ResponseError> {
            todo!()
        }

        fn serial_console_detach(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
        ) -> Result<(), ResponseError> {
            todo!()
        }

        fn reset_prepare(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
        ) -> Result<(), ResponseError> {
            todo!()
        }

        fn reset_trigger(
            &mut self,
            _sender: SocketAddrV6,
            _port: SpPort,
        ) -> Result<Infallible, ResponseError> {
            todo!()
        }

        fn num_devices(&mut self, _sender: SocketAddrV6, _port: SpPort) -> u32 {
            todo!()
        }

        fn device_description(&mut self, _index: u32) -> DeviceDescription<'_> {
            todo!()
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

    fn call_handle_message<Req>(req: Req) -> SpMessage
    where
        Req: Serialize + SerializedSize,
    {
        let mut req_buf = vec![0; Req::MAX_SIZE];
        let m = crate::serialize(&mut req_buf, &req).unwrap();

        let mut buf = [0; crate::MAX_SERIALIZED_SIZE];
        let n = handle_message(
            any_socket_addr_v6(),
            SpPort::One,
            &req_buf[..m],
            &mut FakeHandler,
            &mut buf,
        );

        let (resp, _) = crate::deserialize::<SpMessage>(&buf[..n]).unwrap();
        resp
    }

    // Smoke test that a valid request returns an `Ok(_)` response.
    #[test]
    fn handle_valid_request() {
        let req = Request {
            header: RequestHeader {
                version: version::V1,
                request_id: 0x01020304,
            },
            kind: RequestKind::Discover,
        };

        let resp = call_handle_message(req);

        assert_eq!(
            resp,
            SpMessage {
                version: version::V1,
                kind: SpMessageKind::Response {
                    request_id: req.header.request_id,
                    result: Ok(ResponseKind::Discover(DiscoverResponse {
                        sp_port: SpPort::One
                    }))
                }
            }
        );
    }

    #[test]
    fn bad_version() {
        let req = Request {
            header: RequestHeader {
                version: 0x0badf00d,
                request_id: 0x01020304,
            },
            kind: RequestKind::Discover,
        };

        let resp = call_handle_message(req);

        assert_eq!(
            resp,
            SpMessage {
                version: version::V1,
                kind: SpMessageKind::Response {
                    request_id: 0x01020304,
                    result: Err(ResponseError::BadRequest(
                        BadRequestReason::WrongVersion {
                            sp: version::V1,
                            request: 0x0badf00d
                        }
                    )),
                }
            }
        );
    }

    #[test]
    fn bad_request_header() {
        // Valid request...
        let req = Request {
            header: RequestHeader {
                version: version::V1,
                request_id: 0x01020304,
            },
            kind: RequestKind::Discover,
        };
        let mut req_buf = vec![0; Request::MAX_SIZE];
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
        let (resp1, _) = crate::deserialize::<SpMessage>(&buf[..n]).unwrap();

        // ... or only the first 7 bytes (incomplete request ID field)
        let n = handle_message(
            any_socket_addr_v6(),
            SpPort::One,
            &req_buf[..7],
            &mut FakeHandler,
            &mut buf,
        );
        let (resp2, _) = crate::deserialize::<SpMessage>(&buf[..n]).unwrap();

        assert_eq!(resp1, resp2);
        assert_eq!(
            resp1,
            SpMessage {
                version: version::V1,
                kind: SpMessageKind::Response {
                    // Header is incomplete, so we don't know the request ID.
                    request_id: 0xffff_ffff,
                    result: Err(ResponseError::BadRequest(
                        BadRequestReason::DeserializationError
                    )),
                }
            }
        );
    }

    #[test]
    fn bad_request_kind() {
        #[derive(SerializedSize, Serialize)]
        struct FakeRequest {
            version: u32,
            request_id: u32,
            kind: u8,
        }

        let req = FakeRequest {
            version: version::V1,
            request_id: 0x01020304,
            // Hubpack encodes the real `RequestKind` enum using an initial byte
            // to identify the variant; send a byte that is past the end of our
            // enum (assuming we never have 256 cases).
            kind: 0xff,
        };

        let resp = call_handle_message(req);

        assert_eq!(
            resp,
            SpMessage {
                version: version::V1,
                kind: SpMessageKind::Response {
                    request_id: 0x01020304,
                    result: Err(ResponseError::BadRequest(
                        BadRequestReason::DeserializationError
                    )),
                }
            }
        );
    }
}
