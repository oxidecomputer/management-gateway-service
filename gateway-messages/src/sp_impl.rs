// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Behavior implemented by both real and simulated SPs.

use crate::version;
use crate::BadRequestReason;
use crate::BulkIgnitionState;
use crate::ComponentUpdatePrepare;
use crate::DiscoverResponse;
use crate::IgnitionCommand;
use crate::IgnitionState;
use crate::PowerState;
use crate::RequestKind;
use crate::ResponseError;
use crate::ResponseKind;
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
    // If we can't read the request ID, we have to fill in _something_ in our
    // response. We'll use 0xffff_ffff.
    let mut request_id = u32::MAX;
    let result = read_request_header(data, &mut request_id).and_then(
        |request_kind_data| {
            handle_message_impl(sender, port, request_kind_data, handler)
        },
    );

    // We control `SpMessage` and know all cases can successfully serialize
    // into `self.buf`.
    let response = SpMessage {
        version: version::V1,
        kind: SpMessageKind::Response { request_id, result },
    };

    // We know `response` is well-formed and fits into `out` (since it's
    // statically sized for `SpMessage`), so we can unwrap serialization.
    match hubpack::serialize(&mut out[..], &response) {
        Ok(n) => n,
        Err(_) => panic!(),
    }
}

/// Read the version and request_id from the front of `data`.
///
/// Our API is slightly unidiomatic here: we take a `&mut u32` that we fill in
/// with the request ID instead of returning it because we may be able to
/// determine the request_id even in the error case.
///
/// If `data.len() >= 8`, interprets the first 4 bytes as the request version
/// and the subsequent bytes as the request ID, filling in `*request_id`. If the
/// version is compatible, returns `Ok(rest_of_data)`. If the version is
/// incompatible, returns `Err(reason)`.
///
/// If `data.len() < 8`, returns `Err(reason)` without modifying `*request_id`,
/// as there isn't enough data to know what it should be.
fn read_request_header<'a>(
    data: &'a [u8],
    request_id: &mut u32,
) -> Result<&'a [u8], ResponseError> {
    // Split off the first four bytes for `version`.
    let version = data.get(0..mem::size_of::<u32>()).ok_or(
        ResponseError::BadRequest(BadRequestReason::DeserializationError),
    )?;
    let data = &data[mem::size_of::<u32>()..];
    let version = u32::from_le_bytes(version.try_into().unwrap());

    // Split off the next four bytes for `request_id`.
    let request_id_bytes = data.get(0..mem::size_of::<u32>()).ok_or(
        ResponseError::BadRequest(BadRequestReason::DeserializationError),
    )?;
    let data = &data[mem::size_of::<u32>()..];
    *request_id = u32::from_le_bytes(request_id_bytes.try_into().unwrap());

    // Version check.
    if version == version::V1 {
        Ok(data)
    } else {
        Err(ResponseError::BadRequest(BadRequestReason::WrongVersion {
            sp: version::V1,
            request: version,
        }))
    }
}

/// Parses the remainder of a request (after `version` and `request_id`, which
/// are handled by `read_request_header`) and calls `handler`.
fn handle_message_impl<H: SpHandler>(
    sender: SocketAddrV6,
    port: SpPort,
    request_kind_data: &[u8],
    handler: &mut H,
) -> Result<ResponseKind, ResponseError> {
    let (kind, leftover) = hubpack::deserialize::<RequestKind>(
        request_kind_data,
    )
    .map_err(|_| {
        ResponseError::BadRequest(BadRequestReason::DeserializationError)
    })?;

    // Do we expect any trailing raw data? Only for specific kinds of messages;
    // if we get any for other messages, bail out.
    let trailing_data = match &kind {
        RequestKind::UpdateChunk(_)
        | RequestKind::SerialConsoleWrite { .. } => {
            unpack_trailing_data(leftover).map_err(|_| {
                ResponseError::BadRequest(
                    BadRequestReason::DeserializationError,
                )
            })?
        }
        _ => {
            if !leftover.is_empty() {
                return Err(ResponseError::BadRequest(
                    BadRequestReason::UnexpectedTrailingData,
                ));
            }
            &[]
        }
    };

    // call out to handler to provide response
    match kind {
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
    }
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
            version: version::V1,
            request_id: 0x01020304,
            kind: RequestKind::Discover,
        };

        let resp = call_handle_message(req);

        assert_eq!(
            resp,
            SpMessage {
                version: version::V1,
                kind: SpMessageKind::Response {
                    request_id: req.request_id,
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
            version: 0x0badf00d,
            request_id: 0x01020304,
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
            version: version::V1,
            request_id: 0x01020304,
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
