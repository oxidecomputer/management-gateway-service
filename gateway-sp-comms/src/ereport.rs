// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

use crate::error::CommunicationError;
use crate::error::EreportError;
use crate::shared_socket;
use crate::single_sp;
use crate::SpRetryConfig;
use async_trait::async_trait;
pub use gateway_messages::ereport::Ena;
use gateway_messages::ereport::EreportRequest;
use gateway_messages::ereport::EreportResponseHeader;
use gateway_messages::ereport::RequestIdV0;
use gateway_messages::ereport::RequestV0;
use gateway_messages::ereport::ResponseHeaderV0;
pub use gateway_messages::ereport::RestartId;
use serde::Deserialize;
use serde_cbor::Value as CborValue;
use serde_json::Value as JsonValue;
use slog::debug;
use slog::error;
use slog::trace;
use slog::warn;
use slog_error_chain::SlogInlineError;
use std::collections::BTreeMap;
use std::num::NonZeroU8;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use uuid::Uuid;

pub const SP_PORT: u16 = 57005; // 0xDEAD
pub const MGS_PORT: u16 = 57007; // 0xDEAF

#[derive(Debug, Default)]
pub struct EreportHandler {}

#[derive(Debug)]
pub struct EreportTranche {
    pub restart_id: Uuid,
    pub ereports: Vec<Ereport>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Ereport {
    pub ena: Ena,
    pub data: MetadataMap,
}

pub(crate) struct WorkerRequest {
    pub(crate) restart_id: Uuid,
    pub(crate) start_ena: Ena,
    pub(crate) limit: NonZeroU8,
    pub(crate) committed_ena: Option<Ena>,
    pub(crate) rsp_tx: oneshot::Sender<Result<EreportTranche, EreportError>>,
}

pub(crate) struct Worker<S> {
    req_rx: mpsc::Receiver<WorkerRequest>,
    /// Each v0 ereport request has an 8-bit sequence number incremented on
    /// every request from MGS and included by the SP in responses to that
    /// request. This allows the gateway to determine if a packet received from
    /// the SP is a response to the current request, or is in response to a
    /// previous request that may have timed out or been retried.
    request_id: RequestIdV0,
    retry_config: SpRetryConfig,
    socket: S,
    outbuf: [u8; <EreportRequest as hubpack::SerializedSize>::MAX_SIZE],
    /// The current map of metadata added to all received ereports.
    ///
    /// When MGS starts up, this is initially `None`, and we must ask the SP for
    /// metadata before we can start processing ereports.
    metadata: Option<MetadataMap>,
}

type MetadataMap = serde_json::Map<String, JsonValue>;

impl<S> Worker<S>
where
    S: single_sp::InnerSocket<Vec<u8>>,
{
    pub(crate) fn new(
        retry_config: SpRetryConfig,
        socket: S,
    ) -> (Self, mpsc::Sender<WorkerRequest>) {
        let (tx, req_rx) = mpsc::channel(8);
        let this = Self {
            req_rx,
            request_id: RequestIdV0(0),
            retry_config,
            socket,
            outbuf: [0u8;
                <EreportRequest as hubpack::SerializedSize>::MAX_SIZE],
            metadata: None,
        };
        (this, tx)
    }

    pub(crate) async fn run(mut self) {
        while let Some(req) = self.req_rx.recv().await {
            // If we have just started up, or we were previously unable to
            // refresh the SP's metadata, try to do so now.
            if self.metadata.is_none() {
                trace!(self.log(), "requesting initial SP metadata...");
                match self.request_ereports(Uuid::nil(), Ena(0), 0, None).await
                {
                    Ok((restart_id, ereports)) => {
                        if !ereports.is_empty() {
                            // The SP was told not to send ereports in this
                            // request, just metadata. If it sends us ereports,
                            // that could indicate a bug on the SP side, but we
                            // assume the metadata is still valid regardless.
                            warn!(
                                self.log(),
                                "received ereports in response to a request \
                                 with limit 0, seems weird";
                                "restart_id" => ?restart_id,
                                "ereports" => ?ereports
                            );
                        }
                        debug!(
                            self.log(),
                            "received initial SP metadata";
                            "metadata" => ?self.metadata,
                            "restart_id" => ?restart_id
                        );
                    }
                    Err(error) => {
                        warn!(
                            self.log(),
                            "error requesting SP ereport metadata";
                            &error,
                        );
                        if req.rsp_tx.send(Err(error)).is_err() {
                            warn!(self.log(), "ereport request cancelled");
                        }
                        continue;
                    }
                }
            }

            // Okay, now actually get some ereports.
            let rsp = match self
                .request_ereports(
                    req.restart_id,
                    req.start_ena,
                    req.limit.get(),
                    req.committed_ena,
                )
                .await
            {
                Ok((restart_id, ereports)) => {
                    debug!(
                        self.log(),
                        "received {} ereports", ereports.len();
                        "restart_id" => ?restart_id,
                        "req_restart_id" => ?req.restart_id,
                        "req_start_ena" => ?req.start_ena,
                        "req_limit" => ?req.limit,
                        "req_committed_ena" => ?req.committed_ena,
                    );
                    Ok(EreportTranche { restart_id, ereports })
                }
                Err(error) => {
                    warn!(
                        self.log(),
                        "error requesting SP ereports";
                        &error,
                        "req_restart_id" => ?req.restart_id,
                        "req_start_ena" => ?req.start_ena,
                        "req_limit" => ?req.limit,
                        "req_committed_ena" => ?req.committed_ena,
                    );
                    Err(error)
                }
            };

            if req.rsp_tx.send(rsp).is_err() {
                warn!(self.log(), "ereport request cancelled");
            }
        }
    }

    fn log(&self) -> &slog::Logger {
        self.socket.log()
    }

    async fn request_ereports(
        &mut self,
        restart_id: Uuid,
        start_ena: Ena,
        limit: u8,
        committed_ena: Option<Ena>,
    ) -> Result<(Uuid, Vec<Ereport>), EreportError> {
        let req = EreportRequest::V0(RequestV0::new(
            RestartId(restart_id.as_u128()),
            self.request_id,
            start_ena,
            limit,
            committed_ena,
        ));
        let amt = match gateway_messages::serialize(&mut self.outbuf, &req) {
            Ok(amt) => amt,
            Err(error) => {
                unreachable!(
                    "hubpack serialization should only fail if the buffer \
                    is not large enough, or if the type is not able to \
                    be serialized by hubpack at all. therefore, \
                    serializing an ereport request should never fail. \
                    however, the following request could not be \
                    serialized: {req:?}\nerror: {error}"
                );
            }
        };

        // Actually sending the request is wrapped in an immediately awaited
        // async block that functions as a sort of "try/catch" mechanism. This
        // is to ensure we always increment the request ID for the next request,
        // regardless of whether we succeeded or failed to receive a response.
        let result = async {
            let packet = &self.outbuf[..amt];
            for attempt in 1..=self.retry_config.max_attempts_general {
                slog::trace!(
                    self.log(),
                    "sending ereport request to SP";
                    "request_id" => ?self.request_id,
                    "restart_id" => ?restart_id,
                    "request" => ?req,
                    "attempt" => attempt,
                );
                self.socket.send(packet).await?;
                'attempt: while let Ok(Some(msg)) = tokio::time::timeout(
                    self.retry_config.per_attempt_timeout,
                    self.socket.recv(),
                )
                .await
                {
                    // Decode the header and the body in separate steps, so that we
                    // don't waste time decoding the bodies of packets that don't
                    // match the current request ID.
                    let (header, packet) = decode_header(&msg)?;
                    match header {
                        // If the request ID doesn't match the ID of the current
                        // request, it was probably intended as a response to a
                        // previous request that we may have attempted multiple
                        // times. If that's the case, ignore it and wait for the
                        // next packet.
                        EreportResponseHeader::V0(ResponseHeaderV0 {
                            request_id,
                            ..
                        }) if request_id != self.request_id => {
                            slog::debug!(
                                self.log(),
                                "ignoring a response that doesn't match the \
                                 current request ID";
                                "request_id" => ?request_id,
                                "current_request_id" => ?self.request_id,
                            );
                            continue 'attempt;
                        }
                        // Otherwise, it's a response to the current request.
                        // Decode the body, potentially updating our current
                        // metadata.
                        EreportResponseHeader::V0(header) => {
                            return decode_body_v0(
                                restart_id,
                                &header,
                                &mut self.metadata,
                                packet,
                            )
                            .map_err(EreportError::from);
                        }
                    }
                }
            }

            Err(EreportError::Communication(
                CommunicationError::ExhaustedNumAttempts(
                    self.retry_config.max_attempts_general,
                ),
            ))
        }
        .await;

        // Regardless of whether we received a successful response or not, make
        // sure to increment the request ID. This ensures that if we later
        // receive any packets that were intended as responses for *this*
        // request, we'll ignore them.
        self.request_id.increment();
        result
    }
}

fn decode_header(
    packet: &[u8],
) -> Result<(EreportResponseHeader, &[u8]), DecodeError> {
    gateway_messages::deserialize::<EreportResponseHeader>(packet)
        .map_err(DecodeError::Header)
}

fn decode_body_v0(
    restart_id: Uuid,
    header: &ResponseHeaderV0,
    metadata: &mut Option<MetadataMap>,
    packet: &[u8],
) -> Result<(Uuid, Vec<Ereport>), DecodeError> {
    // Deserialize a CBOR-encoded value from a byte slice, returning the
    // deserialized value and any remaining trailing data in the slice.
    fn deserialize_cbor<'data, T: Deserialize<'data>>(
        data: &'data [u8],
    ) -> Result<(T, &'data [u8]), serde_cbor::Error> {
        let mut deserializer = serde_cbor::Deserializer::from_slice(data);
        let value = T::deserialize(&mut deserializer)?;
        let rest = &data[deserializer.byte_offset()..];
        Ok((value, rest))
    }

    let received_restart_id = Uuid::from_u128(header.restart_id.0);
    // V0 ereport packets consist of:
    //
    // 1. A CBOR map (using the "indefinite-length" encoding) of strings to
    //    CBOR values, containing metadata. If the requested restart ID matches
    //    the current one, the metadata map will generally be empty.
    //
    //    The packet may end here if it contains no ereports.
    //
    // 2. If the packet contains ereports, the ENA of the first ereport in the
    //    packet.
    //
    // 3. A CBOR list of ereports (using the "indefinite-length" encoding),
    //    where each entry is a CBOR list of 4 elements:
    //      1. The name of the task that produced the ereport
    //      2. The task's generation number
    //      3. The system uptime in milliseconds
    //      4. A CBOR byte array containing the body of the ereport. The bytes
    //         in this array should be decoded as a map of strings to CBOR
    //         values, but they are encoded as an array within the outer
    //         message to escape any potentially malformed ereport data.
    //
    // See RFD 545 4.4 for details:
    // https://rfd.shared.oxide.computer/rfd/0545#_readresponse
    //
    let (cbor_metadata, packet) =
        deserialize_cbor::<BTreeMap<CborValue, CborValue>>(packet)
            .map_err(DecodeError::MetadataDeserialize)?;
    let mut new_metadata = serde_json::Map::with_capacity(cbor_metadata.len());
    convert_cbor_object_into(cbor_metadata, &mut new_metadata)
        .map_err(DecodeError::MetadataJson)?;

    if !new_metadata.is_empty() || received_restart_id != restart_id {
        *metadata = Some(new_metadata);
    }

    if packet.is_empty() {
        return Ok((received_restart_id, Vec::new()));
    }

    // Okay, there's data left in the packet. This should be interpreted as
    // ereports. First, the starting ENA of the ereport list:
    let (start_ena, packet) = gateway_messages::deserialize::<Ena>(packet)
        .map_err(DecodeError::Ena)?;

    // Now, the ereports themselves:
    let cbor_ereports = serde_cbor::from_slice::<Vec<Vec<CborValue>>>(packet)
        .map_err(DecodeError::EreportsDeserialize)?;

    let mut ereports = Vec::with_capacity(cbor_ereports.len());
    let mut task_names = Vec::new();
    let mut ena = start_ena;
    for (n, mut parts) in cbor_ereports.into_iter().enumerate() {
        // Each ereport is a list of 4 CBOR values.
        //
        // The fourth value is the body of the ereport, as a byte array whose
        // contents are a CBOR-encoded map.
        let CborValue::Bytes(body) =
            parts.pop().ok_or(DecodeError::MalformedEreport {
                n,
                msg: "ereport list empty",
            })?
        else {
            return Err(DecodeError::MalformedEreport {
                n,
                msg: "expected ereport body to be a byte array",
            });
        };
        // The third value is the SP's uptime in milliseconds.
        let uptime = parts.pop().ok_or(DecodeError::MalformedEreport {
            n,
            msg: "missing Hubris uptime list entry",
        })?;
        // The second value is the generation number of the task that emitted
        // the ereport.
        let task_gen = parts.pop().ok_or(DecodeError::MalformedEreport {
            n,
            msg: "missing task generation list entry",
        })?;
        // Finally, the first value is the name of the task that emitted the
        // ereport. This may be represented either as a string, or as the
        // integer index of a previous ereport (in which case, the name is the
        // same as the one in the previous ereport).
        let task_name = match parts.pop() {
            Some(CborValue::Text(name)) => {
                task_names.push(name.clone());
                name
            }
            Some(CborValue::Integer(i)) => {
                task_names.get(i as usize).cloned().ok_or(
                    DecodeError::BadTaskNameIndex { n, index: i as usize },
                )?
            }
            Some(actual) => {
                return Err(DecodeError::InvalidTaskNameType { n, actual })
            }
            None => {
                return Err(DecodeError::MalformedEreport {
                    n,
                    msg: "missing task name list entry",
                })
            }
        };
        // That should really be everything.
        //
        // XXX(eliza): perhaps we ought to just log a warning here, rather than
        // returning an error and throwing out the whole packet?
        if !parts.is_empty() {
            return Err(DecodeError::MalformedEreport {
                n,
                msg: "unexpected bonus stuff in ereports list",
            });
        }

        let cbor_ereport = serde_cbor::from_slice::<
            BTreeMap<CborValue, CborValue>,
        >(&body)
        .map_err(|error| DecodeError::DeserializeEreportBody { n, error })?;

        let mut data = serde_json::Map::with_capacity(
            // Let's just do One Big Allocation with enough space for
            // the whole thing! We'll need:
            // the number of fields in the ereport body
            cbor_ereport.len()
                    // plus the number of fields from the metadata fragment
                    // we'll append to it
                    + metadata.as_ref().map(|m| m.len()).unwrap_or(0)
                    // the task name'
                    + 1
                    // the task generation
                    + 1
                    // hubris uptime
                    + 1,
        );
        convert_cbor_object_into(cbor_ereport, &mut data)
            .map_err(DecodeError::mk_json(n, "body"))?;
        // jam the metadata fragment onto it
        data.extend(
            metadata.iter().flatten().map(|(k, v)| (k.clone(), v.clone())),
        );
        data.insert(
            "hubris_task_name".to_string(),
            JsonValue::String(task_name),
        );
        data.insert(
            "hubris_task_gen".to_string(),
            convert_cbor_value(task_gen)
                .map_err(DecodeError::mk_json(n, "hubris_task_gen"))?,
        );
        data.insert(
            "hubris_uptime_ms".to_string(),
            convert_cbor_value(uptime)
                .map_err(DecodeError::mk_json(n, "hubris_uptime_ms"))?,
        );
        ereports.push(Ereport { ena, data });

        // Increment the ENA for the next ereport in the packet.
        ena.0 += 1;
    }

    Ok((received_restart_id, ereports))
}

#[derive(Debug, Error, SlogInlineError)]
pub enum DecodeError {
    #[error("failed to deserialize ereport response header")]
    Header(#[source] hubpack::Error),
    #[error("failed to deserialize ereport response ENA")]
    Ena(#[source] hubpack::Error),
    #[error("failed to deserialize ereports")]
    EreportsDeserialize(#[source] serde_cbor::Error),
    #[error("failed to convert ereport[{n}] CBOR {what} to JSON")]
    EreportJson {
        n: usize,
        what: &'static str,
        #[source]
        error: CborToJsonError,
    },
    #[error("malformed ereport[{n}]: {msg}")]
    MalformedEreport { n: usize, msg: &'static str },
    #[error("failed to decode ereport[{n}] body")]
    DeserializeEreportBody {
        n: usize,
        #[source]
        error: serde_cbor::Error,
    },
    #[error("failed to deserialize ereport metadata refresh fragment")]
    MetadataDeserialize(#[source] serde_cbor::Error),
    #[error("failed to convert metadata refresh fragment to JSON")]
    MetadataJson(#[source] CborToJsonError),
    #[error("ereport[{n}] invalid task name index {index}")]
    BadTaskNameIndex { n: usize, index: usize },
    #[error("ereport[{n}] task name must be a string or integer, but found: {actual:?}")]
    InvalidTaskNameType { n: usize, actual: CborValue },
}

impl DecodeError {
    fn mk_json(
        n: usize,
        what: &'static str,
    ) -> impl Fn(CborToJsonError) -> Self {
        move |error| Self::EreportJson { n, what, error }
    }
}

fn convert_cbor_value(value: CborValue) -> Result<JsonValue, CborToJsonError> {
    use base64::{
        engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD},
        Engine,
    };
    use serde_json::value::Number as JsonNumber;

    // See https://www.rfc-editor.org/rfc/rfc8949.html#section-6.1 for advice
    // from the CBOR RFC on how to convert CBOR values to JSON value.
    Ok(match value {
        CborValue::Null => JsonValue::Null,
        CborValue::Bool(b) => JsonValue::Bool(b),
        CborValue::Float(cbor) => {
            // Per RFC 8949 section 6.1:
            //
            // > A floating-point value (major type 7, additional information
            // > 25 through 27) becomes a JSON number if it is finite (that is,
            // > it can be represented in a JSON number); if the value is
            // > non-finite (NaN, or positive or negative Infinity), it is
            // > represented by the substitute value.
            JsonNumber::from_f64(cbor)
                .map(JsonValue::Number)
                .unwrap_or(JsonValue::Null)
        }
        CborValue::Integer(cbor) => {
            let json = JsonNumber::from_i128(cbor)
                .ok_or(CborToJsonError::InvalidInteger(cbor))?;
            JsonValue::Number(json)
        }
        CborValue::Array(cbor) => {
            let json = cbor
                .into_iter()
                .map(convert_cbor_value)
                .collect::<Result<Vec<_>, _>>()?;
            JsonValue::Array(json)
        }
        CborValue::Map(cbor) => {
            let mut json = serde_json::Map::with_capacity(cbor.len());
            convert_cbor_object_into(cbor, &mut json)?;
            JsonValue::Object(json)
        }
        CborValue::Text(s) => JsonValue::String(s),

        // Per RFC 8949 section 6.1:
        //
        // > A byte string (major type 2) that is not embedded in a tag that
        // > specifies a proposed encoding is encoded in base64url without
        // > padding and becomes a JSON string.
        CborValue::Bytes(b) => {
            let base64 = URL_SAFE_NO_PAD.encode(b);
            JsonValue::String(base64)
        }

        CborValue::Tag(tag, value) => {
            // Per RFC 8949 section 6.1:
            //
            // > A byte string (major type 2) that is not embedded in a tag
            // > that specifies a proposed encoding is encoded in base64url
            // > without padding and becomes a JSON string.
            //
            // > A bignum (major type 6, tag number 2 or 3) is represented
            // > by encoding its byte string in base64url without padding
            // > and becomes a JSON string. For tag number 3
            // > (negative bignum), a "~" (ASCII tilde) is inserted before
            // > the base-encoded value. (The conversion to a binary blob
            // > instead of a number is to prevent a likely numeric overflow f
            // > or the JSON decoder.)
            //
            // > For all other tags (major type 6, any other tag number), the
            // > tag content is represented as a JSON value; the tag number is
            // > ignored.
            match (tag, *value) {
                // Tag 3: Negative bignum
                (3, CborValue::Bytes(bytes)) => {
                    let mut string = "~".to_string();
                    URL_SAFE_NO_PAD.encode_string(bytes, &mut string);
                    JsonValue::String(string)
                }
                // Tag 21: Expected conversion to base64url encoding
                // Tag 2: Positive bignum
                (21, CborValue::Bytes(bytes))
                | (2, CborValue::Bytes(bytes)) => {
                    let base64 = URL_SAFE_NO_PAD.encode(bytes);
                    JsonValue::String(base64)
                }
                // Tag 22: Expected conversion to base64 encoding
                (22, CborValue::Bytes(bytes)) => {
                    let base64 = STANDARD_NO_PAD.encode(bytes);
                    JsonValue::String(base64)
                }
                // Tag 23: Expected conversion to base16 encoding (i.e. hex)
                (23, CborValue::Bytes(bytes)) => {
                    let hex = hex::encode(bytes);
                    JsonValue::String(hex)
                }
                (_, value) => convert_cbor_value(value)?,
            }
        }

        // They really shouldn't have reserved the ability to add new variants
        // in a semver-compatible change; it's pretty unfortunate to panic here.
        // Hopefully we catch this in testing...
        _ => unimplemented!("the CBOR crate has added a new variant"),
    })
}

fn convert_cbor_object_into(
    cbor: BTreeMap<CborValue, CborValue>,
    json: &mut serde_json::Map<String, JsonValue>,
) -> Result<(), CborToJsonError> {
    for (key, val) in cbor {
        match key {
            CborValue::Text(key) => {
                json.insert(key, convert_cbor_value(val)?);
            }
            // HEY CLIFF DON'T GIVE ME NON-STRING OBJECT KEYS PLEASE :)
            key => return Err(CborToJsonError::NonStringKey(key)),
        };
    }

    Ok(())
}

/// Errors converting CBOR ereport data received from the SP to JSON data for
/// the control plane.
#[derive(Debug, Error, SlogInlineError)]
pub enum CborToJsonError {
    /// JSON objects must be maps of `String`s to values, but CBOR permits maps
    /// to have key types other than strings.
    #[error("non-string object key: {0:?}")]
    NonStringKey(CborValue),
    /// JSON numbers may not be NaN or infinite.
    #[error("CBOR float {0} was not a valid JSON number")]
    InvalidFloat(f64),
    #[error("CBOR integer too large for JSON: {0}")]
    InvalidInteger(i128),
    #[error("the snitch is not expected to use CBOR tags")]
    TagsNotYetImplemented,
}

#[async_trait]
impl shared_socket::RecvHandler for EreportHandler {
    type Message = Vec<u8>;

    async fn run(self, socket: shared_socket::RecvSocket<Vec<u8>>) {
        // Unlike the `RecvHandler` implementation for control-plane-agent
        // messages, the ereport `RecvHandler` simply takes the received packet,
        // turns it into a `Vec`, and sends it off to the corresponding
        // single-SP handler, which actually parses the message.
        //
        // This is because we don't need to do more complex dispatching of the
        // message based on its contents, so we need not parse it here. Instead,
        // parsing the message in the single-SP handler allows us to return
        // nicer errors to the caller when a message cannot be parsed correctly,
        // and also means that the next incoming packet need not wait until the
        // previous one has been parsed before it can be dispatched.
        let mut buf = [0; gateway_messages::MAX_SERIALIZED_SIZE];
        loop {
            let (peer, data) = socket.recv_packet(&mut buf).await;

            if let Err(err) =
                socket.sps.forward_to_single_sp(peer, data.to_vec()).await
            {
                warn!(
                    socket.log,
                    "failed to forward incoming ereport message to handler";
                    "peer" => %peer,
                    err,
                );
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde::Serializer;
    use std::io::Cursor;

    enum TaskName<'a> {
        Index(usize),
        String(&'a str),
    }

    macro_rules! cbor_map {
        ($($key:literal: $val:expr),* $(,)?) => {{
            let mut map = BTreeMap::new();
            $(
                map.insert(CborValue::Text($key.to_string()), CborValue::from($val));
            )+
            map
        }}
    }

    macro_rules! json_map {
        ($($obj:tt)*) => {{
            match serde_json::json!({$($obj)*}) {
                JsonValue::Object(map) => map,
                x => unreachable!("this macro should only be used to make maps, but got: {x:?}"),
            }
        }}
    }

    fn mk_ereport_list(
        task_name: TaskName<'_>,
        task_gen: u32,
        uptime: u64,
        body: BTreeMap<CborValue, CborValue>,
    ) -> Vec<CborValue> {
        let task_name = match task_name {
            TaskName::Index(i) => CborValue::Integer(i as i128),
            TaskName::String(s) => CborValue::Text(s.to_string()),
        };
        // The body itself is serialized as a CBOR byte array, to escape the
        // payload from the reporting task (in case it e.g. contains CBOR break
        // bytes in wrong locations).
        let body_bytes = match serde_cbor::to_vec(&body) {
            Ok(bytes) => bytes,
            Err(e) => {
                panic!("failed to serialize ereportbody: {e}\nbody: {body:#?}")
            }
        };
        vec![
            task_name,
            CborValue::from(task_gen),
            CborValue::from(uptime),
            CborValue::from(body_bytes),
        ]
    }

    const TASK_NAME_THINGY: &str = "drv_thingy_server";
    const TASK_NAME_APOLLO_13: &str = "task_apollo_server";
    const KEY_ARCHIVE: &str = "hubris_archive_id";
    const KEY_TASK: &str = "hubris_task_name";
    const KEY_GEN: &str = "hubris_task_gen";
    const KEY_UPTIME: &str = "hubris_uptime_ms";
    const KEY_SERIAL: &str = "baseboard_serial";

    fn serialize_ereport_list<'buf>(
        buf: &'buf mut [u8],
        ereports: &[Vec<CborValue>],
    ) -> usize {
        use serde::ser::SerializeSeq;

        let mut cursor = Cursor::new(buf);
        // Rather than just using `serde_cbor::to_writer`, we'll manually
        // construct a `Serializer`, so that we can call the `serialize_seq`
        // method *without* a length to force it to use the "indefinite-length"
        // encoding.
        let mut serializer = serde_cbor::Serializer::new(
            serde_cbor::ser::IoWrite::new(&mut cursor),
        );
        let mut seq =
            serializer.serialize_seq(None).expect("sequence should start");
        for ereport in ereports {
            seq.serialize_element(ereport).expect("element should serialize");
        }
        seq.end().expect("sequence should end");
        cursor.position() as usize
    }

    fn serialize_metadata<'buf>(
        buf: &'buf mut [u8],
        metadata: &MetadataMap,
    ) -> usize {
        use serde::ser::SerializeMap;

        let mut cursor = Cursor::new(buf);
        // Rather than just using `serde_cbor::to_writer`, we'll manually
        // construct a `Serializer`, so that we can call the `serialize_map`
        // method *without* a length to force it to use the "indefinite-length"
        // encoding.
        let mut serializer = serde_cbor::Serializer::new(
            serde_cbor::ser::IoWrite::new(&mut cursor),
        );
        let mut map = serializer.serialize_map(None).expect("map should start");
        for (key, value) in metadata {
            map.serialize_entry(key, value).expect("element should serialize");
        }
        map.end().expect("map should end");
        cursor.position() as usize
    }

    fn dump_packet(packet: &[u8]) {
        eprint!("packet [{}B]:", packet.len());
        for (i, byte) in packet.iter().enumerate() {
            if i % 16 == 0 {
                eprint!("\n  ");
            }
            eprint!("{:02x} ", byte);
        }
        eprintln!("");
    }

    #[track_caller]
    fn decode_packet(
        restart_id: Uuid,
        metadata: &mut Option<MetadataMap>,
        packet: &[u8],
    ) -> (Uuid, RequestIdV0, Vec<Ereport>) {
        dump_packet(packet);
        let (header, packet) = match decode_header(packet) {
            Ok((EreportResponseHeader::V0(header), packet)) => {
                (dbg!(header), packet)
            }
            Err(e) => panic!("header did not decode: {e:#?}"),
        };
        let (restart_id, ereports) =
            match decode_body_v0(restart_id, &header, metadata, packet) {
                Ok(ereports) => ereports,
                Err(e) => panic!("body did not decode: {e:#?}"),
            };
        (restart_id, header.request_id, ereports)
    }

    #[test]
    fn decode_ereports() {
        let mut packet = [0u8; 1024];
        let restart_id = Uuid::new_v4();
        let request_id = RequestIdV0(1);
        let start_ena = Ena(42);

        let header = EreportResponseHeader::V0(ResponseHeaderV0 {
            restart_id: RestartId(restart_id.as_u128()),
            request_id,
        });
        let end = {
            let mut len = hubpack::serialize(&mut packet, &header)
                .expect("header should serialize");

            // Empty metadata map
            len +=
                serialize_metadata(&mut packet[len..], &MetadataMap::default());

            // Start ENA
            len += hubpack::serialize(&mut packet[len..], &start_ena)
                .expect("ENA should serialize");
            len += serialize_ereport_list(
                &mut packet[len..],
                &[
                    mk_ereport_list(
                        TaskName::String(TASK_NAME_THINGY),
                        1,
                        569,
                        cbor_map! {
                            "class": "flagrant system error".to_string(),
                            "badness": 10000,
                        },
                    ),
                    mk_ereport_list(
                        TaskName::String(TASK_NAME_APOLLO_13),
                        13,
                        572,
                        cbor_map! {
                            "msg": "houston, we have a problem".to_string(),
                            "crew": vec![
                                CborValue::from("Lovell".to_string()),
                                CborValue::from("Swigert".to_string()),
                                CborValue::from("Hayes".to_string()),
                            ],
                        },
                    ),
                    mk_ereport_list(
                        TaskName::Index(0),
                        1,
                        575,
                        cbor_map! {
                           "class": "problem changed".to_string(),
                           "bonus_stuff": cbor_map!{ "foo": 1, "bar": 2, },
                        },
                    ),
                ],
            );
            len
        };
        let packet = &packet[..end];
        dump_packet(packet);

        let initial_meta = json_map! {
            KEY_ARCHIVE: "decadefaced".to_string(),
            KEY_SERIAL: "BRM69000420".to_string(),
        };
        let mut meta = Some(initial_meta.clone());

        let (decoded_restart_id, decoded_request_id, ereports) =
            decode_packet(restart_id, &mut meta, packet);

        assert_eq!(decoded_restart_id, restart_id);
        assert_eq!(decoded_request_id, request_id);
        assert_eq!(
            meta.as_ref(),
            Some(&initial_meta),
            "metadata should be unchanged"
        );

        assert_eq!(
            ereports.len(),
            3,
            "expected 3 ereports, but got: {ereports:#?}"
        );

        assert_eq!(dbg!(ereports[0].ena), start_ena);
        assert_eq!(
            dbg!(&ereports[0].data),
            &json_map! {
                KEY_ARCHIVE: "decadefaced",
                KEY_SERIAL: "BRM69000420",
                KEY_TASK: TASK_NAME_THINGY,
                KEY_GEN: 1,
                KEY_UPTIME: 569,
                "class": "flagrant system error",
                "badness": 10000,
            },
        );

        assert_eq!(dbg!(ereports[1].ena), Ena(start_ena.0 + 1));
        assert_eq!(
            dbg!(&ereports[1].data),
            &json_map! {
                KEY_ARCHIVE: "decadefaced",
                KEY_SERIAL: "BRM69000420",
                KEY_TASK: TASK_NAME_APOLLO_13,
                KEY_GEN: 13,
                KEY_UPTIME: 572,
                "msg": "houston, we have a problem",
                "crew": ["Lovell", "Swigert", "Hayes"],
            },
        );

        assert_eq!(dbg!(ereports[2].ena), Ena(start_ena.0 + 2));
        assert_eq!(
            dbg!(&ereports[2].data),
            &json_map! {
                KEY_ARCHIVE: "decadefaced",
                KEY_SERIAL: "BRM69000420",
                KEY_TASK: TASK_NAME_THINGY,
                KEY_GEN: 1,
                KEY_UPTIME: 575,
                "class": "problem changed",
                "bonus_stuff": { "foo": 1, "bar": 2, },
            },
        );
    }

    #[test]
    fn decode_ereports_and_meta() {
        let mut packet = [0u8; 1024];
        let restart_id = Uuid::new_v4();
        let request_id = RequestIdV0(1);

        let header = EreportResponseHeader::V0(ResponseHeaderV0 {
            restart_id: RestartId(restart_id.as_u128()),
            request_id,
        });

        let new_meta = json_map! {
            KEY_ARCHIVE: "defaceddead".to_string(),
            KEY_SERIAL: "BRM69000666".to_string(),
            "sled_is_evil": true,
        };
        let end = {
            let mut len = hubpack::serialize(&mut packet, &header)
                .expect("header should serialize");

            // Metadata map
            len += serialize_metadata(&mut packet[len..], &new_meta);

            // Start ENA
            len += hubpack::serialize(&mut packet[len..], &Ena(0))
                .expect("ENA should serialize");
            len += serialize_ereport_list(
                &mut packet[len..],
                &[
                    mk_ereport_list(
                        TaskName::String(TASK_NAME_THINGY),
                        1,
                        569,
                        cbor_map! {
                            "class": "flagrant system error".to_string(),
                            "badness": 10000,
                        },
                    ),
                    mk_ereport_list(
                        TaskName::String(TASK_NAME_APOLLO_13),
                        13,
                        572,
                        cbor_map! {
                            "msg": "houston, we have a problem".to_string(),
                            "crew": vec![
                                CborValue::from("Lovell".to_string()),
                                CborValue::from("Swigert".to_string()),
                                CborValue::from("Hayes".to_string()),
                            ],
                        },
                    ),
                    mk_ereport_list(
                        TaskName::Index(0),
                        1,
                        575,
                        cbor_map! {
                           "class": "problem changed".to_string(),
                           "bonus_stuff": cbor_map!{ "foo": 1, "bar": 2, },
                        },
                    ),
                ],
            );
            len
        };
        let packet = &packet[..end];

        let initial_meta = json_map! {
            KEY_ARCHIVE: "decadefaced".to_string(),
            KEY_SERIAL: "BRM69000420".to_string(),
        };
        let mut meta = Some(initial_meta.clone());

        let (decoded_restart_id, decoded_request_id, ereports) =
            decode_packet(Uuid::new_v4(), &mut meta, packet);
        assert_eq!(decoded_restart_id, restart_id);
        assert_eq!(decoded_request_id, request_id);
        assert_eq!(
            dbg!(meta.as_ref()),
            Some(&new_meta),
            "expected metadata to be updated"
        );

        assert_eq!(
            ereports.len(),
            3,
            "expected 3 ereports, but got: {ereports:#?}"
        );

        assert_eq!(dbg!(ereports[0].ena), Ena(0));
        assert_eq!(
            dbg!(&ereports[0].data),
            &json_map! {
                KEY_ARCHIVE: "defaceddead".to_string(),
                KEY_SERIAL: "BRM69000666".to_string(),
                "sled_is_evil": true,
                KEY_TASK: TASK_NAME_THINGY,
                KEY_GEN: 1,
                KEY_UPTIME: 569,
                "class": "flagrant system error",
                "badness": 10000,
            },
        );

        assert_eq!(dbg!(ereports[1].ena), Ena(1));
        assert_eq!(
            dbg!(&ereports[1].data),
            &json_map! {
                KEY_ARCHIVE: "defaceddead".to_string(),
                KEY_SERIAL: "BRM69000666".to_string(),
                "sled_is_evil": true,
                KEY_TASK: TASK_NAME_APOLLO_13,
                KEY_GEN: 13,
                KEY_UPTIME: 572,
                "msg": "houston, we have a problem",
                "crew": ["Lovell", "Swigert", "Hayes"],
            },
        );

        assert_eq!(dbg!(ereports[2].ena), Ena(2));
        assert_eq!(
            dbg!(&ereports[2].data),
            &json_map! {
                KEY_ARCHIVE: "defaceddead".to_string(),
                KEY_SERIAL: "BRM69000666".to_string(),
                "sled_is_evil": true,
                KEY_TASK: TASK_NAME_THINGY,
                KEY_GEN: 1,
                KEY_UPTIME: 575,
                "class": "problem changed",
                "bonus_stuff": { "foo": 1, "bar": 2, },
            },
        );
    }

    #[test]
    fn decode_meta_only() {
        let mut packet = [0u8; 1024];
        let restart_id = Uuid::new_v4();
        let request_id = RequestIdV0(1);

        let header = EreportResponseHeader::V0(ResponseHeaderV0 {
            restart_id: RestartId(restart_id.as_u128()),
            request_id,
        });
        let meta = json_map! {
            KEY_ARCHIVE: "decadefaced".to_string(),
            KEY_SERIAL: "BRM69000420".to_string(),
            "foo": 1,
            "bar": [1, 2, 3],
            "baz": { "hello": "joe", "system_working": true },
        };
        let end = {
            let mut len = hubpack::serialize(&mut packet, &header)
                .expect("header should serialize");

            len += serialize_metadata(&mut packet[len..], &meta);
            // That's the whole packet, folks!
            len
        };

        let packet = &packet[..end];
        dump_packet(packet);

        let mut found_meta = None;

        let (decoded_restart_id, decoded_request_id, ereports) =
            decode_packet(restart_id, &mut found_meta, packet);
        assert_eq!(decoded_restart_id, restart_id);
        assert_eq!(decoded_request_id, request_id);
        assert_eq!(dbg!(found_meta.as_ref()), Some(&meta),);

        assert_eq!(
            dbg!(&ereports).len(),
            0,
            "expected 0 ereports, but got: {ereports:#?}"
        );
    }

    #[test]
    fn decode_empty_packets() {
        let mut packet = [0u8; 1024];
        let restart_id = Uuid::new_v4();
        let start_ena = Ena(0);
        let request_id = RequestIdV0(1);

        let header = EreportResponseHeader::V0(ResponseHeaderV0 {
            restart_id: RestartId(restart_id.as_u128()),
            request_id,
        });
        let end = {
            let mut len = hubpack::serialize(&mut packet, &header)
                .expect("header should serialize");

            // Empty metadata map
            len +=
                serialize_metadata(&mut packet[len..], &MetadataMap::default());

            // Start ENA
            len += hubpack::serialize(&mut packet[len..], &start_ena)
                .expect("ENA should serialize");

            // Empty ereport list.
            len += serialize_ereport_list(&mut packet[len..], &[]);
            len
        };
        let packet = &packet[..end];
        dump_packet(packet);

        let initial_meta = json_map! {
            KEY_ARCHIVE: "decadefaced".to_string(),
            KEY_SERIAL: "BRM69000420".to_string(),
        };
        let mut meta = Some(initial_meta.clone());

        let (decoded_restart_id, decoded_request_id, ereports) =
            decode_packet(restart_id, &mut meta, packet);

        assert_eq!(decoded_restart_id, restart_id);
        assert_eq!(decoded_request_id, request_id);
        assert_eq!(
            dbg!(meta.as_ref()),
            Some(&initial_meta),
            "metadata should be unchanged"
        );

        assert_eq!(
            dbg!(&ereports).len(),
            0,
            "expected 0 ereports, but got: {ereports:#?}"
        );
    }
}
