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
use base64::{
    engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD},
    Engine,
};
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
use slog_error_chain::InlineErrorChain;
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

/// An individual ereport.
#[derive(Debug, Eq, PartialEq)]
pub struct Ereport {
    pub ena: Ena,
    pub data: JsonObject,
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
    metadata: Option<JsonObject>,
}

type JsonObject = serde_json::Map<String, JsonValue>;

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
                    Ok(EreportTranche { restart_id, ereports }) => {
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
                Ok(tranche) => {
                    debug!(
                        self.log(),
                        "received {} ereports", tranche.ereports.len();
                        "restart_id" => ?tranche.restart_id,
                        "req_restart_id" => ?req.restart_id,
                        "req_start_ena" => ?req.start_ena,
                        "req_limit" => ?req.limit,
                        "req_committed_ena" => ?req.committed_ena,
                    );
                    Ok(tranche)
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
    ) -> Result<EreportTranche, EreportError> {
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
                trace!(
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
                            debug!(
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
                                self.socket.log(),
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

// JSON key names for well-known fields in ereport packets.
const KEY_TASK_NAME: &str = "hubris_task_name";
const KEY_TASK_GEN: &str = "hubris_task_gen";
const KEY_UPTIME: &str = "hubris_uptime_ms";
const KEY_PROTO_VERSION: &str = "ereport_message_version";

fn decode_header(
    packet: &[u8],
) -> Result<(EreportResponseHeader, &[u8]), DecodeError> {
    gateway_messages::deserialize::<EreportResponseHeader>(packet)
        .map_err(DecodeError::Header)
}

fn decode_body_v0(
    log: &slog::Logger,
    requested_restart_id: Uuid,
    header: &ResponseHeaderV0,
    metadata: &mut Option<JsonObject>,
    packet: &[u8],
) -> Result<EreportTranche, DecodeError> {
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

    let restart_id = Uuid::from_u128(header.restart_id.0);
    //  As described in RFD 545 4.4:
    //  https://rfd.shared.oxide.computer/rfd/0545#_readresponse
    //
    // V0 ereport packets consit of the following:
    //
    // 1. A CBOR map (using the "indefinite-length" encoding) of strings to
    //    CBOR values, containing metadata.
    //
    //    If the requested restart ID matches the current one, the metadata
    //    map will generally be empty.
    //
    //    The packet may end here if it contains no ereports.
    let (cbor_metadata, packet) =
        deserialize_cbor::<BTreeMap<CborValue, CborValue>>(packet)
            .map_err(DecodeError::MetadataDeserialize)?;
    let mut new_metadata = serde_json::Map::with_capacity(cbor_metadata.len());
    convert_cbor_object_into(cbor_metadata, &mut new_metadata)
        .map_err(DecodeError::MetadataJson)?;

    if !new_metadata.is_empty() || restart_id != requested_restart_id {
        debug!(
            log,
            "updating ereport metadata";
            "restart_id" => ?restart_id,
            "requested_restart_id" => ?requested_restart_id,
            "metadata" => ?new_metadata,
        );
        *metadata = Some(new_metadata);
    }
    if packet.is_empty() {
        return Ok(EreportTranche { restart_id, ereports: Vec::new() });
    }
    // 2. If the packet contains ereports, the ENA of the first ereport in the
    //    packet.
    let (start_ena, packet) = gateway_messages::deserialize::<Ena>(packet)
        .map_err(DecodeError::Ena)?;
    // 3. A CBOR list of ereports (using the "indefinite-length" encoding),
    //    where each entry is a CBOR list of 4 elements:
    //      1. The name of the task that produced the ereport,
    //         which is encoded either as a CBOR string, or as the integer
    //         index of a previous ereport in the packet.
    //      2. The task's generation number
    //      3. The system uptime in milliseconds
    //      4. A CBOR byte array containing the body of the ereport. The bytes
    //         in this array should be decoded as a map of strings to CBOR
    //         values, but they are encoded as an array within the outer
    //         message to escape any potentially malformed ereport data.
    #[derive(serde::Deserialize)]
    struct EreportEntry<'a>(
        TaskNameV0<'a>,
        u8,
        u32,
        #[serde(with = "serde_bytes")] &'a [u8],
    );

    let metadata = metadata.as_ref();
    let meta_len = metadata.map(JsonObject::len).unwrap_or(0);
    let cbor_ereports = serde_cbor::from_slice::<Vec<EreportEntry>>(packet)
        .map_err(DecodeError::EreportsDeserialize)?;
    let mut ereports = Vec::with_capacity(cbor_ereports.len());

    // Number of extra fields added to every ereport's body by the gateway.
    const EXTRA_FIELDS: usize = {
        1   // task name
        + 1 // task generation
        + 1 // hubris uptime
        + 1 // ereport protocol version
    };

    let decode_entry = |&EreportEntry(task_name, _, _, body_bytes)| -> Result<(String, JsonObject),EreportDecodeError> {
        let task_name = {
            // The task name may either be a string or the index of a previous
            // task name in the packet.
            //
            // I doubt the SP will emit task name indices that point at an
            // ereport whose task name is also an index, but it's not *that*
            // much harder to handle this case and continue traversing...
            let mut current_name = task_name;
            loop {
                match current_name {
                    TaskNameV0::Index(i) => {
                        let &EreportEntry(name, _, _, _) = cbor_ereports.get(i).ok_or(EreportDecodeError::TaskNameIndex(i))?;
                        current_name = name;
                    },
                    TaskNameV0::Name(s) => {
                        break s.to_owned();
                    }
                }
            }
        };
        // Decode the body, which is a byte array containing a CBOR-encoded map.
        let cbor_body = serde_cbor::from_slice::<BTreeMap<CborValue, CborValue>>(
            body_bytes,
        )?;

        let mut data = serde_json::Map::with_capacity(
            // Let's just do One Big Allocation with enough space for
            // the whole thing! We'll need:
            cbor_body.len() + meta_len + EXTRA_FIELDS,
        );
        convert_cbor_object_into(cbor_body, &mut data)?;
        Ok((task_name, data))
    };

    let mut ena = start_ena;
    for ereport @ &EreportEntry(task_name, task_gen, uptime_ms, body_bytes) in
        &cbor_ereports
    {
        let mut data = match decode_entry(ereport) {
            Ok((task_name, mut data)) => {
                trace!(
                    log,
                    "decoded ereport";
                    "ena" => ?ena,
                    KEY_TASK_NAME => &task_name,
                    KEY_TASK_GEN => task_gen,
                    KEY_UPTIME => uptime_ms,
                    "data" => ?data,
                );
                data.insert(KEY_TASK_NAME.to_string(), task_name.into());
                data
            }
            Err(error) => {
                // If attempting to interpret an ereport entry fails, we emit a
                // "malformed ereport" entry and continue processing the rest of
                // the ereports. Malformed ereports are emitted in situations
                // where the data controlled by the Hubris task that *generated*
                // the ereport is incorrect (e.g. it is not valid CBOR, or the
                // CBOR cannot be converted to JSON nicely). This way,
                // well-formed ereports from other tasks are not discarded if
                // one task has misbehaved. We assume that the data coming from
                // `packrat` must be correct, and give up on the whole packet if
                // this is not the case, as a bug in how the packrat task
                // encodes ereports would effect all data in the packet.
                warn!(
                    log,
                    "received a malformed ereport";
                    "ena" => ?ena,
                    KEY_TASK_NAME => ?task_name,
                    KEY_TASK_GEN => task_gen,
                    KEY_UPTIME => uptime_ms,
                    "error" => &error,
                );
                let mut data = serde_json::Map::with_capacity(
                    meta_len
                    + EXTRA_FIELDS
                    + 1  // error message
                    + 1, // body bytes
                );
                data.insert(
                    "invalid_ereport_error".to_string(),
                    InlineErrorChain::new(&error).to_string().into(),
                );
                data.insert(
                    "invalid_ereport_body_bytes".to_string(),
                    URL_SAFE_NO_PAD.encode(body_bytes).into(),
                );
                data.insert(
                    KEY_TASK_NAME.to_string(),
                    match task_name {
                        TaskNameV0::Name(name) => name.to_owned().into(),
                        TaskNameV0::Index(i) => i.into(),
                    },
                );
                data
            }
        };

        // Populate task generation, uptime, ereport message version, and
        // metadata regardless of whether the ereport body was decoded
        // successfully or not.
        data.insert(KEY_TASK_GEN.to_string(), task_gen.into());
        data.insert(KEY_UPTIME.to_string(), uptime_ms.into());
        // If the ereport was decoded by this function, the protocol version is
        // always 0 --- this is `decode_body_v0` :)
        data.insert(KEY_PROTO_VERSION.to_string(), 0.into());
        data.extend(
            metadata
                .into_iter()
                .flat_map(JsonObject::iter)
                .map(|(k, v)| (k.clone(), v.clone())),
        );

        ereports.push(Ereport { ena, data });

        // Increment the ENA for the next ereport in the packet.
        ena.0 += 1;
    }

    Ok(EreportTranche { restart_id, ereports })
}

#[derive(Debug, Error, SlogInlineError)]
pub enum DecodeError {
    #[error("failed to deserialize ereport response header")]
    Header(#[source] hubpack::Error),
    #[error("failed to deserialize ereport response ENA")]
    Ena(#[source] hubpack::Error),
    #[error("failed to deserialize ereports")]
    EreportsDeserialize(#[source] serde_cbor::Error),
    #[error("failed to deserialize ereport metadata refresh fragment")]
    MetadataDeserialize(#[source] serde_cbor::Error),
    #[error("failed to convert metadata refresh fragment to JSON")]
    MetadataJson(#[source] CborToJsonError),
}

/// Errors that may occur while decoding an individual ereport.
#[derive(Debug, Error, SlogInlineError)]
enum EreportDecodeError {
    #[error("invalid body CBOR")]
    Parse(#[from] serde_cbor::Error),
    #[error("task name index {0} out of range")]
    TaskNameIndex(usize),
    #[error("body CBOR cannot be converted to JSON")]
    BodyToJson(#[from] CborToJsonError),
}

fn convert_cbor_value(value: CborValue) -> Result<JsonValue, CborToJsonError> {
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
    // XXX(eliza): it would be much more efficient if we could call
    // `json.reserve(cbor.len())` here before we append stuff to it, but
    // unfortunately, `serde_json::map::Map` has a `with_capacity` constructor
    // but no `reserve` method... :(
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

#[derive(Copy, Clone, Debug, serde::Deserialize)]
#[serde(untagged)]
enum TaskNameV0<'a> {
    Index(usize),
    Name(&'a str),
}

#[cfg(test)]
mod test {
    use super::*;
    use serde::Serializer;
    use std::io::Cursor;

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

    fn logger(test_name: &'static str) -> slog::Logger {
        use slog::Drain;
        let decorator =
            slog_term::PlainSyncDecorator::new(slog_term::TestStdoutWriter);
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        slog::Logger::root(drain, slog::o!("test" => test_name))
    }

    fn mk_ereport_list(
        task_name: TaskNameV0<'_>,
        task_gen: u32,
        uptime: u64,
        body: BTreeMap<CborValue, CborValue>,
    ) -> Vec<CborValue> {
        let task_name = match task_name {
            TaskNameV0::Index(i) => CborValue::Integer(i as i128),
            TaskNameV0::Name(s) => CborValue::Text(s.to_string()),
        };
        // The body itself is serialized as a CBOR byte array, to escape the
        // payload from the reporting task (in case it e.g. contains CBOR break
        // bytes in wrong locations).
        let body_bytes = match serde_cbor::to_vec(&body) {
            Ok(bytes) => bytes,
            Err(e) => {
                panic!("failed to serialize ereport body: {e}\nbody: {body:#?}")
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
    const KEY_SERIAL: &str = "baseboard_serial";
    const KEY_ARCHIVE: &str = "hubris_archive_id";

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
        metadata: &JsonObject,
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
        log: &slog::Logger,
        restart_id: Uuid,
        metadata: &mut Option<JsonObject>,
        packet: &[u8],
    ) -> (Uuid, RequestIdV0, Vec<Ereport>) {
        dump_packet(packet);
        let (header, packet) = match decode_header(packet) {
            Ok((EreportResponseHeader::V0(header), packet)) => {
                (dbg!(header), packet)
            }
            Err(e) => panic!("header did not decode: {e:#?}"),
        };
        let EreportTranche { restart_id, ereports } =
            match decode_body_v0(log, restart_id, &header, metadata, packet) {
                Ok(ereports) => ereports,
                Err(e) => panic!("body did not decode: {e:#?}"),
            };
        (restart_id, header.request_id, ereports)
    }

    #[track_caller]
    fn assert_ereport_matches(ereport: &Ereport, ena: Ena, data: JsonObject) {
        assert_eq!(dbg!(ereport.ena), ena);
        assert_eq!(dbg!(&ereport.data), &data);
    }

    #[test]
    fn decode_ereports() {
        let log = logger("decode_ereports");
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
                serialize_metadata(&mut packet[len..], &JsonObject::default());

            // Start ENA
            len += hubpack::serialize(&mut packet[len..], &start_ena)
                .expect("ENA should serialize");
            len += serialize_ereport_list(
                &mut packet[len..],
                &[
                    mk_ereport_list(
                        TaskNameV0::Name(TASK_NAME_THINGY),
                        1,
                        569,
                        cbor_map! {
                            "class": "flagrant system error".to_string(),
                            "badness": 10000,
                        },
                    ),
                    mk_ereport_list(
                        TaskNameV0::Name(TASK_NAME_APOLLO_13),
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
                        TaskNameV0::Index(0),
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
            decode_packet(&log, restart_id, &mut meta, packet);

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

        assert_ereport_matches(
            &ereports[0],
            start_ena,
            json_map! {
                KEY_ARCHIVE: "decadefaced",
                KEY_SERIAL: "BRM69000420",
                KEY_TASK_NAME: TASK_NAME_THINGY,
                KEY_TASK_GEN: 1,
                KEY_UPTIME: 569,
                KEY_PROTO_VERSION: 0,
                "class": "flagrant system error",
                "badness": 10000,
            },
        );

        assert_ereport_matches(
            &ereports[1],
            Ena(start_ena.0 + 1),
            json_map! {
                KEY_ARCHIVE: "decadefaced",
                KEY_SERIAL: "BRM69000420",
                KEY_TASK_NAME: TASK_NAME_APOLLO_13,
                KEY_TASK_GEN: 13,
                KEY_UPTIME: 572,
                KEY_PROTO_VERSION: 0,
                "msg": "houston, we have a problem",
                "crew": ["Lovell", "Swigert", "Hayes"],
            },
        );

        assert_ereport_matches(
            &ereports[2],
            Ena(start_ena.0 + 2),
            json_map! {
                KEY_ARCHIVE: "decadefaced",
                KEY_SERIAL: "BRM69000420",
                KEY_TASK_NAME: TASK_NAME_THINGY,
                KEY_TASK_GEN: 1,
                KEY_UPTIME: 575,
                KEY_PROTO_VERSION: 0,
                "class": "problem changed",
                "bonus_stuff": { "foo": 1, "bar": 2, },
            },
        );
    }

    // Test decoding ereports whose task names are the index of a prior ereport
    // in the packet.
    #[test]
    fn decode_task_name_indices() {
        let log = logger("decode_task_name_indices");
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
                serialize_metadata(&mut packet[len..], &JsonObject::default());

            // Start ENA
            len += hubpack::serialize(&mut packet[len..], &start_ena)
                .expect("ENA should serialize");
            len += serialize_ereport_list(
                &mut packet[len..],
                &[
                    mk_ereport_list(
                        TaskNameV0::Name(TASK_NAME_THINGY),
                        1,
                        569,
                        cbor_map! {
                            "class": "flagrant system error".to_string(),
                            "badness": 10000,
                        },
                    ),
                    mk_ereport_list(
                        TaskNameV0::Index(0),
                        1,
                        572,
                        cbor_map! {
                            "class": "hello world".to_string(),
                        },
                    ),
                    mk_ereport_list(
                        TaskNameV0::Index(1),
                        1,
                        575,
                        cbor_map! {
                           "class": "cool ereport".to_string(),
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
            decode_packet(&log, restart_id, &mut meta, packet);

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

        assert_ereport_matches(
            &ereports[0],
            start_ena,
            json_map! {
                KEY_ARCHIVE: "decadefaced",
                KEY_SERIAL: "BRM69000420",
                KEY_TASK_NAME: TASK_NAME_THINGY,
                KEY_TASK_GEN: 1,
                KEY_UPTIME: 569,
                KEY_PROTO_VERSION: 0,
                "class": "flagrant system error",
                "badness": 10000,
            },
        );

        assert_ereport_matches(
            &ereports[1],
            Ena(start_ena.0 + 1),
            json_map! {
                KEY_ARCHIVE: "decadefaced",
                KEY_SERIAL: "BRM69000420",
                KEY_TASK_NAME: TASK_NAME_THINGY,
                KEY_TASK_GEN: 1,
                KEY_UPTIME: 572,
                KEY_PROTO_VERSION: 0,
                "class": "hello world",
            },
        );

        assert_ereport_matches(
            &ereports[2],
            Ena(start_ena.0 + 2),
            json_map! {
                KEY_ARCHIVE: "decadefaced",
                KEY_SERIAL: "BRM69000420",
                KEY_TASK_NAME: TASK_NAME_THINGY,
                KEY_TASK_GEN: 1,
                KEY_UPTIME: 575,
                KEY_PROTO_VERSION: 0,
                "class": "cool ereport",
            },
        );
    }

    #[test]
    fn decode_ereports_and_meta() {
        let log = logger("decode_ereports_and_meta");
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
                        TaskNameV0::Name(TASK_NAME_THINGY),
                        1,
                        569,
                        cbor_map! {
                            "class": "flagrant system error".to_string(),
                            "badness": 10000,
                        },
                    ),
                    mk_ereport_list(
                        TaskNameV0::Name(TASK_NAME_APOLLO_13),
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
                        TaskNameV0::Index(0),
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
            decode_packet(&log, Uuid::new_v4(), &mut meta, packet);
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

        assert_ereport_matches(
            &ereports[0],
            Ena(0),
            json_map! {
                KEY_ARCHIVE: "defaceddead".to_string(),
                KEY_SERIAL: "BRM69000666".to_string(),
                "sled_is_evil": true,
                KEY_TASK_NAME: TASK_NAME_THINGY,
                KEY_TASK_GEN: 1,
                KEY_UPTIME: 569,
                KEY_PROTO_VERSION: 0,
                "class": "flagrant system error",
                "badness": 10000,
            },
        );

        assert_ereport_matches(
            &ereports[1],
            Ena(1),
            json_map! {
                KEY_ARCHIVE: "defaceddead".to_string(),
                KEY_SERIAL: "BRM69000666".to_string(),
                "sled_is_evil": true,
                KEY_TASK_NAME: TASK_NAME_APOLLO_13,
                KEY_TASK_GEN: 13,
                KEY_UPTIME: 572,
                KEY_PROTO_VERSION: 0,
                "msg": "houston, we have a problem",
                "crew": ["Lovell", "Swigert", "Hayes"],
            },
        );

        assert_ereport_matches(
            &ereports[2],
            Ena(2),
            json_map! {
                KEY_ARCHIVE: "defaceddead".to_string(),
                KEY_SERIAL: "BRM69000666".to_string(),
                "sled_is_evil": true,
                KEY_TASK_NAME: TASK_NAME_THINGY,
                KEY_TASK_GEN: 1,
                KEY_UPTIME: 575,
                KEY_PROTO_VERSION: 0,
                "class": "problem changed",
                "bonus_stuff": { "foo": 1, "bar": 2, },
            },
        );
    }

    #[test]
    fn decode_meta_only() {
        let log = logger("decode_meta_only");
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

        let mut found_meta = None;

        let (decoded_restart_id, decoded_request_id, ereports) =
            decode_packet(&log, restart_id, &mut found_meta, packet);
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
        let log = logger("decode_empty_packets");
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
                serialize_metadata(&mut packet[len..], &JsonObject::default());

            // Start ENA
            len += hubpack::serialize(&mut packet[len..], &start_ena)
                .expect("ENA should serialize");

            // Empty ereport list.
            len += serialize_ereport_list(&mut packet[len..], &[]);
            len
        };
        let packet = &packet[..end];

        let initial_meta = json_map! {
            KEY_ARCHIVE: "decadefaced".to_string(),
            KEY_SERIAL: "BRM69000420".to_string(),
        };
        let mut meta = Some(initial_meta.clone());

        let (decoded_restart_id, decoded_request_id, ereports) =
            decode_packet(&log, restart_id, &mut meta, packet);

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

    // Tests that a packet containing a single ereport whose body is not
    // well-formed CBOR does not result in the rest of the packet being
    // rejected.
    #[test]
    fn malformed_ereport_body_doesnt_ruin_packet() {
        let log = logger("malformed_ereport_body_doesnt_ruin_packet");
        let mut packet = [0u8; 1024];
        let restart_id = Uuid::new_v4();
        let request_id = RequestIdV0(1);
        let start_ena = Ena(42);
        let bad_body = vec![0xBA, 0xDB, 0xAD]; // ba db ad

        let header = EreportResponseHeader::V0(ResponseHeaderV0 {
            restart_id: RestartId(restart_id.as_u128()),
            request_id,
        });
        let end = {
            let mut len = hubpack::serialize(&mut packet, &header)
                .expect("header should serialize");

            // Empty metadata map
            len +=
                serialize_metadata(&mut packet[len..], &JsonObject::default());

            // Start ENA
            len += hubpack::serialize(&mut packet[len..], &start_ena)
                .expect("ENA should serialize");
            len += serialize_ereport_list(
                &mut packet[len..],
                &[
                    mk_ereport_list(
                        TaskNameV0::Name(TASK_NAME_THINGY),
                        1,
                        569,
                        cbor_map! {
                            "class": "flagrant system error".to_string(),
                            "badness": 10000,
                        },
                    ),
                    // Rather than a CBOR map, the body bytes of this ereport is
                    // just some gibberish.
                    vec![
                        "task_wrong_ereport_server".to_string().into(),
                        1.into(),
                        570.into(),
                        CborValue::Bytes(bad_body.clone()),
                    ],
                    mk_ereport_list(
                        TaskNameV0::Index(0),
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
            decode_packet(&log, restart_id, &mut meta, packet);

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

        assert_ereport_matches(
            &ereports[0],
            start_ena,
            json_map! {
                KEY_ARCHIVE: "decadefaced",
                KEY_SERIAL: "BRM69000420",
                KEY_TASK_NAME: TASK_NAME_THINGY,
                KEY_TASK_GEN: 1,
                KEY_UPTIME: 569,
                KEY_PROTO_VERSION: 0,
                "class": "flagrant system error",
                "badness": 10000,
            },
        );

        assert_ereport_matches(
            &ereports[1],
            Ena(start_ena.0 + 1),
            json_map! {
                KEY_ARCHIVE: "decadefaced",
                KEY_SERIAL: "BRM69000420",
                KEY_TASK_NAME: "task_wrong_ereport_server",
                KEY_TASK_GEN: 1,
                KEY_UPTIME: 570,
                KEY_PROTO_VERSION: 0,
                "invalid_ereport_body_bytes": URL_SAFE_NO_PAD.encode(&bad_body),
                "invalid_ereport_error":
                    "invalid body CBOR: EOF while parsing a value at offset 3",
            },
        );

        assert_ereport_matches(
            &ereports[2],
            Ena(start_ena.0 + 2),
            json_map! {
                KEY_ARCHIVE: "decadefaced",
                KEY_SERIAL: "BRM69000420",
                KEY_TASK_NAME: TASK_NAME_THINGY,
                KEY_TASK_GEN: 1,
                KEY_UPTIME: 575,
                KEY_PROTO_VERSION: 0,
                "class": "problem changed",
                "bonus_stuff": { "foo": 1, "bar": 2, },
            },
        );
    }
}
