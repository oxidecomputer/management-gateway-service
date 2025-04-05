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
use gateway_messages::ereport::RequestV0;
use gateway_messages::ereport::ResponseHeaderV0;
use gateway_messages::ereport::ResponseKindV0;
pub use gateway_messages::ereport::RestartId;
use serde_cbor::Value as CborValue;
use serde_json::Value as JsonValue;
use slog::debug;
use slog::error;
use slog::info;
use slog::trace;
use slog::warn;
use slog_error_chain::SlogInlineError;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::oneshot;

pub const SP_PORT: u16 = 0xDEAD;
pub const MGS_PORT: u16 = 0xDEAF;

pub struct EreportHandler {
    log: slog::Logger,
}

impl EreportHandler {
    pub fn new(log: slog::Logger) -> Self {
        Self { log }
    }
}

#[derive(Debug)]
pub struct EreportTranche {
    pub restart_id: RestartId,
    pub ereports: Vec<Ereport>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Ereport {
    pub ena: Ena,
    pub data: serde_json::Map<String, JsonValue>,
}

pub(crate) struct WorkerRequest {
    pub(crate) restart_id: RestartId,
    pub(crate) start_ena: Ena,
    pub(crate) committed_ena: Option<Ena>,
    pub(crate) rsp_tx: oneshot::Sender<Result<EreportTranche, EreportError>>,
}

pub(crate) struct Worker<S> {
    req_rx: mpsc::Receiver<WorkerRequest>,
    retry_config: SpRetryConfig,
    socket: S,
    outbuf: [u8; <EreportRequest as hubpack::SerializedSize>::MAX_SIZE],
    metadata: Option<serde_json::Map<String, JsonValue>>,
}

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
                match self
                    .request_ereports(&EreportRequest::V0(RequestV0::new(
                        RestartId(0),
                        Ena(0),
                        None,
                    )))
                    .await
                {
                    Ok((restart_id, Response::Metadata(metadata))) => {
                        debug!(
                            self.log(),
                            "received initial SP metadata";
                            "metadata" => ?metadata,
                            "restart_id" => ?restart_id
                        );
                        self.metadata = Some(metadata);
                    }
                    Ok((restart_id, _)) => {
                        warn!(
                            self.log(),
                            "unexpected response to metadata request (it \
                             should always be `Restarted`)";
                            "restart_id" => ?restart_id,
                        );

                        // TODO(eliza): should we...keep trying, or something? The
                        // SP is definitely *alive*...
                        if req
                            .rsp_tx
                            .send(Err(EreportError::ThisIsntMetadata))
                            .is_err()
                        {
                            warn!(self.log(), "ereport request cancelled");
                        };
                        continue;
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

            // Okay, actually get some ereports.
            let mut restart_id = req.restart_id;
            let mut start_ena = req.start_ena;
            let mut committed_ena = req.committed_ena;
            let result = loop {
                match self
                    .request_ereports(&EreportRequest::V0(RequestV0::new(
                        restart_id,
                        start_ena,
                        committed_ena,
                    )))
                    .await
                {
                    Err(error) => {
                        warn!(
                            self.log(),
                            "error requesting SP ereports";
                            &error,
                            "req_restart_id" => ?restart_id,
                            "req_start_ena" => ?start_ena,
                            "req_committed_ena" => ?committed_ena
                        );
                        break Err(error);
                    }
                    Ok((new_restart_id, Response::Metadata(metadata))) => {
                        info!(
                            self.log(),
                            "SP has restarted";
                            "req_restart_id" => ?restart_id,
                            "req_start_ena" => ?start_ena,
                            "req_committed_ena" => ?committed_ena,
                            "sp_restart_id" => ?new_restart_id,
                            "metadata" => ?metadata,
                        );
                        self.metadata = Some(metadata);
                        // Reset the request for the new restart ID, starting at
                        // ENA 0 and not committing any of this restart's ENA.
                        restart_id = new_restart_id;
                        start_ena = Ena(0);
                        committed_ena = None;
                    }
                    Ok((restart_id, Response::Ereports(ereports))) => {
                        debug!(
                            self.log(),
                            "received {} ereports", ereports.len();
                            "req_restart_id" => ?restart_id,
                            "req_start_ena" => ?start_ena,
                            "req_committed_ena" => ?committed_ena,
                        );
                        break Ok(EreportTranche { restart_id, ereports });
                    }
                }
            };
            if req.rsp_tx.send(result).is_err() {
                warn!(self.log(), "ereport request cancelled");
            };
        }
    }

    fn log(&self) -> &slog::Logger {
        self.socket.log()
    }

    async fn request_ereports(
        &mut self,
        req: &EreportRequest,
    ) -> Result<(RestartId, Response), EreportError> {
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
        let packet = &self.outbuf[..amt];
        for attempt in 1..=self.retry_config.max_attempts_general {
            slog::trace!(
                self.log(),
                "sending ereport request to SP";
                "request" => ?req,
                "attempt" => attempt,
            );
            self.socket.send(packet).await?;
            if let Ok(Some(msg)) = tokio::time::timeout(
                self.retry_config.per_attempt_timeout,
                self.socket.recv(),
            )
            .await
            {
                return decode_packet(&self.metadata, &msg).map_err(Into::into);
            }
        }

        Err(EreportError::Communication(
            CommunicationError::ExhaustedNumAttempts(
                self.retry_config.max_attempts_general,
            ),
        ))
    }
}

fn decode_packet(
    metadata: &Option<serde_json::Map<String, JsonValue>>,
    packet: &[u8],
) -> Result<(RestartId, Response), DecodeError> {
    let (header, rest) =
        gateway_messages::deserialize::<EreportResponseHeader>(packet)
            .map_err(DecodeError::Header)?;
    match header {
        // Packet is empty
        EreportResponseHeader::V0(ResponseHeaderV0 {
            kind: ResponseKindV0::Empty,
            restart_id,
            ..
        }) => Ok((restart_id, Response::Ereports(Vec::new()))),
        // Packet is data
        EreportResponseHeader::V0(ResponseHeaderV0 {
            kind: ResponseKindV0::Data,
            restart_id,
            ..
        }) => {
            // V0 ereport packets consist of:
            //
            // - the first ENA in the packet
            // - a CBOR list (using the "indeterminate") encoding, where each
            //   entry is a CBOR list of 4 elements:
            //      1. the name of the task that produced the ereport
            //      2. the task's generation number
            //      3. the system uptime in milliseconds
            //      4. a CBOR object containing the rest of the ereport
            //
            // See RFD 545 4.4 for details:
            // https://rfd.shared.oxide.computer/rfd/0545#_readresponse
            let (start_ena, rest) = gateway_messages::deserialize::<Ena>(rest)
                .map_err(DecodeError::Ena)?;
            let cbor_ereports =
                serde_cbor::from_slice::<Vec<Vec<CborValue>>>(rest)
                    .map_err(DecodeError::EreportsDeserialize)?;

            let mut json_ereports = Vec::with_capacity(cbor_ereports.len());
            let mut task_names = Vec::new();
            let mut ena = start_ena;
            for (n, mut parts) in cbor_ereports.into_iter().enumerate() {
                let ereport =
                    parts.pop().ok_or(DecodeError::MalformedEreport {
                        n,
                        msg: "ereport list empty",
                    })?;
                let uptime =
                    parts.pop().ok_or(DecodeError::MalformedEreport {
                        n,
                        msg: "missing Hubris uptime list entry",
                    })?;
                let task_gen =
                    parts.pop().ok_or(DecodeError::MalformedEreport {
                        n,
                        msg: "missing task generation list entry",
                    })?;
                let task_name = match parts.pop() {
                    Some(CborValue::Text(name)) => {
                        task_names.push(name.clone());
                        name
                    }
                    Some(CborValue::Integer(i)) => task_names
                        .get(i as usize)
                        .cloned()
                        .ok_or(DecodeError::BadTaskNameIndex {
                            n,
                            index: i as usize,
                        })?,
                    Some(actual) => {
                        return Err(DecodeError::InvalidTaskNameType {
                            n,
                            actual,
                        })
                    }
                    None => {
                        return Err(DecodeError::MalformedEreport {
                            n,
                            msg: "missing task name list entry",
                        })
                    }
                };
                if !parts.is_empty() {
                    return Err(DecodeError::MalformedEreport {
                        n,
                        msg: "unexpected bonus stuff in ereports list",
                    });
                }
                let CborValue::Map(cbor_ereport) = ereport else {
                    return Err(DecodeError::MalformedEreport {
                        n,
                        msg: "expected ereport to be an object",
                    });
                };
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
                    metadata
                        .iter()
                        .flatten()
                        .map(|(k, v)| (k.clone(), v.clone())),
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
                json_ereports.push(Ereport { ena, data });

                // Increment the ENA for the next ereport in the packet.
                ena.0 += 1;
            }

            Ok((restart_id, Response::Ereports(json_ereports)))
        }
        // The party you are attempting to dial is not available. Please refresh
        // your metadata and try again.
        EreportResponseHeader::V0(ResponseHeaderV0 {
            kind: ResponseKindV0::Restarted,
            restart_id,
            ..
        }) => {
            let cbor_meta =
                serde_cbor::from_slice::<BTreeMap<String, CborValue>>(rest)
                    .map_err(DecodeError::MetadataDeserialize)?;
            let mut json_meta = serde_json::Map::with_capacity(cbor_meta.len());
            for (key, value) in cbor_meta {
                json_meta.insert(
                    key,
                    convert_cbor_value(value)
                        .map_err(DecodeError::MetadataJson)?,
                );
            }
            Ok((restart_id, Response::Metadata(json_meta)))
        }
    }
}

#[derive(Debug)]
enum Response {
    Metadata(serde_json::Map<String, JsonValue>),
    Ereports(Vec<Ereport>),
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
    use serde_json::value::Number as JsonNumber;

    Ok(match value {
        CborValue::Null => JsonValue::Null,
        CborValue::Bool(b) => JsonValue::Bool(b),
        CborValue::Float(cbor) => {
            // A JSON number may not be infinite or NaN, so return an error if
            // the float is unacceptable.
            let json = JsonNumber::from_f64(cbor)
                .ok_or(CborToJsonError::InvalidFloat(cbor))?;
            JsonValue::Number(json)
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
        CborValue::Bytes(_) => todo!("eliza"),
        CborValue::Tag(_, _) => {
            return Err(CborToJsonError::TagsNotYetImplemented)
        }
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

#[derive(Debug, Error, SlogInlineError)]
pub enum CborToJsonError {
    #[error("non-string object key: {0:?}")]
    NonStringKey(CborValue),
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
    async fn run(
        self,
        socket: Arc<UdpSocket>,
        sps: shared_socket::SpDispatcher<Self::Message>,
    ) {
        // TODO(eliza): a bunch of this code is identical to
        // `ControlPlaneAgentHandler; `RecvHandler` trait could probably just be
        // a "parse and handle message" callback...

        // TODO(eliza): double check that `MAX_SERIALIZED_SIZE` is indeed the
        // largest UDP datagram we can receive from a SP?
        let mut buf = [0; gateway_messages::MAX_SERIALIZED_SIZE];
        loop {
            let (n, peer) = match socket.recv_from(&mut buf).await {
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
                        self.log,
                        "failed to recv on shared MGS ereport socket";
                        "err" => %err,
                    );
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            // Before doing anything else, check our peer's scope ID: If we
            // don't have a `SingleSp` handler for the interface identified by
            // that scope ID, discard this packet.
            let peer_interface = match sps
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
            if !sps
                .single_sp_handlers
                .lock()
                .await
                .contains_key(&peer_interface)
            {
                warn!(
                    self.log,
                    "discarding packet from unknown interface";
                    "interface" => peer_interface.to_string(),
                );
                continue;
            }

            let data = &buf[..n];
            if let Err(err) =
                sps.forward_to_single_sp(peer, data.to_vec()).await
            {
                warn!(
                    self.log,
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
        vec![
            task_name,
            CborValue::from(task_gen),
            CborValue::from(uptime),
            CborValue::from(body),
        ]
    }

    const TASK_NAME_THINGY: &str = "drv_thingy_server";
    const TASK_NAME_APOLLO_13: &str = "task_apollo_server";
    const KEY_ARCHIVE: &str = "hubris_archive_id";
    const KEY_TASK: &str = "hubris_task_name";
    const KEY_GEN: &str = "hubris_task_gen";
    const KEY_UPTIME: &str = "hubris_uptime_ms";
    const KEY_SERIAL: &str = "baseboard_serial";

    #[test]
    fn decode_ereports() {
        let mut packet = [0u8; 1024];
        let restart_id = RestartId(0xfeedf00d);
        let start_ena = Ena(42);

        let header =
            EreportResponseHeader::V0(ResponseHeaderV0::new_data(restart_id));
        let end = {
            let mut len = hubpack::serialize(&mut packet, &header)
                .expect("header should serialize");
            len += hubpack::serialize(&mut packet[len..], &start_ena)
                .expect("ENA should serialize");
            let mut cursor = Cursor::new(&mut packet[len..]);
            serde_cbor::to_writer(
                &mut cursor,
                &vec![
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
            )
            .expect("ereports must serialize");
            len + cursor.position() as usize
        };
        let packet = &packet[..end];

        let meta = Some(json_map! {
            KEY_ARCHIVE: "decadefaced".to_string(),
            KEY_SERIAL: "BRM69000420".to_string(),
        });

        let (decoded_restart_id, rsp) = match decode_packet(&meta, packet) {
            Ok((restart_id, rsp)) => (restart_id, rsp),
            Err(e) => panic!("packet did not decode successfully: {e:#?}"),
        };

        assert_eq!(dbg!(decoded_restart_id), restart_id);
        let ereports = match rsp {
            Response::Ereports(ereports) => ereports,
            Response::Metadata(meta) => {
                panic!("expected ereports, but decoded metadata: {meta:?}")
            }
        };

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
}
