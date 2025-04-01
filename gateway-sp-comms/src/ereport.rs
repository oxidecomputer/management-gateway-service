// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

use crate::shared_socket;
use async_trait::async_trait;
use gateway_messages::ereport::Ena;
use gateway_messages::ereport::RestartId;
use slog::error;
use slog::warn;
use slog_error_chain::SlogInlineError;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::net::UdpSocket;

pub const SP_PORT: u16 = 0xDEAD;

pub struct EreportHandler {
    log: slog::Logger,
}

pub enum EreportMessage {
    Empty {
        restart_id: RestartId,
    },
    Data {
        restart_id: RestartId,
        start_ena: Ena,
        ereports: Vec<serde_cbor::Value>,
    },
    /// The party you have attempted to call is not available.
    Restarted {
        restart_id: RestartId,
        metadata: BTreeMap<serde_cbor::Value, serde_cbor::Value>,
    },
}

#[async_trait]
impl shared_socket::RecvHandler for EreportHandler {
    type Message = EreportMessage;
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
            let msg = match Self::parse_message(data) {
                Ok(msg) => msg,
                Err(err) => {
                    warn!(
                        self.log, "failed to parse incoming packet";
                        "data" => ?data,
                        "peer" => %peer,
                        err,
                    );
                    continue;
                }
            };
            if let Err(err) = sps.forward_to_single_sp(peer, msg).await {
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

#[derive(Debug, Error, SlogInlineError)]
enum ParseError {
    #[error("failed to deserialize ereport response header")]
    Header(#[source] hubpack::Error),
    #[error("failed to deserialize ereport response ENA")]
    Ena(#[source] hubpack::Error),
    #[error("failed to deserialize ereports")]
    Ereports(#[source] serde_cbor::Error),
    #[error("failed to deserialize ereport metadata refresh fragment")]
    Metadata(#[source] serde_cbor::Error),
}

impl EreportHandler {
    fn parse_message(buf: &[u8]) -> Result<EreportMessage, ParseError> {
        use gateway_messages::EreportHeader;
        use gateway_messages::EreportHeaderV0;
        use gateway_messages::EreportResponseKind;

        let (header, rest) =
            gateway_messages::deserialize::<EreportHeader>(buf)
                .map_err(ParseError::Header)?;
        match header {
            EreportHeader::V0(EreportHeaderV0 {
                kind: EreportResponseKind::Empty,
                restart_id,
                ..
            }) => Ok(EreportMessage::Empty { restart_id }),
            EreportHeader::V0(EreportHeaderV0 {
                kind: EreportResponseKind::Data,
                restart_id,
                ..
            }) => {
                let (start_ena, rest) =
                    gateway_messages::deserialize::<Ena>(buf)
                        .map_err(ParseError::Ena)?;
                let ereports = serde_cbor::from_slice(rest)
                    .map_err(ParseError::Ereports)?;
                Ok(EreportMessage::Data { restart_id, start_ena, ereports })
            }
            EreportHeader::V0(EreportHeaderV0 {
                kind: EreportResponseKind::Restarted,
                restart_id,
                ..
            }) => {
                let metadata = serde_cbor::from_slice(rest)
                    .map_err(ParseError::Metadata)?;
                Ok(EreportMessage::Restarted { restart_id, metadata })
            }
        }
    }
}
