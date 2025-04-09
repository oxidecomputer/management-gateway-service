// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! Request and response types for the ereport ingestion protocol.
//!
//! This module defines both the request message sent by MGS
//! ([`EreportRequest`]), and the header for the response to that message by the
//! SP ([`EreportResponseHeader`]).
//!
//! For more information on the high-level design of the ereport ingestion
//! protocol, see [RFD 520] Control Plane Fault Ingestion and Data Model. For
//! details on the encoding of SP ereport messages, refer to [RFD 544] Embedded
//! E-report Formats and [RFD 545] Firmware E-report Aggregation and Evacuation.
//!
//! [RFD 520] https://rfd.shared.oxide.computer/rfd/520
//! [RFD 544] https://rfd.shared.oxide.computer/rfd/544
//! [RFD 545] https://rfd.shared.oxide.computer/rfd/545

use core::fmt;
use hubpack::SerializedSize;
use serde::Deserialize;
use serde::Serialize;

/// An error numeric identifier (ENA).
///
/// ENAs are 64-bit unsigned integers that uniquely identify an ereport within a
/// single reporter restart.
///
/// See [RFD 520 §1.1.1] for details.
///
/// [RFD 520 §1.1.1]: https://rfd.shared.oxide.computer/rfd/0520#enas
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    Serialize,
    Deserialize,
    SerializedSize,
)]
#[repr(transparent)]
pub struct Ena(pub u64);

impl fmt::Debug for Ena {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ena({:#x})", self.0)
    }
}

/// A unique identifier generated by the SP's snitch task when it starts up,
/// used to detect restarts.
///
/// See [RFD 520 §4.2.2] for details.
///
/// [RFD 520 §4.2.2]: https://rfd.shared.oxide.computer/rfd/0520#reporter-crash-recovery
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, SerializedSize,
)]
#[repr(transparent)]
pub struct RestartId(pub u128);

/// A versioned request for ereports aggregated by the SP's snitch task.
///
/// See [RFD 545 §4.4.3.1] for details.
/// [RFD 545 §4.4.3.1]: https://rfd.shared.oxide.computer/rfd/0545#_requestcommit
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, SerializedSize,
)]
pub enum EreportRequest {
    // /!\ ORDER MATTERS /!\
    /// An ereport protocol version 0 request.
    ///
    /// The SP must respond to this request with a [`EreportResponseHeader::V0`]
    /// packet.
    V0(RequestV0),
    // IMPORTANT: when adding new variants to this enum, please add them to the
    // `version_byte_values` test below!
}

/// A request for ereports aggregated by the SP's snitch task, version 0.
///
/// ```text
///     0         1        2        3
/// +--------+--------+--------+--------+
/// | version|-------C| limit  | unused |
/// +--------+--------+--------+--------+
/// |                                   |
/// +                                   +
/// |                                   |
/// +       restart ID (128 bits)       +
/// |                                   |
/// +                                   +
/// |                                   |
/// +--------+--------+--------+--------+
/// |                                   |
/// +   first ENA desired in response   +
/// |                                   |
/// +--------+--------+--------+--------+
/// |                                   |
/// +   last ENA written to database    + only present when C bit set
/// |                                   |
/// +--------+--------+--------+--------+
/// ```
///
/// See [RFD 545 §4.4.3.1] for details.
/// [RFD 545 §4.4.3.1]: https://rfd.shared.oxide.computer/rfd/0545#_requestcommit
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, SerializedSize,
)]
pub struct RequestV0 {
    pub flags: RequestFlagsV0,

    /// Maximum number of ereports to include in the response packet.
    pub limit: u8,

    /// Currently unused as of this protocol version.
    _reserved: [u8; 1],

    /// The restart ID of the SP's snitch task which the control plane believes
    /// is current.
    ///
    /// If this value does not match the reporter's current restart ID, the
    /// reporter's response will include the current restart ID, and will start
    /// at the earliest known ENA, rather than the provided `start_ena`.
    ///
    /// If the control plane does not know the SP's restart ID, this will be 0. IDs
    /// generated by the snitch task on startup must not be 0.
    pub restart_id: RestartId,

    /// If present, the snitch should not include ENAs earlier than this one
    /// in its response, provided that the requested reporter generation matches
    /// the current generation.
    pub start_ena: Ena,

    /// The ENA of the last ereport committed to persistent storage from the
    /// requested reporter restart.
    ///
    /// If the restart ID parameter matches the reporter's current restart,
    /// it is permitted to discard any ereports with ENAs up to and including
    /// this value. If the restart ID has changed from the provided one, the
    /// reporter will not discard data.
    ///
    /// This value is only present if the [`RequestFlagsV0::COMMIT`] bit is
    /// set.
    committed_ena: Ena,
}

/// Flags for [`EreportRequest`] packets.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, SerializedSize,
)]
#[repr(transparent)]
pub struct RequestFlagsV0(u8);

bitflags::bitflags! {
    impl RequestFlagsV0: u8 {
        /// Indicates that a "committed ENA" field is present in this request.
        ///
        /// If this is not set, the "committed ENA" field will be zero, but this
        /// does not indicate that ENA 0 has been committed.
        const COMMIT = 1 << 0;
    }
}

impl RequestV0 {
    pub const fn new(
        restart_id: RestartId,
        start_ena: Ena,
        limit: u8,
        committed_ena: Option<Ena>,
    ) -> Self {
        let (committed_ena, flags) = match committed_ena {
            Some(ena) => (ena, RequestFlagsV0::COMMIT),
            None => (Ena(0), RequestFlagsV0::empty()),
        };
        Self {
            flags,
            limit,
            _reserved: [0u8; 1],
            restart_id,
            start_ena,
            committed_ena,
        }
    }

    /// Returns the "committed ENA" field if this packet contains one.
    ///
    /// This checks the value of the [`RequestFlagsV0::COMMIT`] bit, and returns
    /// the ENA only if it is set.
    #[must_use]
    pub const fn committed_ena(&self) -> Option<Ena> {
        if self.flags.contains(RequestFlagsV0::COMMIT) {
            Some(self.committed_ena)
        } else {
            None
        }
    }
}

/// A versioned header for the response to an [`EreportRequest`].
///
/// See [RFD 545 §4.4.3.1] for details.
/// [RFD 545 §4.4.3.1]: https://rfd.shared.oxide.computer/rfd/0545#_requestcommit
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, SerializedSize,
)]
pub enum EreportResponseHeader {
    // /!\ ORDER MATTERS /!\
    /// An ereport protocol version 0 response header.
    ///
    /// This is sent in response to a [`RequestV0`] message.
    V0(ResponseHeaderV0),
    // IMPORTANT: when adding new variants to this enum, please add them to the
    // `version_byte_values` test below!
}

/// Header for responses to [v0 ereport requests](RequestV0).
///
/// ```text
///     0         1        2        3
/// +--------+--------+--------+--------+
/// | version|                          |
/// +--------+                          +
/// |                                   |
/// +                                   +
/// |       restart ID (128 bits)       |
/// +                                   +
/// |                                   |
/// +                           +-------+
/// |                           |  0xBF | beginning of CBOR metadata map
/// +--------+--------+---------+-------*
///   |
///   +--> if kind == 1 (ResponseKindV0::Data):
///   |    +--------+--------+--------+--------+
///   |    |                                   |
///   |    +   ENA of first record below       +
///   |    |                                   |
///   |    +--------+--------+--------+--------+
///   |    |                                   |
///   |    :   zero or more bytes of data,     :
///   |    :   continuing to end of packet     :
///   |    :                                   :
///   |    |                                   |
///   |    +--------+--------+--------+--------+
///   |
///   +--> if kind == 2 (ResponseKindV0::Restarted):
///        +--------+--------+--------+--------+
///        |                                   |
///        :   CBOR fragment of metadata to    :
///        :   append to subsequent ereports   :
///        :                                   :
///        |                                   |
///        +--------+--------+--------+--------+
/// ```
///
/// See [RFD 545 §4.4.4] for details.
/// [RFD 545 §4.4.4]: https://rfd.shared.oxide.computer/rfd/0545#_readresponse
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, SerializedSize,
)]
pub struct ResponseHeaderV0 {
    /// The reporter restart ID of the SP's snitch task when this response was
    /// produced.
    pub restart_id: RestartId,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn serialize<'buf, M>(buf: &'buf mut [u8], msg: &M) -> &'buf [u8]
    where
        M: Serialize + fmt::Debug,
    {
        match crate::serialize(buf, msg) {
            Ok(n) => &buf[..n],
            Err(e) => {
                panic!("message did not serialize: {e}\n  message: {msg:?}",)
            }
        }
    }

    // Test that the "version" fields in the request and response messages have
    // the expected values.
    //
    // Hubpack serializes enums using single-byte tag values, determined in the
    // struct's declaration order. Because of this, changing the order of
    // variants of the versioned request and response enums (`EreportRequest`
    // and `EreportResponseHeader`) will change the versions they serialize as.
    // This test ensures we don't accidentally do that, provided that new
    // versions are added to this test.
    #[test]
    fn version_byte_values() {
        let mut buf = [0u8; EreportRequest::MAX_SIZE];
        let bytes = serialize(
            &mut buf,
            &EreportRequest::V0(RequestV0::new(
                RestartId(1),
                Ena(2),
                3,
                Some(Ena(4)),
            )),
        );
        assert_eq!(bytes[0], 0, "Request v0 version byte should be 0");

        let mut buf = [0u8; EreportResponseHeader::MAX_SIZE];
        let bytes = serialize(
            &mut buf,
            &EreportResponseHeader::V0(ResponseHeaderV0 {
                restart_id: RestartId(1),
            }),
        );
        assert_eq!(bytes[0], 0, "ResponseHeader v0 version byte should be 0");

        // IMPORTANT: when adding new variants to the versioned message enums,
        // please add tests for them here!
    }
}
