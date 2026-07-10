// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! This source file is named after the protocol version being tested,
//! e.g. v01.rs implements tests for protocol version 1.
//! The tested protocol version is represented by "$VERSION" below.
//!
//! The tests in this module check that the serialized form of messages from MGS
//! protocol version $VERSION have not changed.
//!
//! If a test in this module fails, _do not change the test_! This means you
//! have changed, deleted, or reordered an existing message type or enum
//! variant, and you should revert that change. This will remain true until we
//! bump the `version::MIN` to a value higher than $VERSION, at which point
//! these tests can be removed as we will stop supporting $VERSION.

use gateway_messages::{
    HostBootfailError, HostBootfailPayload, HostInfoRequest, HostPanicError,
    HostPanicPayload, MgsRequest, SpError, SpResponse,
};

use super::assert_serialized;

#[test]
fn get_host_panic_payload_request() {
    let request =
        MgsRequest::GetHostPanicPayload { request: None, len: 0xABCDEF12 };
    #[rustfmt::skip]
    let expected = &[
        // GetHostPanicPayload
        52,
        // None
        0,
        // 0xABCDEF12
        0x12, 0xEF, 0xCD, 0xAB
    ];
    assert_serialized(expected, &request);

    let request = MgsRequest::GetHostPanicPayload {
        request: Some(HostInfoRequest {
            offset: 0x08172635,
            seqno: 0xFAEBDC09,
        }),
        len: 0xBACADAFA,
    };
    #[rustfmt::skip]
    let expected = &[
        // GetHostPanicPayload
        52,
        // Some
        1,
        // 0x08172635
        0x35, 0x26, 0x17, 0x08,
        // 0xFAEBDC09
        0x09, 0xDC, 0xEB, 0xFA,
        // 0xBACADAFA
        0xFA, 0xDA, 0xCA, 0xBA,
    ];
    assert_serialized(expected, &request);
}

#[test]
fn get_bootfail_payload_request() {
    let request =
        MgsRequest::GetHostBootfailPayload { request: None, len: 0xABCDEF12 };
    #[rustfmt::skip]
    let expected = &[
        // GetHostBootfailPayload
        53,
        // None
        0,
        // 0xABCDEF12
        0x12, 0xEF, 0xCD, 0xAB
    ];
    assert_serialized(expected, &request);

    let request = MgsRequest::GetHostBootfailPayload {
        request: Some(HostInfoRequest {
            offset: 0x08172635,
            seqno: 0xFAEBDC09,
        }),
        len: 0xBACADAFA,
    };
    #[rustfmt::skip]
    let expected = &[
        // GetHostBootfailPayload
        53,
        // Some
        1,
        // 0x08172635
        0x35, 0x26, 0x17, 0x08,
        // 0xFAEBDC09
        0x09, 0xDC, 0xEB, 0xFA,
        // 0xBACADAFA
        0xFA, 0xDA, 0xCA, 0xBA,
    ];
    assert_serialized(expected, &request);
}

#[test]
fn get_host_panic_payload_response() {
    let response = SpResponse::HostPanicPayload(HostPanicPayload {
        total_len: 0x01020304,
        seqno: 0xF0E0D0C0,
        slot: None,
    });
    #[rustfmt::skip]
    let expected = &[
        // HostPanicPayload
        54,
        // 0x01020304
        0x04, 0x03, 0x02, 0x01,
        // 0xF0E0D0C0
        0xC0, 0xD0, 0xE0, 0xF0,
        // None
        0x00,
    ];
    assert_serialized(expected, &response);
}

#[test]
fn get_host_bootfail_payload_response() {
    let response = SpResponse::HostBootfailPayload(HostBootfailPayload {
        total_len: 0x01020304,
        seqno: 0xF0E0D0C0,
        reason: 0xAB,
        slot: Some(0x4321),
    });
    #[rustfmt::skip]
    let expected = &[
        // HostBootfailPayload
        55,
        // 0x01020304
        0x04, 0x03, 0x02, 0x01,
        // 0xF0E0D0C0
        0xC0, 0xD0, 0xE0, 0xF0,
        // 0xAB
        0xAB,
        // Some 0x4321
        0x01, 0x21, 0x43,
    ];
    assert_serialized(expected, &response);
}

#[test]
fn get_host_panic_payload_error() {
    let inner_errors = [
        (HostPanicError::NoHostInfo, 0),
        (HostPanicError::InvalidOffset, 1),
        (HostPanicError::InvalidSeqNo, 2),
        (HostPanicError::ServerRestarted, 3),
    ];
    for (e, v) in inner_errors {
        let error = SpError::HostPanic(e);
        let expected = [40, v];
        assert_serialized(&expected, &error);
    }
}

#[test]
fn get_host_bootfail_payload_error() {
    let inner_errors = [
        (HostBootfailError::NoHostInfo, 0),
        (HostBootfailError::InvalidOffset, 1),
        (HostBootfailError::InvalidSeqNo, 2),
        (HostBootfailError::ServerRestarted, 3),
    ];
    for (e, v) in inner_errors {
        let error = SpError::HostBootfail(e);
        let expected = [41, v];
        assert_serialized(&expected, &error);
    }
}
