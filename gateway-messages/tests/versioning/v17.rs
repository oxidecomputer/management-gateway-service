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
//! bump the `version::MIN` to a value higher than $VERSION, at which point these
//! tests can be removed as we will stop supporting $VERSION.

use super::assert_serialized;
use gateway_messages::{
    DumpCompression, DumpError, DumpRequest, DumpResponse, DumpSegment,
    DumpTask, MgsRequest, SpError, SpResponse,
};

#[test]
fn dump_request() {
    let request = MgsRequest::Dump(DumpRequest::TaskDumpCount);
    assert_serialized(&[46, 0], &request);

    let request = MgsRequest::Dump(DumpRequest::TaskDumpReadStart {
        index: 0x1234,
        key: 0x55667788,
    });
    assert_serialized(
        &[46, 1, 0x34, 0x12, 0, 0, 0x88, 0x77, 0x66, 0x55],
        &request,
    );

    let request =
        MgsRequest::Dump(DumpRequest::TaskDumpReadContinue { key: 0x55667788 });
    assert_serialized(&[46, 2, 0x88, 0x77, 0x66, 0x55], &request);
}

#[test]
fn dump_response() {
    let request = SpResponse::Dump(DumpResponse::TaskDumpCount(0x1122));
    assert_serialized(&[47, 0, 0x22, 0x11, 0, 0], &request);

    let request =
        SpResponse::Dump(DumpResponse::TaskDumpReadStarted(DumpTask {
            task: 0x1576,
            time: 0xFF12345678,
            compression: DumpCompression::Lzss,
        }));
    assert_serialized(
        &[47, 1, 0x76, 0x15, 0x78, 0x56, 0x34, 0x12, 0xFF, 0, 0, 0, 0],
        &request,
    );

    let request =
        SpResponse::Dump(DumpResponse::TaskDumpRead(Some(DumpSegment {
            address: 0x12345678,
            compressed_length: 0x1122,
            uncompressed_length: 0x5567,
        })));
    assert_serialized(
        &[47, 2, 1, 0x78, 0x56, 0x34, 0x12, 0x22, 0x11, 0x67, 0x55],
        &request,
    );
}

#[test]
fn dump_error() {
    for (i, e) in [
        DumpError::BadArea,
        DumpError::BadIndex,
        DumpError::NoDumpTaskHeader,
        DumpError::CorruptTaskHeader,
        DumpError::BadKey,
        DumpError::ReadFailed,
        DumpError::NoLongerValid,
        DumpError::SegmentTooLong,
    ]
    .into_iter()
    .enumerate()
    {
        let request = SpError::Dump(e);
        assert_serialized(&[37, i as u8], &request);
    }
}
