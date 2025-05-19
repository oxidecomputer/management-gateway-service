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
use gateway_messages::{MgsRequest, SpError, SpResponse};

#[test]
fn read_host_flash() {
    let request = MgsRequest::ReadHostFlash { addr: 0 };
    assert_serialized(&[47, 0, 0, 0, 0], &request);

    let response = SpResponse::ReadHostFlash;
    assert_serialized(&[49], &response);

    let error1 = SpError::HfNotMuxedToSp;
    assert_serialized(&[38], &error1);

    let error2 = SpError::HfBadAddress;
    assert_serialized(&[39], &error2);

    let error3 = SpError::HfQspiTimeout;
    assert_serialized(&[40], &error3);

    let error4 = SpError::HfQspiTransferError;
    assert_serialized(&[41], &error4);
}
