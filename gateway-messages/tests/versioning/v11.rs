// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The tests in this module check that the serialized form of messages from MGS
//! protocol version 11 have not changed.
//!
//! If a test in this module fails, _do not change the test_! This means you
//! have changed, deleted, or reordered an existing message type or enum
//! variant, and you should revert that change. This will remain true until we
//! bump the `version::MIN` to a value higher than 11, at which point these
//! tests can be removed as we will stop supporting v11.

use super::assert_serialized;
use gateway_messages::MgsRequest;
use gateway_messages::SerializedSize;
use gateway_messages::SpError;
use gateway_messages::SpResponse;
use gateway_messages::VpdError;

#[test]
fn sp_response() {
    let mut out = [0; SpResponse::MAX_SIZE];
    let response = SpResponse::VpdLockState;
    let expected = [41];
    assert_serialized(&mut out, &expected, &response);
}

#[test]
fn host_request() {
    let mut out = [0; MgsRequest::MAX_SIZE];
    let request = MgsRequest::VpdLockState;
    let expected = [41];
    assert_serialized(&mut out, &expected, &request);
}

#[test]
fn vpd_protocol_errors() {
    let mut out = [0; SpResponse::MAX_SIZE];

    for (error, serialized) in [
        (VpdError::InvalidDevice, &[0]),
        (VpdError::NotPresent, &[1]),
        (VpdError::DeviceError, &[2]),
        (VpdError::Unavailable, &[3]),
        (VpdError::DeviceTimeout, &[4]),
        (VpdError::DeviceOff, &[5]),
        (VpdError::BadAddress, &[6]),
        (VpdError::BadBuffer, &[7]),
        (VpdError::BadRead, &[8]),
        (VpdError::BadWrite, &[9]),
        (VpdError::BadLock, &[10]),
        (VpdError::NotImplemented, &[11]),
        (VpdError::IsLocked, &[12]),
        (VpdError::PartiallyLocked, &[13]),
        (VpdError::AlreadyLocked, &[14]),
        (VpdError::TaskRestarted, &[15]),
    ] {
        // Test VpdError variants encoded in an SpResponse
        let response = SpResponse::Error(SpError::Vpd(error));
        let mut expected = vec![17, 34];
        expected.extend_from_slice(serialized);
        assert_serialized(&mut out, &expected, &response);
    }
}
