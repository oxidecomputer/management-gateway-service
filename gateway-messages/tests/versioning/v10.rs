// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The tests in this module check that the serialized form of messages from MGS
//! protocol version 9 have not changed.
//!
//! If a test in this module fails, _do not change the test_! This means you
//! have changed, deleted, or reordered an existing message type or enum
//! variant, and you should revert that change. This will remain true until we
//! bump the `version::MIN` to a value higher than 9, at which point these tests
//! can be removed as we will stop supporting v9.

use super::assert_serialized;
use gateway_messages::CfpaPage;
use gateway_messages::MgsRequest;
use gateway_messages::RotRequest;
use gateway_messages::RotResponse;
use gateway_messages::SerializedSize;
use gateway_messages::SpResponse;

#[test]
fn sp_response() {
    let mut out = [0; SpResponse::MAX_SIZE];
    let response = SpResponse::ReadRot(RotResponse::Ok);
    let expected = [40, 0];
    assert_serialized(&mut out, &expected, &response);
}

#[test]
fn host_request() {
    let mut out = [0; MgsRequest::MAX_SIZE];
    for (r, serialized) in [
        (RotRequest::ReadCmpa, &[0u8] as &[_]),
        (RotRequest::ReadCfpa(CfpaPage::Active), &[1, 0]),
    ] {
        let request = MgsRequest::ReadRot(r);
        let mut expected = vec![
            40, // MgsRequest::ReadRot
        ];
        expected.extend_from_slice(serialized);
        assert_serialized(&mut out, &expected, &request);
    }
}

#[test]
fn cfpa_page() {
    let mut out = [0; CfpaPage::MAX_SIZE];

    assert_serialized(&mut out, &[0], &CfpaPage::Active);
    assert_serialized(&mut out, &[1], &CfpaPage::Inactive);
    assert_serialized(&mut out, &[2], &CfpaPage::Scratch);
}
