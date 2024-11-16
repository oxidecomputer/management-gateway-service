// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The tests in this module check that the serialized form of messages from MGS
//! protocol version 10 have not changed.
//!
//! If a test in this module fails, _do not change the test_! This means you
//! have changed, deleted, or reordered an existing message type or enum
//! variant, and you should revert that change. This will remain true until we
//! bump the `version::MIN` to a value higher than 10, at which point these
//! tests can be removed as we will stop supporting v10.

use super::assert_serialized;
use gateway_messages::CfpaPage;
use gateway_messages::MgsRequest;
use gateway_messages::RotRequest;
use gateway_messages::RotResponse;
use gateway_messages::SpResponse;

#[test]
fn sp_response() {
    let response = SpResponse::ReadRot(RotResponse::Ok);
    let expected = [40, 0];
    assert_serialized(&expected, &response);
}

#[test]
fn host_request() {
    for (r, serialized) in [
        (RotRequest::ReadCmpa, &[0u8] as &[_]),
        (RotRequest::ReadCfpa(CfpaPage::Active), &[1, 0]),
    ] {
        let request = MgsRequest::ReadRot(r);
        let mut expected = vec![
            40, // MgsRequest::ReadRot
        ];
        expected.extend_from_slice(serialized);
        assert_serialized(&expected, &request);
    }
}

#[test]
fn cfpa_page() {
    assert_serialized(&[0], &CfpaPage::Active);
    assert_serialized(&[1], &CfpaPage::Inactive);
    assert_serialized(&[2], &CfpaPage::Scratch);
}
