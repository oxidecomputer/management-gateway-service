// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The tests in this module check that the serialized form of messages from MGS
//! protocol version 5 have not changed.
//!
//! If a test in this module fails, _do not change the test_! This means you
//! have changed, deleted, or reordered an existing message type or enum
//! variant, and you should revert that change. This will remain true until we
//! bump the `version::MIN` to a value higher than 4, at which point these tests
//! can be removed as we will stop supporting v5.

use super::assert_serialized;
use gateway_messages::MgsRequest;
use gateway_messages::SerializedSize;
use gateway_messages::SpComponent;

#[test]
fn mgs_request() {
    let mut out = [0; MgsRequest::MAX_SIZE];

    let request = MgsRequest::ReadComponentCaboose {
        component: SpComponent::SP_ITSELF,
        key: [1, 2, 3, 4],
    };
    let expected = &[
        37, // ReadComponentCaboose
        b's', b'p', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // SP_ITSELF
        1, 2, 3, 4,
    ];
    assert_serialized(&mut out, expected, &request);
}
