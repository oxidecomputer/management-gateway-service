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
use gateway_messages::ApobComponentAction;
use gateway_messages::ApobComponentActionResponse;
use gateway_messages::ComponentAction;
use gateway_messages::ComponentActionResponse;

#[test]
fn apob_component_action() {
    let action = ComponentAction::Apob(ApobComponentAction::Clear);
    assert_serialized(&[2, 0], &action);
}

#[test]
fn apob_component_action_response() {
    for (r, i) in [
        (ApobComponentActionResponse::Success, 0),
        (ApobComponentActionResponse::NotMuxedToSp, 1),
        (ApobComponentActionResponse::NotImplemented, 2),
        (ApobComponentActionResponse::InvalidState, 3),
    ] {
        let action = ComponentActionResponse::Apob(r);
        assert_serialized(&[2, i], &action);
    }
}
