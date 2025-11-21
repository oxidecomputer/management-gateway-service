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
use gateway_messages::{IgnitionCommand, MgsRequest};

#[test]
fn ignition_command_always_transmit() {
    for (command, command_val) in [
        (IgnitionCommand::PowerOn, 0),
        (IgnitionCommand::PowerOff, 1),
        (IgnitionCommand::PowerReset, 2),
        (IgnitionCommand::AlwaysTransmit { enabled: false }, 3),
        (IgnitionCommand::AlwaysTransmit { enabled: true }, 3),
    ] {
        let request = MgsRequest::IgnitionCommand { target: 7, command };
        match command {
            IgnitionCommand::AlwaysTransmit { enabled } => {
                let expected = &[3, 7, command_val, enabled as u8];
                assert_serialized(expected, &request);
            }
            IgnitionCommand::PowerOn
            | IgnitionCommand::PowerOff
            | IgnitionCommand::PowerReset => {
                let expected = &[3, 7, command_val];
                assert_serialized(expected, &request);
            }
        }
    }
}
