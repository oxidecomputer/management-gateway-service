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

use super::assert_serialized;
use gateway_messages::{
    MgsRequest, PowerState, PowerStateWithReason, SpResponse, StateChangeReason,
};

#[test]
fn get_power_state_with_reason_request() {
    let request = MgsRequest::GetPowerStateWithReason;
    assert_serialized(&[54], &request);
}

#[test]
fn get_power_state_with_reason_response() {
    for (reason, i) in [
        (StateChangeReason::Other, 0),
        (StateChangeReason::InitialPowerOn, 1),
        (StateChangeReason::ControlPlane, 2),
        (StateChangeReason::CpuReset, 3),
        (StateChangeReason::HostBootFailure, 4),
        (StateChangeReason::HostPanic, 5),
        (StateChangeReason::HostPowerOff, 6),
        (StateChangeReason::HostReboot, 7),
        (StateChangeReason::Overheat, 8),
        (StateChangeReason::A0Mapo, 9),
        (StateChangeReason::SmerrAssert, 10),
        (StateChangeReason::NicMapo, 11),
        (StateChangeReason::Unknown, 12),
    ] {
        let response = SpResponse::PowerStateWithReason(PowerStateWithReason {
            state: PowerState::A0,
            reason,
            since: 42,
        });
        assert_serialized(&[56, 0, i, 42, 0, 0, 0, 0, 0, 0, 0], &response);
    }
}
