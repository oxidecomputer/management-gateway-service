// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::tlv;
use hubpack::SerializedSize;
use serde::{Deserialize, Serialize};

/// Timestamped count values for a toggling GPIO, used for liveness checks
#[derive(Copy, Clone, Debug, Serialize, Deserialize, SerializedSize)]
pub struct GpioToggleCount {
    /// Number of edges seen on the GPIO
    pub edge_count: u32,
    /// Number of clock cycles since the last GPIO edge has been seen
    pub cycles_since_last_edge: u32,
}

impl GpioToggleCount {
    pub const TAG: tlv::Tag = tlv::Tag(*b"TOGL");
}

/// Most recent POST code seen by the sequencer FPGA
#[derive(Copy, Clone, Debug, Serialize, Deserialize, SerializedSize)]
pub struct LastPostCode(pub u32);

impl LastPostCode {
    pub const TAG: tlv::Tag = tlv::Tag(*b"POST");
}
