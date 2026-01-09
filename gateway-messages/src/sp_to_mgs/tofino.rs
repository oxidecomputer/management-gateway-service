// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::tlv;
use hubpack::SerializedSize;
use serde::{Deserialize, Serialize};

/// A single PCIe register read
#[derive(Copy, Clone, Debug, Serialize, Deserialize, SerializedSize)]
pub struct PcieRegisterRead {
    /// BAR segment
    pub bar: u32,
    /// Offset into BAR
    pub offset: u32,
    /// Result of the read
    pub reg_result: Result<u32, u32>,
}

impl PcieRegisterRead {
    pub const TAG: tlv::Tag = tlv::Tag(*b"PCIE");
}
