// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

use serde::Serialize;

mod v2;
mod v3;
mod v4;
mod v5;
mod v6;
mod v7;
mod v8;
mod v9;
mod v10;

pub fn assert_serialized(
    out: &mut [u8],
    expected: &[u8],
    item: &(impl Serialize + std::fmt::Debug),
) {
    let n = gateway_messages::serialize(out, item).unwrap();
    assert_eq!(expected, &out[..n], "incorrect serialization of {item:?}");
}
