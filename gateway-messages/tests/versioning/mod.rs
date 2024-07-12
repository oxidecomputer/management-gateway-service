// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

use serde::Serialize;

mod v02;
mod v03;
mod v04;
mod v05;
mod v06;
mod v07;
mod v08;
mod v09;
mod v10;
mod v11;
mod v12;
mod v13;
mod v14;

pub fn assert_serialized(
    out: &mut [u8],
    expected: &[u8],
    item: &(impl Serialize + std::fmt::Debug),
) {
    let n = gateway_messages::serialize(out, item).unwrap();
    assert_eq!(
        n,
        expected.len(),
        "bad serialization size: expected {}, got {n}",
        expected.len()
    );
    assert_eq!(expected, &out[..n], "incorrect serialization of {item:?}");
}
