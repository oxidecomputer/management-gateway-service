// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

use hubpack::SerializedSize;
use serde::Deserialize;
use serde::Serialize;

/// Ereport protocol versions.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, SerializedSize,
)]
#[repr(u8)]
pub enum Version {
    V0 = 0,
}

// N.B.: it would be nice to reuse the `Ena` type defined in `ereport-types` in
// the Omicron repo for this, but I'm not sure if it's Considered Good to have
// dependencies on omicron in this repo...
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, SerializedSize,
)]
#[repr(transparent)]
pub struct Ena(pub u64);

// N.B.: it would be nice to reuse the `EreporterGenerationUuid` type defined in
// `ereport-types` in the Omicron repo for this, but that wraps a `Uuid`, which
// lacks impls for traits like `SerializedSize`, and I'm not sure if it's
// considered okay to have dependencies on omicron in this repo...
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, SerializedSize,
)]
#[repr(transparent)]
pub struct ReporterGeneration(pub u128);
