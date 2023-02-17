// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

// NOTE: The `usdt` crate uses inline assembly, which prior to Rust 1.59 or 1.66
// on macOS, required the use of nightly features. These crate-local features
// are used to determine which toolchain is used to compile Dropshot, and then
// include the correct `#![feature(...)]` directives on the basis of that.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    if !version_check::is_min_version("1.59").unwrap_or(false) {
        println!("cargo:rustc-cfg=usdt_need_asm");
    }

    // `feature(asm_sym)` is stable, which is required on macOS.
    #[cfg(target_os = "macos")]
    if version_check::supports_feature("asm_sym").unwrap_or(false)
        && !version_check::is_min_version("1.67").unwrap_or(false)
    {
        println!("cargo:rustc-cfg=usdt_need_asm_sym");
    }
}
