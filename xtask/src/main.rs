// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

use anyhow::ensure;
use anyhow::Context;
use camino::Utf8Path;
use camino::Utf8PathBuf;
use clap::Parser;
use clap::Subcommand;
use omicron_zone_package::package::BuildConfig;
use tokio::fs;

#[derive(Parser, Debug)]
struct Args {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug, Clone)]
enum Command {
    /// Build an omicron-zone-package containing faux-mgs suitable for inclusion
    /// in the switch zone.
    ZonePackage { output_dir: Utf8PathBuf },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    match args.command {
        Command::ZonePackage { output_dir } => {
            build_zone_package(&output_dir).await
        }
    }
}

async fn build_zone_package(output_dir: &Utf8Path) -> anyhow::Result<()> {
    let src = Utf8Path::new("target/release/faux-mgs");
    let proto_dst = Utf8Path::new("target/proto/usr/bin/faux-mgs");
    let proto_dst_dir = proto_dst.parent().unwrap();
    let final_dst = "/usr/bin/faux-mgs";

    ensure!(
        src.exists(),
        "{src} not found - run `cargo build --release --bin faux-mgs` first",
    );

    fs::create_dir_all(proto_dst_dir)
        .await
        .with_context(|| format!("failed to create {proto_dst_dir}"))?;
    fs::copy(src, proto_dst)
        .await
        .with_context(|| format!("failed to copy {src} to {proto_dst}"))?;

    let manifest = format!(
        "
        [package.faux-mgs]
        service_name = \"faux-mgs\"
        source.type = \"local\"
        source.paths = [
          {{from = \"{proto_dst}\" , to = \"{final_dst}\"}},
        ]
        output.type = \"zone\"
    "
    );
    let config = omicron_zone_package::config::parse_manifest(&manifest)
        .context("failed to parse built-in package manifest")?;

    fs::create_dir_all(output_dir)
        .await
        .with_context(|| format!("failed to create {output_dir}"))?;

    for package in config.packages.values() {
        package
            .create("omicron-faux-mgs", output_dir, &BuildConfig::default())
            .await
            .context("failed to create faux-mgs omicron-zone-package")?;
    }

    Ok(())
}
