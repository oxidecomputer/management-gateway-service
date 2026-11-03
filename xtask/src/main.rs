// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

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
    let config = omicron_zone_package::config::parse("package-manifest.toml")
        .context("failed to parse package-manifest.toml")?;

    fs::create_dir_all(output_dir)
        .await
        .with_context(|| format!("failed to create {output_dir}"))?;

    for (name, package) in config.packages {
        package
            .create(&name, output_dir, &BuildConfig::default())
            .await
            .context("failed to create faux-mgs omicron-zone-package")?;
    }

    Ok(())
}
