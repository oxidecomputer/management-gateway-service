// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Context;
use camino::Utf8PathBuf;
use clap::Parser;
use convert_case::Case;
use convert_case::Casing as _;
use gateway_messages::MessageKind;
use gateway_messages::MgsError;
use gateway_messages::MgsRequest;
use gateway_messages::MgsResponse;
use gateway_messages::SpError;
use gateway_messages::SpRequest;
use gateway_messages::SpResponse;
use std::fs;
use std::io;
use std::io::BufWriter;
use std::io::Write as _;
use strum::VariantNames;

#[derive(Parser, Debug)]
struct Args {
    #[clap(default_value = "wireshark")]
    output_dir: Utf8PathBuf,
}

struct LuaWriter {
    output_dir: Utf8PathBuf,
    output_protofields: BufWriter<fs::File>,
}

impl LuaWriter {
    fn new(output_dir: Utf8PathBuf) -> anyhow::Result<Self> {
        fs::create_dir_all(&output_dir).with_context(|| {
            format!("failed to create output dir {output_dir}")
        })?;

        let path = output_dir.join("protofields.lua");
        println!("creating or overwriting {path}");
        let output_protofields =
            BufWriter::new(fs::File::create(&path).with_context(|| {
                format!("failed to create output file {path}")
            })?);

        Ok(Self { output_dir, output_protofields })
    }

    fn write_protofields_preamble(&mut self) -> anyhow::Result<()> {
        || -> io::Result<()> {
            let f = &mut self.output_protofields;

            write_license_header(f)?;
            writeln!(f, "local M = {{}}")?;
            writeln!(f)?;

            Ok(())
        }()
        .with_context(|| {
            format!("failed to write to {}/protofields.lua", self.output_dir)
        })
    }

    fn finish(mut self) -> anyhow::Result<()> {
        writeln!(self.output_protofields, "return M").with_context(|| {
            format!("failed to write to {}/protofields.lua", self.output_dir)
        })
    }

    fn emit_enum<T: VariantNames>(
        &mut self,
        enum_name: &str,
    ) -> anyhow::Result<()> {
        self.append_protofields::<T>(enum_name).with_context(|| {
            format!("failed to write to {}/protofields.lua", self.output_dir)
        })?;

        // Create a placeholder (TODO-filled) dissector lua module, if one
        // doesn't exist already. If it does exist, don't overwrite it: it may
        // well have been hand-edited already.
        let path = self
            .output_dir
            .join(format!("{}.lua", enum_name.to_case(Case::Snake)));
        if !path.exists() {
            println!("creating placeholder dissector module {path}");
            let f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .with_context(|| {
                    format!("failed to create output file {path}")
                })?;
            self.write_dissectors::<T>(enum_name, BufWriter::new(f))
                .with_context(|| format!("failed to write to {path}"))?;
        }

        Ok(())
    }

    fn write_dissectors<T: VariantNames>(
        &mut self,
        enum_name: &str,
        mut f: BufWriter<fs::File>,
    ) -> io::Result<()> {
        write_license_header(&mut f)?;
        writeln!(f, "local util = require('util')")?;
        writeln!(f, "local protofields = require('protofields')")?;
        writeln!(f)?;
        writeln!(f, "local M = {{}}")?;
        writeln!(f)?;

        for v in T::VARIANTS {
            writeln!(f, "M.dissect_{v} = function(buffer, pinfo, tree)")?;
            writeln!(f, "    tree:add(buffer, 'TODO: parse {enum_name} {v}')")?;
            writeln!(f, "end")?;
            writeln!(f)?;
        }

        writeln!(f, "return M")?;

        Ok(())
    }

    fn append_protofields<T: VariantNames>(
        &mut self,
        enum_name: &str,
    ) -> io::Result<()> {
        let f = &mut self.output_protofields;

        let snake = enum_name.to_case(Case::Snake);

        // empty table
        writeln!(f, "M.{snake} = {{}}")?;

        // variant names
        writeln!(f, "M.{snake}.names = {{")?;
        for (i, v) in T::VARIANTS.iter().enumerate() {
            let c = v.to_case(Case::Pascal);
            writeln!(f, r#"    [{i}] = "{c}","#)?;
        }
        writeln!(f, "}}")?;

        // handler function names
        writeln!(f, "M.{snake}.handlers = {{")?;
        for (i, v) in T::VARIANTS.iter().enumerate() {
            writeln!(f, r#"    [{i}] = "dissect_{v}","#)?;
        }
        writeln!(f, "}}")?;

        // proto field
        writeln!(f, "M.{snake}.field = ProtoField.uint8(")?;
        writeln!(f, r#"    "mgs.{snake}","#)?;
        writeln!(f, r#"    "{enum_name}","#)?;
        writeln!(f, r#"    base.DEC,"#)?;
        writeln!(f, r#"    M.{snake}.names"#)?;
        writeln!(f, ")")?;
        writeln!(f)?;

        Ok(())
    }
}

fn write_license_header(f: &mut BufWriter<fs::File>) -> io::Result<()> {
    writeln!(
        f,
        "\
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.\n"
    )
}

macro_rules! emit_enum {
    ($writer:expr, $type:ty) => {
        $writer.emit_enum::<$type>(stringify!($type))?;
    };
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let mut writer = LuaWriter::new(args.output_dir)?;
    writer.write_protofields_preamble()?;
    emit_enum!(writer, MessageKind);
    emit_enum!(writer, MgsError);
    emit_enum!(writer, MgsRequest);
    emit_enum!(writer, MgsResponse);
    emit_enum!(writer, SpError);
    emit_enum!(writer, SpRequest);
    emit_enum!(writer, SpResponse);
    writer.finish()?;
    Ok(())
}
