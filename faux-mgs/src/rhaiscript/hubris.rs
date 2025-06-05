// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::Path;
use crate::PathBuf;
use hubtools::{Caboose, RawHubrisArchive};
use rhai::{CustomType, Dynamic, EvalAltResult, ImmutableString, TypeBuilder};
use serde_json::Value as Json;
use std::sync::Arc;
use toml::Value as Toml;

fn json_text_to_dynamic(
    contents: &[u8],
) -> Result<Dynamic, Box<EvalAltResult>> {
    let text = String::from_utf8_lossy(contents);
    match serde_json::from_str::<Json>(&text) {
        Ok(json) => Ok(Dynamic::from(json)),
        // The Json error includes the original text with a marker
        // indicating where the error is.
        Err(e) => Err(format!("Failed to parse JSON: {}", e).into()),
    }
}

// Adapted from toml crate example toml2json
fn toml2json(tv: Toml) -> Json {
    match tv {
        Toml::String(s) => Json::String(s),
        Toml::Integer(i) => Json::Number(i.into()),
        Toml::Float(f) => {
            if let Some(n) = serde_json::Number::from_f64(f) {
                Json::Number(n)
            } else {
                Json::Null
            }
        }
        Toml::Boolean(b) => Json::Bool(b),
        Toml::Array(arr) => {
            Json::Array(arr.into_iter().map(toml2json).collect())
        }
        Toml::Table(table) => Json::Object(
            table.into_iter().map(|(k, v)| (k, toml2json(v))).collect(),
        ),
        Toml::Datetime(dt) => Json::String(dt.to_string()),
    }
}

#[derive(Debug, CustomType)]
#[rhai_type(name = "Archive", extra = Self::build_archive_inspector)]
pub struct ArchiveInspector {
    #[rhai_type(skip)]
    inner: Arc<RawHubrisArchive>,
}

impl Clone for ArchiveInspector {
    fn clone(&self) -> Self {
        ArchiveInspector { inner: self.inner.clone() }
    }
}

impl ArchiveInspector {
    fn new(inner: Arc<RawHubrisArchive>) -> Self {
        ArchiveInspector { inner }
    }

    pub fn from_vec(contents: Vec<u8>) -> Result<Self, Box<EvalAltResult>> {
        match RawHubrisArchive::from_vec(contents) {
            Ok(archive) => Ok(Self::new(Arc::new(archive))),
            Err(e) => Err(format!("RawHubrisArchive::from_vec: {e}")
                .to_string()
                .into()),
        }
    }

    pub fn load(path: ImmutableString) -> Result<Self, Box<EvalAltResult>> {
        let path = PathBuf::from(path.into_owned());
        match RawHubrisArchive::load(&path) {
            Ok(archive) => Ok(Self::new(Arc::new(archive))),
            Err(e) => {
                Err(format!("RawHubrisArchive::load: {e}").to_string().into())
            }
        }
    }

    fn extract_and_convert(
        &self,
        index: &str,
    ) -> Result<Dynamic, Box<EvalAltResult>> {
        match self.inner.extract_file(index) {
            Ok(contents) => match Path::new(index)
                .extension()
                .and_then(|os| os.to_str())
            {
                Some("bin") | Some("elf") => Ok(Dynamic::from_blob(contents)),
                Some("toml") => Self::toml_to_dynamic(&contents),
                Some("json") => json_text_to_dynamic(&contents),
                _ => {
                    // All remaining files that start with "\x7fELF" or are not valid UTF8
                    // are blobs, everything else is text.
                    if contents[0..4] == *b"\x7fELF" {
                        Ok(Dynamic::from_blob(contents))
                    } else {
                        match String::from_utf8(contents.clone()) {
                            Ok(text) => Ok(Dynamic::from(text)),
                            Err(_) => Ok(Dynamic::from_blob(contents)),
                        }
                    }
                }
            },
            Err(e) => Err(format!("hubtools error: {}", e).into()),
        }
    }

    pub fn indexer(
        &mut self,
        index: &str,
    ) -> Result<Dynamic, Box<EvalAltResult>> {
        match index {
            "caboose" => Ok(Dynamic::from::<CabooseInspector>(
                CabooseInspector::from_archive(&self.inner)?,
            )),
            "image_name" => self
                .inner
                .image_name()
                .map(Dynamic::from)
                .map_or(Ok(Dynamic::UNIT), Ok),
            _ => self.extract_and_convert(index),
        }
    }

    fn toml_to_dynamic(contents: &[u8]) -> Result<Dynamic, Box<EvalAltResult>> {
        let text = String::from_utf8_lossy(contents).to_string();
        let toml_value = text
            .parse::<Toml>()
            .map_err(|e| format!("Failed to parse TOML: {}", e))?;
        match toml2json(toml_value.clone()) {
            Json::Object(json) => Ok(Dynamic::from(json)),
            _ => Err(format!(
                "Failed to convert TOML to JSON object: {:?}",
                toml_value
            )
            .into()),
        }
    }

    fn decode_blob<const N: usize>(
        blob: Dynamic,
        name: &str,
    ) -> Result<[u8; N], Box<EvalAltResult>> {
        let bytes = blob
            .read_lock::<rhai::Blob>()
            .ok_or_else(|| format!("invalid type {}", name))?
            .to_vec();
        if bytes.len() != N {
            return Err(format!(
                "invalid {} length {} != {}",
                name,
                bytes.len(),
                N
            )
            .into());
        }
        bytes.try_into().map_err(|_| format!("invalid {}", name).into())
    }

    pub fn verify_rot_image(
        &mut self,
        cmpa: Dynamic,
        cfpa: Dynamic,
    ) -> Result<Dynamic, Box<EvalAltResult>> {
        let cmpa = Self::decode_blob::<512>(cmpa, "CMPA")?;
        let cfpa = Self::decode_blob::<512>(cfpa, "CFPA")?;
        if let Err(e) = self.inner.verify(&cmpa, &cfpa) {
            return Err(Box::new(EvalAltResult::from(format!("{:?}", e))));
        }
        Ok(true.into())
    }

    pub fn build_archive_inspector(builder: &mut TypeBuilder<Self>) {
        builder
            .with_name("Archive")
            .with_fn("new_archive", ArchiveInspector::from_vec)
            .with_fn("new_archive", ArchiveInspector::load)
            .with_fn("verify_rot_image", ArchiveInspector::verify_rot_image)
            .with_indexer_get(ArchiveInspector::indexer);
    }
}

macro_rules! caboose_tag {
    ($caboose: ident, $method:ident) => {
        $caboose
            .inner
            .$method()
            .map(|v| Ok(u8_to_string(v).into()))
            .unwrap_or(Ok(Dynamic::UNIT))
    };
}

#[derive(Debug, CustomType)]
#[rhai_type(name = "Caboose", extra = Self::build_caboose_inspector)]
pub struct CabooseInspector {
    #[rhai_type(skip)]
    inner: Arc<Caboose>,
}

impl Clone for CabooseInspector {
    fn clone(&self) -> Self {
        CabooseInspector { inner: self.inner.clone() }
    }
}

impl CabooseInspector {
    fn new(inner: Arc<Caboose>) -> Self {
        CabooseInspector { inner }
    }

    pub fn from_archive(
        archive: &RawHubrisArchive,
    ) -> Result<Self, Box<EvalAltResult>> {
        let caboose = archive
            .read_caboose()
            .map_err(|e| format!("RawArchive::read_caboose: {:?}", e))?;
        Ok(CabooseInspector::new(Arc::new(caboose)))
    }

    pub fn indexer(
        &mut self,
        index: &str,
    ) -> Result<Dynamic, Box<EvalAltResult>> {
        match index {
            "BORD" => caboose_tag!(self, board),
            "GITC" => caboose_tag!(self, git_commit),
            "NAME" => caboose_tag!(self, name),
            "SIGN" => caboose_tag!(self, sign),
            "VERS" => caboose_tag!(self, version),
            _ => Err(format!("unknown index: {:?}", index).into()),
        }
    }

    pub fn build_caboose_inspector(builder: &mut TypeBuilder<Self>) {
        builder
            .with_name("Caboose")
            .with_indexer_get(CabooseInspector::indexer);
    }
}

fn u8_to_string(array: &[u8]) -> String {
    String::from_utf8_lossy(
        if let Some(p) = array.iter().position(|&x| x == 0) {
            &array[0..p]
        } else {
            &array[0..]
        },
    )
    .to_string()
}
