// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

use crate::error::HostPhase2Error;
use async_trait::async_trait;
use hubpack::SerializedSize;
use lru_cache::LruCache;
use serde::Deserialize;
use serde_big_array::BigArray;
use slog_error_chain::SlogInlineError;
use std::convert::TryFrom;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;

type Sha256Digest = [u8; 32];

#[derive(Debug, Clone, Copy, Error, SlogInlineError)]
pub enum HostPhase2ImageError {
    #[error("could not deserialize image header")]
    DeserializeHeader(#[from] hubpack::error::Error),
    #[error(
        "incorrect magic in image header (expected {expected:#x}, got {got:#x})"
    )]
    IncorrectMagic { expected: u32, got: u32 },
    #[error(
        "incorrect version in image header (expected {expected:#x}, got {got:#x})"
    )]
    IncorrectVersion { expected: u32, got: u32 },
    #[error("incorrect image size (expected {expected}, got {got})")]
    IncorrectDataSize { expected: u64, got: u64 },
}

#[async_trait]
pub trait HostPhase2Provider: Send + Sync + 'static {
    /// Report the total size of the image identified by `sha256_hash`.
    async fn total_size(
        &self,
        sha256_hash: Sha256Digest,
    ) -> Result<u64, HostPhase2Error>;

    /// Read data from the phase 2 image identified by `sha256_hash` starting at
    /// `offset` into `out`, returning the number of bytes copied.
    async fn read_data(
        &self,
        sha256_hash: Sha256Digest,
        offset: u64,
        out: &mut [u8],
    ) -> Result<usize, HostPhase2Error>;
}

#[async_trait]
impl<T: HostPhase2Provider> HostPhase2Provider for Arc<T> {
    async fn total_size(
        &self,
        sha256_hash: Sha256Digest,
    ) -> Result<u64, HostPhase2Error> {
        (**self).total_size(sha256_hash).await
    }

    async fn read_data(
        &self,
        sha256_hash: Sha256Digest,
        offset: u64,
        out: &mut [u8],
    ) -> Result<usize, HostPhase2Error> {
        (**self).read_data(sha256_hash, offset, out).await
    }
}

#[derive(Debug, Deserialize, SerializedSize)]
struct OnDiskHeader {
    magic: u32,
    version: u32,
    _flags: u64,
    data_size: u64,
    _image_size: u64,
    _target_size: u64,
    sha256: Sha256Digest,
    #[serde(with = "BigArray")]
    _dataset_name: [u8; 128],
}

mod header_const {
    pub(super) const MAGIC: u32 = 0x1DEB0075;
    pub(super) const VERSION: u32 = 2;
    pub(super) const HEADER_BLOCK_SIZE: u64 = 4096;
}

pub struct InMemoryHostPhase2Provider {
    cache: Mutex<LruCache<Sha256Digest, (OnDiskHeader, Vec<u8>)>>,
}

impl InMemoryHostPhase2Provider {
    pub fn with_capacity(capacity: usize) -> Self {
        Self { cache: Mutex::new(LruCache::new(capacity)) }
    }

    pub async fn insert(
        &self,
        image: Vec<u8>,
    ) -> Result<Sha256Digest, HostPhase2ImageError> {
        let (header, _) = hubpack::deserialize::<OnDiskHeader>(&image)?;

        // Basic checks that should prevent inserting non-images:
        //
        // 1. Do we have the right header magic?
        // 2. Do we have the right header version?
        // 3. Does the header's data size match the actual data we have, after
        //    accounting for the header block?
        if header.magic != header_const::MAGIC {
            return Err(HostPhase2ImageError::IncorrectMagic {
                expected: header_const::MAGIC,
                got: header.magic,
            });
        }
        if header.version != header_const::VERSION {
            return Err(HostPhase2ImageError::IncorrectVersion {
                expected: header_const::VERSION,
                got: header.version,
            });
        }
        let expected_image_len =
            header.data_size.saturating_add(header_const::HEADER_BLOCK_SIZE);
        if image.len() as u64 != expected_image_len {
            return Err(HostPhase2ImageError::IncorrectDataSize {
                expected: expected_image_len,
                got: image.len() as u64,
            });
        }

        // Image looks okay; cache it!
        let hash = header.sha256;
        let mut cache = self.cache.lock().await;
        cache.insert(hash, (header, image));

        Ok(hash)
    }
}

#[async_trait]
impl HostPhase2Provider for InMemoryHostPhase2Provider {
    async fn total_size(
        &self,
        sha256_hash: Sha256Digest,
    ) -> Result<u64, HostPhase2Error> {
        let mut cache = self.cache.lock().await;

        let (_header, image) =
            cache.get_mut(&sha256_hash).ok_or_else(|| {
                HostPhase2Error::NoImage { hash: hex::encode(sha256_hash) }
            })?;

        Ok(image.len() as u64)
    }

    async fn read_data(
        &self,
        sha256_hash: Sha256Digest,
        offset: u64,
        out: &mut [u8],
    ) -> Result<usize, HostPhase2Error> {
        let mut cache = self.cache.lock().await;

        // TODO: In the future, we will serve an SP-specific header (modified
        // from the on-disk `_header`) if `offset` falls within the first
        // `HEADER_BLOCK_SIZE` bytes. For now, the SP (or really the host) is
        // expecting an identical header to the one stored on disk, so we can
        // just serve the image as-is regardless of offset.
        let (_header, image) =
            cache.get_mut(&sha256_hash).ok_or_else(|| {
                HostPhase2Error::NoImage { hash: hex::encode(sha256_hash) }
            })?;

        let offset_usize = usize::try_from(offset).map_err(|_| {
            HostPhase2Error::BadOffset {
                hash: hex::encode(sha256_hash),
                offset,
            }
        })?;

        if offset_usize >= image.len() {
            return Err(HostPhase2Error::BadOffset {
                hash: hex::encode(sha256_hash),
                offset,
            });
        }

        let image = &image[offset_usize..];

        let n = usize::min(image.len(), out.len());
        out[..n].copy_from_slice(&image[..n]);

        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[tokio::test]
    async fn parse_header() {
        // `phase2-trimmed.img` was created by truncating a real phase2 image
        // and then hand-editing the `data_size` field of the header to match
        // the truncated length.
        let disk_image = fs::read("tests/phase2-trimmed.img").unwrap();

        let cache = Arc::new(InMemoryHostPhase2Provider::with_capacity(1));
        let inserted_hash = cache.insert(disk_image.clone()).await.unwrap();

        let hash =
            "09595e287e60e51e95cc49b861b1134264270e33035f50ecc9d3cca0673b3501";
        let hash = Sha256Digest::try_from(hex::decode(hash).unwrap()).unwrap();

        {
            let mut inner = cache.cache.lock().await;
            let (header, image) = inner.get_mut(&hash).unwrap();

            assert_eq!(header.sha256, hash);
            assert_eq!(header.sha256, inserted_hash);
            assert_eq!(*image, disk_image);

            // We don't inspect any of these fields in actual use, but for our
            // unit test we can still check them.
            assert_eq!(header._flags, 1);
            assert_eq!(header._image_size, 0x3840_0000);
            assert_eq!(header._target_size, 0x1_0000_0000);

            let mut dataset_name = b"rpool/ROOT/ramdisk".to_vec();
            dataset_name.resize(128, 0_u8);
            assert_eq!(&header._dataset_name[..], dataset_name);
        }

        // Check that we can read the expected data from it.
        let mut out = vec![0; disk_image.len()];
        let n = cache.read_data(hash, 0, &mut out).await.unwrap();
        assert_eq!(n, out.len());
        assert_eq!(out, disk_image);
    }
}
