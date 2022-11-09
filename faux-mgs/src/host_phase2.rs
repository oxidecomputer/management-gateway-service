// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Context;
use anyhow::Result;
use async_trait::async_trait;
use gateway_sp_comms::error::HostPhase2Error;
use gateway_sp_comms::HostPhase2Provider;
use sha2::Digest;
use sha2::Sha256;
use slog::info;
use slog::warn;
use slog::Logger;
use std::collections::HashMap;
use std::convert;
use std::io::SeekFrom;
use std::path::Path;
use tokio::fs;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncSeekExt;
use tokio::sync::Mutex;
use tokio_stream::wrappers::ReadDirStream;
use tokio_stream::StreamExt;

#[derive(Default)]
pub(crate) struct DirectoryHostPhase2Provider {
    // Map of hash -> file on disk; assumes files don't change between when
    // we're created and scan for them and when the SP requests them. This would
    // be nonsense for a real service, but we're faux-mgs and only use for
    // development, so it should be okay.
    images: HashMap<[u8; 32], Mutex<File>>,
}

impl DirectoryHostPhase2Provider {
    pub(super) async fn new(path: &Path, log: &Logger) -> Result<Self> {
        let dir_iter = fs::read_dir(path).await.with_context(|| {
            format!("failed to open directory {} for reading", path.display())
        })?;

        let dir_stream = ReadDirStream::new(dir_iter);

        // Filter out errors reading directory entries.
        let dir_entries = dir_stream.filter_map(|entry| match entry {
            Ok(entry) => Some(entry),
            Err(err) => {
                warn!(
                    log, "error reading entry from {}", path.display();
                    "err" => %err,
                );
                None
            }
        });

        // Convert to a stream of `PathBuf`s of directory entries whose metadata
        // indicates they are files or symlinks to files.
        let dir_files = dir_entries.then(|entry| async move {
            let path = entry.path();
            let file_type = match entry.file_type().await {
                Ok(file_type) => file_type,
                Err(err) => {
                    warn!(
                        log,
                        "error reading file type of {}",
                        path.display();
                        "err" => %err,
                    );
                    return None;
                }
            };

            if file_type.is_symlink() {
                // Attempt to check whether the linked-to file is a file or
                // directory.
                let meta = match fs::metadata(&path).await {
                    Ok(meta) => meta,
                    Err(err) => {
                        warn!(
                            log, "failed to read metadata of {}", path.display();
                            "err" => %err,
                        );
                        return None;
                    }
                };
                meta.file_type().is_file().then_some(path)
            } else {
                file_type.is_file().then_some(path)
            }
        }).filter_map(convert::identity);

        // For all these path bufs, open them and compute hashes.
        let file_hashes = dir_files
            .then(|path| async move {
                let mut file = match File::open(&path).await {
                    Ok(file) => file,
                    Err(err) => {
                        warn!(
                            log, "failed to open {}", path.display();
                            "err" => %err,
                        );
                        return None;
                    }
                };

                // TODO: When the host requests a phase 2 image by hash, it's
                // the hash of the file _after_ its 4 KiB header (that header
                // includes the hash itself). For now in faux-mgs, we'll just
                // skip over the first 4 KiB when computing the hash of files
                // we're going to serve. In real MGS, we probably want to do
                // something smarter here: maybe compute the hash (skipping 4
                // KiB) and then check against the hash in the header itself?
                match file.seek(SeekFrom::Start(4096)).await {
                    Ok(_) => (),
                    Err(err) => {
                        warn!(
                            log, "failed to seek to offset 4096 in {}",
                            path.display();
                            "err" => %err,
                        );
                        return None;
                    }
                }

                let mut hasher = Sha256::new();
                let mut buf = [0; 4096];
                let digest = loop {
                    match file.read(&mut buf).await {
                        Ok(0) => break hasher.finalize(),
                        Ok(n) => hasher.update(&buf[..n]),
                        Err(err) => {
                            warn!(
                                log, "error reading {}", path.display();
                                "err" => %err,
                            );
                            return None;
                        }
                    }
                };

                Some((path, digest, file))
            })
            .filter_map(convert::identity);
        tokio::pin!(file_hashes);

        let mut images = HashMap::new();
        while let Some((path, digest, file)) = file_hashes.next().await {
            info!(
                log, "host phase 2 directory found file";
                "path" => path.display(),
                "hash" => hex::encode(digest),
            );
            images.insert(digest.into(), Mutex::new(file));
        }

        Ok(Self { images })
    }
}

#[async_trait]
impl HostPhase2Provider for DirectoryHostPhase2Provider {
    async fn read_phase2_data(
        &self,
        hash: [u8; 32],
        offset: u64,
        out: &mut [u8],
    ) -> Result<usize, HostPhase2Error> {
        let file = self.images.get(&hash).ok_or_else(|| {
            HostPhase2Error::NoImage { hash: hex::encode(hash) }
        })?;

        let mut file = file.lock().await;

        file.seek(SeekFrom::Start(offset)).await.map_err(|err| {
            HostPhase2Error::Other {
                hash: hex::encode(hash),
                offset,
                err: format!("seek failed: {err}"),
            }
        })?;

        file.read(out).await.map_err(|err| HostPhase2Error::Other {
            hash: hex::encode(hash),
            offset,
            err: format!("read failed: {err}"),
        })
    }
}
