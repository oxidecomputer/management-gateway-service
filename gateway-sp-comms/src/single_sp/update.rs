// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

use super::CursorExt;
use super::InnerCommand;
use super::Result;
use crate::error::CommunicationError;
use crate::error::UpdateError;
use crate::sp_response_expect::*;
use futures::Future;
use futures::FutureExt;
use gateway_messages::ComponentUpdatePrepare;
use gateway_messages::MgsRequest;
use gateway_messages::SpComponent;
use gateway_messages::SpError;
use gateway_messages::SpUpdatePrepare;
use gateway_messages::UpdateChunk;
use gateway_messages::UpdateId;
use gateway_messages::UpdateInProgressStatus;
use gateway_messages::UpdateStatus;
use hubtools::Error as HubtoolsError;
use hubtools::RawHubrisArchive;
use slog::debug;
use slog::error;
use slog::info;
use slog::warn;
use slog::Logger;
use std::convert::TryInto;
use std::io::Cursor;
use std::io::Read;
use std::time::Duration;
use tlvc::TlvcReader;
use tokio::sync::mpsc;
use tokio::task::JoinError;
use tokio::task::JoinHandle;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum UpdateDriverTaskError {
    #[error("update preparation failed: {0}")]
    UpdatePreparation(String),
    #[error("aux flash update failed")]
    AuxFlashUpdate(#[source] CommunicationError),
    #[error("update chunk delivery failed")]
    UpdateChunkDelivery(#[source] CommunicationError),
}

/// A newtype wrapper around the [`JoinHandle`] for the tokio task responsible
/// for driving an update.
///
/// Allows callers to check for completion (and whether that completion
/// succeeded or failed), but does not allow callers to abort the update task.
pub struct UpdateDriverTask {
    inner: JoinHandle<Result<(), UpdateDriverTaskError>>,
}

impl UpdateDriverTask {
    fn spawn<T>(task: T) -> Self
    where
        T: Future<Output = Result<(), UpdateDriverTaskError>> + Send + 'static,
    {
        let inner = tokio::task::spawn(task);
        Self { inner }
    }

    pub fn is_finished(&self) -> bool {
        self.inner.is_finished()
    }
}

impl Future for UpdateDriverTask {
    type Output = Result<Result<(), UpdateDriverTaskError>, JoinError>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.inner.poll_unpin(cx)
    }
}

/// Start an update to the SP itself.
///
/// If the SP acks that the update can begin, spawns a task to deliver the
/// update.
pub(super) async fn start_sp_update(
    cmds_tx: &mpsc::Sender<InnerCommand>,
    update_id: Uuid,
    image: Vec<u8>,
    log: &Logger,
) -> Result<UpdateDriverTask, UpdateError> {
    let archive = RawHubrisArchive::from_vec(image)?;

    let sp_image = archive.image.to_binary()?;
    let sp_image_size =
        sp_image.len().try_into().map_err(|_err| UpdateError::ImageTooLarge)?;

    // Sanity check on `hubtools`: Prior to using hubtools, we would manually
    // extract `img/final.bin` from the archive (which is a zip file); we're now
    // using `archive.image.to_binary()` which _should_ be the same thing. Check
    // here and log a warning if it is not. We should never see this, but if we
    // do it's likely something is about to go wrong, and it'd be nice to have a
    // breadcrumb.
    if let Ok(final_bin) = archive.extract_file("img/final.bin") {
        if sp_image != final_bin {
            warn!(
                log,
                "hubtools `image.to_binary()` DOES NOT MATCH `img/final.bin`",
            );
        }
    }

    // Extract the board from the image's caboose and check that this matches
    // our target's board (e.g., to avoid trying to update a sidecar SP with a
    // gimlet SP image). The SP will also perform this check, but it can't do it
    // until we've streamed the entire update into its flash, so doing it now
    // can avoid an unnecessary erase/write cycle.
    let caboose = archive.read_caboose()?;
    let archive_board = caboose.board()?;

    // In the future, we could use `ReadComponentCaboose` here instead, but
    // `ReadCaboose` is older (and thus more widely compatible with SP images).
    let sp_board =
        super::rpc(cmds_tx, MgsRequest::ReadCaboose { key: *b"BORD" }, None)
            .await
            .result
            .and_then(expect_caboose_value)?;
    if archive_board != sp_board {
        return Err(UpdateError::BoardMismatch {
            sp: String::from_utf8_lossy(&sp_board).to_string(),
            archive: String::from_utf8_lossy(archive_board).to_string(),
        });
    }

    let aux_image = match archive.auxiliary_image() {
        Ok(aux_image) => Some(aux_image),
        Err(HubtoolsError::MissingFile(..)) => None,
        Err(err) => return Err(err.into()),
    };

    let (aux_flash_size, aux_flash_chck) = match &aux_image {
        Some(data) => {
            let size = data
                .len()
                .try_into()
                .map_err(|_err| UpdateError::ImageTooLarge)?;
            let chck = read_auxi_check_from_tlvc(data)?;
            (size, chck)
        }
        None => (0, [0; 32]),
    };

    info!(
        log, "starting SP update";
        "id" => %update_id,
        "aux_flash_chck" => ?aux_flash_chck,
        "aux_flash_size" => aux_flash_size,
        "sp_image_size" => sp_image_size,
    );
    super::rpc(
        cmds_tx,
        MgsRequest::SpUpdatePrepare(SpUpdatePrepare {
            id: update_id.into(),
            aux_flash_size,
            aux_flash_chck,
            sp_image_size,
        }),
        None,
    )
    .await
    .result
    .and_then(expect_sp_update_prepare_ack)?;

    Ok(UpdateDriverTask::spawn(drive_sp_update(
        cmds_tx.clone(),
        update_id,
        aux_image,
        sp_image,
        log.clone(),
    )))
}

/// Function that should be `tokio::spawn`'d to drive an SP update to
/// completion.
async fn drive_sp_update(
    cmds_tx: mpsc::Sender<InnerCommand>,
    update_id: Uuid,
    aux_image: Option<Vec<u8>>,
    sp_image: Vec<u8>,
    log: Logger,
) -> Result<(), UpdateDriverTaskError> {
    let id = update_id.into();

    // Wait until the SP has finished preparing for this update.
    let sp_matched_chck = match poll_until_update_prep_complete(
        &cmds_tx,
        SpComponent::SP_ITSELF,
        id,
        aux_image.is_some(),
        &log,
    )
    .await
    {
        Ok(sp_matched_chck) => {
            info!(
                log, "update preparation complete";
                "update_id" => %update_id,
            );
            sp_matched_chck
        }
        Err(message) => {
            error!(
                log, "update preparation failed";
                "err" => &message,
                "update_id" => %update_id,
            );
            return Err(UpdateDriverTaskError::UpdatePreparation(message));
        }
    };

    // Send the aux flash image, if necessary.
    if !sp_matched_chck {
        // `poll_until_update_prep_complete` can only return `Ok(false)` if we
        // told it we had an aux flash update (i.e., if `aux_image.is_some()`).
        // Therefore, we can safely unwrap here.
        let data = aux_image.unwrap();
        match send_update_in_chunks(
            &cmds_tx,
            SpComponent::SP_AUX_FLASH,
            update_id,
            data,
            &log,
        )
        .await
        {
            Ok(()) => {
                info!(log, "aux flash update complete"; "id" => %update_id);
            }
            Err(err) => {
                error!(
                    log, "aux flash update failed";
                    "id" => %update_id,
                    &err,
                );
                return Err(UpdateDriverTaskError::AuxFlashUpdate(err));
            }
        }
    }

    // Deliver the SP image.
    match send_update_in_chunks(
        &cmds_tx,
        SpComponent::SP_ITSELF,
        update_id,
        sp_image,
        &log,
    )
    .await
    {
        Ok(()) => {
            info!(log, "update complete"; "id" => %update_id);
            Ok(())
        }
        Err(err) => {
            error!(
                log, "update failed";
                "id" => %update_id,
                &err,
            );
            Err(UpdateDriverTaskError::UpdateChunkDelivery(err))
        }
    }
}

fn read_auxi_check_from_tlvc(data: &[u8]) -> Result<[u8; 32], UpdateError> {
    let mut reader = TlvcReader::begin(data).map_err(UpdateError::TlvcError)?;
    let mut chck = None;

    while let Some(chunk) = reader.next().map_err(UpdateError::TlvcError)? {
        if chunk.header().tag != *b"CHCK" {
            // We could recompute the hash on AUXI and make sure it
            // matches, but the SP has to do that itself anyway. We don't expect
            // them to be mismatched more or less ever, so we won't bother
            // checking here and will just let the SP do it.
            continue;
        }
        if chunk.len() != 32 {
            return Err(UpdateError::CorruptTlvc(format!(
                "expected 32-long chck, got {}",
                chunk.len()
            )));
        }
        if chck.is_some() {
            return Err(UpdateError::CorruptTlvc(
                "multiple CHCK entries".to_string(),
            ));
        }

        let mut data = [0; 32];
        chunk.read_exact(0, &mut data[..]).map_err(UpdateError::TlvcError)?;
        chck = Some(data);
    }

    chck.ok_or_else(|| {
        UpdateError::CorruptTlvc("missing CHCK entry".to_string())
    })
}

/// Isolate extraction of bootleby from old-format archives.
// TODO: When old-format archives are eliminated from customer
// racks and spares inventory, then this code can be removed.
fn bootleby_from_old_style_archive(
    image: Vec<u8>,
    log: &Logger,
) -> Result<Vec<u8>, UpdateError> {
    // Try the pre-v1.2.0 Bootleby archive format.
    let cursor = Cursor::new(image.as_slice());
    let mut archive = zip::ZipArchive::new(cursor).map_err(|zip_error| {
        // Return the original Hubris Archive error instead
        // of our attempted zip extraction error.
        HubtoolsError::ZipError(zip_error)
    })?;

    for i in 0..archive.len() {
        match archive.by_index(i) {
            Ok(mut file) => {
                if file.name() == "bootleby.bin" {
                    let mut rot_image = vec![];
                    match file.read_to_end(&mut rot_image) {
                        Ok(_) => {
                            debug!(
                                log,
                                "using bootleby.bin from old-style archive"
                            );
                            return Ok(rot_image);
                        }
                        Err(err) => {
                            error!(log, "cannot access bootleby.bin from zip file index {i}: {err}");
                            return Err(UpdateError::InvalidArchive);
                        }
                    }
                }
            }
            Err(err) => {
                error!(log, "cannot access zip archive at index {i}: {err}")
            }
        }
    }
    Err(UpdateError::ImageNotFound)
}

/// Start an update to the RoT.
pub(super) async fn start_rot_update(
    cmds_tx: &mpsc::Sender<InnerCommand>,
    update_id: Uuid,
    component: SpComponent,
    slot: u16,
    image: Vec<u8>,
    log: &Logger,
) -> Result<UpdateDriverTask, UpdateError> {
    let rot_image = match component {
        SpComponent::ROT => {
            match slot {
                // Hubris images
                0 | 1 => {
                    let archive = RawHubrisArchive::from_vec(image)?;
                    let rot_image = archive.image.to_binary()?;

                    // Sanity check on `hubtools`: Prior to using hubtools, we
                    // would manually extract `img/final.bin` from the archive
                    // (which is a zip file); we're now using
                    // `archive.image.to_binary()` which _should_ be the same
                    // thing. Check here and log a warning if it is not. We
                    // should never see this, but if we do it's likely something
                    // is about to go wrong, and it'd be nice to have a
                    // breadcrumb.
                    if let Ok(final_bin) = archive.extract_file("img/final.bin")
                    {
                        if rot_image != final_bin {
                            warn!(
                                log,
                                "hubtools `image.to_binary()` DOES NOT MATCH `img/final.bin`",
                            );
                        }
                    }

                    // Preflight check 1: Does the image name of this archive
                    // match the target slot?
                    match archive.image_name() {
                        Ok(image_name) => match (image_name.as_str(), slot) {
                            ("a", 0) | ("b", 1) => (), // OK!
                            _ => {
                                return Err(UpdateError::RotSlotMismatch {
                                    slot,
                                    image_name,
                                })
                            }
                        },
                        // At the time of this writing `image-name` is a recent
                        // addition to hubris archives, so skip this check if we
                        // don't have one.
                        Err(HubtoolsError::MissingFile(..)) => (),
                        Err(err) => return Err(err.into()),
                    }

                    // TODO: Add a caboose BORD preflight check just like the SP
                    // has, once the RoT has a caboose and we have RPC calls to
                    // read its values.
                    rot_image
                }
                _ => return Err(UpdateError::InvalidSlotIdForOperation),
            }
        }
        SpComponent::STAGE0 => {
            // Staging area for a Bootloader image:
            // stage0next can be updated directly, stage0 cannot.
            // The RoT will reject updates to slot !=1 but don't
            // waste its time.
            if slot != 1 {
                return Err(UpdateError::InvalidSlotIdForOperation);
            }

            RawHubrisArchive::from_vec(image.clone())
                .and_then(|archive| archive.image.to_binary())
                .or_else(|hubtool_error|
                    // Prior to v1.2.0, Bootleby was packaged as a simple
                    // zip archive containing a "bootleby.bin" file.
                    //
                    // TODO: Remove support for the old image format when
                    // those bootleby versions are no longer used in
                    // manufacturing and rollback protection can be used to
                    // prevent their re-introduction. Until then, we need to
                    // be able to test update and rollback using the oldest
                    // releases that may be in customers' racks or spares pool.
                    bootleby_from_old_style_archive(image, log)
                        // Report the original Hubtools error if
                        // this second chance did not work.
                        .map_err(|_| hubtool_error))?

            // TODO: Even though the RoT will protect itself, put
            // pre-flash checks here for BORD, Bootloader vs Hubris,
            // and signature validity.
        }
        _ => return Err(UpdateError::InvalidComponent),
    };

    start_component_update(cmds_tx, component, update_id, slot, rot_image, log)
        .await
}

/// Start an update to a component of the SP.
///
/// If the SP acks that the update can begin, spawns a task to deliver the
/// update.
pub(super) async fn start_component_update(
    cmds_tx: &mpsc::Sender<InnerCommand>,
    component: SpComponent,
    update_id: Uuid,
    slot: u16,
    image: Vec<u8>,
    log: &Logger,
) -> Result<UpdateDriverTask, UpdateError> {
    let total_size =
        image.len().try_into().map_err(|_err| UpdateError::ImageTooLarge)?;

    info!(
        log, "starting update";
        "component" => component.as_str(),
        "id" => %update_id,
        "total_size" => total_size,
    );
    super::rpc(
        cmds_tx,
        MgsRequest::ComponentUpdatePrepare(ComponentUpdatePrepare {
            component,
            id: update_id.into(),
            slot,
            total_size,
        }),
        None,
    )
    .await
    .result
    .and_then(expect_component_update_prepare_ack)?;

    Ok(UpdateDriverTask::spawn(drive_component_update(
        cmds_tx.clone(),
        component,
        update_id,
        image,
        log.clone(),
    )))
}

/// Function that should be `tokio::spawn`'d to drive a component update to
/// completion.
async fn drive_component_update(
    cmds_tx: mpsc::Sender<InnerCommand>,
    component: SpComponent,
    update_id: Uuid,
    image: Vec<u8>,
    log: Logger,
) -> Result<(), UpdateDriverTaskError> {
    let id = update_id.into();

    // Wait until the SP has finished preparing for this update.
    match poll_until_update_prep_complete(&cmds_tx, component, id, false, &log)
        .await
    {
        Ok(_) => {
            info!(
                log, "update preparation complete";
                "update_id" => %update_id,
            );
        }
        Err(message) => {
            error!(
                log, "update preparation failed";
                "err" => &message,
                "update_id" => %update_id,
            );
            return Err(UpdateDriverTaskError::UpdatePreparation(message));
        }
    }

    // Deliver the update in chunks.
    match send_update_in_chunks(&cmds_tx, component, update_id, image, &log)
        .await
    {
        Ok(()) => {
            info!(log, "update complete"; "id" => %update_id);
            Ok(())
        }
        Err(err) => {
            error!(
                log, "update failed";
                "id" => %update_id,
                &err,
            );
            Err(UpdateDriverTaskError::UpdateChunkDelivery(err))
        }
    }
}

/// Poll an SP until it indicates that preparation for update identified by `id`
/// has completed.
///
/// If `update_has_aux_image` is `true` (i.e., the update we're waiting on is an
/// SP update with an aux flash image), we poll until we see the
/// `SpUpdateAuxFlashChckScan` status from the SP, and then return `true` or
/// `false` indicating whether the SP found a matching CHCK (i.e., returning
/// `Ok(true)` means the SP found a matching CHCK, and we don't need to send the
/// aux flash image). Receiving an `InProgress` status will result in an error
/// being returned, as we don't expect to see that state until we start sending
/// data.
///
/// If `update_has_aux_image` is `false`, we poll until we see the `InProgress`
/// status from the SP. Receiving an `SpUpdateAuxFlashChckScan` status will
/// result in an error being returned. We always return `Ok(true)` upon seeing
/// `InProgress` (i.e., if `update_has_aux_image` is `false`, we will either
/// return `Ok(true)` or an error, never `Ok(false)`).
async fn poll_until_update_prep_complete(
    cmds_tx: &mpsc::Sender<InnerCommand>,
    component: SpComponent,
    id: UpdateId,
    update_has_aux_image: bool,
    log: &Logger,
) -> Result<bool, String> {
    // The choice of interval is relatively arbitrary; we expect update
    // preparation to generally fall in one of two cases:
    //
    // 1. No prep is necessary, and the update can happen immediately
    //    (we'll never sleep)
    // 2. Prep is relatively slow (e.g., erasing a flash part)
    //
    // We choose a few seconds assuming this polling interval is
    // primarily hit when the SP is doing something slow.
    const POLL_UPDATE_STATUS_INTERVAL: Duration = Duration::from_secs(2);

    // Poll SP until update preparation is complete.
    loop {
        // Get update status from the SP or give up.
        let status = match update_status(cmds_tx, component).await {
            Ok(status) => status,
            Err(err) => {
                return Err(format!("could not get status from SP: {err}"));
            }
        };

        // Either sleep and retry (if still preparing), break out of our
        // loop (if prep complete), or fail (anything else).
        match status {
            UpdateStatus::Preparing(sub_status) => {
                if sub_status.id == id {
                    debug!(
                        log,
                        "SP still preparing; sleeping for {:?}",
                        POLL_UPDATE_STATUS_INTERVAL
                    );
                    tokio::time::sleep(POLL_UPDATE_STATUS_INTERVAL).await;
                    continue;
                }
                // Else: fall through to returning an error.
            }
            UpdateStatus::InProgress(sub_status) => {
                if sub_status.id == id && !update_has_aux_image {
                    return Ok(true);
                }
                // Else: fall through to returning an error.
            }
            UpdateStatus::SpUpdateAuxFlashChckScan {
                id: sp_id,
                found_match,
                ..
            } => {
                if sp_id == id && update_has_aux_image {
                    return Ok(found_match);
                }
                // Else: fall through to returning an error.
            }
            UpdateStatus::None
            | UpdateStatus::Complete(_)
            | UpdateStatus::Failed { .. }
            | UpdateStatus::RotError { .. }
            | UpdateStatus::Aborted(_) => {
                // Fall through to returning an error below.
            }
        }

        return Err(format!("update preparation failed; status = {status:?}"));
    }
}

/// Get the status of any update being applied to the given component.
pub(super) async fn update_status(
    cmds_tx: &mpsc::Sender<InnerCommand>,
    component: SpComponent,
) -> Result<UpdateStatus> {
    super::rpc(cmds_tx, MgsRequest::UpdateStatus(component), None)
        .await
        .result
        .and_then(expect_update_status)
}

/// Send an update image to the SP in chunks.
async fn send_update_in_chunks(
    cmds_tx: &mpsc::Sender<InnerCommand>,
    component: SpComponent,
    update_id: Uuid,
    data: Vec<u8>,
    log: &Logger,
) -> Result<()> {
    let mut image = Cursor::new(data);
    let mut offset = 0;
    let id = update_id.into();
    while !CursorExt::is_empty(&image) {
        let prior_pos = image.position();
        debug!(
            log, "sending update chunk";
            "id" => %update_id,
            "offset" => offset,
        );

        let result;
        (image, result) =
            send_single_update_chunk(cmds_tx, component, id, offset, image)
                .await;

        match result {
            Ok(()) => {
                // Update our offset according to how far our cursor advanced.
                offset += (image.position() - prior_pos) as u32;
            }
            Err(
                err @ CommunicationError::SpError(SpError::InvalidUpdateChunk),
            ) => {
                warn!(
                    log,
                    "received invalid update chunk from SP; attempting recovery"
                );
                // Ideally `InvalidUpdateChunk` would return the offset the SP
                // wants. We could add a new error variant for that; fow now,
                // try to recover by asking the SP what chunk it expected.
                if let Some(sp_offset) =
                    determine_update_resume_point_via_update_status(
                        cmds_tx,
                        component,
                        update_id,
                        image.get_ref().len(),
                        log,
                    )
                    .await
                {
                    // Rewind both our offset and the cursor on the data.
                    offset = sp_offset;
                    image.set_position(u64::from(sp_offset));
                } else {
                    // `determine_update_resume_point_via_update_status()`
                    // already logged any meaningful problems fetching the
                    // status; all we can do is bail out.
                    return Err(err);
                }
            }
            Err(err) => {
                return Err(err);
            }
        }
    }
    Ok(())
}

/// Send a portion of an update to the SP.
///
/// `data` is moved into this function, updated based on the amount delivered in
/// this chunk, and returned.
async fn send_single_update_chunk(
    cmds_tx: &mpsc::Sender<InnerCommand>,
    component: SpComponent,
    id: UpdateId,
    offset: u32,
    data: Cursor<Vec<u8>>,
) -> (Cursor<Vec<u8>>, Result<()>) {
    let update_chunk = UpdateChunk { component, id, offset };
    let (result, data) = super::rpc_with_trailing_data(
        cmds_tx,
        MgsRequest::UpdateChunk(update_chunk),
        data,
    )
    .await;

    let result = result.and_then(expect_update_chunk_ack);

    (data, result)
}

/// Attempt to determine what offset the SP is expecting mid-update.
///
/// We use this when receiving an `InvalidUpdateChunk` from the SP, which
/// indicates it's still expecting our update but we've gotten out of sync on
/// how far along it is (e.g., via a lost packet containing an ACK from the SP
/// for some successful chunk that we believe we need to resend).
async fn determine_update_resume_point_via_update_status(
    cmds_tx: &mpsc::Sender<InnerCommand>,
    component: SpComponent,
    update_id: Uuid,
    image_len: usize,
    log: &Logger,
) -> Option<u32> {
    // We can only recover if the SP still thinks this update is in progress.
    let progress =
        match super::rpc(cmds_tx, MgsRequest::UpdateStatus(component), None)
            .await
            .result
            .and_then(expect_update_status)
        {
            Ok(UpdateStatus::InProgress(progress)) => progress,
            Ok(other_status) => {
                error!(
                    log,
                    "invalid update chunk recovery failed: \
                     SP update status is not in progress";
                    "status" => ?other_status,
                );
                return None;
            }
            Err(status_err) => {
                error!(
                    log,
                    "invalid update chunk recovery failed: \
                     could not get update status from SP";
                    &status_err,
                );
                return None;
            }
        };

    let UpdateInProgressStatus { id, bytes_received, total_size } = progress;
    let id = Uuid::from(id);

    // This error check is not load-bearing; if we try to resume with our update
    // ID and some other update is in progress, the SP will reject it with a
    // different error (`InvalidUpdateId`). But it's easy enough to check here
    // too to avoid that round trip in almost all cases, and it makes the
    // "should never happen" cases below more sensible if we know the other
    // fields relate to this same update ID.
    if id != update_id {
        error!(
            log,
            "invalid update chunk recovery failed: \
             a different update is in progress";
            "our_update_id" => %update_id,
            "sp_update_id" => %id,
        );
        return None;
    }

    // This should never happen; if the update ID matches, we and the SP should
    // both know how long the image is.
    if usize::try_from(total_size).expect("u32 fits in usize") != image_len {
        error!(
            log,
            "invalid update chunk recovery failed: \
             SP expects an incorrect image length";
            "our_image_len" => image_len,
            "sp_expects_len" => total_size,
        );
        return None;
    }

    // This should never happen; the SP should never claim to have received more
    // bytes than the total image length.
    if bytes_received > total_size {
        error!(
            log,
            "invalid update chunk recovery failed: \
             invalid update status from SP \
             (bytes_received > total_size ?!)";
            "bytes_received" => bytes_received,
            "total_size" => total_size,
        );
        return None;
    }

    warn!(
        log,
        "invalid update chunk recovery: attempting to resume \
         from offset {bytes_received}"
    );
    Some(bytes_received)
}
