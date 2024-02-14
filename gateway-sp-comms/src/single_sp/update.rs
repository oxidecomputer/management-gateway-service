// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

use super::CursorExt;
use super::InnerCommand;
use super::Result;
use crate::error::UpdateError;
use crate::sp_response_expect::*;
use gateway_messages::ComponentUpdatePrepare;
use gateway_messages::MgsRequest;
use gateway_messages::SpComponent;
use gateway_messages::SpUpdatePrepare;
use gateway_messages::UpdateChunk;
use gateway_messages::UpdateId;
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
use uuid::Uuid;

/// Start an update to the SP itself.
///
/// If the SP acks that the update can begin, spawns a task to deliver the
/// update.
pub(super) async fn start_sp_update(
    cmds_tx: &mpsc::Sender<InnerCommand>,
    update_id: Uuid,
    image: Vec<u8>,
    log: &Logger,
) -> Result<(), UpdateError> {
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

    tokio::spawn(drive_sp_update(
        cmds_tx.clone(),
        update_id,
        aux_image,
        sp_image,
        log.clone(),
    ));

    Ok(())
}

/// Function that should be `tokio::spawn`'d to drive an SP update to
/// completion.
async fn drive_sp_update(
    cmds_tx: mpsc::Sender<InnerCommand>,
    update_id: Uuid,
    aux_image: Option<Vec<u8>>,
    sp_image: Vec<u8>,
    log: Logger,
) {
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
                "err" => message,
                "update_id" => %update_id,
            );
            return;
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
                    err,
                );
                return;
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
        }
        Err(err) => {
            error!(
                log, "update failed";
                "id" => %update_id,
                err,
            );
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

/// Start an update to the RoT.
pub(super) async fn start_rot_update(
    cmds_tx: &mpsc::Sender<InnerCommand>,
    update_id: Uuid,
    component: SpComponent,
    slot: u16,
    image: Vec<u8>,
    log: &Logger,
) -> Result<(), UpdateError> {
    let rot_image = match component {
        SpComponent::ROT => {
            match slot {
                // Hubris images
                0 | 1 => {
                    let archive = RawHubrisArchive::from_vec(image)?;
                    let rot_image = archive.image.to_binary()?;

                    // Sanity check on `hubtools`: Prior to using hubtools, we would manually
                    // extract `img/final.bin` from the archive (which is a zip file); we're now
                    // using `archive.image.to_binary()` which _should_ be the same thing. Check
                    // here and log a warning if it is not. We should never see this, but if we
                    // do it's likely something is about to go wrong, and it'd be nice to have a
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

                    // Preflight check 1: Does the image name of this archive match the target
                    // slot?
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
                        // At the time of this writing `image-name` is a recent addition to
                        // hubris archives, so skip this check if we don't have one.
                        Err(HubtoolsError::MissingFile(..)) => (),
                        Err(err) => return Err(err.into()),
                    }

                    // TODO: Add a caboose BORD preflight check just like the SP has, once the
                    // RoT has a caboose and we have RPC calls to read its values.
                    rot_image
                }
                _ => return Err(UpdateError::InvalidSlotIdForOperation),
            }
        }
        SpComponent::STAGE0 => {
            match slot {
                // Staging area for a Bootloader image
                // stage0next can be updated directly, stage0 cannot.
                1 => {
                    // The Bootleby bootloader has previously been packaged
                    // as a simple zip archive without the extra information
                    // found in the Hubris-style zip archive. The old format
                    // has been used in manufacturing and for updating machines
                    // with debug probes attached.
                    //
                    // When we are satisfied with automated update of bootleby,
                    // then updated manufacturing images and rollback
                    // protection (to be implemented) will allow us to remove
                    // support for the old image format. Until then, we need
                    // to be able to update and rollback using the old and new
                    // releases.
                    //
                    // So, for now, access the Bootleby archive as a plain zip
                    // file where we are looking for either 'bootleby.bin' or
                    // 'img/final.bin'. Later, use RawHubrisArchive as above.
                    let contents = image.clone();
                    let cursor = Cursor::new(contents.as_slice());
                    let mut archive = match zip::ZipArchive::new(cursor) {
                        Ok(archive) => archive,
                        Err(_) => return Err(UpdateError::InvalidArchive),
                    };

                    // Support old format archives for now.
                    let mut rot_image = vec![];
                    for i in 0..archive.len() {
                        let mut file = match archive.by_index(i) {
                            Ok(file) => file,
                            Err(e) => {
                                error!(
                                    log,
                                    "did not find bootloader file: {}", e
                                );
                                return Err(UpdateError::InvalidArchive);
                            }
                        };
                        if matches!(
                            &file.name(),
                            &"bootleby.bin" | &"img/final.bin"
                        ) {
                            if file.read_to_end(&mut rot_image).is_err() {
                                error!(log, "invalid archive");
                                return Err(UpdateError::InvalidArchive);
                            }
                            debug!(
                                log,
                                "found bootloader file {}",
                                &file.name()
                            );
                            break;
                        }
                    }
                    rot_image
                }
                _ => return Err(UpdateError::InvalidSlotIdForOperation),
            }
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
) -> Result<(), UpdateError> {
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

    tokio::spawn(drive_component_update(
        cmds_tx.clone(),
        component,
        update_id,
        image,
        log.clone(),
    ));

    Ok(())
}

/// Function that should be `tokio::spawn`'d to drive a component update to
/// completion.
async fn drive_component_update(
    cmds_tx: mpsc::Sender<InnerCommand>,
    component: SpComponent,
    update_id: Uuid,
    image: Vec<u8>,
    log: Logger,
) {
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
                "err" => message,
                "update_id" => %update_id,
            );
            return;
        }
    }

    // Deliver the update in chunks.
    match send_update_in_chunks(&cmds_tx, component, update_id, image, &log)
        .await
    {
        Ok(()) => {
            info!(log, "update complete"; "id" => %update_id);
        }
        Err(err) => {
            error!(
                log, "update failed";
                "id" => %update_id,
                err,
            );
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

        image = send_single_update_chunk(cmds_tx, component, id, offset, image)
            .await?;

        // Update our offset according to how far our cursor advanced.
        offset += (image.position() - prior_pos) as u32;
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
) -> Result<Cursor<Vec<u8>>> {
    let update_chunk = UpdateChunk { component, id, offset };
    let (result, data) = super::rpc_with_trailing_data(
        cmds_tx,
        MgsRequest::UpdateChunk(update_chunk),
        data,
    )
    .await;

    result.and_then(expect_update_chunk_ack)?;

    Ok(data)
}
