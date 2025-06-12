// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright 2025 Oxide Computer Company

// Helper module for the upgrade-rollback script.
// Contains functions for image processing, firmware updates, state checks,
// and other operational logic that may be useful with various higher level
// scripts.

import `${script_dir}/util` as util;

// --- Functions related to Image Info and Verification ---

/// Checks and organizes image information from configuration.
/// Reads device info (CMPA, CFPA), verifies RoT images, builds GITC map.
///
/// Args:
///   conf (map): The fully resolved configuration map.
///
/// Returns:
///   Map: Image details, caboose info, verification status, GITC mapping.
///   int: `1` if a critical error occurred.
fn get_image_info(conf) {
    let images = #{};

    images["cmpa"] = util::get_cmpa();
    images["cfpa"] = util::get_cfpa();
    if images.cmpa == () || images.cfpa == () {
        debug("error|Failed to read CMPA or CFPA from device.");
        return 1;
    }
    images["keyset"] = util::get_rot_keyset(images.cmpa);
    debug(`info|Detected RoT keyset: ${images.keyset}`);

    let gitc = #{};
    let error_found = false;
    let failed_verify_list = [];

    for branch in ["base", "ut"] {
        images[branch] = #{};
        for image_type in ["sp", "rot_a", "rot_b", "stage0"] {
            let zip_path = conf?[branch]?[image_type];
            if zip_path == () {
                 debug(`warn|Skipping missing path for ${branch}.${image_type}`);
                 continue;
            }
            images[branch][image_type] = #{"path": zip_path};

            // Setup to extract information from Hubris archive files using
            // global custom Rhai object: `Archive` and `Caboose`
            let current_ar = ();
            let archive_ok = true;
            try {
                current_ar = new_archive(zip_path);
            } catch(err) {
                debug(`error|Failed creating archive for ${zip_path}: ${err}`);
                error_found = true;
                archive_ok = false;
            }
            if !archive_ok {
                continue;
            }
            if type_of(current_ar) != "Archive" {
                debug(`error|Invalid archive object for path ${zip_path}`);
                error_found = true;
                continue;
            }
            images[branch][image_type]["caboose"] = #{};

            // Now get the desired information
            let caboose_obj = current_ar?["caboose"];
            if caboose_obj == () || type_of(caboose_obj) == "()" {
                debug(`warn|Could not get caboose object from ${zip_path}`);
            } else if type_of(caboose_obj) == "map" && caboose_obj?.error != () {
                debug(
                    `warn|Error getting caboose object from ${zip_path}: ` +
                    `${caboose_obj.error}`
                );
            } else {
                let caboose_read_ok = true;
                for key in ["BORD", "GITC", "NAME", "SIGN", "VERS"] {
                    let val = ();
                    try { val = caboose_obj[key]; } catch (err) {
                         debug(`warn|Failed reading caboose key '${key}' from ${zip_path}: ${err}`);
                         caboose_read_ok = false;
                    }
                    if val != () {
                        images[branch][image_type]["caboose"][key] = val;
                    }
                }
                if images[branch][image_type]["caboose"]?.GITC == () {
                     debug(
                        `warn|Could not read essential GITC from caboose in ${zip_path}. ` +
                        `Read OK: ${caboose_read_ok}`
                     );
                }
            }

            if image_type != "sp" {
                // Assume that RoT or Stage0 signatures will verify
                let verified = true;
                let verify_error = ();
                try {
                    verified = current_ar.verify_rot_image(images.cmpa, images.cfpa);
                } catch (err) {
                    verified = false;
                    verify_error = err;
                }
                images[branch][image_type]["verified"] = verified;
                if !verified {
                    failed_verify_list += images[branch][image_type]["path"];
                    debug(
                       `warn|Sig verification FAILED: ` +
                       `${images[branch][image_type]["path"]}. Error: ${verify_error}`
                    );
                } else {
                     debug(
                         `info|Sig verified OK: ${images[branch][image_type]["path"]}`
                     );
                }
            } else { // SP image
                images[branch][image_type]["verified"] = true;
                // TODO: Add SP-specific BORD/NAME checks if needed
            }

            let image_gitc = images[branch][image_type]?.caboose?["GITC"];
            if image_gitc != () {
                if gitc?[image_gitc] == () {
                    gitc[image_gitc] = [];
                }
                // TODO: Warn if base and ut GITCs match for sp/rot
                gitc[image_gitc] += [ `${branch}_${image_type}` ];
            }
        }
    }
    debug(`info|Image GITC reverse map: ${gitc}`);
    images["by_gitc"] = gitc;
    images["failed_to_verify"] = failed_verify_list;

    if images.failed_to_verify.len() > 0 {
         debug("warn|Some RoT images FAILED signature verification:");
         for path_str in images.failed_to_verify {
            debug(`warn|failed to verify: ${path_str}`);
         }
    }
    debug("debug|Image Info Map (get_image_info):\n" + images);
    if error_found {
        return 1;
    } else {
        return images;
    }
}

/// Reads caboose for a given component and slot using util::caboose_value.
fn get_caboose(component, slot) {
    let caboose = #{};
    for key in ["BORD", "GITC", "VERS", "NAME", "SIGN"] {
        let value = util::caboose_value(component, slot, key);
        if value != () {
            caboose[key] = value;
        }
    }
    return caboose;
}

/// Checks if SP needs flashing (active image != desired image).
//
// TODO: Should this check that alternate image == desired image and
// thereby avoid erase/flash cycle? This would be a 'check_alternate' flag
// and would require returning additional information in the map.
fn sp_needs_flashing(target_image_label, gitc_map) {
    let sp_gitc = util::caboose_value("sp", "active", "GITC");
    if sp_gitc == () {
         return #{"error": "Could not read active SP GITC."};
    }
    debug(`info|SP is running GITC=${sp_gitc}`);
    let known_images = gitc_map?[sp_gitc];
    debug(`info|Known images for SP GITC ${sp_gitc}: ${known_images}`);
    if known_images == () {
        debug("warn|SP GITC does not match known base/ut images.");
        return #{"ok": true};
    } else if target_image_label in known_images {
        debug(`info|Target ${target_image_label} IS IN known images.`);
        return #{"ok": false};
    } else {
        debug(`warn|Target ${target_image_label} IS NOT in known images.`);
        return #{"ok": true};
    }
}

/// Checks if RoT needs flashing.
//
// TODO: Should this check that alternate image == desired image and
// thereby avoid erase/flash cycle? This would be a 'check_alternate' flag
// and would require returning additional information in the map.
fn rot_needs_flashing(target_branch_prefix, gitc_map) {
    let rot_active_result = get_rot_active();
    if rot_active_result?.error != () {
        return #{"error": `Cannot get active RoT slot: ${rot_active_result.error}`};
    }
    let rot_active_slot = rot_active_result.ok;
    let target_image_label = `${target_branch_prefix}_rot_a`;
    if rot_active_slot == 1 {
        target_image_label = `${target_branch_prefix}_rot_b`;
    }
    let rot_gitc = util::caboose_value("rot", `${rot_active_slot}`, "GITC");
    if rot_gitc == () {
         return #{"error": `Could not read RoT GITC for slot ${rot_active_slot}.`};
    }
    debug(`info|RoT is running GITC=${rot_gitc} on active slot ${rot_active_slot}`);
    let known_images = gitc_map?[rot_gitc];
    debug(`info|Known images for RoT GITC ${rot_gitc}: ${known_images}`);
    if known_images == () {
        debug("info|RoT GITC does not match known base/ut images.");
        return #{"ok": true};
    } else if target_image_label in known_images {
        debug(`info|Target ${target_image_label} IS IN known images.`);
        return #{"ok": false};
    } else {
        debug(`info|Target ${target_image_label} IS NOT in known images.`);
        return #{"ok": true};
    }
}

/// Performs overall image check for SP and RoT against target branch.
//
// TODO: Add option to check if alternate partition has the desired image or
// always include that information. e.g. might return `#{ "sp": false,
// "sp_alternate": true, "rot": true, "rot_alternate": false}` indicating
// that the active sp image does not need to be flashed, the alternate sp image
// should be flashed to make it equal to the active image, the active rot image
// is needs flashing, but that the alternate rot image is the correct image.
// If the alternate rot image were made active, then the correct images would be
// running. The client could then work on matching active==alternate as their
// next step.
fn image_check(branch, images) {
    let ok = #{ "sp": false, "rot": false };
    let error = #{};
    let sp_result = sp_needs_flashing(`${branch}_sp`, images.by_gitc);
    if sp_result?.error != () {
        error["sp"] = `${sp_result.error}`;
    } else {
        ok["sp"] = sp_result.ok;
    }
    let rot_result = rot_needs_flashing(`${branch}`, images.by_gitc);
    if rot_result?.error != () {
        error["rot"] = `${rot_result.error}`;
    } else {
        ok["rot"] = rot_result.ok;
    }
    if error.len() > 0 {
        return #{"error": error};
    } else {
        return #{"ok": ok};
    }
}

/// Gets the currently active RoT slot (0 or 1).
fn get_rot_active() {
    let rbi = util::rot_boot_info();
    if rbi?.error != () {
        return #{"error": `Cannot get RBI: ${rbi.error}`};
    }
    let active_slot = rbi?.active;
    if active_slot == () {
         return #{"error": `Cannot determine active slot from RBI: ${rbi}`};
    }
    return #{"ok": active_slot};
}

/// Determine the *preferred* next RoT boot slot based on RBI preferences.
///
/// Note that if only one image is valid, it will be selected.
/// An update attempt can transmit and flash an incomplete or improperly signed
/// image.
/// The signature validity is only known after an RoT reset.
fn _get_active_and_next_rot_boot_preference() {
    let rbi = util::rot_boot_info();
    if rbi?.error != () {
        return #{"error": `Cannot get RBI: ${rbi.error}`};
    }
    if rbi?.active == () {
        return #{"error": `Invalid RBI: ${rbi}`};
    }

    let next_preferred = if rbi.transient_boot_preference != () {
        debug("info|Next boot by transient");
        rbi.transient_boot_preference
    } else if rbi.pending_persistent_boot_preference != () {
        debug("info|Next boot by pending persistent");
        rbi.pending_persistent_boot_preference
    } else {
        debug("info|Next boot by persistent");
        rbi.persistent_boot_preference
    };

    return #{"ok": #{"active": rbi.active, "next": next_preferred}};
}

/// Check if the currently running RoT firmware supports transient boot commands.
// Note this test will eventually be unnecessary. It modifies the RoT state in
// that it tries to set the transient preference to the currently active slot.
// If it fails, then the image does not have the transient feature implmented.
// In order to clear the transient preference, one needs to reset the RoT.
// This is a kludge.
// This will also fail later for violating rollback protection.
// TODO: Should distinguish the `RollbackProtection` error vs `Unsupported`
fn rot_supports_transient_boot_preference() {
    let r = _get_active_and_next_rot_boot_preference();
    if r?.error != () {
        debug(`error|Cannot get active RoT slot. Error: ${r.error}`);
        return false;
    }
    let active_slot = r.ok.active;
    if util::set_rot_boot_preference(active_slot, true, "transient_support_test") {
        debug("info|transient boot preference feature is supported.");
        return true;
    } else {
        debug(`warn|Failed to set transient boot to ${active_slot}.`);
        return false;
    }
}

/// Resets both SP and RoT components sequentially.
fn reset_sp_and_rot() {
    debug("info|Beginning reset sequence for RoT and SP.");
    for params in [["rot", 3], ["sp", 5]] {
        let component_to_reset = params[0];
        let sleep_duration = params[1];
        debug(`info|Reset ${component_to_reset}`);
        if !util::reset_component(component_to_reset) {
            return #{ "error": `Failed to reset component '${component_to_reset}'.` };
        }
        debug(
            `info|Reset '${component_to_reset}'. Sleeping ${sleep_duration}s.`
        );
        sleep(sleep_duration);
    }
    debug("info|RoT and SP reset sequence complete.");
    return #{"ok": ()};
}


/// Updates SP firmware, resets, and polls for readiness.
fn update_sp(sp_zip) {
    debug(`info|update_sp: ${sp_zip}`);
    if (!util::update_sp_image(sp_zip)) {
        return false;
    }
    debug(`info|SP update command acknowledged.`);
    let r_status1 = util::check_update_in_progress("sp");
    debug(`info|SP status immediately after update command: ${r_status1}`);
    debug("info|Resetting SP to boot new image.");
    if (!util::reset_sp()) {
        return false;
    }
    debug("info|SP reset acknowledged. Polling for readiness.");

    let max_poll_attempts = 15;
    let poll_interval_secs = 1;
    let sp_ready_and_clean = false;
    for attempt in 1..=max_poll_attempts {
        debug(
            `info|Polling SP readiness, attempt ${attempt}` +
            `/${max_poll_attempts}...`
        );
        let sp_status = util::check_update_in_progress("sp");
        if sp_status == () {
            debug("info|SP is ready and no update in progress.");
            sp_ready_and_clean = true;
            break;
        } else if sp_status?.Err != () {
            debug(
                `warn|Readiness check attempt ${attempt}: ` +
                `Error getting SP status: ${sp_status}. Retrying.`
            );
        } else {
            debug(
                `warn|Readiness check attempt ${attempt}: ` +
                `SP reported unexpected status: ${sp_status}. Retrying.`
            );
        }
        if attempt < max_poll_attempts {
            sleep(poll_interval_secs);
        }
    }

    if !sp_ready_and_clean {
        debug(
            `error|SP did not become ready and clean after reset and `+
            `${max_poll_attempts} attempts.`
        );
        debug(`error|SP did not successfully reset and clear update status.\n`);
        return false;
    }
    debug("info|SP readiness and clean status confirmed.");
    debug(`info|SUCCESS update_sp: ${sp_zip}`);
    return true;
}

fn rot_log_initial_params(
    initial_slot, target_slot, image_path, target_label, use_transient_flag
) {
    debug(`info|--- rot_log_initial_params (update-helper) ---`);
    debug(`info|Target Label: ${target_label}, Use Transient: ${use_transient_flag}`);
    debug(`info|Initial Active RoT Slot (before op): ${initial_slot}`);
    debug(`info|Target RoT Update Slot (for op): ${target_slot}`);
    debug(`info|Target RoT Image (for op): ${image_path}`);
}

fn rot_log_rbi_details(
    rbi, context_description, initial_slot,
    target_slot, use_transient_flag_for_op
) {
    debug(`info|--- rot_log_rbi_details (${context_description}, update-helper) ---`);
    debug(`    Initial Active Slot (before op): ${initial_slot}`);
    debug(`    Target Update Slot (for op): ${target_slot}`);
    debug(`    Use Transient Flag (for op): ${use_transient_flag_for_op}`);
    debug(`    Current Active Slot (from RBI): ${rbi.active}`);
    debug(`    Persistent Pref (from RBI): ${rbi.persistent_boot_preference}`);
    debug(`    Transient Pref (from RBI): ${rbi.transient_boot_preference}`);
    debug(`    Pending Persistent Pref (from RBI): ${rbi.pending_persistent_boot_preference}`);
}

/// Check that the post-reset state after using the transient_boot_preference is
// as expected.
fn rot_validate_initial_transient_boot_state(
    rbi, initial_slot, target_update_slot, target_label
) {
    let failure_details = "";

    // The desired hubris image should be the active image.
    if rbi.active != target_update_slot {
        failure_details += ` Active(${rbi.active}) not target(${target_update_slot}).`;
    }

    // Transient_boot_preference will be None
    if rbi.transient_boot_preference != () {
        failure_details += ` transient_boot_preference(${rbi.transient_boot_preference}) not null.`;
    }

    // Pending_persistent_boot_preference will be None
    if rbi.pending_persistent_boot_preference != () {
        failure_details += ` pp_pref (${rbi.pending_persistent_boot_preference}) not null.`;
    }

    if failure_details.len() != 0 {
        debug(`error|Initial transient boot validation FAILED: ` +
              `${failure_details} RBI=${rbi}`);
        return false;
    } else {
        debug(`info|Initial transient boot validation PASSED for '${target_label}'.`);
    }
    return true;
}

fn rot_ensure_persistence_after_transient_boot(
    rbi_after_first_boot, target_update_slot, target_label
) {
    debug("info|--- rot_ensure_persistence_after_transient_boot (update-helper) ---");
    let active_after_first_reset = rbi_after_first_boot.active;
    let p_pref_from_newly_active = rbi_after_first_boot.persistent_boot_preference;
    let set_persistent_needed = true;

    if target_label == "baseline" {
        if p_pref_from_newly_active == active_after_first_reset {
            debug(
                `info|Target '${target_label}': p_pref already matches active. ` +
                `No explicit set_persistent needed.`
             );
            set_persistent_needed = false;
        } else {
            debug(
                `info|Target '${target_label}': p_pref differs from active. ` +
                `Will align by setting persistent.`
            );
        }
    }
    if set_persistent_needed {
        let reason = if target_label == "baseline" {
            "Align for baseline."
        } else {
            "Standard."
        };
        debug(`info|Setting persistent for slot ${target_update_slot} ('${target_label}'). Reason: ${reason}`);
        if !util::set_rot_boot_preference(target_update_slot, false, target_label) { // false -> '-p'
            debug(`error|util::set_rot_boot_preference failed.`);
            return false;
        }
        debug(`debug|util::set_rot_boot_preference called successfully.`);
    } else {
        debug(`debug|Skipping set persistent for '${target_label}'.`);
    }
    return true;
}

fn rot_validate_final_persistent_boot_state(
    final_rbi, target_update_slot, target_label
) {
    debug("info|--- rot_validate_final_persistent_boot_state (update-helper) ---");
    let final_active_slot = final_rbi.active;
    let final_p_pref = final_rbi.persistent_boot_preference;
    debug(`info|Final RBI: active=${final_active_slot}, p_pref=${final_p_pref}`);

    if final_active_slot != target_update_slot {
        debug(`error|Validation FAILED: Target '${target_label}' NOT on persistent slot.`);
        return false;
    }
    if final_p_pref != target_update_slot {
         debug(`warn|Validation NOTE: Target '${target_label}': final p_pref is ${final_p_pref}.`);
    }
    debug(`info|Validation PASSED: Booted '${target_label}' on persistent slot ${final_active_slot}.`);
    return true;
}

fn rot_validate_direct_persistent_boot_state(
    rbi, target_update_slot, target_label
) {
    debug("info|--- rot_validate_direct_persistent_boot_state (update-helper) ---");
    if rbi.active != target_update_slot {
        debug(`error|Validation FAILED: Unexpected active slot for '${target_label}'.`);
        return false;
    }
    debug(`info|Validation PASSED: RoT correctly booted for '${target_label}'.`);
    return true;
}

/// Attempts to power cycle the DUT and log its RoT state afterwards.
/// This is a helper for failure recovery testing.
///
/// Args:
///   conf (map): The main configuration map.
///   context_msg (string): A message describing when this power cycle is happening.
///
/// Returns:
///   None. Logs information about the process.
fn power_cycle_dut(conf, context_msg) {
    if conf?.rot_hubris_power_cycle_on_failure != true {
        debug(`info|Power cycle on RoT Hubris update failure not enabled.`);
        return;
    }

    debug(`info|${context_msg} - Initiating DUT power cycle for recovery test.`);
    let power_off_delay = conf?.power_off_delay_secs;
    if power_off_delay == () || type_of(power_off_delay) != "int" {
      power_off_delay = 2;
    }

    let dut_boot_delay = conf?.dut_boot_delay_secs;
    if dut_boot_delay == () || type_of(dut_boot_delay) != "int" {
      dut_boot_delay = 8;
    }

    if (!util::control_power("dut", "off", conf)) {
        debug(`warn|Failed to power OFF DUT.`);
        // Continue anyway to see if it's already off or attempt power on
    } else {
        debug(`info|DUT power off command sent. Waiting ${power_off_delay}s.`);
        sleep(power_off_delay);
    }

    if (!util::control_power("dut", "on", conf)) {
        debug(`error|Failed to power ON DUT. Recovery state unknown.`);
        return;
    }
    debug(`info|DUT power on command sent. Waiting ${dut_boot_delay}s for boot.`);
    sleep(dut_boot_delay);

    debug("info|Attempting to get RoT state after power cycle...");
    let rbi_after_cycle = util::reset_rot_and_get_rbi("after power cycle recovery", "recovery_check");
    if rbi_after_cycle?.error != () {
        debug(`error|Could not get RBI after power cycle: ${rbi_after_cycle.error}`);
        return;
    }

    let active_slot_after_cycle = rbi_after_cycle.ok.active;
    debug(`info|RoT active slot after power cycle: ${active_slot_after_cycle}`);
    if active_slot_after_cycle != () {
        let gitc_after_cycle = util::caboose_value("rot", `${active_slot_after_cycle}`, "GITC");
        debug(`info|RoT GITC on slot ${active_slot_after_cycle} ` +
            `after power cycle: ${gitc_after_cycle}`
        );
    } else {
        debug(`warn|Could not determine active RoT slot after power cycle.`);
    }
}

/// Updates RoT firmware, handles transient vs persistent, performs resets,
/// validates the final state, and optionally power cycles on failure for recovery testing.
///
/// Args:
///   path_a (string): Path to image for RoT slot A.
///   path_b (string): Path to image for RoT slot B.
///   use_transient (bool): Whether to attempt using transient preference mechanism.
///   target_label (string): Descriptive label (e.g., "baseline", "under-test").
///   conf (map): The main configuration map.
///
/// Returns:
///   bool: `true` on successful original update and validation, `false` otherwise.
fn update_rot_hubris(
    path_a,
    path_b,
    use_transient,
    target_label,
    conf
) {
    debug(`info|update_rot_hubris target=${target_label}`);
    debug(`info|transient=${use_transient}`);
    debug(`info|Image A: ${path_a}`);
    debug(`info|Image B: ${path_b}`);

    // Determine the non-active partition and select the appropriate update
    // image.
    let r = get_rot_active();
    if r?.error != () {
        debug(`error|get_rot_active failed: ${r.error}`);
        return false;
    }
    let initial_slot = r.ok;
    let target_slot = if initial_slot == 0 { 1 } else { 0 };
    let target_image = if target_slot == 0 { path_a } else { path_b };

    rot_log_initial_params(
        initial_slot,
        target_slot,
        target_image,
        target_label,
        use_transient
    );

    if (!util::update_rot_image_file(target_slot, target_image, target_label)) {
        // Power cycle only if recovery test for this type of failure is enabled
        if conf?.rot_hubris_power_cycle_on_failure == true {
            power_cycle_dut(conf, "RoT image file update command failed");
        }
        return false;
    }

    if (!util::set_rot_boot_preference(target_slot, use_transient, target_label)) {
        if conf?.rot_hubris_power_cycle_on_failure == true {
            power_cycle_dut(conf, "RoT set boot preference command failed");
        }
        return false;
    }

    let r = util::reset_rot_and_get_rbi(
        "after initial preference set", target_label
    );
    if r?.error != () { // Checks for the "error" key
        debug(
            `error|RoT first reset or RBI read failed. Error details: ` +
            `${r.error}`
        );
        // Decide to power cycle based on the error_type
        if conf?.rot_hubris_power_cycle_on_failure == true {
            let error_type = r?.error_type;
            // Only power cycle on errors where device might be unresponsive or in bad state
            if error_type == "reset_command_failed" ||
               error_type == "rbi_fetch_failed"
            {
                 debug(
                    `info|Error type '${error_type}' suggests power cycle might help.`
                 );
                 power_cycle_dut(conf, `RoT reset/RBI read failed (${error_type})`);
            } else {
                 debug(
                    `info|Error type '${error_type}' - power cycle ` +
                    `likely won't resolve. Skipping.`
                 );
            }
        }
        return false;
    }
    let rbi = r.ok; // Get the actual RBI data

    rot_log_rbi_details(
        rbi, "after first reset", initial_slot,
        target_slot, use_transient
    );

    if use_transient {
        // TODO: When Hubris issue #2066 is fixed, then the boot loader
        // decision log will be available in RotBootInfo. We will then be able
        // to confirm that the Hubris image was chosen due to the transient
        // preference feature.

        if (!rot_validate_initial_transient_boot_state(
            rbi, initial_slot,
            target_slot, target_label
        )) {
            if (conf?.rot_hubris_power_cycle_on_failure == true) {
                power_cycle_dut(conf, "RoT initial transient boot validation failed");
            }
            return false;
        }
        if (!rot_ensure_persistence_after_transient_boot(
            rbi, target_slot, target_label
        )) {
            if (conf?.rot_hubris_power_cycle_on_failure == true) {
                power_cycle_dut(conf, "RoT ensure persistence failed");
            }
            return false;
        }

        let final_rbi_result = util::reset_rot_and_get_rbi(
            "after setting persistence", target_label
        );
        if final_rbi_result?.error != () {
            if (conf?.rot_hubris_power_cycle_on_failure == true) {
                let error_type = final_rbi_result?.error_type;
                if error_type == "reset_command_failed" || error_type == "rbi_fetch_failed" {
                     power_cycle_dut(conf, `RoT final reset/RBI read failed (${error_type})`);
                }
            }
            return false;
        }
        let final_rbi = final_rbi_result.ok;

        rot_log_rbi_details(
            final_rbi, "after final reset (persistence check)",
            initial_slot, target_slot, use_transient
        );
        if (!rot_validate_final_persistent_boot_state(
            final_rbi, target_slot, target_label
        )) {
            if (conf?.rot_hubris_power_cycle_on_failure == true) {
                power_cycle_dut(conf, "RoT final persistent boot validation failed");
            }
            return false;
        }
    } else {
        // Direct Persistent Boot Flow
        if (!rot_validate_direct_persistent_boot_state(
            rbi, target_slot, target_label
        )) {
            // No specific error type from this local helper yet to condition power cycle
            if (conf?.rot_hubris_power_cycle_on_failure == true) {
                power_cycle_dut(conf, "RoT direct persistent boot validation failed");
            }
            return false;
        }
    }

    debug(`info|updated and booted target:${target_label} slot=${target_slot}`);
    return true;
}

/// Ensures the device is in a clean state and running baseline firmware.
/// This is a high-cost function that may use resets to sanitize the state.
/// It should be called once at the beginning of a test run.
fn ensure_initial_baseline_state(conf, images) {
    debug("info|Phase 1: Sanitize state to establish a clean baseline.");

    // Step 1: Sanitize any lingering preferences from previous runs.
    // This may reset the RoT.
    if (!sanitize_boot_preferences(conf)) {
        debug("error|Failed to sanitize boot preferences during initial setup.");
        return false;
    }

    // Step 2: Clear any stuck "Complete" update states.
    // This may also reset the RoT and SP.
    let problems = 0;
    for attempt in 1..=2 {
        problems = 0;
        for component in ["rot", "sp"] {
            let r_check = util::check_update_in_progress(component);
            if r_check?.Err != () {
                debug(`error|util::check_update_in_progress for ${component}: ${r_check}`);
                return false;
            }
            if r_check != () {
                problems += 1;
                debug(`info|Component ${component} has update status: ${r_check}.`);
                let id = r_check?.id;
                if (id != ()) {
                    util::abort_update(component, `${id}`);
                }
            }
        }
        if problems == 0 {
            break;
        }
        debug(`warn|Attempt ${attempt}: Found ${problems} issues. Resetting SP and RoT.`);
        if (reset_sp_and_rot()?.error != ()) {
            debug(`error|Cannot reset RoT/SP to clear update status.`);
            return false;
        }
    }
    if problems > 0 {
        debug(`error|Devices stuck with update status after resets.`);
        return false;
    }

    // --- STABLE STATE ---
    // At this point, all sanitizing operations and potential resets are complete.
    // We can now safely check the device's state and act on it.

    debug("info|Phase 2: State is clean. Checking firmware versions against baseline.");
    let initial_check = image_check("base", images);
    if initial_check?.error != () {
        debug(`error|Initial image_check for baseline: ${initial_check.error}`);
        return false;
    }
    let flash_sp = initial_check.ok?.sp;
    let flash_rot = initial_check.ok?.rot;

    if !flash_sp && !flash_rot {
        debug("info|Device is already running correct baseline firmware.");
    } else {
        debug(`info|Device needs baseline flashing. SP: ${flash_sp}, RoT: ${flash_rot}`);
        if flash_rot {
            debug("info|Updating RoT to baseline (persistent).");
            if !update_rot_hubris(conf.base.rot_a, conf.base.rot_b, false, "baseline_setup", conf) {
                debug("error|Failed to update RoT to baseline.");
                return false;
            }
        }
        if flash_sp {
            debug("info|Updating SP to baseline.");
            if !update_sp(conf.base.sp) {
                debug("error|Failed to update SP to baseline.");
                return false;
            }
        }

        // Final verification after flashing.
        debug("info|Re-checking images after baseline updates.");
        let post_update_check = image_check("base", images);
        if post_update_check?.error != () || post_update_check.ok?.sp || post_update_check.ok?.rot {
            debug(`warn|Post-baseline image_check FAILED or images are still not correct: ${post_update_check}`);
            return false;
        }
    }

    debug("info|ensure_initial_baseline_state completed successfully.");
    return true;
}

/// Tests that a RoT update to a preferred slot fails, then recovers by
/// clearing the transient preference (without a reset) and successfully
/// completes the update.
///
/// Args:
///   conf (map): The main configuration map.
///   target_branch_name (string): "base" or "ut", to select the correct image paths.
///
/// Returns:
///   bool: `true` if the entire test passes, `false` otherwise.
fn test_and_recover_from_preferred_slot_update_failure(conf, target_branch_name) {
    debug(`info|--- Starting Negative Test for '${target_branch_name}' (Reset-less Recovery) ---`);

    // 1. SETUP
    let r = get_rot_active();
    if r?.error != () { return false; }
    let initial_active_slot = r.ok;
    let preferred_slot = if initial_active_slot == 0 { 1 } else { 0 };
    debug!(`//// conf=${conf}`);
    debug!(`//// target_branch_name=${target_branch_name}`);
    let branch_conf = conf[target_branch_name];
    debug!(`//// branch_conf=${branch_conf}`);
    let image_path = if preferred_slot == 0 { branch_conf.rot_a } else { branch_conf.rot_b };
    let test_label = `neg_test_${target_branch_name}`;

    debug(`info|Negative Test: Initial active=${initial_active_slot}, setting transient pref to=${preferred_slot}`);

    // 2. INDUCE FAILURE: Set transient preference, then confirm update fails.
    if (!util::set_rot_boot_preference(preferred_slot, true, test_label)) {
        debug(`error|Negative Test: Could not set transient pref for '${test_label}'.`);
        return false;
    }
    if (util::update_rot_image_file(preferred_slot, image_path, test_label)) {
        debug(`error|Negative Test FAILED: Update to preferred slot '${preferred_slot}' SUCCEEDED.`);
        return false;
    }
    debug("info|Negative Test PASSED: Update to preferred slot failed as expected.");

    // 3. RECOVER: Use the new helper to clear the preference without a reset.
    if (!clear_transient_preference_without_reset()) {
        debug("error|Negative Test FAILED: Could not recover by clearing transient preference.");
        return false;
    }
    debug("info|Negative Test: Recovery successful. Conflicting preference cleared.");

    // 4. RETRY UPDATE: Attempt the same update again. It should now succeed.
    debug(`info|Negative Test: Retrying update on slot ${preferred_slot}.`);
    if (!util::update_rot_image_file(preferred_slot, image_path, test_label)) {
        debug(`error|Negative Test FAILED: Update retry on slot ${preferred_slot} failed.`);
        return false;
    }
    debug("info|Negative Test PASSED: Update retry succeeded.");

    // 5. FINALIZE (Optional but good practice):
    // To leave the device in a predictable state, we can now set the preference
    // and reset to actually boot the image we just flashed.
    debug(`info|Negative Test: Finalizing by setting persistent pref to ${preferred_slot} and resetting.`);
    if (!util::set_rot_boot_preference(preferred_slot, false, test_label)) {
        return false;
    }
    let rbi_result = util::reset_rot_and_get_rbi("finalizing negative test", test_label);
    if (rbi_result?.error != () || rbi_result.ok.active != preferred_slot) {
        debug(`error|Negative Test FAILED: Could not boot into newly updated image. RBI: ${rbi_result}`);
        return false;
    }

    debug(`info|--- Negative Test for '${target_branch_name}' COMPLETED SUCCESSFULLY ---`);
    return true;
}

/// Clears an active transient boot preference without a reset by setting the
/// transient preference to the already-active slot. It then verifies that
/// the transient preference field in RotBootInfo is null.
///
/// Returns:
///   bool: `true` if the preference was successfully cleared, `false` otherwise.
fn clear_transient_preference_without_reset() {
    debug("info|Attempting to clear transient preference without reset.");
    let r_active = get_rot_active();
    if r_active?.error != () {
        debug(`error|clear_transient_preference: Could not get active slot: ${r_active.error}`);
        return false;
    }
    let active_slot = r_active.ok;

    debug(`info|clearing transient pref by setting it to current active slot: ${active_slot}`);
    if (!util::set_rot_boot_preference(active_slot, true, "clearing_transient")) {
        debug("error|clear_transient_preference: Call to set_rot_boot_preference failed.");
        return false;
    }

    // Verify it was cleared
    let rbi = util::rot_boot_info();
    if rbi?.error != () || rbi.transient_boot_preference != () {
        debug(`error|clear_transient_preference: Verification failed. RBI: ${rbi}`);
        return false;
    }

    debug("info|Successfully cleared transient boot preference.");
    return true;
}

/// Ensures there are no conflicting boot preferences set for the inactive slot.
/// This function is intended to be called before any update operation to ensure
/// the device is in a clean state.
/// - If a conflicting transient preference is found, it is cleared without a reset.
/// - If a conflicting pending persistent preference is found, it uses a
///   workaround (#2093) or the ideal method based on the conf flag.
///
/// Args:
///   conf (map): The configuration map, used to check for workarounds.
///
/// Returns:
///   bool: `true` if the state is clean or was successfully cleaned, `false` otherwise.
fn sanitize_boot_preferences(conf) {
    debug("info|Sanitizing boot preferences...");
    let rbi = util::rot_boot_info();
    if rbi?.error != () {
        debug(`error|sanitize_boot_preferences: Could not get initial RBI: ${rbi.error}`);
        return false;
    }

    let active = rbi.active;
    let inactive = if active == 0 { 1 } else { 0 };

    // Case 1: Conflicting transient preference (clear is the same for both cases)
    if rbi.transient_boot_preference == inactive {
        debug(`warn|Found conflicting transient preference for inactive slot ${inactive}. Clearing it.`);
        if (!clear_transient_preference_without_reset()) {
            debug("error|sanitize_boot_preferences: Failed to clear conflicting transient preference.");
            return false;
        }
    }

    // Case 2: Conflicting pending persistent preference
    let rbi = util::rot_boot_info(); // Re-fetch state
    if rbi.pending_persistent_boot_preference == inactive {
        debug(`warn|Found conflicting pending persistent preference for inactive slot ${inactive}.`);

        if (conf?.hubris_2093_workaround) {
            // --- WORKAROUND for Hubris issue #2093 ---
            // The current firmware has a bug preventing a pending preference
            // from being cleared by setting a new persistent one.
            // The only reliable way to clear it is to reset the RoT.
            debug("info|Hubris #2093 workaround enabled. Resetting RoT to clear pending preference.");
            if !util::reset_component("rot") {
                debug("error|sanitize_boot_preferences: Failed to reset RoT to clear pending preference.");
                return false;
            }
            sleep(5); // Wait for RoT to come back up.
        } else {
            // --- IDEAL a.k.a. POST-BUGFIX LOGIC ---
            // Once the firmware is fixed, we should be able to clear a pending
            // preference for the inactive slot by simply re-setting the
            // persistent preference to the already-active slot.
            debug("info|Hubris #2093 workaround disabled. Attempting to clear pending preference without reset.");
            if !util::set_rot_boot_preference(active, false, "clearing_pending") {
                debug("error|sanitize_boot_preferences: Failed to send command to clear pending preference.");
                return false;
            }
        }

        // Final verification
        let final_rbi = util::rot_boot_info();
        if final_rbi?.error != () || final_rbi.pending_persistent_boot_preference != () {
             debug(`error|sanitize_boot_preferences: Failed to verify pending pref was cleared. RBI: ${final_rbi}`);
             return false;
        }
    }

    debug("info|Boot preferences sanitized successfully.");
    return true;
}

/// Injects a fault by setting a conflicting pending persistent preference.
/// This sets up a state that should cause the next update attempt to fail.
///
/// Returns: bool - true on success
fn inject_conflicting_pending_preference() {
    debug("info|FAULT INJECTION: Setting a conflicting pending persistent preference.");
    let rbi = util::rot_boot_info();
    if rbi?.error != () { return false; }
    let inactive_slot = if rbi.active == 0 { 1 } else { 0 };

    // Set persistent preference for the INACTIVE slot.
    // This creates a pending preference that conflicts with any update to that slot.
    return util::set_rot_boot_preference(inactive_slot, false, "inject_pending_fault");
}

/// Injects a fault by setting a conflicting transient preference.
fn inject_conflicting_transient_preference() {
    debug("info|FAULT INJECTION: Setting a conflicting transient preference.");
    let rbi = util::rot_boot_info();
    if rbi?.error != () { return false; }
    let inactive_slot = if rbi.active == 0 { 1 } else { 0 };

    // Set transient preference for the INACTIVE slot.
    return util::set_rot_boot_preference(inactive_slot, true, "inject_transient_fault");
}


