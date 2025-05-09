// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright 2025 Oxide Computer Company

// Helper module for the upgrade-rollback script.
// Contains functions for image processing, firmware updates, state checks,
// and other operational logic.

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
        print("ERROR: get_image_info: Failed to read CMPA or CFPA from device.");
        return 1;
    }
    images["keyset"] = util::get_rot_keyset(images.cfpa);
    debug(`info|get_image_info: Detected RoT keyset: ${images.keyset}`);

    let gitc = #{};
    let error_found = false;
    let failed_verify_list = [];

    for branch in ["base", "ut"] {
        images[branch] = #{};
        for image_type in ["sp", "rot_a", "rot_b", "stage0"] {
            let zip_path = conf[branch][image_type];
            if zip_path == () {
                 print(`Warn: get_image_info: Skipping missing path for ${branch}.${image_type}`);
                 continue;
            }
            images[branch][image_type] = #{"path": zip_path};

            let current_ar = ();
            let archive_ok = true;
            try {
                current_ar = new_archive(zip_path); // Global custom Rhai function
            } catch(err) {
                print(`ERROR: get_image_info: Failed creating archive for ${zip_path}: ${err}`);
                error_found = true;
                archive_ok = false;
            }
            if !archive_ok {
                continue;
            }

            if type_of(current_ar) != "Archive" {
                print(`ERROR: get_image_info: Invalid archive object for path ${zip_path}`);
                error_found = true;
                continue;
            }

            images[branch][image_type]["caboose"] = #{};
            let caboose_obj = current_ar?["caboose"];
            if caboose_obj == () || type_of(caboose_obj) == "()" {
                print(`WARN: get_image_info: Could not get caboose object from ${zip_path}`);
            } else if type_of(caboose_obj) == "map" && caboose_obj?.error != () {
                 print(`WARN: get_image_info: Error getting caboose object from ${zip_path}: ${caboose_obj.error}`);
            } else {
                let caboose_read_ok = true;
                for key in ["BORD", "GITC", "NAME", "SIGN", "VERS"] {
                    let val = ();
                    try { val = caboose_obj[key]; } catch (err) {
                         debug(`warn|get_image_info: Failed reading caboose key '${key}' from ${zip_path}: ${err}`);
                         caboose_read_ok = false;
                    }
                    if val != () {
                        images[branch][image_type]["caboose"][key] = val;
                    }
                }
                if images[branch][image_type]["caboose"]?.GITC == () {
                     print(
                        `WARN: get_image_info: Could not read essential GITC from caboose in ${zip_path}. ` +
                        `Read OK: ${caboose_read_ok}`
                     );
                }
            }

            if image_type != "sp" { // RoT or Stage0 images
                let verified = true;
                let verify_error = ();
                try {
                    verified = current_ar.verify_rot_image(images.cmpa, images.cfpa);
                } catch (err) {
                    verified = false; verify_error = err;
                }
                images[branch][image_type]["verified"] = verified;
                if !verified {
                    failed_verify_list += images[branch][image_type]["path"];
                    print(
                       `WARN: get_image_info: Sig verification FAILED: ` +
                       `${images[branch][image_type]["path"]}. Error: ${verify_error}`
                    );
                } else {
                     debug(`info|get_image_info: Sig verified OK: ${images[branch][image_type]["path"]}`);
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
    debug(`info|get_image_info: Image GITC reverse map: ${gitc}`);
    images["by_gitc"] = gitc;
    images["failed_to_verify"] = failed_verify_list;

    if images.failed_to_verify.len() > 0 {
         print("WARN: get_image_info: Some RoT images FAILED signature verification:");
         for path_str in images.failed_to_verify {
            print(`  - ${path_str}`);
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

/// Checks if SP needs flashing.
fn sp_needs_flashing(target_image_label, gitc_map) {
    let sp_gitc = util::caboose_value("sp", "active", "GITC");
    if sp_gitc == () {
         return #{"error": "Could not read active SP GITC."};
    }
    debug(`info|SP is running GITC=${sp_gitc}`);
    let known_images = gitc_map?[sp_gitc];
    debug(`info|sp_needs_flashing: Known images for SP GITC ${sp_gitc}: ${known_images}`);
    if known_images == () {
        print("    SP GITC does not match known base/ut images.");
        return #{"ok": true};
    } else if target_image_label in known_images {
        print(`    Target ${target_image_label} IS IN known images.`);
        return #{"ok": false};
    } else {
        print(`    Target ${target_image_label} IS NOT in known images.`);
        return #{"ok": true};
    }
}

/// Checks if RoT needs flashing.
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
    print(`RoT is running GITC=${rot_gitc} on active slot ${rot_active_slot}`);
    let known_images = gitc_map?[rot_gitc];
    debug(`info|rot_needs_flashing: Known images for RoT GITC ${rot_gitc}: ${known_images}`);
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

/// Determines the *preferred* next RoT boot slot based on RBI preferences.
fn get_active_and_next_rot_boot_preference() {
    let rbi = util::rot_boot_info();
    if rbi?.error != () {
        return #{"error": `Cannot get RBI: ${rbi.error}`};
    }
    if rbi?.active == () {
        return #{"error": `Invalid RBI: ${rbi}`};
    }
    let active = rbi.active;
    let next_preferred = active;
    let pend_persist = rbi.pending_persistent_boot_preference;
    if pend_persist != () {
        next_preferred = pend_persist;
        debug(`info|get_active_and_next: Next boot by pending persistent: ${next_preferred}`);
    } else {
        let transient_select = rbi.transient_boot_preference;
        if transient_select != () {
             next_preferred = transient_select;
             debug(`info|get_active_and_next: Next boot by transient: ${next_preferred}`);
        } else {
            let persistent_pref = rbi.persistent_boot_preference;
            if persistent_pref != () {
                next_preferred = persistent_pref;
                debug(`info|get_active_and_next: Next boot by persistent: ${next_preferred}`);
            } else {
                debug(`info|get_active_and_next: No explicit pref. Next likely active: ${active}`);
            }
        }
    }
    return #{"ok": #{"active": active, "next": next_preferred}};
}

/// Checks if the currently running RoT firmware supports transient boot commands.
fn rot_supports_transient_boot_preference() {
    debug(`info|Checking if current RoT supports transient preference command...`);
    let r_boot_info = get_active_and_next_rot_boot_preference();
    if r_boot_info?.error != () {
        debug(
            `error|rot_supports_transient_boot_preference: Cannot get active RoT slot. ` +
            `Error: ${r_boot_info.error}`
        );
        return false;
    }
    let active_slot = r_boot_info.ok.active;
    debug(
        `info|rot_supports_transient_boot_preference: Testing transient setting ` +
        `capability on active slot ${active_slot}.`
    );
    if util::set_rot_boot_preference(active_slot, true, "transient_support_test") {
        debug(
            `info|rot_supports_transient_boot_preference: Command succeeded. ` +
            `Assuming feature supported.`
        );
        return true;
    } else {
        debug(
            `warn|rot_supports_transient_boot_preference: Command failed for slot `+
            `${active_slot}. Assuming feature not supported.`
        );
        return false;
    }
}

/// Resets both SP and RoT components sequentially.
fn reset_sp_and_rot() {
    debug("info|reset_sp_and_rot: Beginning reset sequence for RoT and SP.");
    for params in [["rot", 3], ["sp", 5]] {
        let component_to_reset = params[0];
        let sleep_duration = params[1];
        debug(`info|Reset ${component_to_reset}`);
        if !util::reset_component(component_to_reset) {
            return #{ "error": `Failed to reset component '${component_to_reset}'.` };
        }
        debug(
            `info|reset_sp_and_rot: Reset '${component_to_reset}'. Sleeping ${sleep_duration}s.`
        );
        sleep(sleep_duration);
    }
    debug("info|reset_sp_and_rot: RoT and SP reset sequence complete.");
    return #{"ok": ()};
}


/// Updates SP firmware, resets, and polls for readiness.
fn update_sp(sp_zip) {
    debug(`info|update_sp: ${sp_zip}`);
    if (!util::update_sp_image(sp_zip)) {
        return false;
    }
    debug(`info|update_sp: SP update command acknowledged.`);
    let r_status1 = util::check_update_in_progress("sp");
    debug(`info|update_sp: SP status immediately after update command: ${r_status1}`);
    debug("info|update_sp: Resetting SP to boot new image.");
    if (!util::reset_sp()) {
        return false;
    }
    debug("info|update_sp: SP reset acknowledged. Polling for readiness.");

    let max_poll_attempts = 15;
    let poll_interval_secs = 1;
    let sp_ready_and_clean = false;
    for attempt in 1..=max_poll_attempts {
        debug(
            `info|update_sp: Polling SP readiness, attempt ${attempt}` +
            `/${max_poll_attempts}...`
        );
        let sp_status = util::check_update_in_progress("sp");
        if sp_status == () {
            debug("info|update_sp: SP is ready and no update in progress.");
            sp_ready_and_clean = true;
            break;
        } else if sp_status?.Err != () {
            debug(
                `warn|update_sp: Readiness check attempt ${attempt}: ` +
                `Error getting SP status: ${sp_status}. Retrying.`
            );
        } else {
            debug(
                `warn|update_sp: Readiness check attempt ${attempt}: ` +
                `SP reported unexpected status: ${sp_status}. Retrying.`
            );
        }
        if attempt < max_poll_attempts {
            sleep(poll_interval_secs);
        }
    }

    if !sp_ready_and_clean {
        debug(
            `error|update_sp: SP did not become ready and clean after reset and `+
            `${max_poll_attempts} attempts.`
        );
        print(`FAIL - SP did not successfully reset and clear update status.\n`);
        return false;
    }
    debug("info|update_sp: SP readiness and clean status confirmed.");
    print(`### SUCCESS update_sp: ${sp_zip}`);
    print("");
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
    rbi, context_description, initial_slot_before_op,
    target_update_slot_for_op, use_transient_flag_for_op
) {
    debug(`info|--- rot_log_rbi_details (${context_description}, update-helper) ---`);
    debug(`    Initial Active Slot (before op): ${initial_slot_before_op}`);
    debug(`    Target Update Slot (for op): ${target_update_slot_for_op}`);
    debug(`    Use Transient Flag (for op): ${use_transient_flag_for_op}`);
    debug(`    Current Active Slot (from RBI): ${rbi.active}`);
    debug(`    Persistent Pref (from RBI): ${rbi.persistent_boot_preference}`);
    debug(`    Transient Pref (from RBI): ${rbi.transient_boot_preference}`);
    debug(`    Pending Persistent Pref (from RBI): ${rbi.pending_persistent_boot_preference}`);
}

fn rot_validate_initial_transient_boot_state(
    rbi, initial_slot_before_op, target_update_slot, target_label
) {
    debug("info|--- rot_validate_initial_transient_boot_state (update-helper) ---");
    let active_after_first_reset = rbi.active;
    let p_pref_from_newly_active = rbi.persistent_boot_preference;
    let t_pref_from_newly_active = rbi.transient_boot_preference;
    let pp_pref_from_newly_active = rbi.pending_persistent_boot_preference;
    let is_ok = true;
    let failure_details = "";

    if active_after_first_reset != target_update_slot {
        is_ok = false;
        failure_details += ` Active slot (${active_after_first_reset}) != target (${target_update_slot}).`;
    }
    if t_pref_from_newly_active != () {
        is_ok = false;
        failure_details += ` t_pref (${t_pref_from_newly_active}) not null.`;
    }
    if pp_pref_from_newly_active != () {
        is_ok = false;
        failure_details += ` pp_pref (${pp_pref_from_newly_active}) not null.`;
    }
    if p_pref_from_newly_active != initial_slot_before_op {
        if target_label == "baseline" {
            debug(
                `info|Target '${target_label}': p_pref (${p_pref_from_newly_active}) ` +
                `differs from original active (${initial_slot_before_op}). ` +
                `Acceptable for baseline.`
            );
        } else {
            is_ok = false;
            failure_details += ` p_pref (${p_pref_from_newly_active}) != ` +
                               `original active (${initial_slot_before_op}).`;
        }
    }
    if !is_ok {
        debug(`error|Initial transient boot validation FAILED: ` +
              `${failure_details} RBI=${rbi}`);
    } else {
        debug(`info|Initial transient boot validation PASSED for '${target_label}'.`);
    }
    return is_ok;
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
            debug(`error|ensure_persistence: util::set_rot_boot_preference failed.`);
            return false;
        }
        debug(`info|ensure_persistence: util::set_rot_boot_preference called successfully.`);
    } else {
        debug(`info|ensure_persistence: Skipping set persistent for '${target_label}'.`);
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

/// Updates RoT firmware, handles transient vs persistent, resets, and validates.
fn update_rot_hubris(path_a, path_b, use_transient, target_label) {
    print("");
    print(
        `### update_rot_hubris (target: ${target_label}, ` +
        `use_transient: ${use_transient})`
    );
    print(`    Image A: ${path_a}`);
    print(`    Image B: ${path_b}`);

    let r_get_active = get_rot_active();
    if r_get_active?.error != () {
        return false;
    }
    let initial_slot = r_get_active.ok;
    let target_slot = if initial_slot == 0 { 1 } else { 0 };
    let target_image = if target_slot == 0 { path_a } else { path_b };

    rot_log_initial_params(initial_slot, target_slot, target_image, target_label, use_transient);

    if (!util::update_rot_image_file(target_slot, target_image, target_label)) {
        return false;
    }
    if (!util::set_rot_boot_preference(target_slot, use_transient, target_label)) {
        return false;
    }

    let rbi1 = util::reset_rot_and_get_rbi("after initial preference set", target_label);
    if rbi1?.error != () {
        return false;
    }
    rot_log_rbi_details(rbi1, "after first reset", initial_slot, target_slot, use_transient);

    if use_transient {
        if (!rot_validate_initial_transient_boot_state(rbi1, initial_slot, target_slot, target_label)) {
            return false;
        }
        if (!rot_ensure_persistence_after_transient_boot(rbi1, target_slot, target_label)) {
            return false;
        }
        let rbi2 = util::reset_rot_and_get_rbi("after setting persistence", target_label);
        if rbi2?.error != () {
            return false;
        }
        rot_log_rbi_details(rbi2, "after final reset", initial_slot, target_slot, use_transient);
        if (!rot_validate_final_persistent_boot_state(rbi2, target_slot, target_label)) {
            return false;
        }
    } else { // Direct Persistent Boot Flow
        if (!rot_validate_direct_persistent_boot_state(rbi1, target_slot, target_label)) {
            return false;
        }
    }
    print(`### SUCCESS update_rot_hubris (target: ${target_label}): updated slot ${target_slot}`);
    print("");
    return true;
}

/// Ensures the device is in a clean state and running baseline firmware.
/// Called once at the beginning of the main script.
fn ensure_initial_baseline_state(conf, images) {
    print("\n## Phase 1: Determine initial FW state and install baseline if needed");
    let problems = 0;
    for attempt in 1..=2 {
        problems = 0;
        for component in ["rot", "sp"] {
            let r_check = util::check_update_in_progress(component);
            if r_check?.Err != () {
                print(`Error util::check_update_in_progress for ${component}: ${r_check}`);
                return false;
            }
            if r_check != () {
                problems += 1;
                let id = r_check?.id;
                debug(`info|Component ${component} has update status: ${r_check}. Aborting id=${id}.`);
                print(`SP component '${component}' may need reset. Aborting update id=${id}`);
                let r_abort = util::abort_update(component, `${id}`);
                debug(`info|Abort result for ${component} id ${id}: ${r_abort}`);
            }
        }
        if problems == 0 {
            break;
        }
        debug(`warn|Attempt ${attempt}: Found ${problems} issues. Resetting SP and RoT.`);
        let r_reset = reset_sp_and_rot();
        if r_reset?["error"] != () {
            print(`ERROR: Cannot reset RoT/SP: ${r_reset.error}`);
            return false;
        }
    }
    if problems > 0 {
        print(`ERROR: Devices stuck with update status after resets.`);
        return false;
    }

    debug("info|Checking initial images against baseline.");
    let initial_check = image_check("base", images);
    if initial_check?.error != () {
        print(`ERROR: Initial image_check for baseline: ${initial_check.error}`);
        return false;
    }
    let flash_sp = initial_check.ok?.sp;
    let flash_rot = initial_check.ok?.rot;

    if !flash_sp && !flash_rot {
        debug("info|Initial state: SP and RoT already on baseline.");
    } else {
        print(`info|Initial state needs baseline flashing. SP: ${flash_sp}, RoT: ${flash_rot}`);
    }

    if flash_rot {
        debug("info|Initial: RoT needs baseline update (persistent).");
        if !update_rot_hubris(conf.base.rot_a, conf.base.rot_b, false, "baseline_setup") {
            debug("error|Failed to update RoT to baseline (initial setup).");
            return false;
        }
    }
    if flash_sp {
        debug("info|Initial: SP needs baseline update.");
        if !update_sp(conf.base.sp) {
            debug("error|Failed to update SP to baseline (initial setup).");
            return false;
        }
    }

    if flash_sp || flash_rot {
        debug("info|Re-checking images after baseline updates.");
        let post_update_check = image_check("base", images);
        if post_update_check?.error != () || post_update_check.ok?.sp || post_update_check.ok?.rot {
            debug(`warn|Post-baseline image_check failed or not correct: ${post_update_check}`);
            return false;
        }
        debug("info|Successfully installed/verified baseline images.");
    }
    debug("info|ensure_initial_baseline_state completed successfully.");
    return true;
}
