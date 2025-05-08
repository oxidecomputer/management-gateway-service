// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright 2025 Oxide Computer Company

import `${script_dir}/util` as util;

/// Print command line usage
fn usage(prog, error) {
    if error != () {
        print(`Error: ${error}`);
    }
    print(
        `Usage: faux-mgs ... rhai ${prog} [-v] [-h] [-c config.json] ` +
        `[path0] [path1]`
    );
    print("  -c CONFIG.JSON # Path to configuration");
    print("  -t # Use transient boot preference to vet RoT Hubris");
    print("  -v # be verbose");
    print("  -h # Help. Print this message");
    print("path0 - optionally override configuration base_repo value");
    print("path1 - optionally override configuration ut_repo value");
    print("");
}

fn main() {
    let start_ts = timestamp();
    let start_time = datetime_local();
    debug(`info|Starting at ${start_time}`);

    let conf = process_cli(argv);
    switch type_of(conf) {
        "i64" => {
            return conf; // Exit code from process_cli
        }
        "map" => {
            () // Configuration map successfully parsed
        }
        _ => {
            print("ERROR: process_cli returned unexpected type.");
            return 1;
        }
    }

    let images = get_image_info(conf);
    if type_of(images) == "i64" {
        // Assuming get_image_info returns exit code on error
        print("ERROR: Failed to get image info.");
        return images;
    }

    print("\n## Determine initial FW state and update if needed");
    let problems = 0;
    for attempt in 1..=2 {
        problems = 0;
        for component in ["rot", "sp"] {
            let r_check = util::check_update_in_progress(component);
            if r_check?.Err != () {
                print(
                    `Error from util::check_update_in_progress for ` +
                    `${component}: ${r_check}`
                );
                return 1;
            }
            // If not null, an update was in progress or completed
            if r_check != () {
                problems += 1;
                let id = r_check?.id;
                debug(
                    `info|Component ${component} had existing update status: ` +
                    `${r_check}. Attempting abort with id=${id}.`
                );
                print(
                    `The SP component '${component}' may need reset after ` +
                    `abort. Trying to abort update id=${id}`
                );

                let r_abort = util::abort_update(component, `${id}`);
                // The existing debug log is still useful
                debug(
                    `info|update-abort result for ${component} id ${id}: ` +
                    `${r_abort}`
                 );
                // Optional: Check r_abort for r_abort?.ack == "aborted" if needed
                // if r_abort?.ack != "aborted" {
                //     print(`WARN|Failed to confirm abort for ${component} id ${id}. Result: ${r_abort}`);
                // }
            }
        } // end component loop

        if problems == 0 {
            debug("info|No pending updates found or they were abortable.");
            break; // Exit attempt loop
        }

        debug(
            `warn|Attempt ${attempt}: Problems found with component updates. ` +
            `Resetting SP and RoT.`
        );
        // Assuming reset_sp_and_rot is a local helper
        let r_reset_all = reset_sp_and_rot();
        if r_reset_all?["error"] != () {
            print(`ERROR: Cannot reset RoT and SP: ${r_reset_all.error}`);
            print(
                `Check that RoT has no pending update and STLINK is off. ` +
                `See Hubris issue #1022.`
            );
            return 1;
        }
    } // end attempt loop

    if problems > 0 {
        print(
            `ERROR: Devices still stuck in update after reset attempts. ` +
            `Needs hard-reset.`
        );
        return 1;
    }

    debug("info|Checking initial image versions against baseline.");
    // "base" refers to v.branch value for image_check
    let result_initial_check = image_check("base", images);
    let err_initial_check = result_initial_check?.error;
    if err_initial_check != () {
        print(
            `ERROR: Initial image_check for baseline failed: ` +
            `${err_initial_check}`
        );
        return 1;
    }
    let flash_sp_for_base = result_initial_check?.ok?.sp;
    let flash_rot_for_base = result_initial_check?.ok?.rot;

    print("");
    print(`Elapsed time: ${start_ts.elapsed}`);
    print(`Now=${datetime_local()}`);
    print("");

    // N.B.: Try to always flash the RoT before the SP so that the RoT can be
    // ready to measure the SP when the SP resets.
    if flash_rot_for_base {
        debug(
            "info|Initial state: RoT needs update to baseline. " +
            "Using persistent update."
        );
        // For initial RoT update to baseline, use_transient is false.
        // The target_label for this initial setup is "baseline_setup".
        if !update_rot_hubris(
            conf.base.rot_a, conf.base.rot_b, false, "baseline_setup"
        ) {
            debug("error|Failed to update RoT to baseline image. Exiting.");
            return 1;
        }
    } else {
        debug(
            "info|Initial state: RoT is already on a baseline " +
            "(or equivalent) image."
        );
    }

    if flash_sp_for_base {
        debug("info|Initial state: SP needs update to baseline.");
        // Assuming update_sp is a local helper function
        if !update_sp(conf.base.sp) {
            debug("error|Failed to update SP to baseline image. Exiting.");
            return 1;
        }
    } else {
        debug(
            "info|Initial state: SP is already on a baseline " +
            "(or equivalent) image."
        );
    }

    // Verify baseline images are installed if updates were performed
    if flash_sp_for_base || flash_rot_for_base {
        debug(
            "info|Re-checking images after potentially updating to baseline."
        );
        let result_post_base_update = image_check("base", images);
        if result_post_base_update?.error != () ||
           result_post_base_update.ok?.sp ||
           result_post_base_update.ok?.rot
        {
            // If any check failed OR SP/RoT still need flashing -> Error
            debug(
                `warn|Post-baseline update image_check error or images still ` +
                `not correct: ${result_post_base_update}`
            );
            return 1;
        }
        debug("info|Successfully installed/verified baseline images on SP and RoT.");
    } else {
         debug(
             "info|SP and RoT were already on baseline images. " +
             "No initial updates performed."
         );
    }

    // Main upgrade/rollback loop
    for v in [
        #{
            "up_down": "upgrade",
            "label": "under-test",   // Descriptive label
            "branch": "ut",          // Key for image paths in conf
            "sp_path": conf.ut.sp,
            "rot_a_path": conf.ut.rot_a,
            "rot_b_path": conf.ut.rot_b,
        },
        #{
            "up_down": "rollback",
            "label": "baseline",
            "branch": "base",
            "sp_path": conf.base.sp,
            "rot_a_path": conf.base.rot_a,
            "rot_b_path": conf.base.rot_b,
        }
    ] {
        print(
            `\n## Starting ${v.up_down} to ${v.label} ` +
            `(${v.branch} branch versions)`
        );
        let use_transient_for_this_op = false;
        // Determine if transient mechanism should be attempted for RoT
        if conf.use_transient_boot_preference {
            // Check if the *currently active* RoT supports transient commands
            if rot_supports_transient_boot_preference() { // Assumes local helper
                debug(
                    `info|Current RoT supports transient commands. ` +
                    `Attempting transient update to ${v.label}.`
                 );
                use_transient_for_this_op = true;
            } else {
                debug(
                    `warn|Current RoT does NOT support transient commands. ` +
                    `Using persistent update to ${v.label}.`
                );
                // use_transient_for_this_op remains false
            }
        } else {
            debug(
                `info|Transient preference not enabled via -t option. ` +
                `Using persistent update to ${v.label}.`
            );
            // use_transient_for_this_op remains false
        }

        // Update RoT first
        debug(
            `info|Updating RoT Hubris to ${v.label} image ` +
            `(use_transient=${use_transient_for_this_op}).`
        );
        if !update_rot_hubris(
            v.rot_a_path, v.rot_b_path, use_transient_for_this_op, v.label
        ) {
            debug(
                `error|Failed to ${v.up_down} RoT Hubris to ${v.label} image.`
            );
            return 1; // Exit script on failure
        }

        // Then update SP
        debug(`info|Updating SP Hubris to ${v.label} image.`);
        if !update_sp(v.sp_path) {
            debug(
                `error|Failed to ${v.up_down} SP Hubris to ${v.label} image.`
            );
            return 1; // Exit script on failure
        }

        // Verify images after SP and RoT updates for this cycle
        let result_loop_check = image_check(v.branch, images); // Use v.branch
        if result_loop_check?.error != () ||
           result_loop_check.ok?.sp ||
           result_loop_check.ok?.rot
        {
            // If check fails or SP/RoT still need flashing -> Error
            debug(
                `error|image_check error or failed ${v.label} image updates: ` +
                `${result_loop_check}`
            );
            return 1;
        }
        debug(
            `info|### SUCCESS: ${v.up_down} to SP and RoT ${v.label} images ` +
            `completed successfully.`
        );
    } // end upgrade/rollback loop

    print("");
    print(`Elapsed time so far: ${start_ts.elapsed}`);
    print(`Now=${datetime_local()}`);
    print("Done");
    return 0; // All is well, exit with code 0
}

/// Parse the Rhai script command line options including the required
/// JSON configuration file.
/// Return an exit code or the configuration map
fn process_cli(argv) {
    // Process command line options
    let prog = argv[0];
    // Options with arguments followed by ':'
    let options = "hc:b:u:tv"; // Added t, v here as per usage string
    // Use util::getopts
    let parsed = util::getopts(argv, options);
    if parsed?["error"] != () {
        usage(prog, parsed.error); // Pass error message
        return 1;
    }

    if parsed.result?["h"] == true {
        usage(prog, ());
        return 0;
    }

    // Build the configuration map
    let conf = #{};

    conf["verbose"] = false;
    if parsed.result?["v"] == true {
        conf.verbose = true;
    }

    conf["use_transient_boot_preference"] = false;
    if parsed.result?["t"] == true {
        conf["use_transient_boot_preference"] = true;
    }

    let conf_path = parsed.result?["c"];
    if conf_path == () {
        usage(prog, "Missing required option: -c config.json");
        return 1;
    }
    // TODO: Consider validating conf_path format if needed before path() call
    let conf_path = path(conf_path); // Assumes path() function exists
    if !conf_path.is_file {
        usage(prog, `Config file not found or not a file: ${conf_path}`);
        return 1;
    }

    conf["conf_path"] = conf_path; // Store validated path

    // Process the JSON format configuration file into a map.
    let conf_json = ""; // Initialize
    let read_ok = true;
    try {
        // Attempt to open and read the file within the try block
        let conf_file = open_file(conf_path);
        conf_json = conf_file.read_string();
        debug(`info|Successfully read config file: ${conf_path}`);
    } catch (err) {
        // Handle file open or read errors caught here
        print(`ERROR: Cannot open or read config file ${conf_path}: ${err}`);
        read_ok = false;
    }

    // Exit if file could not be opened or read
    if !read_ok {
        return 1;
    }

    // Now, parse the JSON content (conf_json)
    // Assuming json_to_map handles errors and returns map with 'error' key
    let config = json_to_map(conf_json);
    if config?.error != () {
         print(`ERROR: Failed to parse JSON from config file: ${conf_path}`);
         print(`       ${config.error}`);
         return 1;
    }

    if conf.verbose {
        print("");
        // Note: 'config' is the map parsed from JSON, 'conf' is the final map being built
        print(`Parsed JSON config from ${conf_path}: ${config}`);
    }

    // Optionally override baseline and under test repo paths from CLI
    let base_repo_override = parsed?.positional[0];
    if base_repo_override != () {
        print("Overriding config 'base_repo' from command line:");
        print(`  was: ${config?.base_repo}`);
        config.base_repo = base_repo_override;
        print(`  now: ${config.base_repo}`);
    }
    let ut_repo_override = parsed?.positional[1];
    if ut_repo_override != () {
        print("Overriding config 'ut_repo' from command line:");
        print(`  was: ${config?.ut_repo}`);
        config.ut_repo = ut_repo_override;
        print(`  now: ${config.ut_repo}`);
    }

    // --- Expand paths using variables from config and environment ---
    // Ensure base 'repo-home' or similar is defined if used in paths below
    if config?["repo-home"] == () && (
            config?.base_repo?.contains("${repo-home}") ||
            config?.ut_repo?.contains("${repo-home}") )
    {
         debug("warn|'repo-home' used in paths but not defined in config.");
    }

    // Pass the parsed 'config' map itself as the override map for env_expand
    conf["sp_bord"] = util::env_expand(config?.bord?.sp, config);
    conf["rot_bord"] = util::env_expand(config?.bord?.rot, config);

    for branch in ["base", "ut"] {
        conf[branch] = #{}; // Ensure branch map exists
        for image in ["sp", "rot_a", "rot_b", "stage0"] {
            let image_path_template = config?.images?[branch]?[image];
            if image_path_template == () {
                 debug(`warn|No config path found for image ${branch}.${image}`);
                 conf[branch][image] = ();
                 continue;
            }
            let zip_path = util::env_expand(image_path_template, config);
            if zip_path == () {
                debug(
                    `error|Failed expanding path for ${branch}.${image}: ` +
                    `'${image_path_template}'`
                 );
                conf[branch][image] = (); // Set to null on expansion failure
            } else {
                conf[branch][image] = zip_path;
                debug(`info|Expanded path ${branch}.${image} = ${zip_path}`);
            }
        } // end image loop
    } // end branch loop

    // Handle IPCC config expansion
    let faux_ipcc_path_template = config?.ipcc?.faux_ipcc;
    if faux_ipcc_path_template != () {
        conf.ipcc = #{
            "use_ipcc": true,
            "faux_ipcc": util::env_expand(faux_ipcc_path_template, config),
            "port": util::env_expand(config?.ipcc?.port, config), // Expand optional port
        };
    } else {
        conf.ipcc = #{ "use_ipcc": false };
    }

    // Final display of fully resolved conf map if verbose
    if conf.verbose {
        print("\nFully resolved configuration map:");
        print(conf); // Print the final map passed to main logic
    }

    return conf; // Return the fully processed configuration map
}

// Check and organize the images mentioned in the configuration
fn get_image_info(conf) {
    let images = #{};

    // Get the current CFPA and CMPA to verify the RoT test images.
    images["cmpa"] = util::get_cmpa();
    images["cfpa"] = util::get_cfpa();
    if images.cmpa == () || images.cfpa == () {
        print("ERROR: Failed to read CMPA or CFPA from device.");
        return 1; // Indicate error
    }
    images["keyset"] = util::get_rot_keyset(images.cfpa);
    debug(`info|Detected RoT keyset: ${images.keyset}`);

    let gitc = #{};
    let error_found = false; // Use flag instead of returning string
    let failed_verify_list = []; // Accumulate paths

    for branch in ["base", "ut"] {
        images[branch] = #{};
        for image in ["sp", "rot_a", "rot_b", "stage0"] {
            let zip_path = conf[branch][image];
            if zip_path == () {
                 // Path was missing or failed expansion in process_cli
                 print(`Warn: Skipping image check for ${branch}.${image} due to missing path.`);
                 continue;
            }
            images[branch][image] = #{"path": zip_path};

            // Use 'try..catch' if 'new_archive' can throw errors
            let current_ar = ();
            let archive_ok = true;
            try {
                current_ar = new_archive(zip_path); // Assumes this func exists
            } catch(err) {
                print(`ERROR: Failed creating archive object for ${zip_path}: ${err}`);
                error_found = true;
                archive_ok = false;
            }
            if !archive_ok { continue; } // Skip rest if archive failed

            if type_of(current_ar) != "Archive" {
                print(`ERROR: Invalid archive object for path ${zip_path}`);
                error_found = true;
                continue;
            }

            // Extract caboose info using the custom object's indexer
            images[branch][image]["caboose"] = #{}; // Initialize caboose map
            let caboose_obj = current_ar?["caboose"]; // Get CabooseInspector object

            if caboose_obj == () || type_of(caboose_obj) == "()" {
                // Check if the object itself is null/unit
                print(`WARN: Could not get caboose object from ${zip_path}`);
                // Mark as potentially problematic if caboose is essential
                // error_found = true; // Depending on requirements
            } else if type_of(caboose_obj) == "map" && caboose_obj?.error != () {
                 // Handle potential error map returned *instead* of caboose object
                 print(`WARN: Error getting caboose object from ${zip_path}: ${caboose_obj.error}`);
                 // error_found = true;
            } else {
                // Attempt to access keys via the object's indexer
                let caboose_read_ok = true;
                for key in ["BORD", "GITC", "NAME", "SIGN", "VERS"] {
                    let val = ();
                    // Use try..catch in case indexer fails for a specific key
                    try {
                        val = caboose_obj[key];
                    } catch (err) {
                         debug(`warn|Failed reading caboose key '${key}' from ${zip_path}: ${err}`);
                         caboose_read_ok = false;
                    }

                    if val != () { // Store if value is not null
                         images[branch][image]["caboose"][key] = val;
                    } else {
                         // Optional: log if a specific expected key is missing
                         // debug(`info|Caboose key '${key}' is null in ${zip_path}`);
                    }
                }
                // Check if essential keys like GITC were actually found after trying
                if images[branch][image]["caboose"]?.GITC == () {
                     print(
                        `WARN: Could not read essential GITC from caboose in ${zip_path}. `+
                        `Read successful: ${caboose_read_ok}`
                     );
                     // If GITC is essential for later checks, mark as error
                     // error_found = true;
                }
            }

            // Verify RoT images
            if image != "sp" {
                let verified = true; // Default ok
                let verify_error = ();
                // Use try..catch for verification function
                try {
                    verified = current_ar.verify_rot_image(
                        images.cmpa, images.cfpa
                    );
                } catch (err) {
                    verified = false;
                    verify_error = err;
                }

                images[branch][image]["verified"] = verified;
                if !verified {
                    failed_verify_list += images[branch][image]["path"];
                    print(
                       `WARN: Image signature verification FAILED for: ` +
                       `${images[branch][image]["path"]}. ` +
                       `Error: ${verify_error}`
                    );
                     // Decide if this is a fatal error - maybe allow testing?
                     // error_found = true;
                } else {
                     debug(
                        `info|Image signature verified OK for: `+
                        `${images[branch][image]["path"]}`
                     );
                }
            } else {
                // SP image doesn't use the same RoT keys for verification here
                images[branch][image]["verified"] = true; // Assume OK for now
                // TODO: Add SP-specific BORD/NAME checks if needed
            }

            // Reverse map GITC to image labels
            let image_gitc = images[branch][image]?.caboose?["GITC"];
            if image_gitc != () {
                if gitc?[image_gitc] == () {
                    gitc[image_gitc] = [];
                }
                // TODO: Warn if base and ut images (esp sp/rot) have same GITC.
                gitc[image_gitc] += [ `${branch}_${image}` ];
            }
        } // end image loop
    } // end branch loop

    debug(`info|Image GITC reverse map: ${gitc}`);
    images["by_gitc"] = gitc;
    images["failed_to_verify"] = failed_verify_list; // Store list

    // Report images that failed verification, if any
    if images.failed_to_verify.len() > 0 {
         print("WARN: The following RoT images FAILED signature verification:");
         for path in images.failed_to_verify {
             print(`  - ${path}`);
         }
         // Decide if this constitutes a fatal error for the script
         // error_found = true; // Uncomment if failure should stop script
    }

    // Display the accumulated information to document this run.
    if conf.verbose {
        print("");
        print(`## images info map=${images}`);
    }

    // Return 1 if critical errors occurred, otherwise the map
    if error_found {
        return 1;
    } else {
        return images;
    }
}

/// Updates SP with specified image, resets, and polls for readiness
/// and clean update status.
/// Uses util::update_sp_image, util::reset_sp, and util::check_update_in_progress.
fn update_sp(sp_zip) {
    print("");
    print(`### update_sp: ${sp_zip}`);

    // Step 1: Call util function to update the SP image
    if (!util::update_sp_image(sp_zip)) {
        // Error already printed by util function
        return false;
    }
    debug(`info|update_sp: SP update command acknowledged by SP.`);

    // Step 2: Check status immediately after update (optional, for logging)
    // This status might still show "Complete" or even "InProgress" if the
    // SP hasn't fully processed the end of the update yet.
    let r_status1 = util::check_update_in_progress("sp");
    debug(`info|update_sp: SP status immediately after update command: ${r_status1}`);
    // No action needed based on this status, proceed to reset.

    // Step 3: Call util function to reset the SP
    debug("info|update_sp: Resetting SP to boot new image.");
    if (!util::reset_sp()) {
        // Error already printed by util function
        return false;
    }
    debug("info|update_sp: SP reset acknowledged. Starting polling for readiness.");

    // Step 4: Poll for SP readiness and clean update status
    let max_poll_attempts = 15; // e.g., 15 attempts
    let poll_interval_secs = 1;  // e.g., 1 seconds
    let sp_ready_and_clean = false;

    for attempt in 1..=max_poll_attempts {
        debug(
            `info|update_sp: Polling SP readiness, attempt ${attempt}` +
            `/${max_poll_attempts}...`
        );
        let sp_status = util::check_update_in_progress("sp");

        if sp_status == () {
            // This is the desired state: SP is responsive and no update pending.
            debug("info|update_sp: SP is ready and no update in progress.");
            sp_ready_and_clean = true;
            break; // Exit polling loop
        } else if sp_status?.Err != () {
            // An error occurred trying to get status (e.g., SP not responsive yet)
            debug(
                `warn|update_sp: Readiness check attempt ${attempt}: ` +
                `Error getting SP status: ${sp_status}. Retrying after sleep.`
            );
        } else {
            // SP is responsive, but an update is still marked as InProgress or Complete.
            // This is unexpected after a reset intended to clear it.
            debug(
                `warn|update_sp: Readiness check attempt ${attempt}: ` +
                `SP reported unexpected update status: ${sp_status}. ` +
                `Expected clean state (none). Retrying after sleep.`
            );
        }

        // Wait before next attempt, unless it's the last one
        if attempt < max_poll_attempts {
            sleep(poll_interval_secs);
        }
    }

    if (!sp_ready_and_clean) {
        debug(
            `error|update_sp: SP did not become ready with a clean update state ` +
            `after reset and ${max_poll_attempts} attempts.`
        );
        print(
            `FAIL - SP did not successfully reset and clear update status.\n`
        );
        return false; // SP failed to come up cleanly
    }

    debug("info|update_sp: SP readiness and clean status confirmed.");
    print(`### SUCCESS update_sp: ${sp_zip}`);
    print("");
    return true;
}

// --- Local Helper functions for update_rot_hubris ---

fn _rot_log_initial_params(
    initial_slot, target_slot, image_path, target_label, use_transient_flag
) {
    debug(
        `info|--- RoT Update Operation Start `+
        `(in upgrade-rollback.rhai) ---`
    );
    debug(`info|Target Label: ${target_label}, Use Transient: ${use_transient_flag}`);
    debug(`info|Initial Active RoT Slot (before this op): ${initial_slot}`);
    debug(`info|Target RoT Update Slot for this op: ${target_slot}`);
    debug(`info|Target RoT Image for this op: ${image_path}`);
}

fn _rot_log_rbi_details(
    rbi, context_description, initial_slot_before_op,
    target_update_slot_for_op, use_transient_flag_for_op
) {
    debug(
        `info|RoT Boot Info (${context_description}, ` +
        `from upgrade-rollback.rhai):`
    );
    debug(`    Initial Active Slot (before op): ${initial_slot_before_op}`);
    debug(`    Target Update Slot (for op): ${target_update_slot_for_op}`);
    debug(`    Use Transient Flag (for op): ${use_transient_flag_for_op}`);
    debug(`    Current Active Slot (from RBI): ${rbi.active}`);
    debug(`    Persistent Pref (from RBI): ${rbi.persistent_boot_preference}`);
    debug(`    Transient Pref (from RBI): ${rbi.transient_boot_preference}`);
    debug(`    Pending Persistent Pref (from RBI): ${rbi.pending_persistent_boot_preference}`);
}

fn _rot_validate_initial_transient_boot_state(
    rbi, initial_slot_before_op, target_update_slot, target_label
) {
    let active_after_first_reset = rbi.active;
    let p_pref_from_newly_active = rbi.persistent_boot_preference;
    let t_pref_from_newly_active = rbi.transient_boot_preference;
    let pp_pref_from_newly_active = rbi.pending_persistent_boot_preference;
    let is_ok = true;
    let failure_details = "";

    if active_after_first_reset != target_update_slot {
        is_ok = false;
        failure_details +=
            ` Active slot (${active_after_first_reset}) ` +
            `is not target (${target_update_slot}).`;
    }
    if t_pref_from_newly_active != () {
        is_ok = false;
        failure_details +=
            ` t_pref (${t_pref_from_newly_active}) not null.`;
    }
    if pp_pref_from_newly_active != () {
        is_ok = false;
        failure_details +=
            ` pp_pref (${pp_pref_from_newly_active}) not null.`;
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
            failure_details +=
                ` p_pref (${p_pref_from_newly_active}) not original active ` +
                `(${initial_slot_before_op}).`;
        }
    }
    if !is_ok {
        debug(
            `error|Initial transient boot state validation failed for ` +
            `'${target_label}'.${failure_details} RBI=${rbi}`
        );
    }
    return is_ok;
}

fn _rot_ensure_persistence_after_transient_boot(
    rbi_after_first_boot, target_update_slot, target_label
) {
    // Calls util::set_rot_boot_preference
    let active_after_first_reset = rbi_after_first_boot.active;
    let p_pref_from_newly_active = rbi_after_first_boot.persistent_boot_preference;
    let set_persistent_needed = true;

    if target_label == "baseline" {
        if p_pref_from_newly_active == active_after_first_reset {
            debug(
                `info|Target '${target_label}': p_pref already matches ` +
                `active. No explicit set_persistent needed.`
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
            "Standard transient-to-persistent."
        };
        debug(
            `info|Setting persistent pref for slot ${target_update_slot} ` +
            `('${target_label}'). Reason: ${reason}`
        );
        // Call the function moved to util.rhai
        if !util::set_rot_boot_preference(
            target_update_slot, false, target_label // false -> use '-p'
        ) {
            debug(
                `error|util::set_rot_boot_preference failed for ` +
                `'${target_label}', slot ${target_update_slot}.`
            );
            return false;
        }
        debug(
            `info|Successfully called util::set_rot_boot_preference `+
            `for slot ${target_update_slot} ('${target_label}').`
        );
    }
    return true;
}

fn _rot_validate_final_persistent_boot_state(
    final_rbi, target_update_slot, target_label
) {
    let final_active_slot = final_rbi.active;
    let final_p_pref = final_rbi.persistent_boot_preference;

    debug(
        `info|RoT boot info after final reset (target '${target_label}'): ` +
        `active=${final_active_slot}, p_pref=${final_p_pref}`
    );

    if final_active_slot != target_update_slot {
        debug(
            `error|Target '${target_label}' NOT on persistently set slot. `+
            `Expected ${target_update_slot}, got ${final_active_slot}. ` +
            `RBI=${final_rbi}`
         );
        return false;
    }
    if final_p_pref != target_update_slot {
         debug(
             `warn|Target '${target_label}': final p_pref is ${final_p_pref}, ` +
             `not ${target_update_slot}. May be acceptable for baseline.`
         );
    }
    debug(
        `info|Successfully booted '${target_label}' on persistently `+
        `set slot ${final_active_slot}.`
    );
    return true;
}

fn _rot_validate_direct_persistent_boot_state(
    rbi, target_update_slot, target_label
) {
    if rbi.active != target_update_slot {
        debug(
            `error|Unexpected active slot ${rbi.active} `+
            `(expected ${target_update_slot}) after non-transient update ` +
            `of '${target_label}'. RBI=${rbi}`
        );
        return false;
    }
    return true;
}
// --- End of Local Helper functions ---

// Refactored main update_rot_hubris function
fn update_rot_hubris(path_a, path_b, use_transient, target_label) {
    print(""); // Keep some top-level progress indicators
    print(
        `### update_rot_hubris (target: ${target_label}, ` +
        `use_transient: ${use_transient})`
    );
    print(`    Image A: ${path_a}`);
    print(`    Image B: ${path_b}`);

    let r_get_active = get_rot_active();
    if r_get_active?.error != () {
        print(`ERROR: get_rot_active failed: ${r_get_active.error}`);
        return false;
    }
    let initial_slot_before_op = r_get_active.ok;
    let target_update_slot_for_op = if initial_slot_before_op == 0 { 1 } else { 0 };
    let target_update_image_for_op =
        if target_update_slot_for_op == 0 { path_a } else { path_b };

    _rot_log_initial_params(
        initial_slot_before_op, target_update_slot_for_op,
        target_update_image_for_op, target_label, use_transient
    );

    // Call util function for image update
    if (!util::update_rot_image_file(
        target_update_slot_for_op, target_update_image_for_op, target_label
    )) {
        return false;
    }

    // Call util function to set boot preference
    if (!util::set_rot_boot_preference(
        target_update_slot_for_op, use_transient, target_label
    )) {
        return false;
    }

    // Call util function to reset RoT and get RBI
    let rbi_after_first_reset = util::reset_rot_and_get_rbi(
        "after initial preference set", target_label
    );
    // Check if util function returned an error map
    if rbi_after_first_reset?.error != () {
        return false; // Error already logged by util function
    }
    _rot_log_rbi_details(
        rbi_after_first_reset, "after first reset", initial_slot_before_op,
        target_update_slot_for_op, use_transient
    );

    if use_transient {
        // --- Transient Boot Flow ---
        // Validate state after first transient boot
        if (!_rot_validate_initial_transient_boot_state(
            rbi_after_first_reset, initial_slot_before_op,
            target_update_slot_for_op, target_label
        )) {
            return false;
        }
        // Ensure the slot is made persistent
        if (!_rot_ensure_persistence_after_transient_boot(
            rbi_after_first_reset, target_update_slot_for_op, target_label
        )) {
            return false;
        }

        // Final reset to apply persistence and final validation
        let final_rbi = util::reset_rot_and_get_rbi(
            "after setting persistence", target_label
        );
        if final_rbi?.error != () {
            return false;
        }
        _rot_log_rbi_details(
            final_rbi, "after final reset (persistence check)",
            initial_slot_before_op, target_update_slot_for_op, use_transient
        );

        if (!_rot_validate_final_persistent_boot_state(
            final_rbi, target_update_slot_for_op, target_label
        )) {
            return false;
        }
    } else {
        // --- Direct Persistent Boot Flow ---
        if (!_rot_validate_direct_persistent_boot_state(
            rbi_after_first_reset, target_update_slot_for_op, target_label
        )) {
            return false;
        }
    }

    print(
        `### SUCCESS update_rot_hubris (target: ${target_label}): ` +
        `successfully updated and booted slot ${target_update_slot_for_op} ` +
        `with ${target_update_image_for_op}`
    );
    print("");
    return true;
}


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

fn reset_sp_and_rot() {
    // The disable watchdog should not be required for the SP.
    // The STLINK needs to be powered down for some reset scenarios.
    debug("info|reset_sp_and_rot: Beginning reset sequence for RoT and SP.");
    for params in [["rot", 3], ["sp", 5]] {
        let component_to_reset = params[0];
        let sleep_duration = params[1];

        print(`### Reset ${component_to_reset}`);

        if !util::reset_component(component_to_reset) {
            // util::reset_component logs its own specific errors
            return #{
                "error": `Failed to reset component '${component_to_reset}' via util function.`
            };
        }

        debug(
            `info|reset_sp_and_rot: Successfully reset component ` +
            `'${component_to_reset}'. Sleeping for ${sleep_duration}s.`
        );
        sleep(sleep_duration);
    }
    debug("info|reset_sp_and_rot: RoT and SP reset sequence complete.");
    return #{"ok": ()};
}

fn get_rot_active() {
    // fetch RoT boot info using util function
    let rbi = util::rot_boot_info();
    // Check if util function returned error map
    if rbi?.error != () {
        return #{"error": `Cannot get RBI: ${rbi.error}`};
    }
    // Ensure 'active' key exists and is not null
    let active_slot = rbi?.active;
    if active_slot == () {
         return #{"error": `Cannot determine active RoT slot from RBI: ${rbi}`};
    }
    return #{"ok": active_slot};
}

fn rot_supports_transient_boot_preference() {
    debug(`info|Checking if current RoT supports transient boot preference command...`);
    // First, determine the currently active RoT slot
    let r_boot_info = get_active_and_next_rot_boot_preference(); // Assumes this local helper is suitable
    if r_boot_info?.error != () {
        debug(
            `error|rot_supports_transient_boot_preference: Cannot determine current RoT ` +
            `active slot to test transient support. Error: ${r_boot_info.error}`
        );
        return false;
    }

    let active_slot = r_boot_info.ok.active;
    // The 'next' slot isn't strictly needed for this test, only 'active'
    debug(
        `info|rot_supports_transient_boot_preference: Current active RoT slot is ${active_slot}. ` +
        `Attempting to set transient preference on this slot as a test.`
    );

    // Call the existing util function to attempt to set the transient preference.
    // The 'target_label' can be specific to indicate this is a test call.
    // 'true' for use_transient_flag to set the '--transient' option.
    if util::set_rot_boot_preference(active_slot, true, "transient_support_test") {
        debug(
            `info|rot_supports_transient_boot_preference: ` +
            `Successfully executed command to set transient boot preference. ` +
            `Assuming feature is supported.`
        );
        // Note: This command, if successful, *will* set the transient preference.
        // The original script did not appear to revert this test-set if successful.
        // If this function should be purely a check without side effects,
        // a subsequent call to clear/revert the preference would be needed.
        // For now, this matches the implied behavior of the original script.
        return true;
    } else {
        debug(
            `warn|rot_supports_transient_boot_preference: ` +
            `Command to set transient boot preference failed for slot ${active_slot}. ` +
            `Assuming feature is not supported.`
        );
        return false;
    }
}

// ... (rest of upgrade-rollback.rhai) ...

// Determine the next active bank preference based on RBI.
fn get_active_and_next_rot_boot_preference() {
    // fetch RoT boot info
    let rbi = util::rot_boot_info();
    if rbi?.error != () {
        return #{"error": `Cannot get RBI: ${rbi.error}`};
    }
    if rbi?.active == () {
        return #{"error": `Invalid RBI structure from util::rot_boot_info: ${rbi}`};
    }

    let active = rbi.active;
    let next_preferred = active; // Start assuming current active is preferred

    // Check pending persistent preference first
    let pend_persist = rbi.pending_persistent_boot_preference;
    if pend_persist != () {
        next_preferred = pend_persist;
        debug(`info|Next boot determined by pending persistent pref: ${next_preferred}`);
    } else {
        // If no pending persistent, check transient preference
        let transient_select = rbi.transient_boot_preference;
        if transient_select != () {
             next_preferred = transient_select;
             debug(`info|Next boot determined by transient pref: ${next_preferred}`);
        } else {
            // If no transient, check persistent preference
            let persistent_pref = rbi.persistent_boot_preference;
            if persistent_pref != () {
                next_preferred = persistent_pref;
                debug(`info|Next boot determined by persistent pref: ${next_preferred}`);
            } else {
                debug(
                    `info|No explicit preference set in RBI. ` +
                    `Next boot likely current active: ${active}`
                );
            }
        }
    }
    return #{"ok": #{"active": active, "next": next_preferred}};
}


// Check if SP and RoT images match desired branches.
fn image_check(branch, images) {
    let ok = #{ "sp": false, "rot": false }; // Initialize
    let error = #{};

    let sp_needs_flash_result = sp_needs_flashing(
        `${branch}_sp`, images.by_gitc
    );
    if sp_needs_flash_result?.error != () {
        print(`Error checking SP image: ${sp_needs_flash_result.error}`);
        error["sp"] = `${sp_needs_flash_result.error}`;
    } else {
        ok["sp"] = sp_needs_flash_result.ok;
    }

    let rot_needs_flash_result = rot_needs_flashing(
        `${branch}`, images.by_gitc
    );
    if rot_needs_flash_result?.error != () {
        debug(`error checking RoT image: ${rot_needs_flash_result.error}`);
        error["rot"] = `${rot_needs_flash_result.error}`;
    } else {
        ok["rot"] = rot_needs_flash_result.ok;
    }

    if error.len() > 0 {
        // Return error map if any component check failed
        return #{"error": error};
    } else {
        // Return map indicating which components need flashing
        return #{"ok": ok};
    }
}

fn sp_needs_flashing(target_image_label, gitc_map) {
    let sp_gitc = util::caboose_value("sp", "active", "GITC");
    if sp_gitc == () {
         return #{"error": "Could not read active SP GITC via caboose."};
    }
    print(`### SP is running GITC=${sp_gitc}`);

    let known_images_for_this_gitc = gitc_map?[sp_gitc];
    debug(`info|Known images for SP GITC ${sp_gitc}: ${known_images_for_this_gitc}`);

    if known_images_for_this_gitc == () {
        print("    SP GITC is not from known BASE or UNDER-TEST images.");
        return #{"ok": true}; // Needs flashing
    } else if target_image_label in known_images_for_this_gitc {
        print(`    ${target_image_label} IS in ${known_images_for_this_gitc}`);
        return #{"ok": false}; // Does not need flashing
    } else {
        print(`    ${target_image_label} IS NOT in ${known_images_for_this_gitc}`);
        return #{"ok": true}; // Needs flashing
    }
}

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

    let known_images_for_this_gitc = gitc_map?[rot_gitc];
    debug(`info|Known images for RoT GITC ${rot_gitc}: ${known_images_for_this_gitc}`);

    if known_images_for_this_gitc == () {
        debug("info|RoT GITC is not from known BASE or UNDER-TEST images.");
        return #{"ok": true}; // Needs flashing
    } else if target_image_label in known_images_for_this_gitc {
        debug(`info|${target_image_label} IS in ${known_images_for_this_gitc}`);
        return #{"ok": false}; // Does not need flashing
    } else {
        debug(`info|${target_image_label} IS NOT in ${known_images_for_this_gitc}`);
        return #{"ok": true}; // Needs flashing
    }
}
