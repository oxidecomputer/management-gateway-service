import `${script_dir}/util` as util;

/// Print command line usage
fn usage(prog, error) {
    if error != () {
        print(`Error: ${error}`);
    }
    print(`Usage: faux-mgs ... rhai ${prog} [-v] [-h] [-c config.json] [path0] [path1]`);
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
        "i64" => return conf, // Exit code from process_cli (e.g., for -h or error)
        "map" => (),          // Configuration map successfully parsed
        _ => {
            print("ERROR: process_cli returned unexpected type.");
            return 1;
        }
    }

    let images = get_image_info(conf);
    if type_of(images) == "i64" { // Assuming get_image_info might return exit code on error
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
                print(`Error from util::check_update_in_progress for ${component}: ${r_check}`);
                return 1;
            }
            if r_check != () { // If not null, an update was in progress or completed
                problems += 1;
                let id = r_check?.id;
                debug(`info|Component ${component} had existing update status: ${r_check}. Attempting abort with id=${id}.`);
                print(`The SP component '${component}' may need reset after abort. Trying to abort update id=${id}`);
                let r_abort = faux_mgs(["update-abort", component, `${id}`]);
                debug(`info|update-abort result for ${component} id ${id}: ${r_abort}`);
                // Check r_abort for success if needed, though script continues regardless
            }
        }
        if problems == 0 {
            debug("info|No pending updates found or they were abortable.");
            break;
        }
        debug(`warn|Attempt ${attempt}: Problems found with component updates. Resetting SP and RoT.`);
        let r_reset_all = reset_sp_and_rot(); // Assuming this local helper function exists
        if r_reset_all?["error"] != () {
            print(`ERROR: Cannot reset RoT and SP: ${r_reset_all.error}`);
            print(`Check that RoT has no pending update and STLINK is off. See Hubris issue #1022.`);
            return 1;
        }
    }
    if problems > 0 {
        print(`ERROR: Devices still stuck in update after reset attempts. Needs hard-reset.`);
        return 1;
    }

    debug("info|Checking initial image versions against baseline.");
    let result_initial_check = image_check("base", images); // "base" refers to v.branch value
    let err_initial_check = result_initial_check?.error;
    if err_initial_check != () {
        print(`ERROR: Initial image_check for baseline failed: ${err_initial_check}`);
        return 1;
    }
    let flash_sp_for_base = result_initial_check?.ok?.sp;
    let flash_rot_for_base = result_initial_check?.ok?.rot;

    print("");
    print(`Elapsed time: ${start_ts.elapsed}`);
    print(`Now=${datetime_local()}`);
    print("");

    // N.B.: Try to always flash the RoT before the SP so that the RoT can be ready to
    // measure the SP when the SP resets.
    if flash_rot_for_base {
        debug("info|Initial state: RoT needs update to baseline. Using persistent update.");
        // For initial RoT update to baseline, use_transient is false.
        // The target_label for this initial setup is "baseline".
        if !update_rot_hubris(conf.base.rot_a, conf.base.rot_b, false, "baseline_setup") {
            debug("error|Failed to update RoT to baseline image. Exiting.");
            return 1;
        }
    } else {
        debug("info|Initial state: RoT is already on a baseline (or equivalent) image.");
    }

    if flash_sp_for_base {
        debug("info|Initial state: SP needs update to baseline.");
        if !update_sp(conf.base.sp) { // Assuming update_sp is a local helper function
            debug("error|Failed to update SP to baseline image. Exiting.");
            return 1;
        }
    } else {
        debug("info|Initial state: SP is already on a baseline (or equivalent) image.");
    }

    if flash_sp_for_base || flash_rot_for_base {
        debug("info|Re-checking images after potentially updating to baseline.");
        let result_post_base_update = image_check("base", images);
        if result_post_base_update?.error != () || result_post_base_update.ok?.sp || result_post_base_update.ok?.rot {
            debug(`warn|Post-baseline update image_check error or images still not correct: ${result_post_base_update}`);
            return 1;
        }
        debug("info|Successfully installed baseline images on SP and RoT.");
    } else {
         debug("info|SP and RoT were already on baseline images. No initial updates performed.");
    }

    // Main upgrade/rollback loop
    for v in [
        #{
            "up_down": "upgrade",
            "label": "under-test",   // For the target_label parameter of update_rot_hubris
            "branch": "ut",          // For image_check and image path lookups in 'conf'
            "sp_path": conf.ut.sp,
            "rot_a_path": conf.ut.rot_a,
            "rot_b_path": conf.ut.rot_b,
        },
        #{
            "up_down": "rollback",
            "label": "baseline",   // For the target_label parameter of update_rot_hubris
            "branch": "base",        // For image_check and image path lookups in 'conf'
            "sp_path": conf.base.sp,
            "rot_a_path": conf.base.rot_a,
            "rot_b_path": conf.base.rot_b,
        }
    ] {
        print(`\n## Starting ${v.up_down} to ${v.label} (${v.branch} branch versions)`);
        let use_transient_for_this_op = false;
        if conf.use_transient_boot_preference { // If -t flag was used
            // Check if the *current* RoT image (before this update_rot_hubris call) supports transient boot commands
            if rot_supports_transient_boot_preference() {
                debug(`info|Current RoT image supports transient boot commands. Will attempt to use transient mechanism for RoT update to ${v.label}.`);
                use_transient_for_this_op = true;
            } else {
                debug(`warn|Current RoT image does NOT support transient boot commands. Will use persistent mechanism for RoT update to ${v.label}.`);
                use_transient_for_this_op = false;
            }
        } else {
            debug(`info|Not configured to use transient boot preference (-t option not used). Using persistent mechanism for RoT update to ${v.label}.`);
            use_transient_for_this_op = false;
        }

        debug(`info|Updating RoT Hubris to ${v.label} image (use_transient=${use_transient_for_this_op}).`);
        if !update_rot_hubris(v.rot_a_path, v.rot_b_path, use_transient_for_this_op, v.label) {
            debug(`error|Failed to ${v.up_down} RoT Hubris to ${v.label} image.`);
            return 1;
        }

        debug(`info|Updating SP Hubris to ${v.label} image.`);
        if !update_sp(v.sp_path) {
            debug(`error|Failed to ${v.up_down} SP Hubris to ${v.label} image.`);
            return 1;
        }

        let result_loop_check = image_check(v.branch, images); // Use v.branch for image_check
        if result_loop_check?.error != () || result_loop_check.ok?.sp || result_loop_check.ok?.rot {
            debug(`error|image_check error or failed ${v.label} image updates: ${result_loop_check}`);
            return 1;
        }
        debug(`info|### SUCCESS: ${v.up_down} to SP and RoT ${v.label} images completed successfully.`);
    }

    print("");
    print(`Elapsed time so far: ${start_ts.elapsed}`);
    print(`Now=${datetime_local()}`);
    print("Done");
    0 // All is well, exit with code 0
}

// TODO: Parameterize update orders for upgrade and rollback with defaults
// that match what omicron or wicket would do.
// e.g. in config.json: "upgrade-order": ["sp", "rot", "stage0"],
//                      "rollback-order": ["sp", "rot", "stage0"];
//
// TODO: Take a TUF repo as a set of baseline or under-test images.
// Alternatively, write a script that will extract from a TUF repo(s)
// and write a configuration file for this script.

/// Parse the Rhai script command line options including the required
/// JSON configuration file.
/// Return an exit code or the configuration map
fn process_cli(argv) {
    // Process command line options
    let prog = argv[0];
    let options = "hc:b:u:"; // Options with arguments are followed by ':'
    let parsed = util::getopts(argv, "hc:tv");
    if parsed?["error"] != () {
        usage(prog, parsed?["error"]);
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
        conf.verbose=true;
    }

    if parsed.result?["t"] == true {
      conf["use_transient_boot_preference"] = true;
    }
    if conf?["use_transient_boot_preference"] == () {
      conf["use_transient_boot_preference"] = false;
    }

    let conf_path = parsed["result"]?["c"];
    if conf_path == () {
        usage(prog, "Missing option: -c config.json");
        return 1;
    }
    let conf_path = path(conf_path);
    if !conf_path.is_file {
        usage(prog, `${conf_path} is not a regular file`);
        return 1
    }
    conf["conf_path"] = conf_path;

    // Process the JSON format configuration file into a map.
    let conf_file = open_file(conf_path);
    let conf_json = conf_file.read_string();
    let config = json_to_map(conf_json);
    if conf.verbose {
        print("");
        print(`config=${config}`);
    }

    // Optionally override baseline and under test repo from command line
    let repo_path = parsed?.positional[0];
    if repo_path != () {
      print("override config base_repo:");
      print(`  was: ${config?.base_repo}`);
      config.base_repo = repo_path;
      print(`  now: ${config?.base_repo}`);
    }
    let repo_path = parsed?.positional[1];
    if repo_path != () {
      print("override config ut_repo:");
      print(`  was: ${config?.ut_repo}`);
      config.ut_repo = repo_path;
      print(`  now: ${config?.ut_repo}`);
    }

    // Expand the paths to archives so that the config file
    // can use vars from the environment and the configuration file itself.
    conf["sp_bord"] = util::env_expand(config.bord.sp, config);
    conf["rot_bord"] = util::env_expand(config.bord.rot, config);

    for branch in ["base", "ut"] {
        conf[branch] = #{};
        for image in ["sp", "rot_a", "rot_b", "stage0"] {
            let zip_path =  util::env_expand(config.images[branch][image], config);
            if zip_path == () {
                print(`No configuration for image ${branch}.${image}`);
            } else {
                conf[branch][image] = zip_path;
                debug(`info|conf.${branch}.${image}=${zip_path}`);
            }
        };
    }

    // If ipcc has been specified, then include that as well
    let faux_ipcc_path = config?.ipcc?.faux_ipcc;
    let x = 1;
    let a = if x == 2 {
      3
    } else {
      4
    };
    print(x);
    conf.ipcc = if faux_ipcc_path != () {
        #{
          "use_ipcc": true,
          "faux_ipcc": util::env_expand(config.ipcc.faux_ipcc, config),
          "port": util::env_expand(config.ipcc?.port, config),
        }
    } else {
        #{
          "use_ipcc": false,
        }
    };

    if conf.verbose {
        print("");
        print(`Parsed conf=${conf}`);
    }

    conf
}

// Check and organize the images mentioned in the configuration
fn get_image_info(conf) {
    let images = #{};

    // Get the current CFPA and CMPA in order to verify the RoT test images.
    images["cmpa"] = util::get_cmpa();
    images["cfpa"] = util::get_cfpa();
    images["keyset"] = util::get_rot_keyset(images["cfpa"]);

    let gitc = #{};
    let error = false;
    for branch in ["base", "ut"] {
        images[branch] = #{};
        for image in ["sp", "rot_a", "rot_b", "stage0"] {
            let zip_path = conf[branch][image];
            images[branch][image] = #{"path": zip_path};
            let current_ar = new_archive(zip_path);
            if type_of(current_ar) != "Archive" {
                print(`Invalid archive path ${zip_path}`);
                error = true;
                continue;
            }
            // images[branch][image]["ar"] = current_ar;
            images[branch][image]["caboose"] = #{};
            let caboose = current_ar?["caboose"];
            for key in ["BORD", "GITC", "NAME", "SIGN", "VERS"] {
                images[branch][image]["caboose"][key] = caboose[key];
            }
            if image == "sp" {
                // TODO: Do some sanity checks to make sure BORD and NAME
                // are appropriate for the attached SP.
                images[branch][image]["verified"] = true;
            } else {
                // All others are RoT images and need signature verification.
                // stage0, rot_a, and rot_b images are verified against the
                // current RoT device's configured keys in its CMPA.
                let verified = current_ar.verify_rot_image(images.cmpa, images.cfpa);
                images[branch][image]["verified"] = verified;
                if !verified {
                    if images?["failed_to_verify"] == () {
                        images["failed_to_verify"] = [];
                    }
                    // The caller may want to test with bad images or not.
                    images["failed_to_verify"] += images[branch][image]["path"];
                }
            }
            // Reverse map GITC to the set of images built at that commit.
            let image_gitc = images[branch][image]["caboose"]?["GITC"];
            if image_gitc != () {
                if gitc?[image_gitc] == () {
                    gitc[image_gitc] = [];
                }

                // TODO: There should be a warning if the base and ut image
                // have the same GITC. This is true for some stage0 images
                // that differ only in packaging but not in the image
                // themselves. Otherwise it represents a release engineering
                // failure or a case where the test is not configured properly.

                gitc[image_gitc] += [ `${branch}_${image}` ];
            }
        }
    }
    debug(`gitc=${gitc}`);
    images["by_gitc"] = gitc;
    // Display the accumulated information to document this run.
    if conf.verbose {
        print("");
        print(`## images=${images}`);
    }
    if error {
        return 1;
    }
    images
}

/// Update SP with specified image
fn update_sp(sp_zip) {
    print("");
    print(`### update_sp: ${sp_zip}`);

    // TODO: Move any faux_mgs() calls to util.rhai
    let r = faux_mgs(["update", "sp", "0", sp_zip]);
    debug(`update result = ${r}`);
    if r?.ack == "updated" {
        debug("info|flash_sp updated");
    } else {
        debug("error|#### FAILED flash_sp update");
        print("FAIL\n");
        return false;
    }

    let r = util::check_update_in_progress("sp");
    if r?.Ok != () {
        debug(`error|Update sp did not complete: r=${r}`);
        debug("error|FAIL");
        return false;
    }

    /*
    let r = faux_mgs(["component-active-slot", "--persist", "-s", "0", "sp"]);
    debug(`persist result = ${r}`);
    if r?["ack"] == () || r.ack != "set" || r.slot != 0 {
        debug("error|Failed to persist");
        print("FAIL\n");
        return false;
    }
    */

    // Reset the SP to boot into the new image.
    let r = faux_mgs(["reset"]);
    debug(`faux-mgs reset => ${r}`);
    if r?.ack != "reset" {
        debug(`warn|unexpected sp reset response: ${r}`);
        print("FAIL\n");
        return false;
    }
    sleep(10);

    let r = util::check_update_in_progress("sp");
    if r?.Ok != () {
        print(`ERROR: Update sp did not complete: r=${r}`);
        print("");
        return false;
    }
    print(`### SUCCESS update_sp: ${sp_zip}`);
    print("");
    return true;
}

fn update_rot_hubris(path_a, path_b, use_transient, target_label) {
    print("");
    print(`### update_rot_hubris (target: ${target_label}): ${path_a} ${path_b}`);

    let r_get_active = get_rot_active(); // Local helper function
    if r_get_active?.error != () {
        print(`get_rot_active failed: ${r_get_active.error}`);
        return false;
    }
    let rot_active_initial_slot = r_get_active.ok; // Slot before this update operation

    let rot_update_slot = if rot_active_initial_slot == 0 { 1 } else { 0 };
    let rot_update_image = if rot_update_slot == 0 { path_a } else { path_b };

    debug(`info|Current RoT active slot (before this update): ${rot_active_initial_slot}. Target update slot: ${rot_update_slot} with image: ${rot_update_image}`);

    let r_update = faux_mgs(["update", "rot", `${rot_update_slot}`, rot_update_image]);
    debug(`info|faux_mgs update rot (target '${target_label}') result: ${r_update}`);
    if r_update?.ack != "updated" {
        print(`ERROR: RoT update command failed for target '${target_label}': ${r_update}`);
        return false;
    }

    let duration_param = if use_transient { "-t" } else { "-p" };
    let r_set_slot = faux_mgs(["component-active-slot", duration_param, "-s", `${rot_update_slot}`, "rot"]);
    debug(`info|faux_mgs component-active-slot ${duration_param} slot ${rot_update_slot} (target '${target_label}') result: ${r_set_slot}`);
    if r_set_slot?.ack != "set" || r_set_slot?.slot != rot_update_slot {
        debug(`error|Failed to set initial slot preference for RoT (target '${target_label}', duration ${duration_param}): ${r_set_slot}`);
        return false;
    }

    debug(`info|Resetting RoT for target '${target_label}' to boot slot ${rot_update_slot}.`);
    let r_reset = faux_mgs(["reset-component", "rot"]);
    if r_reset?.ack != "reset" {
        debug(`error|RoT reset command failed for target '${target_label}': ${r_reset}`);
        return false;
    }
    sleep(5); // Wait for RoT to reset and boot

    let rbi = util::rot_boot_info();
    if rbi?.error != () {
        debug(`error|Failed to get RoT boot info after first reset for target '${target_label}': ${rbi.error}`);
        return false;
    }

    debug(`info|RoT boot info after first reset (target '${target_label}' now active):`);
    debug(`    Initial active slot before this update op: ${rot_active_initial_slot}`);
    debug(`    Target update slot for this op: ${rot_update_slot}`);
    let active_after_first_reset = rbi["active"];
    debug(`    Newly active slot (active_after_first_reset): ${active_after_first_reset}`);
    let t_pref_from_newly_active = rbi["transient_boot_preference"];
    debug(`    Transient Boot Preference (from newly active): ${t_pref_from_newly_active}`);
    let p_pref_from_newly_active = rbi["persistent_boot_preference"];
    debug(`    Persistent Boot Preference (from newly active): ${p_pref_from_newly_active}`);
    let pp_pref_from_newly_active = rbi["pending_persistent_boot_preference"];
    debug(`    Pending Persistent Boot Preference (from newly active): ${pp_pref_from_newly_active}`);
    debug(`    use_transient flag for this op: ${use_transient}`);

    if use_transient {
        // --- Validations for transient boot (first phase: boot to transiently preferred slot) ---
        let transient_phase1_ok = true;
        let failure_details = "";

        if active_after_first_reset != rot_update_slot {
            transient_phase1_ok = false;
            failure_details += ` Active slot (${active_after_first_reset}) is not the target updated slot (${rot_update_slot}).`;
        }
        if t_pref_from_newly_active != () {
            transient_phase1_ok = false;
            failure_details += ` transient_boot_preference (${t_pref_from_newly_active}) is not null after reset.`;
        }
        if pp_pref_from_newly_active != () {
            transient_phase1_ok = false;
            failure_details += ` pending_persistent_boot_preference (${pp_pref_from_newly_active}) is not null.`;
        }

        if p_pref_from_newly_active != rot_active_initial_slot {
            if target_label == "baseline" {
                debug(`info|Target '${target_label}': p_pref (${p_pref_from_newly_active}) from booted image differs from original active slot (${rot_active_initial_slot}). This is acceptable if baseline RoT doesn't preserve/report original p_pref across transient boot.`);
            } else {
                transient_phase1_ok = false;
                failure_details += ` persistent_boot_preference (${p_pref_from_newly_active}) from booted image does not match original active slot (${rot_active_initial_slot}).`;
            }
        }

        if !transient_phase1_ok {
            debug(`error|Transient boot initial validation failed for target '${target_label}'. Reason(s):${failure_details} Full rbi=${rbi}`);
            return false;
        }
        debug(`info|Transient boot initial validation passed for target '${target_label}'. Proceeding to ensure persistence.`);

        // --- Ensure persistence for the newly active slot (rot_update_slot) ---
        let set_persistent_needed = true;

        if target_label == "baseline" {
            if p_pref_from_newly_active == active_after_first_reset {
                debug(`info|Target '${target_label}': p_pref (${p_pref_from_newly_active}) already matches current active slot (${active_after_first_reset}). No explicit set_persistent command needed for alignment.`);
                set_persistent_needed = false;
            } else {
                debug(`info|Target '${target_label}': p_pref (${p_pref_from_newly_active}) differs from current active slot (${active_after_first_reset}). Will attempt to align by setting persistent preference.`);
                // set_persistent_needed remains true
            }
        }
        // For non-baseline targets using transient flow, we always try to set persistent.
        // For baseline targets, we set it if p_pref is not already aligned with active.

        if set_persistent_needed {
            let reason_msg = if target_label == "baseline" { "Aligning p_pref for baseline." } else { "Standard transient-to-persistent." };
            debug(`info|Setting persistent preference for slot ${rot_update_slot} (target '${target_label}'). Reason: ${reason_msg}`);
            let r_set_persistent_cmd = faux_mgs(["component-active-slot", "-p", "-s", `${rot_update_slot}`, "rot"]);
            debug(`info|Result of set_persistent command for slot ${rot_update_slot} (target '${target_label}'): ${r_set_persistent_cmd}`);

            if r_set_persistent_cmd?.ack != "set" || r_set_persistent_cmd?.slot != rot_update_slot {
                debug(`error|Failed to execute set_persistent command for '${target_label}' on slot ${rot_update_slot}. Result: ${r_set_persistent_cmd}`);
                return false;
            }
            debug(`info|Successfully executed set_persistent command for slot ${rot_update_slot} (target '${target_label}').`);
        }

        // --- Final reset and validation for persistence ---
        debug(`info|Final reset for RoT (target '${target_label}') to apply/confirm persistent preference for slot ${rot_update_slot}.`);
        let r_reset_final = faux_mgs(["reset-component", "rot"]);
        if r_reset_final?.ack != "reset" {
            debug(`error|Final RoT reset (to apply/confirm persistence) failed for '${target_label}': ${r_reset_final}`);
            return false;
        }
        sleep(5);

        let final_rbi = util::rot_boot_info();
        if final_rbi?.error != () {
             debug(`error|Failed to get RoT boot info after final reset for '${target_label}': ${final_rbi.error}`);
             return false;
        }
        let final_active_slot = final_rbi.active;
        let final_p_pref = final_rbi.persistent_boot_preference;
        debug(`info|RoT boot info after final reset (target '${target_label}'): active=${final_active_slot}, p_pref=${final_p_pref}`);

        if final_active_slot != rot_update_slot {
            debug(`error|Target '${target_label}' did NOT boot into persistently set slot. Expected ${rot_update_slot}, but active is ${final_active_slot}. Full final_rbi=${final_rbi}`);
            return false;
        }
        // Check if persistent_boot_preference itself now reflects the new slot.
        // This might vary based on RoT firmware behavior (e.g., if baseline doesn't update p_pref predictably).
        if final_p_pref != rot_update_slot {
             debug(`warn|Target '${target_label}': final p_pref in RBI is ${final_p_pref}, not the expected ${rot_update_slot}. This might be acceptable if RoT '${target_label}' doesn't update/report p_pref reliably even after 'set -p' command.`);
             // For now, we don't fail the operation solely on this `final_p_pref` check if `final_active_slot` is correct.
             // This could be made stricter if needed, or specific to `target_label`.
        }
        debug(`info|Successfully booted '${target_label}' into persistently set slot ${final_active_slot}.`);

    } else { // This is the !use_transient path (persistent update directly)
        if active_after_first_reset != rot_update_slot {
            debug(`error|Unexpected active slot=${active_after_first_reset} (expected ${rot_update_slot}) after non-transient update of '${target_label}'. rbi=${rbi}`);
            return false;
        }
    }

    print(`### SUCCESS update_rot_hubris (target: ${target_label}): successfully updated and booted slot ${rot_update_slot} with ${rot_update_image}`);
    print("");
    return true; // Indicate overall success of this function
}

fn get_caboose(component, slot) {
    let caboose = #{};
    for key in ["BORD", "GITC", "VERS", "NAME", "SIGN"] {
        let value = util::caboose_value(component, slot, key);
        if value != () {
            caboose[key] = value;
        }
    }
    caboose
}

fn reset_sp_and_rot() {
    // The disable watchdog should not be required for the SP.
    // The STLINK needs to be powered down.
    // e.g. not:
    //   faux_mgs(["reset-component", "sp", "--disable-watchdog"]);
    for params in [["rot", 3], ["sp", 5]] {
        print(`### Reset ${params[0]}`);
        let r = faux_mgs(["reset-component", params[0]]);
        if r?.error != () {
            return #{"error": `${r}`};
        }
        sleep(params[1]);
    }
    #{"ok": ()}
}

fn get_rot_active() {
    // fetch RoT boot info
    let rbi = util::rot_boot_info();
    if rbi == () {
        return #{"error": "Cannot determine active RoT flash bank"};
    }
    #{"ok": rbi?["active"]}
}

fn rot_supports_transient_boot_preference() {
  // Find the current next boot preference
  debug(`debug|get_active_and_next_rot_boot_preference`);
  let r_boot = get_active_and_next_rot_boot_preference();
  if r_boot?.error == () {
    let active = r_boot.ok.active;
    let next = r_boot.ok.next;
    // Does the RoT image support transient update?
    // To find out, set the transient preference to the same as the next boot
    // preference.
    debug(`debug|test transient setting to ${active}`);
    let r = faux_mgs(["component-active-slot", "--transient", "-s", `${active}`, "rot"]);
    if r?.error != () {
        debug(`warn|failed setting transient boot preference to ${active}`);
        debug(`error|${r.error}`);
        false
    } else {
        debug(`info|transient boot preference is supported`);
        true
    }
  } else {
    debug(`error|image does not support transient preference`);
    false
  }
}

// Determine the next active bank preference.
// If the preferred bank is not properly signed,
// then the alternate bank will be used.
fn get_active_and_next_rot_boot_preference() {
    // fetch RoT boot info
    let rbi = util::rot_boot_info();
    if rbi == () {
        return #{"error": "Cannot determine active RoT flash bank"};
    }

    let active = rbi?["active"];
    let next = rbi?["active"];
    let pend_persist = rbi?["pending_persistent_boot_preference"];
    if pend_persist != () {
        next = pend_persist;
        debug(`warn|update from pend_persist=${next}`);
    }
    let transient_select = rbi?["transient_boot_preference"];
    if transient_select != () {
        next = transient_select;
        debug(`warn|update from transient_select=${next}`);
    }
    // Note that if the selected bank is not properly signed then the other bank
    // will be executed if it is properly signed (else brick).
    #{"ok": #{"active": active, "next": next}}
}

// Check if SP and RoT images match desired branches.
// if no issues getting info, returns
//   ${"ok": #{"sp": bool, "rot": bool}}
// on error, returns one or both of "sp" and "rot" error messages:
//   ${"error": #{"sp": message, "rot": message}}
fn image_check(branch, images) {
    let ok = #{};
    let error = #{};
    // debug(`image_check: images.by_gitc=${images.by_gitc}`);

    let need_flash = sp_needs_flashing(`${branch}_sp`, images.by_gitc);
    if need_flash?.error != () {
        print(`Error: ${need_flash}`);
        error["sp"] = `${need_flash}`;
    } else {
        ok["sp"] = need_flash.ok;
    }

    let need_flash = rot_needs_flashing(`${branch}`, images.by_gitc);
    if need_flash?.error != () {
        debug(`error|${need_flash}`);
        error["rot"] = `${flash_rot}`;
    } else {
        ok["rot"] = need_flash.ok;
    }
    if ok.len() == 2 {
        #{"ok": ok}
    } else {
        #{"error": error}
    }
}

fn sp_needs_flashing(name, gitc) {
    let sp_gitc = util::caboose_value("sp", "active", "GITC");
    print(`### SP is running GITC=${sp_gitc}`);
    debug(`info|gitc=${gitc}`);
    debug(`info|gitc?[${sp_gitc}]=${gitc?[sp_gitc]}`);
    let known_gitc = gitc?[sp_gitc];
    debug(`known_gitc=${known_gitc}`);
    if known_gitc == () {
        print("    the SP is not running a BASE or UNDER-TEST image.");
        #{"ok": true}
    } else  if name in known_gitc {
        print(`    ${name} IS in ${known_gitc}`);
        #{"ok": false}
    } else {
        print(`    ${name} IS NOT in ${known_gitc}`);
        #{"ok": true}
    }
}

fn rot_needs_flashing(branch, gitc) {
    let rot_active = get_rot_active();
    if rot_active?.error != () {
        return #{"error": `get_rot_active: ${rot_active}`};
    }
    let rot_active = rot_active.ok;

    let branch_rot_name = `${branch}_rot_a`;
    if rot_active == 1 {
        branch_rot_name = `${branch}_rot_b`;
    }

    let rot_gitc = util::caboose_value("rot", `${rot_active}`, "GITC");
    print(`RoT is running GITC=${rot_gitc}`);
    debug(`gitc[${rot_gitc}]=${gitc?[rot_gitc]}`);
    let known_gitc = gitc?[rot_gitc];
    if known_gitc == () {
        debug("info|the RoT is not running a BASE or UNDER-TEST image.");
        #{"ok": true}
    } else if branch_rot_name in known_gitc {
        debug(`info|${branch_rot_name} IS in ${known_gitc}`);
        #{"ok": false}
    } else {
        debug(`info|${branch_rot_name} IS NOT in ${known_gitc}`);
        #{"ok": true}
    }
}
