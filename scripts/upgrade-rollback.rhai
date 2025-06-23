// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright 2025 Oxide Computer Company

import `${script_dir}/util` as util;
import `${script_dir}/update-helper` as helper;

/// Print command line usage
fn usage(prog, error) {
    if error != () {
        debug(`error|${error}`);
    }
    print(
        `Usage: faux-mgs ... rhai ${prog} [-v] [-h] [-c config.json] ` +
        `[path0] [path1]`
    );
    print("  -b BASELINE_PATH # Path to baseline hubris repo");
    print("  -c CONFIG.JSON # Path to configuration");
    print("  -h # Help. Print this message");
    print("  --hubris-2093      # Enable workaround for issue #2093 (pending pref bug)");
    print("  -f <T>, --inject-fault <T> # Inject fault(s). T is a comma-separated list,");
    print("                           # e.g., 'pending,transient'");
    print("  -N # Run negative test for RoT update failure and recovery");
    print("  -t # Use transient boot preference to vet RoT Hubris");
    print("  -u UNDER_TEST_PATH # Path to under-test hubris repo");
}

/// Parse command line options including the required / JSON configuration file.
fn process_cli(argv) {
    let prog = argv[0];
    let options = "b:c:f:hNtu:";
    let parsed = util::getopts(argv, options);
    if parsed?["error"] != () {
        usage(prog, parsed.error);
        return 1;
    }

    if parsed.result?["h"] == true {
        usage(prog, ());
        return 0;
    }

    let conf = #{};
    conf["use_transient_boot_preference"] = parsed.result?["t"] == true;
    conf["run_negative_tests"] = parsed.result?["N"] == true;
    conf["hubris_2093_workaround"] = parsed.result?["hubris-2093"] == true;

    let conf_path_str = parsed.result?["c"];
    if conf_path_str == () {
        usage(prog, "Missing required option: -c config.json");
        return 1;
    }
    let conf_path = path(conf_path_str);
    if !conf_path.is_file {
        usage(prog, `Config file not found or not a file: ${conf_path}`);
        return 1;
    }
    conf["conf_path"] = conf_path;

    let conf_json = "";
    let read_ok = true;
    try {
        let conf_file = open_file(conf_path);
        conf_json = conf_file.read_string();
    } catch (err) {
        debug(`error|Cannot open or read config file ${conf_path}: ${err}`);
        read_ok = false;
    }
    if !read_ok { return 1; }

    let config_from_file = json_to_map(conf_json);
    if config_from_file?.error != () {
         debug(
             `error|Failed to parse JSON from config file: ${conf_path}` +
             `: ${config_from_file.error}`
         );
         return 1;
    }

    conf += config_from_file;

    // --- FAULT INJECTION CONFIG ---
    let faults_to_inject = conf?.fault_injection?.tests;
    if faults_to_inject == () || type_of(faults_to_inject) != "array" {
        faults_to_inject = [];
    }
    let cli_faults = parsed.result?["inject-fault"] ?? parsed.result?["f"];
    if cli_faults != () {
        faults_to_inject = []; // CLI overrides config file.
        for fault in cli_faults.split(',') {
            let f = fault;
            f.trim();
            if f != "" && f !in faults_to_inject {
                faults_to_inject.push(f);
            }
        }
    }
    conf["faults_to_inject"] = faults_to_inject;

    let base_repo_override = parsed?.result?["b"];
    if base_repo_override != () {
        debug(`info|Overriding config 'base_repo' from command line:`);
        debug(`info|  was: ${conf?.base_repo}`);
        conf.base_repo = base_repo_override;
        debug(`info|  now: ${conf.base_repo}`);
    }

    let ut_repo_override = parsed?.result?["u"];
    if ut_repo_override != () {
        debug(`info|Overriding config 'ut_repo' from command line:`);
        debug(`info|  was: ${conf?.ut_repo}`);
        conf.ut_repo = ut_repo_override;
        debug(`info|  now: ${conf.ut_repo}`);
    }

    // --- Expand paths ---
    conf["sp_bord"] = util::env_expand(conf?.bord?.sp, conf);
    conf["rot_bord"] = util::env_expand(conf?.bord?.rot, conf);

    for branch in ["base", "ut"] {
        conf[branch] = #{};
        for image_type in ["sp", "rot_a", "rot_b", "stage0"] {
            let image_path_template = conf?.images?[branch]?[image_type];
            if image_path_template == () {
                conf[branch][image_type] = ();
                continue;
            }
            let zip_path = util::env_expand(image_path_template, conf);
            if zip_path == () {
                debug(
                    `error|process_cli: Failed expanding path for ${branch}.${image_type}: ` +
                    `'${image_path_template}'`
                );
                conf[branch][image_type] = ();
            } else {
                conf[branch][image_type] = zip_path;
            }
        }
    }

    debug("trace|Fully resolved configuration map (process_cli): " + conf);
    return conf;
}

/// Contains the main upgrade/rollback test procedure.
fn run_standard_test_flow(conf, images) {
    let start_ts = timestamp();

    if (!helper::ensure_initial_baseline_state(conf, images)) {
        debug("error|Failed to ensure initial baseline state. Exiting test run.");
        return 1;
    }

    debug(`info|Elapsed time after setup: ${start_ts.elapsed}`);
    debug(`info|Current time: ${datetime_local()}`);

    // Main upgrade/rollback loop
    for v_params in [
        #{
            "up_down": "upgrade", "label": "under-test", "branch": "ut",
            "sp_path": conf.ut.sp, "rot_a_path": conf.ut.rot_a, "rot_b_path": conf.ut.rot_b,
        },
        #{
            "up_down": "rollback", "label": "baseline", "branch": "base",
            "sp_path": conf.base.sp, "rot_a_path": conf.base.rot_a, "rot_b_path": conf.base.rot_b,
        }
    ] {
        debug(
            `info|--- Starting ${v_params.up_down} to ${v_params.label} ` +
            `(${v_params.branch} branch versions) ---`
        );

        let supports_transient = helper::rot_supports_transient_boot_preference();

        if (conf.run_negative_tests) {
            debug(`info|Checking transient support on current RoT for '${v_params.label}' negative test.`);
            if (supports_transient) {
                if (!helper::test_and_recover_from_preferred_slot_update_failure(conf, v_params.branch)) {
                    debug(`error|Negative test for '${v_params.label}' FAILED.`);
                    return 1;
                }
                debug(`info|Negative test for '${v_params.label}' PASSED. Resetting to known good state.`);
                if (!helper::ensure_initial_baseline_state(conf, images)) { return 1; }
            } else {
                if (v_params.up_down == "rollback") {
                    debug(`error|FATAL: The under-test image was active but does not support transient preference.`);
                    return 1;
                } else {
                    debug(`warn|Skipping negative test for '${v_params.label}': currently running baseline firmware does not support transient preference.`);
                }
            }
        }

        let use_transient_for_this_op = false;
        if conf.use_transient_boot_preference {
            if (supports_transient) {
                debug(`info|Attempting transient update to ${v_params.label}.`);
                use_transient_for_this_op = true;
            } else {
                debug(`warn|Current RoT does NOT support transient commands. Using persistent update.`);
            }
        } else {
            debug(`info|Transient preference not enabled via -t. Using persistent update.`);
        }

        if !helper::update_rot_hubris(
            v_params.rot_a_path, v_params.rot_b_path,
            use_transient_for_this_op, v_params.label, conf
        ) {
            debug(`error|Failed to ${v_params.up_down} RoT to ${v_params.label}.`);
            return 1;
        }

        if !helper::update_sp(v_params.sp_path) {
            debug(`error|Failed to ${v_params.up_down} SP to ${v_params.label}.`);
            return 1;
        }

        let result_loop_check = helper::image_check(v_params.branch, images);
        if result_loop_check?.error != () ||
           result_loop_check.ok?.sp ||
           result_loop_check.ok?.rot
        {
            debug(
                `error|image_check error or failed ${v_params.label} updates: ` +
                `${result_loop_check}`
            );
            return 1;
        }
        debug(
            `info|SUCCESS: ${v_params.up_down} to SP and RoT ${v_params.label} ` +
            `images completed successfully.`
        );
    }

    debug(`info|Elapsed time total: ${start_ts.elapsed}`);
    debug(`info|Current time: ${datetime_local()}`);
    debug("info|Done.");
    return 0;
}

/// Main entry point and test runner.
fn main() {
    debug(`info|Starting upgrade-rollback script at ${datetime_local()}`);

    let conf = process_cli(argv);
    if type_of(conf) == "i64" { return conf; }

    let images = helper::get_image_info(conf);
    if type_of(images) == "i64" { return images; }

    if (conf.faults_to_inject.len() > 0) {
        // --- FAULT INJECTION MODE ---
        debug("info|--- Executing in Fault Injection & Recovery Mode ---");
        debug(`info|Faults to inject: ${conf.faults_to_inject}`);
        let failed_tests = [];
        let passed_tests = [];

        if (helper::is_fault_enabled(conf, "pending")) {
            debug("info|--- FAULT INJECTION: PENDING PREFERENCE ---");
            if (!helper::ensure_initial_baseline_state(conf, images)) { return 1; }
            if (!helper::inject_conflicting_pending_preference()) {
                debug("error|Failed to inject pending preference fault.");
                failed_tests.push("pending");
            } else {
                debug("info|Fault injected. Running standard test flow to verify recovery.");
                if (run_standard_test_flow(conf, images) == 0) {
                    debug("info|SUCCESS: System recovered from 'pending' fault and passed tests.");
                    passed_tests.push("pending");
                } else {
                    debug("error|FAILURE: System did NOT recover from 'pending' fault.");
                    failed_tests.push("pending");
                }
            }
        }

        if (helper::is_fault_enabled(conf, "transient")) {
            debug("info|--- FAULT INJECTION: TRANSIENT PREFERENCE ---");
            if (!helper::ensure_initial_baseline_state(conf, images)) { return 1; }
            if (!helper::inject_conflicting_transient_preference()) {
                debug("error|Failed to inject transient preference fault.");
                failed_tests.push("transient");
            } else {
                debug("info|Fault injected. Running standard test flow to verify recovery.");
                if (run_standard_test_flow(conf, images) == 0) {
                    debug("info|SUCCESS: System recovered from 'transient' fault and passed tests.");
                    passed_tests.push("transient");
                } else {
                    debug("error|FAILURE: System did NOT recover from 'transient' fault.");
                    failed_tests.push("transient");
                }
            }
        }

        debug("info|--- FAULT INJECTION SUMMARY ---");
        if (passed_tests.len() > 0) {
            debug(`info|PASSED: ${passed_tests}`);
        }
        if (failed_tests.len() > 0) {
            debug(`error|FAILED: ${failed_tests}`);
            return 1;
        }
        return 0;

    } else {
        // --- STANDARD MODE ---
        debug("info|--- Executing in Standard Upgrade/Rollback Mode ---");
        return run_standard_test_flow(conf, images);
    }
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
    let set_pref_result = util::rot_boot_preference(preferred_slot, util::SET, true, test_label);
    if set_pref_result?.error != () {
        // Check if the error is due to a pending persistent preference
        if set_pref_result.error.contains("pending preference must be canceled first") {
            debug("info|Negative Test: Found pending persistent preference. Attempting to clear it.");
            let rbi = util::rot_boot_info();
            if rbi?.error != () { return false; }
            let inactive_slot = if rbi.active == 0 { 1 } else { 0 };
            let clear_pending_result = util::rot_boot_preference(inactive_slot, util::PREF_CLEAR, false, "clear_pending_for_test");
            if clear_pending_result?.error != () {
                debug("error|Negative Test: Failed to clear pending persistent preference.");
                return false;
            }
            debug("info|Negative Test: Pending persistent preference cleared. Retrying set transient preference.");
            // Retry setting the transient preference
            let retry_set_pref_result = util::rot_boot_preference(preferred_slot, util::SET, true, test_label);
            if retry_set_pref_result?.error != () {
                debug(`error|Negative Test: Could not set transient pref after clearing pending: '${test_label}'. Error: ${retry_set_pref_result.error}`);
                return false;
            }
        } else {
            debug(`error|Negative Test: Could not set transient pref for '${test_label}' (unexpected error: ${set_pref_result.error}).`);
            return false;
        }
    }
    if (util::update_rot_image_file(preferred_slot, image_path, test_label)) {
        debug(`error|Negative Test FAILED: Update to preferred slot '${preferred_slot}' SUCCEEDED unexpectedly.`);
        return false;
    }
    debug("info|Negative Test PASSED: Update to preferred slot failed as expected due to transient preference.");

    // 3. RECOVER: clear the RoT Hubris transient boot preference without a reset.
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
    let final_set_pref_result = util::rot_boot_preference(preferred_slot, util::PREF_SET, false, test_label);
    if final_set_pref_result?.error != () {
        debug(`error|Negative Test: Finalizing by setting persistent pref failed: ${final_set_pref_result.error}`);
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

    let rbi = util::rot_boot_info();
    if rbi?.error != () {
        debug(`error|clear_transient_preference: could not get rbi: ${rbi}`);
        return false;
    }
    let target_slot = rbi.transient_boot_preference;

    if target_slot == () {
        debug("info|clear_transient_preference: No transient preference to clear.");
        return true;
    }

    debug(`info|clearing transient pref for slot: ${target_slot}`);
    let clear_pref_result = util::rot_boot_preference(target_slot, util::PREF_CLEAR, true, "clearing_transient");
    if clear_pref_result?.error != () {
        debug(`error|clear_transient_preference: Call to rot_boot_preference PREF_CLEAR failed: ${clear_pref_result.error}`);
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
    debug(`crit|XXX active=${active} type=${type_of(active)}`);
    debug(`crit|XXX inactive=${inactive} type=${type_of(inactive)}`);

    // Older RoT Hubris does not report transient or pending persistent
    // preferences. As a work-around, we could always reset the RoT.

    let pending_transient = rbi.transient_boot_preference;
    debug(`crit|XXX pending_transient=${pending_transient} ${type_of(pending_transient)}`);

    let pending_persistent = rbi.pending_persistent_boot_preference;
    debug(`crit|XXX pending_persistent=${pending_persistent} ${type_of(pending_persistent)}`);


    // Case 1: Clear transient preference if set
    if pending_transient != () {
        debug(`warn|Found pending transient preference (${pending_transient}). Clearing it.`);
        if (!clear_transient_preference_without_reset()) {
            debug("error|sanitize_boot_preferences: Failed to clear conflicting transient preference.");
            return false;
        }
    } else {
      debug("info|No pending transient preference");
    }


    // Case 2: Conflicting pending persistent preference
    if pending_persistent != () {
        debug(`warn|Found conflicting pending persistent preference.`);

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
            // preference for the inactive slot.
            let clear_pref_result = util::rot_boot_preference(inactive, util::PREF_CLEAR, false, "clearing_pending");
            if clear_pref_result?.error != () {
                // Check if the error is due to WrongVersion, which means the feature is not supported
                if clear_pref_result.error.contains("WrongVersion") {
                    debug(`warn|sanitize_boot_preferences: Firmware does not support clearing pending persistent preference via -c: ${clear_pref_result.error}`);
                } else {
                    debug(`error|sanitize_boot_preferences: Failed to send command to clear pending preference: ${clear_pref_result.error}`);
                    return false;
                }
            }
        }

        // Final verification
        let final_rbi = util::rot_boot_info();
        if final_rbi?.error != () || final_rbi.pending_persistent_boot_preference != () {
             debug(`error|sanitize_boot_preferences: Failed to verify pending pref was cleared. RBI: ${final_rbi}`);
             return false;
        }
    } else {
      debug("info|No pending persistent preference");
    }

    debug("info|Boot preferences sanitized successfully.");
    return true;
}

/// Checks for the specific case of an an SWD debugger attached to the SP and
/// the SP having a pending update.
/// Returns:
///   bool: `true` if no debugger and pending update detected, `false` otherwise.
//
/// Fixing Hubris issue 2066 will give us more definitive information to use in
/// testing.
fn check_for_sp_debugger_and_sp_pending_update() {
    debug("info|Performing pre-flight check for attached SP debugger...");

    // We call faux_mgs directly here instead of util::reset_component
    // so we can inspect the specific error message.
    let result = faux_mgs(["reset-component", "sp"]);

    if result?.ack == "reset" {
        debug("info|SP reset successful. No debugger detected.");
        // A reset here is fine and helps ensure a clean state.
        sleep(5);
        return true;
    }

    if result?.error != () {
        // Use the 'message' key to get the detailed error string
        let error_string = `${result.message}`;
        if "the SP programming dongle is connected" in error_string {
            debug("error|FATAL: SP Debugger Detected.");
            debug("error|A JTAG/SWD debugger probe appears to be attached to the SP.");
            debug("error|Please disconnect or power-off the debugger and restart the test.");
            return false;
        } else {
            debug(`error|An unexpected error occurred while trying to reset the SP: ${result}`);
            return false;
        }
    }

    // Should not be reached if the command returns a well-formed map.
    debug(`warn|Unexpected result from SP reset command: ${result}`);
    return false;
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
    let set_pref_result = util::rot_boot_preference(inactive_slot, util::PREF_SET, false, "inject_pending_fault");
    return set_pref_result?.ok == true;
}

/// Injects a fault by setting a conflicting transient preference.
fn inject_conflicting_transient_preference() {
    debug("info|FAULT INJECTION: Setting a conflicting transient preference.");
    let rbi = util::rot_boot_info();
    if rbi?.error != () { return false; }
    let inactive_slot = if rbi.active == 0 { 1 } else { 0 };
    // Set transient preference for the INACTIVE slot.
    let set_pref_result = util::rot_boot_preference(inactive_slot, util::PREF_SET, true, "inject_transient_fault");
    return set_pref_result?.ok == true;
}

/// Checks if a specific fault injection test is enabled in the config.
///
/// Args:
///   conf (map): The configuration map.
///   fault_name (string): The name of the fault to check (e.g., "pending").
///
/// Returns:
///   bool: `true` if the fault is in the list of tests to run.
fn is_fault_enabled(conf, fault_name) {
    if conf?.faults_to_inject == () {
        return false;
    }
    return fault_name in conf.faults_to_inject;
}
