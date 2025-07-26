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
            use_transient_for_this_op, v_params.branch, conf, images
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


