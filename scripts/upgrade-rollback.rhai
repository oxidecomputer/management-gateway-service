// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright 2025 Oxide Computer Company

import `${script_dir}/util` as util;
import `${script_dir}/update-helper` as helper;

/// Print command line usage
fn usage(prog, error) {
    if error != () {
        print(`Error: ${error}`);
    }
    print(
        `Usage: faux-mgs ... rhai ${prog} [-v] [-h] [-c config.json] ` +
        `[path0] [path1]`
    );
    print("  -b BASELINE_PATH # Path to baseline hubris repo");
    print("  -c CONFIG.JSON # Path to configuration");
    print("  -h # Help. Print this message");
    print("  --hubris-2093 # Enable workaround for Hubris issue #2093 (pending pref bug)");
    print("  -N # Run negative test for RoT update failure and recovery");
    print("  -t # Use transient boot preference to vet RoT Hubris");
    print("  -u UNDER_TEST_PATH # Path to under-test hubris repo");
    print("  -v # be verbose");
}

/// Parse command line options including the required / JSON configuration file.
/// Return an exit code or the configuration map
fn process_cli(argv) {
    let prog = argv[0];
    let options = "b:c:hNtu:v";
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
    conf["verbose"] = parsed.result?["v"] == true;
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
        debug(`Successfully read config file: ${conf_path}`);
    } catch (err) {
        debug(`error|Cannot open or read config file ${conf_path}: ${err}`);
        read_ok = false;
    }
    if !read_ok { return 1; }

    let config_from_file = json_to_map(conf_json); // Global custom Rhai function
    if config_from_file?.error != () {
         debug(
            `error|Failed to parse JSON from config file: ${conf_path}` +
            `: ${config_from_file.error}`
         );
         return 1;
    }
    if conf.verbose {
        print("");
        print(`Parsed JSON config from ${conf_path}: ${config_from_file}`);
    }
    // The base configurartion is in `config_from_file`, command line options
    // and positional parameters override the base.
    let merged_config = config_from_file;

    let base_repo_override = parsed?.result?["b"];
    if base_repo_override != () {
        print("Overriding config 'base_repo' from command line:");
        print(`  was: ${merged_config?.base_repo}`);
        merged_config.base_repo = base_repo_override;
        print(`  now: ${merged_config.base_repo}`);
    }

    let ut_repo_override = parsed?.result?["u"];
    if ut_repo_override != () {
        print("Overriding config 'ut_repo' from command line:");
        print(`  was: ${merged_config?.ut_repo}`);
        merged_config.ut_repo = ut_repo_override;
        print(`  now: ${merged_config.ut_repo}`);
    }

    // Add CLI flags to the config map passed around
    conf += merged_config; // Add contents of merged_config to conf
    // Now 'conf' contains original JSON + CLI overrides + verbose/transient flags

    // --- Expand paths using variables from conf and environment ---
    conf["sp_bord"] = util::env_expand(conf?.bord?.sp, conf);
    conf["rot_bord"] = util::env_expand(conf?.bord?.rot, conf);

    for branch in ["base", "ut"] {
        conf[branch] = #{};
        for image_type in ["sp", "rot_a", "rot_b", "stage0"] {
            let image_path_template = conf?.images?[branch]?[image_type];
            if image_path_template == () {
                 debug(`warn|process_cli: No config path for ${branch}.${image_type}`);
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
                debug(`info|process_cli: Expanded path ${branch}.${image_type} = ${zip_path}`);
            }
        }
    }

    let faux_ipcc_path_template = conf?.ipcc?.faux_ipcc;
    if faux_ipcc_path_template != () {
        conf.ipcc_resolved = #{ // Store resolved IPCC paths in a sub-map
            "use_ipcc": true,
            "faux_ipcc": util::env_expand(faux_ipcc_path_template, conf),
            "port": util::env_expand(conf?.ipcc?.port, conf),
        };
    } else {
        conf.ipcc_resolved = #{ "use_ipcc": false };
    }

    if conf.verbose {
        print("\nFully resolved configuration map (process_cli):");
        print(conf);
    }
    return conf;
}

fn main() {
    let start_ts = timestamp();
    let start_time = datetime_local();
    debug(`info|Starting upgrade-rollback script at ${start_time}`);

    let conf = process_cli(argv);
    if type_of(conf) == "i64" {
        // This is an error code.
        return conf;
    }

    let images = helper::get_image_info(conf);
    if type_of(images) == "i64" {
        // Error code from get_image_info
        debug("error|Failed to get image info.");
        return images;
    }

    // Ensure device is in a clean state with baseline firmware
    if (!helper::ensure_initial_baseline_state(conf, images)) {
        debug("error|Failed to ensure initial baseline state. Exiting.");
        return 1;
    }

    print("");
    print(`Elapsed time after setup: ${start_ts.elapsed}`);
    print(`Current time: ${datetime_local()}`);
    print("");

    // Main upgrade/rollback loop
    for v_params in [
        #{
            "up_down": "upgrade",
            "label": "under-test",
            "branch": "ut",
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
        debug(
            `info|Starting ${v_params.up_down} to ${v_params.label} ` +
            `(${v_params.branch} branch versions)`
        );

        // This variable is needed by both the negative test and the main update logic.
        let supports_transient = helper::rot_supports_transient_boot_preference();

        // This logic runs for each iteration (upgrade and rollback) if -N is present.
        if (conf.run_negative_tests) {
            debug(`info|Checking transient support on current RoT for '${v_params.label}' negative test.`);
            if (supports_transient) {
                // Call the test with the correct string argument: v_params.branch
                if (!helper::test_and_recover_from_preferred_slot_update_failure(conf, v_params.branch)) {
                    debug(`error|Negative test for '${v_params.label}' FAILED.`);
                    return 1;
                }
                debug(`info|Negative test for '${v_params.label}' PASSED. Resetting to known good state.`);
                // Re-run ensure_initial_baseline_state to get back to a clean slate before the next operation.
                if (!helper::ensure_initial_baseline_state(conf, images)) { return 1; }
            } else {
                if (v_params.branch == "ut") {
                    debug(`error|FATAL: Under-test image MUST support transient preference, but it does not.`);
                    return 1;
                } else {
                    debug(`warn|Skipping negative test for '${v_params.label}': RoT does not support transient preference.`);
                }
            }
        }

        let use_transient_for_this_op = false;
        if conf.use_transient_boot_preference {
            if (supports_transient) {
                debug(
                    `info|Current RoT supports transient commands. ` +
                    `Attempting transient update to ${v_params.label}.`
                );
                use_transient_for_this_op = true;
            } else {
                debug(
                    `warn|Current RoT does NOT support transient commands. ` +
                    `Using persistent update to ${v_params.label}.`
                );
            }
        } else {
            debug(
                `info|Transient preference not enabled (-t option). ` +
                `Using persistent update to ${v_params.label}.`
            );
        }

        debug(
            `info|Updating RoT Hubris to ${v_params.label} image ` +
            `(use_transient=${use_transient_for_this_op}).`
        );
        // Call helper
        if !helper::update_rot_hubris(
            v_params.rot_a_path,
            v_params.rot_b_path,
            use_transient_for_this_op,
            v_params.label,
            conf
        ) {
            debug(`error|Failed to ${v_params.up_down} RoT to ${v_params.label}.`);
            return 1;
        }

        debug(`info|Updating SP Hubris to ${v_params.label} image.`);
        // Call helper
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

    print("");
    print(`Elapsed time total: ${start_ts.elapsed}`);
    print(`Current time: ${datetime_local()}`);
    print("Done");
    return 0;
}
