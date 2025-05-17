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
    print("  -u UNDER_TEST_PATH # Path to a repo with faulty images to test");
    print("  -v # be verbose");
    print("  -h # Help. Print this message");
}

/// Parse command line options including the required / JSON configuration file.
/// Return an exit code or the configuration map
fn process_test_cli(argv) {
    let prog = argv[0];
    let options = "b:c:hu:v";

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
        print(`Parsed JSON config from ${conf_path}: ${config_from_file}`);
    }

    let base_repo_override = parsed?.result?["b"];
    if base_repo_override != () {
        conf.base_repo = base_repo_override;
    }

    let ut_repo_override = parsed?.result?["u"];
    if ut_repo_override != () {
        conf.ut_repo = ut_repo_override;
    }

    // The base configurartion is in `config_from_file`.
    // Some command line options override the config file.

    // CLI flags override the config file.
    let conf = config_from_file + conf;

    // Ensure power cycle settings are present or provide defaults
    if conf?.power_off_delay_secs == () {
      conf.power_off_delay_secs = 3;
    }

    if conf?.dut_boot_delay_secs == () {
      conf.dut_boot_delay_secs = 10;
    }

    // Explicitly enable the power cycle on failure for this test script's context
    conf.rot_hubris_power_cycle_on_failure = true;
    debug(`info|rot_hubris_power_cycle_on_failure=${conf.rot_hubris_power_cycle_on_failure}`);

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


    return conf;
}

fn main() {
    let start_ts = timestamp();
    let start_time = datetime_local();
    print(`info|Starting RoT Power Cycle Recovery Test at ${start_time}`);
    debug(`info|Starting RoT Power Cycle Recovery Test at ${start_time}`);
    let conf = ();
    let images = ();

    try {
        conf = process_test_cli(argv);
        if type_of(conf) == "int" {
            return conf;
        }

        images = helper::get_image_info(conf);
        if type_of(images) == "int" { return images; }

        // 1. Ensure DUT is on a known-good baseline state initially
        debug("info|Ensuring DUT is on baseline firmware before test...");
        if (!helper::ensure_initial_baseline_state(conf, images)) {
            debug("error|Failed to set initial baseline state. Cannot proceed with test.");
            return 1;
        }
        let initial_rbi = util::rot_boot_info();
        if initial_rbi?.error != () {
            debug(`error|Failed to get RBI of baseline: ${initial_rbi.error}`);
            return 1;
        }
        let pre_test_active_slot = initial_rbi.active;
        debug(`info|DUT is on baseline. Pre-test active RoT slot: ${pre_test_active_slot}`);

        // 2. Attempt to update to the "faulty" under-test RoT image.
        //    This update is EXPECTED to fail and trigger a power cycle.
        //    Assume conf.ut.rot_a/b point to your faulty images.
        debug(
            "info|Attempting to update to FAULTY under-test RoT image. " +
            "Expecting this update to fail and trigger power cycle recovery."
        );
        let update_to_faulty_image_succeeded = helper::update_rot_hubris(
            conf.ut.rot_a, // Path to FAULTY RoT A image
            conf.ut.rot_b, // Path to FAULTY RoT B image
            true,          // Attempt using transient for maximum effect
            "faulty-ut",   // Label for this attempt
            conf
        );

        if update_to_faulty_image_succeeded {
            debug("error|TEST FAILED: Update to faulty RoT image SUCCEEDED, but was expected to fail.");
            return 1;
        }

        debug("info|Update to faulty RoT image failed as expected, and power cycle was attempted.");

        // 3. Verify recovery: Check the state of the RoT after the power cycle.
        //    The power_cycle_dut function (called within update_rot_hubris) already logs
        //    the state after power cycling. Here, we add explicit checks.
        print("INFO: Verifying RoT state after power cycle recovery attempt...");
        let rbi_after_recovery = util::rot_boot_info();

        if rbi_after_recovery?.error != () {
            debug(`error|TEST FAILED: Could not get RoT state after power cycle recovery: ${rbi_after_recovery.error}`);
            return 1;
        }
        let rbi_recovered = rbi_after_recovery; // rot_boot_info returns RBI map directly on success

        debug(`info|RoT state after power cycle: active=${rbi_recovered.active}, p_pref=${rbi_recovered.persistent_boot_preference}`);

        // Define "successful recovery":
        // - Is it back on the original baseline slot (pre_test_active_slot)?
        // - Or, if the faulty image was on the other bank, did it revert to 'pre_test_active_slot'?
        // This depends heavily on the bootloader's behavior after an interrupted/failed update and power loss.
        // For now, let's check if it's on the pre_test_active_slot and that slot has the baseline GITC.
        if rbi_recovered.active == pre_test_active_slot {
            debug(`info|Recovery check: RoT correctly booted back to original slot ${pre_test_active_slot}.`);
            // Further check: is the GITC on this slot actually the baseline's?
            let gitc_after_recovery = util::caboose_value("rot", `${rbi_recovered.active}`, "GITC");
            let expected_baseline_gitc = if rbi_recovered.active == 0 {
                images.base?.rot_a?.caboose?.GITC;
            } else {
                images.base?.rot_b?.caboose?.GITC;
            };


            if gitc_after_recovery == expected_baseline_gitc && expected_baseline_gitc != () {
                debug(
                    `info|TEST PASSED: RoT recovered to baseline slot ${pre_test_active_slot} `+
                    `with correct GITC ${gitc_after_recovery}.`
                );
                // Test success!
                return 0;
            } else {
                debug(
                    `error|TEST FAILED: RoT recovered to slot ${pre_test_active_slot}, `+
                    `but GITC mismatch. Expected: ${expected_baseline_gitc}, Got: ${gitc_after_recovery}.`
                );
                return 1;
            }
        } else {
            debug(
                `error|TEST FAILED: RoT did not recover to original slot ${pre_test_active_slot}. ` +
                `Currently active: ${rbi_recovered.active}.`
            );
            return 1;
        }

    } catch (err) {
        debug(`error|FATAL ERROR in RoT Power Recovery Test: ${err}`);
        return 1;
    }
}
