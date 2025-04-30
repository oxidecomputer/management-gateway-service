import `${script_dir}/util` as util;

/// Print command line usage
fn usage(prog, error) {
    if error != () {
        print(`Error: ${error}`);
    }
    print(`Usage: faux-mgs ... rhai ${prog} [-v] [-h] [-c config.json] [path0] [path1]`);
    print("  -c CONFIG.JSON # Path to configuration");
    print("  -v # be verbose");
    print("  -h # Help. Print this message");
    print("path0 - optionally override configuration base_repo value");
    print("path1 - optionally override configuration ut_repo value");
    print("");
}

fn main() {
    // Display start time
    let start_ts = timestamp();
    let start_time = datetime_local();
    debug(`info|Starting at ${start_time}`);

    let conf = process_cli(argv);
    switch type_of(conf) {
        "i64" => return conf,
        "map" => (),
        _ => return 1,
    }
    // Collect GITC and signature verification info.
    let images = get_image_info(conf);

    print("\n## Determine initial FW state and update if needed");

    // Generally, there should no updates in progress
    // and we can proceed with installation of the
    // baseline images if needed.
    // .
    // If a previous test was aborted, some recovery may
    // be necessary.
    //
    // A corner case that may require a hard-reset is described in:
    // https://github.com/oxidecomputer/hubris/issues/1022

    let problems = 0;
    for attempt in 1..=2 {
        problems = 0;
        for component in ["rot", "sp"] {
            let r = check_update_in_progress(component);
            if r?.Err != () {
                print(`Error check_update_in_progress=${r}`);
                return 1;
            }
            debug(`check_update_in_progress(${component})=${r}`);
            if r != () {
                problems += 1;
                let id = r?.id;
                debug(`r=${r}`);
                debug(`id=${id}`);
                debug(`Failed: component ${component}: ${r}`);
                print(`The SP probably needs to be reset before continuing`);
                print(`Trying to abort the update with id=${id}`);
                let r = faux_mgs(["update-abort", component, `${id}`]);
                debug(`info|update-abort = ${r}`);
            }
        }
        if problems == 0 {
            break;
        }
        let r = reset_sp_and_rot();
        if r?["error"] != () {
            print(`Cannot reset rot and sp: ${r.error}`);
            print(`Check that RoT has no pending update and STLINK is off`);
            print("Also see https://github.com/oxidecomputer/hubris/issues/1022");
            return 1;
        }
    }
    if problems > 0 {
        print(`Devices are stuck in update and need to be hard-reset before continuing`);
        return 1;
    }

    // Check initial vs desired state based on GITC values.
    //
    // Note that during development, GITC+"dirty" won't
    // distinguish between your various iterations.
    // It would be better to use FWID values all around.
    // TODO: When hubtools has fwidgen integrated and when SP can report
    // the FWID of its active and inactive flash banks, and old images
    // without those features do not need to be supported, transition to
    // FWID-based assessment. Note: The RoT can report SP Active bank FWID
    // over IPCC.
    let result = image_check("base", images);
    let err = result?["error"];
    if err != () {
        print(`image_check error: ${err}`);
        return 1;
    }
    let flash_sp = result?.ok?.sp;
    let flash_rot = result?.ok?.rot;

    print("");
    print(`Elapsed time: ${start_ts.elapsed}`);
    print(`Now=${datetime_local()}`);
    print("");

    // Update SP with baseline image if needed.
    if flash_sp && !update_sp(conf.base.sp) {
        return 1;
    }

    // Update RoT with baseline image
    debug(`info|Flash baseline rot hubris`);
    if flash_rot && !update_rot_hubris(conf.base.rot_a, conf.base.rot_b) {
        return 1
    }

    // Both SP and RoT should have baseline images installed.

    // Verify that SP and RoT are running correct images.
    // Check updated vs desired state based on GITC values.
    if flash_sp || flash_rot {
        let result = image_check("base", images);
        if result?.error != () || result.ok.sp || result.ok.rot {
            // Not able to check images or one or both base images not installed.
            debug(`warn|image_check error or failed BASE image updates: ${result}`);
            return 1;
        }
    }

    // Upgrade to under-test then rollback to baseline images.
    for v in [
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
        debug(`info|${v.up_down} Rot Hubris to ${v.label} image`);
        if !update_rot_hubris(v.rot_a_path, v.rot_b_path) {
            debug(`error|Failed to ${v.up_down} RoT Hubris to ${v.label} image: ${r}`);
            return 1
        }

        debug(`info|${v.up_down} SP Hubris to ${v.label} image`);
        if !update_sp(v.sp_path) {
            debug(`error|Failed to ${v.up_down} SP Hubris to ${v.label} image`);
            return 1;
        }

        let result = image_check(v.branch, images);
        if result?.error != () || result.ok.sp || result.ok.rot {
            // Not able to check images or one or both ${branch} images not installed.
            debug(`error|image_check error or failed ${label} image updates: ${result}`);
            return 1;
        }
        debug(`info|### SUCCESS: ${v.up_down} to SP and RoT ${v.label} images`);
    }

    print("");
    print(`Elapsed time so far: ${start_ts.elapsed}`);
    print(`Now=${datetime_local()}`);
    print("Done");
    // All is well. Exit with code 0
    0
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
    let parsed = util::getopts(argv, "hc:v");
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

// Check for update in progress.
// This will normally return () indicating no update in progress.
// The result is a re-write of the `update-status` return value:
//
// #{"Ok":"None"} => ()
// #{"Ok":{"Complete":[94,4,54,248,142,146,79,45,187,3,82,219,240,213,7,53]}]
//  => #{"state": "Complete", "id": "5e0436f88e924f2dbb0352dbf0d50735"}
// #{"Ok":{"InProgress":{"bytes_received":53790,
//   "id":[51,22,226,160,87,133,65,112,134,62,131,83,143,203,4,155],
//   "total_size":201896}}}
//   => #{"state": "InProgress",
//      "bytes_received": 53790,
//      "id": "3316e2a057854170863e83538fcb049b",
//      "total_size":201896
//      }
// #{"Err": "some error message"} => #{"Err": "some error message"}
fn check_update_in_progress(component) {
    let r = faux_mgs(["update-status", component]);
    debug(`update_status(${component})=${r}`);
    if r?.Err != () {
        debug(`error|failed update-status: ${r}`);
        return r;
    }
    if r?.Ok == "None" {
        debug("update-status ok");
        return ();
    }
    // Status was retrieved
    if r?.InProgress != () {
        debug(`update-status: ${r}`);
        return #{
            "state": "InProgress",
            "id":  util::to_hexstring(r.InProgress.id),
            "bytes_received": r.InProgress.bytes_received,
            "total_size": r.InProgress.total_size
        };
    }
    if r?.Complete != () {
        debug(`update-status: ${r}`);
        return #{
            "state": "Complete",
            "id":  util::to_hexstring(r.Complete),
        };
    }
    debug(`error|update-status: ${r}`);
    return #{"Err": `unknown update-status: ${r}`};
}

/// Update SP with specified image
fn update_sp(sp_zip) {
    print("");
    print(`### update_sp: ${sp_zip}`);

    let r = faux_mgs(["update", "sp", "0", sp_zip]);
    debug(`update result = ${r}`);
    if r?.ack == "updated" {
        print("flash_sp updated");
    } else {
        debug("error|#### FAILED flash_sp update");
        print("FAIL\n");
        return false;
    }

    let r = check_update_in_progress("sp");
    if r?.Ok != () {
        print(`ERROR: Update sp did not complete: r=${r}`);
        print("FAIL\n");
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

    let r = check_update_in_progress("sp");
    if r?.Ok != () {
        print(`ERROR: Update sp did not complete: r=${r}`);
        print("");
        return false;
    }
    print(`### SUCCESS update_sp: ${sp_zip}`);
    print("");
    return true;
}

fn update_rot_hubris(path_a, path_b) {
    print("");
    print(`### update_rot_hubris: ${path_a} ${path_b}`);
    let r = get_rot_active();
    if r?.error != () {
        print(`get_rot_active failed: ${rot_active}`);
        print("");
        return #{"error": `${rot_active["error"]}`};
    }
    let rot_active = r.ok;

    // Assume that A is active
    let rot_update_slot = 1;
    let rot_update_image = path_b;
    if rot_active == 1 {
        // Nope, B is active. Need to update A.
        rot_update_slot = 0;
        rot_update_image = path_a;
    }
    debug(`selected: rot_update_slot=${rot_update_slot} rot_update_image=${rot_update_image}`);
    let r = faux_mgs(["update", "rot", `${rot_update_slot}`, rot_update_image]);
    debug(`update result = ${r}`);
    if r?.ack == "updated" {
        print("SUCCESS");
    } else {
        print(`update failed: ${r}`);
        print("");
        return false;
    }
    let r = faux_mgs(["component-active-slot", "-p", "-s", `${rot_update_slot}`, "rot"]);
    debug(`persist result = ${r}`);
    if r?.ack == () || r.ack != "set" || r.slot != rot_update_slot {
        debug(`error|Failed to persist rot: r=${r}`);
        print("");
        return false;
    }
    let r = faux_mgs(["reset-component", "rot"]);
    if r?.ack != "reset" {
        debug(`error|reset failed: ${r}`);
        print("");
        return false;
    }
    sleep(5);
    print(`### SUCCESS update_rot_hubris: updated slot ${rot_update_slot} with ${rot_update_image}`);
    print("");
    true
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
    debug(`gitc=${gitc}`);
    debug(`gitc?[${sp_gitc}]=${gitc?[sp_gitc]}`);
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
