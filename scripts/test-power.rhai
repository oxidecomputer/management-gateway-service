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
    print("  -c CONFIG.JSON # Path to configuration");
    print("  -v # be verbose");
    print("  -h # Help. Print this message");
    print("");
}

/// Parse command line options including the required / JSON configuration file.
/// Return an exit code or the configuration map
fn process_cli(argv) {
    let prog = argv[0];
    let options = "b:c:htu:v";
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
        print("");
        print(`Parsed JSON config from ${conf_path}: ${config_from_file}`);
    }
    // The base configurartion is in `config_from_file`, command line options
    // and positional parameters override the base.
    let merged_config = config_from_file;

    // Add CLI flags to the config map passed around
    conf += merged_config; // Add contents of merged_config to conf
    // Now 'conf' contains original JSON + CLI overrides + verbose/transient flags

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

    print("");
    print(`Elapsed time after setup: ${start_ts.elapsed}`);
    print(`Current time: ${datetime_local()}`);
    print("");

    // Turn power on
    if util::control_power("dut", "on", conf) {
        print("Power on success");
    }

    // Turn power off
    if util::control_power("dut", "off", conf) {
        print("Power off success");
    }

    let r = util::control_power("dut", "status", conf);
    if type_of(r) == "map" {
        print(`Error: cannot get DUT power state: ${r}`);
        return 1;
    }
    // Else, state is an informative string, expected to be "OFF"
    if r != "OFF" {
        print(`Error: unexpected power state for dut: ${r}`);
        return 1;
    } else {
        print(`Power state is ${r}`);
    }

    // Turn power on
    if util::control_power("dut", "on", conf) {
        print("Power on success");
    }

    let r = util::control_power("dut", "status", conf);
    if type_of(r) == "map" {
        print(`Error: cannot get DUT power state: ${r}`);
        return 1;
    }
    // Else, state is an informative string, expected to be "ON"
    if r != "ON" {
        print(`Error: unexpected power state for dut: ${r}`);
        return 1;
    } else {
        print(`Power state is ${r}`);
    }


    print(`Elapsed time total: ${start_ts.elapsed}`);
    print(`Current time: ${datetime_local()}`);
    print("Done");
    return 0;
}
