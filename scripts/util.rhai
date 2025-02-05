// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright 2025 Oxide Computer Company

/// Print out commonly available environment variables to demonstrate
/// the env_expand function.
fn show_env() {
    print(`cwd=${cwd().to_string()}`);
    print("Common environment variables:");
    print(`    ${env_expand("PWD=${PWD}", #{})}`);
    print(`    ${env_expand("HOME=${HOME}", #{})}`);
    print(`    ${env_expand("LOGNAME=${LOGNAME}", #{})}`);
    print(`    ${env_expand("SHELL=${SHELL}", #{})}`);
    print(`    ${env_expand("USER=${USER}", #{})}`);
}

// Reformat a byte array as a hex byte string representation.
fn to_hexstring(a) {
    let s = "";
    for b in a {
        let h = b.to_hex();
        if h.len() == 1 {
            s += "0";
        }
        s += h;
    }
    s.to_string()
}

// Reformat an ASCII byte array with 0x00 padding into a string
// The trailing NUL is optional.
fn cstring_to_string(a) {
    let data = blob();
    for b in a {
        if b == 0 {
            break;
        }
        data += b;
    }
    data.as_string()
}

// Format a byte array into an ASCII mac address.
fn array_to_mac(a) {
    let mac = "";
    mac += a[0].to_hex();
    for i in 1..a.len() {
        mac += ":";
        mac += a.get(i).to_hex();
    }
    mac
}

// Translate A/B RoT bank name to 0/1 equivalent
fn ab_to_01(v) {
    switch v {
        "A" => 0,
        "B" => 1,
        () => (),
    }
}

// Expand string using environment and values from the override map
// For no override, use #{} in place of the override map.
fn env_expand(s, override) {
    if s == () {
        print!("Warning: trying to expand ()");
        return ();
    }
    // Note: Using an ImmutableString when there are usually
    // zero to three varable expansions on relatively small strings
    // is not a big deal.
    // Escaping '$' may be needed someday.
    let out = "";

    let remain = s;
    let envmap = envs();
    while remain.len() > 0 {
        if out.len() > 2048 {
            print(`env_expand error: out.len() has reached ${out.len()}`);
            return ();
        }
        let i = remain.index_of("${");
        if i == -1 {
            out += remain;
            return out;
        }
        out += remain[0..i];
        remain.crop(i+2);
        let i = remain.index_of("}");
        if i == -1 {
            out += "${" + remain;
            remain = "";
            continue;
        }
        let key = remain[0..i];
        remain.crop(key.len() + 1);
        // We have key from within a string, e.g. "abc${key}def"
        let value = ();
        // If there is a '.' in the key, then this is a nested reference
        // within `override`
        let dot = key.index_of(".");
        if dot > 0 {
            let orig_key = key;
            let vars = override;
            while dot > 0 {
                let topkey = key[0..dot];
                key = key[dot+1..];
                vars = vars?[topkey];
                if vars == () {
                    print("Error: env_expand: out of vars!");
                    print(`Expansion of "${s}" is "${out}" with remainder "${remain}"`);
                    return ();
                }
                dot = key.index_of(".");
            }
            if key in vars {
                value = vars[key];
            } else {
                print(`Cannot expand ${orig_key}`);
                print(`Expansion of "${s}" is "${out}" with remainder "${remain}"`);
            }
        } else {
            // No dot in key, top-level from `override` or
            // from env()
            if key in override {
                value = override[key];
            } else if key in envmap {
                value = env(key);
            } else {
                // TODO: tie into faux-mgs logging
                print(`Cannot expand ${key}`);
                print(`Expansion of "${s}" is "${out}" with remainder "${remain}"`);
                return ()
            }
        }
        remain = value + remain;
    }
    out
}

// --- Wrapped faux_mgs functions to make them easier to digest in the main script.

/// Make RotBootInfoV3 more rhai friendly.
fn rot_boot_info() {
    let r = faux_mgs(["rot-boot-info", "--version", "3"]);
    // print(`RESULTS: ${type_of(r)}:`);
    // print(`${r}`);
    if r.V3?.active == () {
        return (#{})
    }
    let v3 = r.V3;
    let rbi = #{
        active: ab_to_01(v3.active),
        persistent_boot_preference: ab_to_01(v3.persistent_boot_preference),
        pending_persistent_boot_preference: ab_to_01(v3.pending_persistent_boot_preference),
        transient_boot_preference: ab_to_01(v3.transient_boot_preference),
        slot_a: #{
            fwid: to_hexstring(v3.slot_a_fwid.Sha3_256),
            status: v3.slot_a_status,
        },
        slot_b: #{
            fwid: to_hexstring(v3.slot_b_fwid.Sha3_256),
            status: v3.slot_b_status,
        },
        stage0: #{
            fwid: to_hexstring(v3.stage0_fwid.Sha3_256),
            status: v3.stage0_status,
        },
        stage0next: #{
            fwid: to_hexstring(v3.stage0next_fwid.Sha3_256),
            status: v3.stage0next_status,
        },
    };
    rbi
}

// faux-mgs state without the redundant rot_boot_info struct.
fn state() {
    let r = faux_mgs(["state"]);
    let v2 = r.V2;
    #{
        base_mac_address: array_to_mac(v2.base_mac_address),
        hubris_archive_id: to_hexstring(v2.hubris_archive_id),
        model: cstring_to_string(v2.model),
        power_state: v2.power_state,
        revision: v2.revision,
        // Ignore the rot state in favor of rot_boot_info
    }
}

/// Read Caboose Value
// "stage0", "rot", and "sp" are the interesting components here though others may exist.
// "stage0" doesn't have a caboose.
fn caboose_value(component, slot, key) {
    let r = faux_mgs(["read-component-caboose", "--component", component, "--slot", slot, key]);
    r?.value
}

// Connect though the SP to get caboose values for all RoT and SP images.
fn get_device_cabooses() {
    let caboose = #{};
    for component in ["stage0", "rot", "sp"] {
    for slot in ["0", "1"] {
    if (component in caboose) == false {
        caboose[component] = #{};
    }
    if (slot in caboose[component]) == false {
        caboose[component][slot] = #{};
    }
    caboose[component][slot] = get_caboose(component, slot);
}
}
caboose
}

// Translate the LPC55's Root Key Table Hash to a well-known keyset name or
// leave it as the original value.
fn rkth_to_key_name(rkth) {
    switch rkth {
        "84332ef8279df87fbb759dc3866cbc50cd246fbb5a64705a7e60ba86bf01c27d" =>
        "Bart",
        "11594bb5548a757e918e6fe056e2ad9e084297c9555417a025d8788eacf55daf" =>
        "StagingDevGimlet",
        "1432cc4cfe5688c51b55546fe37837c753cfbc89e8c3c6aabcf977fdf0c41e27" =>
        "StagingDevSidecar",
        "f592d8f109b81881221eed5af6438abad9b5df8c220b9129c03763e7e10b22c7" =>
        "StagingDevPSC",
        "31942f8d53dc908c5cb338bdcecb204785fa87834e8b18f706fc972a42886c8b" =>
        "ProdRelPSC",
        "5796ee3433f840519c3bcde73e19ee82ccb6af3857eddaabb928b8d9726d93c0" =>
        "ProdRelGimlet",
        "5c69a42ee1f1e6cd5f356d14f81d46f8dbee783bb28777334226c689f169c0eb" =>
        "ProdRelSidecar",
        _ => rkth
    }
}

// Convert a byte array returned from faux-mgs using JSON into a native blob type.
fn array_to_blob(a) {
    let out = blob();
    for byte in a {
        out.push(byte);
    }
    out
}

// Get the RoT device CMPA as a blob
fn get_cmpa() {
    let cmpa = faux_mgs(["read-cmpa"])?["cmpa"];
    if cmpa != () {
        array_to_blob(cmpa)
    } else {
        ()
    }
}

// Get the RoT device CFPA as a blob
fn get_cfpa() {
    let cfpa = faux_mgs(["read-cfpa"])?["cfpa"];
    if cfpa != () {
        array_to_blob(cfpa)
    } else {
        ()
    }
}

// Identify the keyset name from the RoT device's CMPA.
fn get_rot_keyset(cmpa) {
    rkth_to_key_name(to_hexstring(cmpa.extract(80,32)))
}

// fn rot_boot_info() {
// fn state() {
// fn caboose_value(component, slot, key) {
// fn get_device_cabooses

//   component-active-slot       Get or set the active slot of a component (e.g., `host-boot-flash`)
//   current-time                Ask the SP for its current system time (interpreted as human time or as a raw
//   dump                        List and read per-task crash dumps
//   power-state                 Get or set the power state
//   read-caboose                Read a single key from the caboose
//   read-cfpa                   Reads a CFPA slot from an attached Root of Trust
//   read-cmpa                   Reads the CMPA from an attached Root of Trust
//   read-component-caboose      Read a single key from the caboose
//   read-sensor-value           Reads a single sensor by `SensorId`, returning a `f32`
//   reset-component             Reset a component
//   reset                       Instruct the SP to reset
//   rot-boot-info               Read the RoT's boot-time information
//   set-ipcc-key-value          Set an IPCC key/value
//   system-led                  Controls the system LED
//   update-abort                Abort an in-progress update
//   update-status               Get the status of an update to the specified component
//   update                      Upload a new image to the SP or one of its components



// getops - This code was generated by gemini.google.com.
// When asked, "Gemini" indicated that the code was free to use.
//
// The following prompt was given:
//
// Write a Rhai script that implements a command-line argument parser similar
// to the bash `getopts` function. The script should define a function
// `getopts(argv, options)` where:
//
// * `argv` is a vector of strings representing the command-line arguments
//   (including the script name as the first element).
// * `options` is a string specifying the valid options. Options that
//   require an argument are indicated by a trailing colon (e.g., "a:b:c").
// * The function should parse `argv` and return a Rhai map containing two
//   keys: "result" and "positional".
//     * "result" should be a map containing the parsed options and their
//       values. Short options (e.g., `-a`) and long options (e.g., `--long`)
//       should be supported.
//     * "positional" should be a vector of strings containing the positional
//       arguments (those not starting with `-` or `--`).
// * Short options can be combined (e.g., `-abc`).
// * A double dash (`--`) should stop option processing; any remaining `argv`
//   elements should be treated as positional arguments.
// * If an option requires an argument but it is missing, or if an unknown
//   option is encountered, the function should return a map with an "error"
//   key containing an error message.
// * Rhai does not have a `substr` function, use `sub_string` instead.
// * Rhai does not have a native `any` function for iterators, implement the
//   functionality manually.
// * Rhai does not have an error function, return a map with an error key
//   instead.
//
// Provide example usage demonstrating the function's functionality, including
// cases with combined short options, missing arguments, unknown options,
// and the double dash argument.
//
fn getopts(argv, options) {
    let result = #{};
    let positional = [];
    let i = 1;

    while i < argv.len() {
        let arg = argv[i];

        if arg == "--" {
            i += 1;
            while i < argv.len() {
                positional.push(argv[i]);
                i += 1;
            }
            break;
        } else if arg.starts_with("--") {
            let opt = arg.sub_string(2, arg.len());
            if options.contains(opt + ":") {
                if i + 1 < argv.len() {
                    result[opt] = argv[i + 1];
                    i += 2;
                } else {
                    return #{ "error": "Option '" + opt + "' requires an argument." };
                }
            } else if options.contains(opt) {
                result[opt] = true;
                i += 1;
            } else {
                return #{ "error": "Unknown option '" + opt + "'." };
            }
        } else if arg.starts_with("-") {
            let opts = arg.sub_string(1, arg.len()).chars();
            for opt in opts {
                let opt_str = opt.to_string();
                if options.contains(opt_str + ":") {
                    if i + 1 < argv.len() {
                        result[opt_str] = argv[i + 1];
                        i += 2;
                        break;
                    } else {
                        return #{ "error": "Option '" + opt_str + "' requires an argument." };
                    }
                } else if options.contains(opt_str) {
                    result[opt_str] = true;
                } else {
                    return #{ "error": "Unknown option '" + opt_str + "'." };
                }
            }
            let short_opts = arg.sub_string(1, arg.len()).chars();
            let has_argument_required = false;
            for o in short_opts{
                if options.contains(o.to_string()+":"){
                    has_argument_required = true;
                    break;
                }
            }
            if !has_argument_required{
                i += 1;
            }
        } else {
            positional.push(arg);
            i += 1;
        }
    }

    return #{ "result": result, "positional": positional };
}
