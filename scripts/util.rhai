// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright 2025 Oxide Computer Company

// Define constants used in this module
const ROT_FLASH_PAGE_SIZE = 512;

/// Prints commonly available environment variables to the debug log.
/// This function is primarily for demonstrating the `env_expand` function
/// and for debugging purposes.
fn show_env() {
    debug(`info|cwd=${cwd().to_string()}`);
    debug("info|Common environment variables:");
    debug(`info|    ${env_expand("PWD=${PWD}", #{})}`);
    debug(`info|    ${env_expand("HOME=${HOME}", #{})}`);
    debug(`info|    ${env_expand("LOGNAME=${LOGNAME}", #{})}`);
    debug(`info|    ${env_expand("SHELL=${SHELL}", #{})}`);
    debug(`info|    ${env_expand("USER=${USER}", #{})}`);
}

/// Converts an array or blob of byte-like values into a hexadecimal string.
/// Each byte is represented by two hexadecimal characters.
/// Throws an error if any element cannot be converted to hex or if .to_hex()
/// does not produce a string.
///
/// Args:
///   a (array | blob): The input array or blob. Elements are expected to
///                     have a `.to_hex()` method.
///
/// Returns:
///   string: The resulting hexadecimal string on success.
///   string: "invalid_input_type" if 'a' is not an array or blob.
///   string: An empty string if 'a' is empty or null.
///
/// Throws:
///   Map: `#{ error: "message", value: original_value }` if an element
///        cannot be converted.
fn to_hexstring(a) {
    let s = "";
    let type_of_a = type_of(a);
    if type_of_a != "array" && type_of_a != "blob" {
        debug(`warn|to_hexstring: Input is not array or blob: ${type_of_a}`);
        return "invalid_input_type";
    }
    if a == () || a.len() == 0 {
        return "";
    }

    for b in a {
        let h = ();
        try {
             h = b.to_hex();
        } catch (err) {
             let error_msg =
                `Value cannot be converted to hex: ${b} (original error: ${err})`;
             debug(`error|to_hexstring: ${error_msg}`);
             throw #{ // Make this fatal
                "error": "to_hexstring: " + error_msg,
                "value": b
             };
        }

        if type_of(h) == "string" {
            if h.len() == 1 {
                s += "0"; // Pad with leading zero if necessary
            }
            s += h;
        } else {
            let error_msg =
                `.to_hex() did not return a string for value: ${b}. Got type: ${type_of(h)}`;
            debug(`error|to_hexstring: ${error_msg}`);
            throw #{ // Make this fatal
                "error": "to_hexstring: " + error_msg,
                "value": b,
                "hex_result_type": type_of(h)
            };
        }
    }
    return s.to_string();
}

/// Converts a C-style null-terminated string from an array or blob of bytes
/// into a Rhai string. Processing stops at the first NUL (0x00) character.
///
/// Args:
///   a (array | blob): The input array or blob containing byte-like values.
///
/// Returns:
///   string: The resulting string. Returns an empty string if the input is
///           invalid, null, or if non-integer/out-of-byte-range values
///           are encountered before a NUL terminator.
fn cstring_to_string(a) {
    let type_of_a = type_of(a);
    if type_of_a != "array" && type_of_a != "blob" {
        debug(`warn|cstring_to_string: Input not array or blob: ${type_of_a}`);
        return "";
    }
    if a == () {
        return "";
    }

    let data = blob();
    for b_val in a {
        let int_b = b_val;
        if type_of(b_val) != "int" {
            debug(`warn|cstring_to_string: Non-integer value in array: ${b_val}, skipping.`);
            continue;
        }
        if int_b == 0 { // NUL terminator
            break;
        }
        if int_b < 0 || int_b > 255 { // Ensure it's a valid byte value
            debug(`error|cstring_to_string: Value out of byte range: ${int_b}, skipping.`);
            continue;
        }
        data += int_b;
    }
    return data.as_string();
}

/// Formats a byte array or blob into an ASCII MAC address string.
/// Example: "00:11:22:AA:BB:CC".
///
/// Args:
///   a (array | blob): The input array/blob, typically 6 bytes long,
///                     containing byte values.
///
/// Returns:
///   string: The formatted MAC address string. Returns an empty string if input
///           is invalid or "format_error:..." if elements are not integers.
fn array_to_mac(a) {
    let type_of_a = type_of(a);
    if type_of_a != "array" && type_of_a != "blob" {
        debug(`warn|array_to_mac: Input not array or blob: ${type_of_a}`);
        return "";
    }
    if a == () || a.len() == 0 {
        return "";
    }

    let first_byte = a[0];
    if type_of(first_byte) != "int" {
        debug(`error|array_to_mac: First element is not an integer.`);
        return "format_error:non_integer_element";
    }
    let mac_str = first_byte.to_hex();
     if mac_str.len() == 1 {
         mac_str = "0" + mac_str;
     }

    for i in 1..a.len() {
        mac_str += ":";
        let byte_val = a.get(i);
        if type_of(byte_val) != "int" {
            debug(`error|array_to_mac: Element at index ${i} is not an integer.`);
            return "format_error:non_integer_element";
        }
        let hex_part = byte_val.to_hex();
        if hex_part.len() == 1 {
             mac_str += "0";
        }
        mac_str += hex_part;
    }
    return mac_str;
}

/// Translates RoT bank designators ("A", "B", or null/unit type) to
/// numeric (0, 1) or null/unit type `()`.
///
/// Args:
///   v (string | ()): The bank designator, typically "A", "B", or `()`.
///
/// Returns:
///   int | (): `0` for "A", `1` for "B", or `()` if input is `()` or unrecognized.
fn ab_to_01(v) {
    switch v {
        "A" => {
            return 0;
        }
        "B" => {
            return 1;
        }
        () => {
            return ();
        }
        _ => {
             debug(`warn|ab_to_01: Received unexpected value: ${v}, returning ().`);
             return ();
        }
    }
}

/// Expands variables in a string using environment variables and an override map.
/// Variables are denoted by `${VAR_NAME}` (for environment or top-level override)
/// or `${map.nested.key}` (for nested keys in the override map).
/// Values from `override_map` take precedence over environment variables.
///
/// Args:
///   s (string): The input string containing variables to expand.
///   override_map (map): A map of key-value pairs for overrides.
///
/// Returns:
///   string: The string with variables expanded.
///   (): Returns `()` if the input string `s` is null or not a string, or if
///       output string grows beyond a safety limit (2048 chars).
///       Unfound variables are treated as literal text (e.g., "${UNFOUND_VAR}").
fn env_expand(s, override_map) {
    if s == () {
        debug("error|env_expand: Input string is null.");
        return ();
    }
    if type_of(s) != "string" {
        debug(`error|env_expand: Requires a string input, got: ${type_of(s)}`);
        return ();
    }

    let out = "";
    let remain = s;
    let envmap = envs(); // Cache environment variables map

    while remain.len() > 0 {
        if out.len() > 2048 { // Basic guard against runaway expansion
            debug(
                `error|env_expand: Output exceeded safety limit during ` +
                `expansion of original string: ${s}`
            );
            return ();
        }

        let start_index = remain.index_of("${");
        if start_index == -1 {
            out += remain;
            return out; // No more variables found
        }

        out += remain.sub_string(0, start_index);
        remain = remain.sub_string(start_index + 2, remain.len()); // Skip "${"

        let end_index = remain.index_of("}");
        if end_index == -1 {
            debug(`warn|env_expand: Missing closing '}' in expansion: ${s}`);
            out += "${" + remain; // Treat as literal
            remain = ""; // Stop processing
            continue;
        }

        let key = remain.sub_string(0, end_index);
        remain = remain.sub_string(end_index + 1, remain.len()); // Skip "}"

        let value = ();
        let found = false;

        // Check override_map (supports nested keys like "path.to.value")
        if key.contains(".") {
            let key_parts = key.split(".");
            let current_val = override_map;
            let path_valid = true;
            for part in key_parts {
                if type_of(current_val) == "map" && (part in current_val) {
                    current_val = current_val[part];
                } else {
                    path_valid = false;
                    break;
                }
            }
            if path_valid {
                value = current_val;
                found = true;
            }
        } else {
            // Check top-level in override_map
            if type_of(override_map) == "map" && (key in override_map) {
                value = override_map[key];
                found = true;
            }
        }

        // If not in override_map, check environment variables
        if !found {
            if key in envmap {
                value = envmap[key]; // Use cached envmap
                found = true;
            }
        }

        if found {
            if type_of(value) != "string" {
                value = value.to_string();
            }
            remain = value + remain; // Prepend value for further expansion
        } else {
            debug(`warn|env_expand: Cannot expand variable '${key}' in: ${s}`);
            out += "${" + key + "}"; // Treat unfound variable as literal
        }
    }
    return out;
}


// --- Wrapped faux_mgs functions ---

/// Reads RoT Boot Information (RBI) using `faux_mgs rot-boot-info --version 3`.
/// Parses the V3 structure into a more script-friendly map.
///
/// Returns:
///   Map: A map containing RBI fields (`active`, `persistent_boot_preference`,
///        `slot_a.fwid`, etc.) on success.
///   Map: An error map like `#{ error: "message" }` or the direct error map
///        from `faux_mgs` on failure.
fn rot_boot_info() {
    let r = faux_mgs(["rot-boot-info", "--version", "3"]);
    if r?.error != () {
        debug(`error|util::rot_boot_info: faux_mgs command failed: ${r.error}`);
        return r;
    }
    if r?.V3 == () || r.V3?.active == () {
        let err_msg = "Failed to parse V3 rot-boot-info or missing key fields.";
        debug(`error|util::rot_boot_info: ${err_msg} Raw Response: ${r}`);
        return #{"error": err_msg};
    }

    let v3 = r.V3;
    let rbi = #{
        active: ab_to_01(v3.active),
        persistent_boot_preference: ab_to_01(v3.persistent_boot_preference),
        pending_persistent_boot_preference:
            ab_to_01(v3.pending_persistent_boot_preference),
        transient_boot_preference: ab_to_01(v3.transient_boot_preference),
        slot_a: #{
            fwid: to_hexstring(v3?.slot_a_fwid?.Sha3_256),
            status: v3?.slot_a_status,
        },
        slot_b: #{
            fwid: to_hexstring(v3?.slot_b_fwid?.Sha3_256),
            status: v3?.slot_b_status,
        },
        stage0: #{
            fwid: to_hexstring(v3?.stage0_fwid?.Sha3_256),
            status: v3?.stage0_status,
        },
        stage0next: #{
            fwid: to_hexstring(v3?.stage0next_fwid?.Sha3_256),
            status: v3?.stage0next_status,
        },
    };
    if rbi.active == () {
         debug(`error|util::rot_boot_info: Parsed RBI is missing a valid 'active' slot.`);
         return #{"error": "Parsed RBI missing valid 'active' slot."};
    }
    return rbi;
}

/// Gets system state information using `faux_mgs state`. Parses the V2 structure.
///
/// Returns:
///   Map: A map of selected state fields (e.g., `base_mac_address`, `model`)
///        on success.
///   Map: An error map `#{ error: "message" }` or the direct error map
///        from `faux_mgs` on failure.
fn state() {
    let r = faux_mgs(["state"]);
    if r?.error != () {
        debug(`error|util::state: faux_mgs command failed: ${r.error}`);
        return r;
    }
    if r?.V2 == () {
        let err_msg = "Failed to parse V2 state info from 'faux_mgs state'.";
        debug(`error|util::state: ${err_msg} Raw Response: ${r}`);
        return #{"error": err_msg};
    }

    let v2 = r.V2;
    let state_map = #{
        base_mac_address: array_to_mac(v2?.base_mac_address),
        hubris_archive_id: to_hexstring(v2?.hubris_archive_id),
        model: cstring_to_string(v2?.model),
        power_state: v2?.power_state,
        revision: v2?.revision,
    };
    return state_map;
}

/// Reads a specific key from a component's caboose.
/// Wraps `faux_mgs read-component-caboose ...`.
///
/// Args:
///   component (string): The component name (e.g., "sp", "rot").
///   slot (string | int): The slot identifier (e.g., "0", "1", "active").
///   key (string): The caboose key to read (e.g., "GITC", "VERS").
///
/// Returns:
///   string: The value of the caboose key if found.
///   (): Returns null/unit `()` if the key is not found or an error occurs.
fn caboose_value(component, slot, key) {
    let r = faux_mgs([
        "read-component-caboose", "--component", component,
        "--slot", `${slot}`, key // Ensure slot is stringified
    ]);
    if r?.error != () || r?.value == () {
         debug(
             `warn|util::caboose_value: Failed to read key '${key}' for ` +
             `${component} slot ${slot}. Result: ${r}`
         );
         return ();
    }
    return r.value;
}

/// Reads caboose information for standard components (RoT, SP, Stage0).
/// Iteratively calls `util::caboose_value`.
///
/// Returns:
///   Map: A nested map structured as `#{ component: #{ slot: #{ key: value } } }`.
///        Missing values will not be present in the inner maps.
fn get_device_cabooses() {
    let caboose_data = #{};
    let components_slots = #{
        "rot": ["0", "1"],
        "sp": ["0"],
        "stage0": ["0"],
    };

    for component in components_slots.keys() {
        caboose_data[component] = #{};
        for slot in components_slots[component] {
            caboose_data[component][slot] = #{};
            for key in ["BORD", "GITC", "VERS", "NAME", "SIGN"] {
                 let value = caboose_value(component, slot, key);
                 if value != () {
                     caboose_data[component][slot][key] = value;
                 }
            }
        }
    }
    return caboose_data;
}

/// Translates a Root Key Table Hash (RKTH) string to a well-known keyset name.
///
/// Args:
///   rkth (string): The RKTH hex string.
///
/// Returns:
///   string: The human-readable keyset name if known; otherwise, the original rkth.
///           Returns the input if it's not a string.
fn rkth_to_key_name(rkth) {
    if type_of(rkth) != "string" {
        debug(`warn|rkth_to_key_name: Expected string input, got ${type_of(rkth)}`);
        return rkth;
    }
    let known_rkths = #{
        "84332ef8279df87fbb759dc3866cbc50cd246fbb5a64705a7e60ba86bf01c27d": "Bart",
        "11594bb5548a757e918e6fe056e2ad9e084297c9555417a025d8788eacf55daf": "StagingDevGimlet",
        "1432cc4cfe5688c51b55546fe37837c753cfbc89e8c3c6aabcf977fdf0c41e27": "StagingDevSidecar",
        "f592d8f109b81881221eed5af6438abad9b5df8c220b9129c03763e7e10b22c7": "StagingDevPSC",
        "31942f8d53dc908c5cb338bdcecb204785fa87834e8b18f706fc972a42886c8b": "ProdRelPSC",
        "5796ee3433f840519c3bcde73e19ee82ccb6af3857eddaabb928b8d9726d93c0": "ProdRelGimlet",
        "5c69a42ee1f1e6cd5f356d14f81d46f8dbee783bb28777334226c689f169c0eb": "ProdRelSidecar"
    };

    if rkth in known_rkths {
        return known_rkths[rkth];
    } else {
        debug(`info|rkth_to_key_name: Unrecognized RKTH: ${rkth}`);
        return rkth;
    }
}

/// Converts an array of numbers (typically from JSON) into a Rhai blob.
///
/// Args:
///   a (array): The input array of numbers.
///
/// Returns:
///   blob: The created blob. Returns an empty blob if input is not an array.
fn array_to_blob(a) {
    if type_of(a) != "array" {
        debug(`warn|array_to_blob: Input is not an array, type=${type_of(a)}`);
        return blob();
    }
    let out = blob();
    for byte_val in a {
        // Assumes elements are directly compatible with blob.push (e.g., integers)
        out.push(byte_val);
    }
    return out;
}

/// Reads the RoT Customer Manufacturing Page Area (CMPA) as a blob.
/// Calls `faux_mgs read-cmpa`. Validates the size.
///
/// Returns:
///   blob: The CMPA data as a blob on success.
///   (): Returns null/unit `()` on failure (e.g., command error, wrong size).
fn get_cmpa() {
    let r = faux_mgs(["read-cmpa"]);
    let cmpa_array = r?["cmpa"];

    if r?.error != () {
        debug(`warn|util::get_cmpa: Failed to read CMPA. Error: ${r.error}`);
        return ();
    }
    if cmpa_array == () || type_of(cmpa_array) != "array" {
        debug(
             `error|util::get_cmpa: Missing or invalid 'cmpa' field in response. ` +
             `Result: ${r}`
         );
        return ();
    }

    let cmpa_blob = array_to_blob(cmpa_array);
    if cmpa_blob.len() != global::ROT_FLASH_PAGE_SIZE {
        debug(
            `warn|util::get_cmpa: Invalid CMPA blob size ` +
            `(${cmpa_blob.len()} != ${global::ROT_FLASH_PAGE_SIZE}).`
        );
        return ();
    }
    return cmpa_blob;
}

/// Reads the RoT Customer Factory Page Area (CFPA) as a blob.
/// Calls `faux_mgs read-cfpa`. Validates the size.
///
/// Returns:
///   blob: The CFPA data as a blob on success.
///   (): Returns null/unit `()` on failure.
fn get_cfpa() {
    let r = faux_mgs(["read-cfpa"]);
    let cfpa_array = r?["cfpa"];

    if r?.error != () {
        debug(`warn|util::get_cfpa: Failed to read CFPA. Error: ${r.error}`);
        return ();
    }
    if cfpa_array == () || type_of(cfpa_array) != "array" {
        debug(
            `error|util::get_cfpa: Missing or invalid 'cfpa' field in response.`+
            ` Result: ${r}`
         );
        return ();
    }

    let cfpa_blob = array_to_blob(cfpa_array);
    if cfpa_blob.len() != global::ROT_FLASH_PAGE_SIZE {
         debug(
             `error|util::get_cfpa: Invalid CFPA blob size `+
             `(${cfpa_blob.len()} != ${global::ROT_FLASH_PAGE_SIZE}).`
         );
         return ();
    }
    return cfpa_blob;
}

/// Extracts the RoT keyset name from a provided CMPA blob.
///
/// Args:
///   cmpa_blob (blob): The CMPA data, expected to be `ROT_FLASH_PAGE_SIZE` bytes.
///
/// Returns:
///   string: The well-known keyset name, the RKTH hex string if unrecognized,
///           or "unknown" if extraction fails or CMPA is invalid.
fn get_rot_keyset(cmpa_blob) {
    if type_of(cmpa_blob) != "blob" ||
       cmpa_blob.len() != global::ROT_FLASH_PAGE_SIZE
    {
         debug(
            `warn|util::get_rot_keyset: Invalid CMPA blob provided ` +
            `(type: ${type_of(cmpa_blob)}, len: ${cmpa_blob.len()}).`
         );
         return "unknown_cmpa_format";
    }
    // RKTH is 32 bytes starting at offset 80 in CMPA
    let rkth_blob = cmpa_blob.extract(80, 32);
    if rkth_blob.len() != 32 {
        debug(`error|util::get_rot_keyset: Extracted RKTH blob is not 32 bytes.`);
        return "unknown_rkth_extraction";
    }
    return rkth_to_key_name(to_hexstring(rkth_blob));
}


// --- Functions for specific script logic (e.g., upgrade-rollback) ---

/// Checks for an update in progress for a given component.
/// Wraps `faux_mgs update-status <component>`.
///
/// Args:
///   component (string): The component name (e.g., "sp", "rot").
///
/// Returns:
///   Map: Parsed status like `#{ state: "InProgress", id: "...", ... }` or
///        `#{ state: "Complete", id: "..." }`.
///   (): If no update is in progress (typically `{"Ok": "None"}`).
///   Map: An error map (e.g., `#{ Err: ... }` or `#{ "Err": ... }`) on
///        command failure or if the response structure is unrecognized.
fn check_update_in_progress(component) {
    let r = faux_mgs(["update-status", component]);
    debug(
        `info|util::check_update_in_progress: raw update_status(${component}) `+
        `result = ${r}`
    );

    if r?.Err != () {
        debug(
            `error|util::check_update_in_progress: faux_mgs error for `+
            `${component}: ${r}`
        );
        return r;
    }

    if r?.Ok != () {
        let ok_value = r.Ok;
        if type_of(ok_value) == "string" && ok_value == "None" {
            debug(
                `info|util::check_update_in_progress: no update for `+
                `${component} (Ok: "None").`
            );
            return ();
        }
        if type_of(ok_value) == "map" {
            if ok_value?.InProgress != () {
                let details = ok_value.InProgress;
                debug(
                    `info|util::check_update_in_progress: update InProgress `+
                    `(Ok.InProgress) for ${component}: ${details}`
                );
                return #{
                    "state": "InProgress", "id": to_hexstring(details.id),
                    "bytes_received": details.bytes_received,
                    "total_size": details.total_size
                };
            }
            if ok_value?.Complete != () {
                let id = ok_value.Complete;
                debug(
                    `info|util::check_update_in_progress: update Complete `+
                    `(Ok.Complete) for ${component}: ${id}`
                );
                return #{ "state": "Complete", "id": to_hexstring(id) };
            }
        }
    } else { // No "Ok" key, check for top-level status
        if r?.InProgress != () {
            let details = r.InProgress;
            debug(
                `info|util::check_update_in_progress: update InProgress `+
                `(top-level) for ${component}: ${details}`
            );
            return #{
                "state": "InProgress", "id": to_hexstring(details.id),
                "bytes_received": details.bytes_received,
                "total_size": details.total_size
            };
        }
        if r?.Complete != () {
            let id = r.Complete;
            debug(
                `info|util::check_update_in_progress: update Complete `+
                `(top-level) for ${component}: ${id}`
            );
            return #{ "state": "Complete", "id": to_hexstring(id) };
        }
    }

    debug(
        `error|util::check_update_in_progress: unrecognized structure for ` +
        `${component}: ${r}`
    );
    return #{"Err": `unrecognized update-status structure: ${r}`};
}

/// Updates a RoT image file on a specified slot.
/// Wraps `faux_mgs update rot <slot> <image_path>`.
///
/// Args:
///   target_slot (int): The RoT slot to update (0 or 1).
///   image_path (string): Path to the RoT image file.
///   target_label (string): Descriptive label for logging (e.g., "baseline").
///
/// Returns:
///   true if the command was acknowledged as "updated", false otherwise.
fn update_rot_image_file(target_slot, image_path, target_label) {
    debug(
        `info|util::update_rot_image_file: Updating RoT slot ${target_slot} `+
        `with ${image_path} (target '${target_label}').`
    );
    let r_update = faux_mgs(["update", "rot", `${target_slot}`, image_path]);
    debug(
        `info|util::update_rot_image_file: Result for '${target_label}': `+
        `${r_update}`
    );
    if r_update?.ack == "updated" {
        return true;
    } else {
        print(
            `ERROR: util::update_rot_image_file: RoT update failed for ` +
            `'${target_label}', slot ${target_slot}. Result: ${r_update}`
        );
        return false;
    }
}

/// Sets the RoT boot preference (transient or persistent).
/// Wraps `faux_mgs component-active-slot <duration> -s <slot> rot`.
///
/// Args:
///   target_slot (int): The RoT slot to set preference for.
///   use_transient_flag (bool): If true, sets transient ('-t') preference;
///                              otherwise, persistent ('-p').
///   target_label (string): Descriptive label for logging.
///
/// Returns:
///   true if command acknowledged as "set" for correct slot, false otherwise.
fn set_rot_boot_preference(target_slot, use_transient_flag, target_label) {
    let duration_param = if use_transient_flag { "-t" } else { "-p" };
    debug(
        `info|util::set_rot_boot_preference: Setting RoT pref: `+
        `slot ${target_slot}, type ${duration_param} (target '${target_label}').`
    );
    let r_set_slot = faux_mgs([
        "component-active-slot", duration_param, "-s", `${target_slot}`, "rot"
    ]);
    debug(
        `info|util::set_rot_boot_preference: Result for '${target_label}': `+
        `${r_set_slot}`
    );
    if r_set_slot?.ack == "set" && r_set_slot?.slot == target_slot {
        return true;
    } else {
        debug(
            `error|util::set_rot_boot_preference: Failed for '${target_label}' `+
            `(slot ${target_slot}, type ${duration_param}). Result: ${r_set_slot}`
        );
        return false;
    }
}

/// Resets the RoT component, waits, gets RotBootInfo (RBI), and validates RBI.
/// Wraps `faux_mgs reset-component rot` and calls `util::rot_boot_info()`.
///
/// Args:
///   reset_description (string): Description for logging (e.g., "after update").
///   target_label (string): Descriptive label for logging.
///
/// Returns:
///   Map: The RBI map on success.
///   Map: An error map `#{ "error": "message" }` on any failure.
fn reset_rot_and_get_rbi(reset_description, target_label) {
    debug(
        `info|util::reset_rot_and_get_rbi: Resetting RoT: ` +
        `${reset_description} (target '${target_label}').`
    );
    let r_reset = faux_mgs(["reset-component", "rot"]);
    if r_reset?.ack != "reset" {
        let err_msg =
            `RoT reset command failed (${reset_description}, ` +
            `target '${target_label}'). Result: ${r_reset}`;
        debug(`error|util::reset_rot_and_get_rbi: ${err_msg}`);
        return #{"error": err_msg};
    }
    sleep(5); // Consider making sleep duration a global constant

    let rbi = rot_boot_info(); // Calls this file's rot_boot_info()
    if rbi?.error != () {
        let err_msg =
            `Failed to get RBI after reset (${reset_description}, ` +
            `target '${target_label}'). Error: ${rbi.error}`;
        debug(`error|util::reset_rot_and_get_rbi: ${err_msg}`);
        return rbi; // Propagate RBI's error map
    }
    if rbi?.active == () { // Basic validity check
        let err_msg =
            `RBI invalid/incomplete after reset (${reset_description}, `+
            `target '${target_label}'). RBI: ${rbi}`;
        debug(`error|util::reset_rot_and_get_rbi: ${err_msg}`);
        return #{"error": err_msg};
    }
    debug(
        `info|util::reset_rot_and_get_rbi: Success ` +
        `(${reset_description}, target '${target_label}'). Active: ${rbi.active}`
    );
    return rbi;
}

/// Updates the SP image file (assumes slot 0).
/// Wraps `faux_mgs update sp 0 <image_path>`.
///
/// Args:
///   image_path (string): Path to the SP image file.
///
/// Returns:
///   true if acknowledged as "updated", false otherwise.
fn update_sp_image(image_path) {
    debug(`info|util::update_sp_image: Updating SP with image ${image_path}`);
    let r_update = faux_mgs(["update", "sp", "0", image_path]);
    debug(`info|util::update_sp_image: Result of 'update sp': ${r_update}`);
    if r_update?.ack == "updated" {
        return true;
    } else {
        print(
            `ERROR: util::update_sp_image: SP image update command failed. ` +
            `Result: ${r_update}`
        );
        return false;
    }
}

/// Resets the Service Processor (SP).
/// Wraps `faux_mgs reset`.
///
/// Returns:
///   true if acknowledged as "reset", false otherwise.
fn reset_sp() {
    debug(`info|util::reset_sp: Resetting SP.`);
    let r_reset = faux_mgs(["reset"]);
    debug(`info|util::reset_sp: Result of 'reset': ${r_reset}`);
    if r_reset?.ack == "reset" {
        return true;
    } else {
        let err_msg =
            `SP reset command failed or gave unexpected ack. Result: ${r_reset}`;
        debug(`error|util::reset_sp: ${err_msg}`);
        print(`FAIL - ${err_msg}\n`);
        return false;
    }
}

/// Aborts an update in progress for a given component and update ID.
/// Wraps `faux_mgs update-abort <component> <id>`.
///
/// Args:
///   component (string): Component (e.g., "sp", "rot").
///   id (string): Hex string ID of the update to abort.
///
/// Returns:
///   Map: The result map from the `faux_mgs` command (includes `ack` or `error`).
fn abort_update(component, id) {
    debug(
        `info|util::abort_update: Aborting update for component '${component}' ` +
        `with ID '${id}'.`
    );
    let result = faux_mgs(["update-abort", component, id]);
    debug(
        `info|util::abort_update: Result for component '${component}', `+
        `ID '${id}': ${result}`
    );
    return result;
}

/// Resets a specified component (e.g., "sp", "rot").
/// Wraps `faux_mgs reset-component <component_name>`.
///
/// Args:
///   component_name (string): The name of the component to reset.
///
/// Returns:
///   true if acknowledged as "reset", false otherwise (errors logged/printed).
fn reset_component(component_name) {
    debug(
        `info|util::reset_component: Attempting to reset ` +
        `component '${component_name}'.`
    );
    let result = faux_mgs(["reset-component", component_name]);
    debug(
        `info|util::reset_component: Result for 'reset-component ` +
        `${component_name}': ${result}`
    );

    if result?.ack == "reset" {
        debug(
            `info|util::reset_component: Component '${component_name}' ` +
            `reset acknowledged.`
        );
        return true;
    } else if result?.error != () {
        print(
            `ERROR: util::reset_component: Failed to reset component ` +
            `'${component_name}'. Error: ${result.error}`
        );
        return false;
    } else {
        print(
            `ERROR: util::reset_component: Unexpected response for reset ` +
            `component '${component_name}'. Ack: ${result?.ack}, Full: ${result}`
        );
        return false;
    }
}


// A getopts implementation very similar to the bash built-in function.
// TODO: Add detailed doc comments for getopts parameters and return value.
// TODO: Write tests for getopts(), maybe move getopts() to a separate file.
fn getopts(argv, options) {
    let result = #{};
    let positional = [];
    let i = 1; // Start parsing from the first argument after script name

    while i < argv.len() {
        let arg = argv[i];

        if arg == "--" {
            // End of options, all subsequent are positional
            i += 1;
            while i < argv.len() {
                positional.push(argv[i]);
                i += 1;
            }
            break; // Exit outer loop
        } else if arg.starts_with("--") && arg.len() > 2 {
            // Long option
            let opt_full = arg.sub_string(2, arg.len());
            let opt_name = opt_full;
            let opt_val = true; // Default for flag options

            // Check if option expects an argument (e.g., --option=value)
            // This basic getopts doesn't support --option value (space separated)
            // Nor does it check 'options' string for long opt definitions directly
            // This part would need more advanced parsing if those features are required.
            // For now, assuming long options are flags or use '=' for value.

            // If using Rhai version that supports string.split_once(char) or similar:
            // if let Some((name, val_str)) = opt_full.split_once('=') {
            //    opt_name = name;
            //    opt_val = val_str;
            // } else {
            //    opt_name = opt_full;
            //    opt_val = true; // Flag
            // }
            // For simplicity without split_once:
            let eq_idx = opt_full.index_of("=");
            if eq_idx != -1 {
                opt_name = opt_full.sub_string(0, eq_idx);
                opt_val = opt_full.sub_string(eq_idx + 1, opt_full.len());
            }

            // Long options are not validated against 'options' string in this basic impl.
            result[opt_name] = opt_val;
            i += 1;
        } else if arg.starts_with("-") && arg.len() > 1 {
            // Short options, potentially combined: -a, -b, -c value, -dvalue
            let short_opts_str = arg.sub_string(1, arg.len());
            let current_opt_char_idx = 0;
            let consumed_next_argv_for_opt = false;

            while current_opt_char_idx < short_opts_str.len() {
                 let opt_char = short_opts_str[current_opt_char_idx];
                 let opt_str = opt_char.to_string();
                 let opt_spec_index = options.index_of(opt_str);

                 if opt_spec_index == -1 {
                     return #{ "error": `Unknown option '-${opt_str}'.` };
                 }

                 let requires_arg = (opt_spec_index + 1 < options.len() &&
                                     options[opt_spec_index + 1] == ":");

                 if requires_arg {
                      if current_opt_char_idx + 1 < short_opts_str.len() {
                           // Argument attached: -ovalue
                           result[opt_str] = short_opts_str.sub_string(
                               current_opt_char_idx + 1, short_opts_str.len()
                           );
                           current_opt_char_idx = short_opts_str.len(); // Processed whole token
                      } else if i + 1 < argv.len() {
                           // Argument separate: -o value
                           result[opt_str] = argv[i + 1];
                           consumed_next_argv_for_opt = true;
                           current_opt_char_idx += 1;
                      } else {
                           return #{ "error": `Option '-${opt_str}' requires an argument.` };
                      }
                 } else {
                      // Option is a flag
                      result[opt_str] = true;
                      current_opt_char_idx += 1;
                 }
            } // End while for chars in short_opts_str

            i += 1; // Consumed current argv element (e.g., "-abc" or "-o")
            if consumed_next_argv_for_opt {
                i += 1; // Also consumed the next argv element if it was an opt arg
            }
        } else {
            // Positional argument
            positional.push(arg);
            i += 1;
        }
    } // End while loop through argv

    return #{ "result": result, "positional": positional };
}
