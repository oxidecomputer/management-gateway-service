// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright 2025 Oxide Computer Company

// Define constants used in this module
const ROT_FLASH_PAGE_SIZE = 512;

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
             throw #{
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
            throw #{
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
///   slot (int): The RoT slot to update (0 or 1).
///   image_path (string): Path to the RoT image file.
///   label (string): Descriptive label for logging (e.g., "baseline").
///
/// Returns:
///   true if the command was acknowledged as "updated", false otherwise.
fn update_rot_image_file(slot, image_path, label) {
    debug(`info|Updating RoT slot ${slot} with ${image_path} (target '${label}').`);
    let r = faux_mgs(["update", "rot", `${slot}`, image_path]);
    debug(`info|Result for '${label}': ${r}`);
    if r?.ack == "updated" {
        return true;
    } else {
        debug(`error|RoT update failed for '${label}' slot ${slot}): ${r}`);
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

/// Reset the RoT, wait, get RotBootInfo (RBI), and validate RBI.
/// Wraps `faux_mgs reset-component rot` and calls `util::rot_boot_info()`.
///
/// Args:
///   reset_description (string): Description for logging (e.g., "after update").
///   target_label (string): Descriptive label for logging.
///
/// Returns:
///   Map: `#{ "ok": rbi_map }` on full success, where `rbi_map` is the parsed RBI.
///   Map: An error map on any failure, structured as
///        `#{ "error": "message", "error_type": "type", "details": original_map_if_any }`.
///        Possible `error_type` values include: "reset_command_failed",
///        "reset_ack_mismatch", "rbi_fetch_failed", "rbi_invalid_structure".
fn reset_rot_and_get_rbi(reset_description, target_label) {
    debug(`info|Resetting RoT: ${reset_description} (target '${target_label}')`);

    let r_reset = faux_mgs(["reset-component", "rot"]);

    // Check 1: Did the faux_mgs command itself return an error?
    if r_reset?.Err != () {
        let err_msg = `RoT reset command failed. Error: ${r_reset.Err}`;
        debug(`error|${err_msg}`);
        return #{
            "error": err_msg,
            "error_type": "reset_command_failed",
            "details": r_reset // Contains the original "Err" from faux_mgs
        };
    }

    // Check 2: Did the command succeed but not give the expected ack?
    if r_reset?.ack != "reset" {
        let err_msg =
            `RoT reset command did not return expected 'ack: "reset"'. ` +
            `Received: ${r_reset}`;
        debug(`error|${err_msg}`);
        return #{
            "error": err_msg,
            "error_type": "reset_ack_mismatch",
            "details": r_reset
        };
    }

    debug(
        `info|RoT reset command acknowledged. Waiting for RoT to boot ` +
        `(context: ${reset_description}).`
    );
    // TODO: Consider replacing this fixed sleep with active polling for RoT readiness
    //       if a lightweight "ping" or status command for RoT becomes available.
    sleep(5);

    // util::rot_boot_info() itself returns either an error map or the RBI map.
    let rbi_result = util::rot_boot_info();

    if rbi_result?.error != () {
        // This means rot_boot_info detected an error (either its own parsing
        // or an error propagated from its internal faux_mgs call).
        let err_msg =
            `Failed to get valid RBI after reset (${reset_description}, ` +
            `target '${target_label}'). Underlying error: ${rbi_result.error}`;
        debug(`error|${err_msg}`);
        let error_type = if rbi_result?.error_type != () {
          rbi_result.error_type
        } else {
          "rbi_fetch_failed"
        };
        return #{
            "error": err_msg,
            // Attempt to preserve original error type if possible, or use a general one
            "error_type": error_type,
            "details": rbi_result // Contains the original error map from rot_boot_info
        };
    }
    // If no 'error' key, rbi_result *is* the RBI map.
    // The current util::rot_boot_info already checks rbi.active internally
    // and returns an error map if it's missing/invalid.

    debug(
        `info|Successfully reset RoT and fetched RBI ` +
        `(${reset_description}, target '${target_label}'). Active: ${rbi_result.active}`
    );
    // Standardize success return
    return #{ "ok": rbi_result };
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
        debug(`error|SP image update command failed. Result: ${r_update}`);
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
        debug(`error|reset component ${component_name}: ${result.error}`);
        return false;
    } else {
        debug(`error|reset ${component_name}: result=${result}`);
        return false;
    }
}

/// Retrieves and expands a power control command array from the configuration.
/// Each element of the command array will be expanded using `util::env_expand`.
/// (This function remains largely the same as proposed in Turn 52, ensuring
/// it returns () on errors which control_power will then handle.)
///
/// Args:
///   conf (map): The main configuration map.
///   target_device (string): Key for the target device in `conf.power_control`.
///   action (string): Power action ("on", "off", "status").
///
/// Returns:
///   array: An array of strings representing the expanded command and its arguments.
///   (): Returns null/unit `()` if the command is not defined, not an array,
///       empty, contains non-string elements, or if any part fails expansion.
fn get_power_command(conf, target_device, action) {
    let cmd_key = action + "_cmd";
    let command_template_array = conf?.power_control?[target_device]?[cmd_key];

    if command_template_array == () {
        debug(
            `warn|util::get_power_command: No command array defined for device ` +
            `'${target_device}', action '${action}' (expected key '${cmd_key}').`
        );
        return ();
    }
    if type_of(command_template_array) != "array" {
        debug(
            `error|util::get_power_command: Command for ` +
            `'${target_device}.${cmd_key}' is not an array.`
        );
        return ();
    }
    if command_template_array.len() == 0 {
        debug(
            `error|util::get_power_command: Command array for ` +
            `'${target_device}.${cmd_key}' is empty.`
        );
        return ();
    }

    let expanded_command_array = [];
    for part_template in command_template_array {
        if type_of(part_template) != "string" {
            debug(
                `error|util::get_power_command: Non-string element ` +
                `'${part_template}' in command array for '${target_device}.${cmd_key}'.`
            );
            return ();
        }
        let expanded_part = env_expand(part_template, conf);
        if expanded_part == () || type_of(expanded_part) != "string" {
            debug(
                `error|util::get_power_command: Failed to expand or got non-string ` +
                `for part '${part_template}' in command for '${target_device}.${cmd_key}'.`
            );
            return ();
        }
        expanded_command_array.push(expanded_part);
    }
    debug(
        `info|util::get_power_command: Expanded for '${target_device}' action '${action}': `+
        `${expanded_command_array}`
    );
    return expanded_command_array;
}

/// Controls power for a specified target device using external commands as arrays.
/// Uses the Rhai `system()` function to execute configured commands.
///
/// Args:
///   target_device (string): Key for the target device in `conf.power_control`.
///   action (string): Power action: "on", "off", or "status".
///   conf (map): Main configuration map including the `power_control` section.
///
/// Returns:
///   For "on", "off" actions:
///     true: If command executes with exit code 0.
///     false: If command not defined, fails execution, or has non-zero exit code.
///   For "status" action:
///     "ON" (string): Power is confirmed to be ON.
///     "OFF" (string): Power is confirmed to be OFF.
///     "UNKNOWN" (string): Command ran successfully but output was ambiguous.
///     Map `#{ "error": "message", ... }`: If status could not be determined due
///                                        to configuration error or command failure.
fn control_power(target_device, action, conf) {
    debug(
        `info|util::control_power: Requesting action '${action}' ` +
        `for device '${target_device}'.`
    );
    let command_array = get_power_command(conf, target_device, action);

    if command_array == () { // Checks for null from get_power_command indicating config error
        let err_msg =
            `Configuration error: Could not retrieve command for ` +
            `'${target_device}' action '${action}'.`;
        debug(`error|util::control_power: ${err_msg}`);
        return #{ "error": err_msg };
    }
    // No need to check type_of(command_array) != "array" or len == 0 here
    // as get_power_command would have returned () in those cases.

    debug(`info|util::control_power: Executing command array: ${command_array}`);
    let system_result = system(command_array);

    if system_result?.error != () { // Error from system() call itself
        let err_msg =
            `Command execution failed: system() call for '${command_array[0]}' ` +
            `failed: ${system_result.error}`;
        debug(`error|util::control_power: ${err_msg}`);
        return #{ "error": err_msg, "details": system_result };
    }

    debug(`info|util::control_power: System result for '${action}' on '${target_device}': ${system_result}`);

    if action == "on" || action == "off" {
        if system_result.exit_code == 0 {
            debug(
                `info|util::control_power: Action '${action}' for ` +
                `'${target_device}' SUCCEEDED (exit code 0).`
            );
            return true;
        } else {
            let err_msg =
                `Action '${action}' for '${target_device}' FAILED ` +
                `(command exit code ${system_result.exit_code}).`;
            debug(
                `error|util::control_power: ${err_msg} `+
                `Stdout: [${system_result.stdout}], Stderr: [${system_result.stderr}]`
            );
            return false; // Explicit false for command failure for on/off actions
        }
    } else if action == "status" {
        let cmd_name = if command_array.len() > 0 { command_array[0] } else { "unknown_command" };
        if system_result.exit_code != 0 {
            let err_msg =
                `Status command '${cmd_name}' for '${target_device}' indicated failure ` +
                `with exit code ${system_result.exit_code}.`;
            debug(
                `error|util::control_power: ${err_msg} Stdout: [${system_result.stdout}], ` +
                `Stderr: [${system_result.stderr}]`
            );
            return #{ "error": err_msg, "details": system_result };
        }

        // Status command executed successfully (exit code 0). Now determine power state.
        let expected_on_text = conf?.power_control?[target_device]?.status_on_stdout_contains;

        if expected_on_text != () && type_of(expected_on_text) == "string" && expected_on_text.len() > 0 {
            // status_on_stdout_contains is configured, use it
            if system_result.stdout.contains(expected_on_text) {
                debug(
                    `info|util::control_power: Status for '${target_device}' is ON ` +
                    `(stdout matched '${expected_on_text}').`
                );
                return "ON";
            } else {
                debug(
                    `info|util::control_power: Status for '${target_device}' is OFF `+
                    `(stdout did not match '${expected_on_text}'). Stdout: [${system_result.stdout}]`
                );
                return "OFF";
            }
        } else {
            // No status_on_stdout_contains configured. Exit code 0 from status_cmd means ON.
            debug(
                `info|util::control_power: Status for '${target_device}' is ON ` +
                `(exit code 0 from command, no specific stdout check configured).`
            );
            return "ON";
        }
    } else {
        let err_msg = `Unknown action '${action}' requested for power control.`;
        debug(`error|util::control_power: ${err_msg}`);
        return #{ "error": err_msg }; // Should not happen if called correctly
    }
}

/// Parses command-line arguments from an argv-style array based on an options string.
/// This function is inspired by the behavior of POSIX getopts and GNU getopt,
/// supporting short options, combined short options, options with arguments
/// (attached or separate), and basic long option support (flag or with '=').
///
/// Args:
///   argv (array): An array of strings representing the command-line arguments.
///                 Typically, `argv[0]` is the script name, and parsing starts
///                 from `argv[1]`.
///   options (string): A string specifying the valid short options.
///                     - Each character is a short option (e.g., "a", "b", "c").
///                     - If a character is followed by a colon `:`, it signifies
///                       that this short option requires an argument
///                       (e.g., "ab:c" means -a and -c are flags, -b takes an argument).
///                     - Long options are not defined in this string but are parsed
///                       if they start with "--". Their argument requirement is
///                       determined by the presence of an '=' sign.
///
/// Returns:
///   Map:
///     On success:
///       #{
///           "result": #{ // Map of parsed options
///               // e.g., "a": true (for flag -a)
///               //       "b": "value" (for option -b value or -bvalue)
///               //       "long-option": true (for --long-option)
///               //       "another-opt": "val" (for --another-opt=val)
///           },
///           "positional": [ // Array of positional arguments
///               // e.g., "arg1", "arg2"
///           ]
///       }
///     On failure (e.g., unknown short option, missing argument for short option):
///       #{ "error": "Descriptive error message string" }
///
/// Behavior Notes:
///   - Parsing stops at the first non-option argument if options are not intermingled
///     with positional arguments, or when "--" is encountered. Any subsequent
///     arguments are treated as positional. (Current basic implementation might
///     collect all non-options as positional as it finds them).
///   - Combined short options (e.g., `-abc`) are treated as `-a -b -c`.
///   - If a short option in a combined group requires an argument (e.g., `options = "ab:c"`,
///     and `-cbvalue` is passed), `value` is taken as the argument for `b`.
///   - Long options (`--option`):
///     - Are not validated against the `options` string.
///     - If in the form `--option=value`, `option` is set to `"value"`.
///     - If in the form `--option` (no `=`), `option` is set to `true` (boolean flag).
///   - `--`: All subsequent arguments are treated as positional.
//
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
            break;
        } else if arg.starts_with("--") && arg.len() > 2 {
            // Long option (e.g., --option, --option=value)
            let opt_full = arg.sub_string(2, arg.len());
            let opt_name = opt_full;
            let opt_val = true; // Default for flag if no '='

            let eq_idx = opt_full.index_of("=");
            if eq_idx != -1 {
                opt_name = opt_full.sub_string(0, eq_idx);
                opt_val = opt_full.sub_string(eq_idx + 1, opt_full.len());
            }
            result[opt_name] = opt_val;
            i += 1;
        } else if arg.starts_with("-") && arg.len() > 1 {
            // Short options (e.g., -a, -b val, -bval, -abc)
            let short_opts_str = arg.sub_string(1, arg.len());
            let current_opt_char_idx = 0;
            // True if the *next* argv element was consumed as an argument
            // to the last short option in this group.
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
                      // This short option requires an argument
                      if current_opt_char_idx + 1 < short_opts_str.len() {
                           // Argument is attached (e.g., -fFILENAME)
                           result[opt_str] = short_opts_str.sub_string(
                               current_opt_char_idx + 1, short_opts_str.len()
                           );
                           // Consumed the rest of this combined arg token
                           current_opt_char_idx = short_opts_str.len();
                      } else if i + 1 < argv.len() {
                           // Argument is the next argv element (e.g., -f FILENAME)
                           result[opt_str] = argv[i + 1];
                           consumed_next_argv_for_opt = true;
                           current_opt_char_idx += 1; // Move past this option char
                      } else {
                           return #{ "error": `Option '-${opt_str}' requires an argument.` };
                      }
                 } else {
                      // Option is a flag (does not require an argument)
                      result[opt_str] = true;
                      current_opt_char_idx += 1; // Move to next char in combined opts
                 }
            }

            i += 1; // Consumed the current argv element (e.g., "-abc" or "-o")
            if consumed_next_argv_for_opt {
                i += 1; // Also consumed the next argv element if it was an opt arg
            }
        } else {
            // Positional argument
            positional.push(arg);
            i += 1;
        }
    }

    return #{ "result": result, "positional": positional };
}
