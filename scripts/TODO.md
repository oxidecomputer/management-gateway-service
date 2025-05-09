# TODO List for Rhai scripting in the `faux-mgs` utility

  - Prioritize this list in favor of code correctness, clarity, security, and testability.

## Refactoring, Code Quality & Maintainability

  - Refactor any direct calls to `faux_mgs()` into the `scripts/util.rhai` file.
    * **Solution:** Identify all `faux_mgs([...])` calls in `*.rhai` scripts (e.g., `upgrade-rollback-transient.rhai`) and create corresponding wrapper functions in `util.rhai` that provide a clearer interface and handle potential errors more gracefully.
  - Refactor any repeated code snippets in Rhai scripts into reasonable functions, likely within `util.rhai` or script-specific helper functions.
    * **Solution:** Analyze scripts for duplicated logic (e.g., common setup sequences, polling loops, result parsing) and abstract them into reusable functions.
  - Remove dead code and useless comments from all scripts and Rust files.
    * **Solution:** Perform a thorough code review to identify and remove unused variables, functions, and comments that no longer add value or are out of date.
  - The calling convention and error reporting for functions in `scripts/util.rhai` seems clunky. Can it be improved?
    * **Solution:** Design a consistent error handling pattern for `util.rhai` functions. For example, functions could return a map like `#{ ok: result, err: error_message }` or leverage Rhai's error throwing/catching mechanisms more consistently. Document this pattern.
  - The top level flow in `main()` of `upgrade-rollback-transient.rhai` (and other complex scripts) should be easy to read and understand.
    * **Solution:** Break down large `main()` functions into smaller, well-named functions that represent logical stages of the script. Aim for a declarative style at the top level.
  - Consider breaking down very long Rhai scripts (e.g., `upgrade-rollback-transient.rhai`) into smaller, more manageable modules or by importing other Rhai scripts.
    * **Solution:** Explore Rhai's `import` capabilities further to logically segment parts of complex scripts (e.g., CLI parsing, image handling, update logic specific to components).
  - Standardize logging practices within Rhai scripts.
    * **Solution:** Define guidelines for log levels (using the `debug("level|message")` convention) and message formats to ensure consistent and useful log output.
  - (From `rhaiscript.rs`) Check for non-string non-i64 values in the `faux_mgs` `script_args` from Rhai and return an error instead of potentially panicking during execution.
    * **Solution:** In `faux-mgs/src/rhaiscript.rs`, before converting `script_args` to `Vec<String>`, iterate and validate each `serde_json::Value` to ensure it's a string or number. If not, send an appropriate error JSON back to the Rhai script.

## Error Handling & Robustness

  - The new transient boot preference selection feature is not present in the current baseline RoT Hubris image. The `upgrade-rollback-transient.rhai` test doesn't handle this as well as it could.
    * **Solution:** Modify the script to gracefully detect if the transient boot preference feature is supported by the current RoT. If not, either skip transient-specific tests with a clear message or use an alternative validation path.
  - (From `upgrade-rollback-transient.rhai`) Need a better liveness test and decision on failure for RoT reset in `update_rot_hubris`.
    * **Solution:** Instead of a fixed `sleep()`, implement a polling mechanism (e.g., trying to read `rot_boot_info()` or another status indicator) with a timeout to confirm RoT is responsive after reset. Define clear actions for timeout/failure.
  - (From `upgrade-rollback-transient.rhai`) Implement fault insertion and test recovery paths, especially for transient boot failures during RoT updates.
    * **Solution:** Design specific test scenarios that intentionally cause failures (e.g., using a corrupted image if verification is bypassed, or power cycling at critical moments if power control is available). Verify that the script's recovery mechanisms (or manual recovery steps) work.
  - Improve error reporting from Rust Rhai integration back to the script and user.
    * **Solution:** Ensure that errors originating in `rhaiscript.rs` or `hubris.rs` (e.g., file access, command execution, archive parsing) are propagated to Rhai as structured error objects/maps rather than generic strings, allowing scripts to make better decisions.

## Testing & Validation

  - Develop a test suite or test harness for Rhai scripts.
    * **Solution:** Create a framework (perhaps another Rhai script or a Rust test module) that can execute test scripts. This might involve mocking `faux_mgs` calls to simulate different hardware responses and test script logic in isolation.
  - Add unit tests for utility functions in `scripts/util.rhai`.
    * **Solution:** Write Rhai test functions within `util.rhai` or in separate test scripts that call and verify the behavior of functions like `env_expand`, `to_hexstring`, `getopts`, etc., with various inputs.
  - Implement schema validation for `scripts/targets.json` and any other JSON configuration files used by scripts.
    * **Solution:** Define a JSON schema. This could be validated by a Rhai function at script startup using `json_to_map` and manual checks, or by an external tool during a linting/CI step.
  - Review the `getopts` function in `util.rhai` (generated by Gemini) for completeness, edge cases, and adherence to common `getopts` behavior.
    * **Solution:** Test `getopts` with a comprehensive set of argument patterns, including combined short options, options with and without arguments, optional arguments, various uses of `--`, and error conditions. Compare behavior with standard `getopts`.

## Features & Enhancements

  - (From `upgrade-rollback-transient.rhai`) When `hubtools` has `fwidgen` integrated and SP/RoT can report FWID for active/inactive banks, transition to FWID-based assessment instead of relying solely on GITC/VERS.
    * **Solution:** Monitor `hubtools` and firmware developments. Once available, update `image_check` and related functions to fetch and use FWIDs for more precise image identification.
  - (From `upgrade-rollback-transient.rhai`) Parameterize update orders (e.g., SP then RoT, or RoT then SP) for upgrade and rollback scenarios, potentially via `targets.json`.
    * **Solution:** Add a configuration option in `targets.json` (e.g., `"update_sequence": ["sp", "rot"]`) and modify the `upgrade-rollback-transient.rhai` script to respect this order.
  - (From `upgrade-rollback-transient.rhai`) Allow specifying a TUF repository as a source for baseline or under-test images.
    * **Solution:** This is a larger feature. It would likely involve adding new `faux_mgs` commands or Rhai functions to interact with TUF (e.g., download artifacts, verify metadata). An alternative is a separate tool that prepares a `targets.json`-compatible structure from a TUF repo.
  - (From `upgrade-rollback-transient.rhai`) Do some sanity checks in `get_image_info` to make sure `BORD` and `NAME` from image cabooses are appropriate for the attached SP/hardware.
    * **Solution:** Fetch expected `BORD`/`NAME` from the connected SP (if possible via `faux-mgs state` or similar) and compare against values from the image caboose being processed. Log warnings or errors if mismatched.
  - (From `upgrade-rollback-transient.rhai`) Add a warning in `get_image_info` if the base and under-test images (especially SP or RoT images) have the same GITC, as this might indicate a misconfiguration unless it's for components like stage0 that might only differ in packaging.
    * **Solution:** Store GITCs seen for base images and compare them against UT images. If a match is found for critical components, issue a prominent warning.
  - Add a power control function for testing recovery after a failed RoT Hubris update. Power control is through a configured shell command run via Rhai `system()`.
    * **Solution:**
        1.  Define a structure in `targets.json` for power control commands (e.g., `power_control: { rot: { on: "cmd_rot_on", off: "cmd_rot_off", status: "cmd_rot_status" } }`).
        2.  Create functions in `util.rhai` (e.g., `power_cycle_rot(conf)`) that use `system()` to execute these configured commands.
        3.  Integrate these into test scripts where power cycling is needed for recovery.
  - Add a power control function for controlling the STLINK probe attached to the SP, similar to the RoT power control.
    * **Solution:**
        1.  Extend `targets.json` for STLINK power commands (e.g., `power_control: { stlink: { ... } }`).
        2.  Add corresponding functions in `util.rhai`.
  - Develop a library of common pre-flight checks for scripts.
    * **Solution:** Create functions in `util.rhai` that check for SP connectivity, required tools (`jq` if used by `system` calls), minimum `faux-mgs` version, etc. Scripts can call these at the beginning.
  - Explore creating a template or skeleton for new Rhai test scripts.
    * **Solution:** Develop a basic `.rhai` file that includes common imports (`util.rhai`), `main()` structure, `usage()` function, CLI argument parsing setup, and placeholders for test logic.
  - Investigate providing more context/globals from `faux-mgs` (Rust) to Rhai scripts if useful.
    * **Solution:** Review `faux-mgs/src/rhaiscript.rs` and identify if additional information from the `SingleSp` struct or global `faux-mgs` settings would be beneficial to scripts, then add them to the Rhai `Scope`.
  - Expose more `hubtools::RawHubrisArchive` or `hubtools::Caboose` functionality through Rhai custom types/functions if needed.
    * **Solution:** If scripts frequently need to perform complex operations on archives/cabooses currently done with intricate Rhai logic, consider adding new methods to `ArchiveInspector` or `CabooseInspector` in `faux-mgs/src/rhaiscript/hubris.rs`.

## Documentation

  - Update the `scripts/README.md` file.
    * **Solution:** Review and update `README.md` to reflect new features, functions added to `util.rhai`, changes in script execution, and new scripts. Add a section on error handling and debugging.
  - Properly document any non-obvious functions in Rhai scripts and in `util.rhai`.
    * **Solution:** Add comments explaining the purpose, arguments, return values, and any non-trivial logic for functions. Use a consistent documentation style.
  - Document the schema for `scripts/targets.json` thoroughly.
    * **Solution:** Create a section in `README.md` or a separate `CONFIG_SCHEMA.md` detailing all possible keys in `targets.json`, their purpose, expected values, and if they are optional or required.
  - Expand `README.md` with more examples, advanced usage scenarios, and a guide on writing new scripts.
    * **Solution:** Add sections covering common patterns, best practices for scripting with `faux-mgs`, how to debug scripts, and step-by-step examples of creating a new test script.

## Configuration Management

  - Allow easier local overrides for `scripts/targets.json` without direct modification.
    * **Solution:** Implement logic in `process_cli` (or a dedicated config loading function in `util.rhai`) to look for an optional `targets.local.json` and merge its values over the base `targets.json`.
  - Consider a `faux-mgs` subcommand or a utility script to validate a script's configuration (`targets.json`).
    * **Solution:** This could be a Rhai script itself (`check_config.rhai`) that loads `targets.json`, performs schema checks, and verifies path existence for images.

## Security

  - Harden the `system()` function in `rhaiscript.rs` if scripts are ever run in less trusted environments or with externally sourced configurations.
    * **Solution:** Options:
        1.  Add a `faux-mgs` CLI flag to disable `system()` altogether.
        2.  Introduce a configuration setting (e.g., in `faux-mgs` config or an environment variable) to provide a whitelist or blacklist of allowed commands for `system()`.
        3.  Log all `system()` calls prominently.
  - Review security implications of file system access granted to Rhai scripts, especially if script sources or configurations could be untrusted.
    * **Solution:** Document the trust model for Rhai scripts. If necessary, explore options to restrict `rhai_fs::FilesystemPackage` (e.g., to subdirectories of the main script or project).

## CI/CD (Continuous Integration / Continuous Delivery)

  - Integrate static analysis or linting for Rhai scripts into a CI pipeline.
    * **Solution:** While specific Rhai linters might be rare, a CI step could check for basic syntax validity (`rhai-cli check <script>`) or enforce formatting conventions using a generic code beautifier if applicable.
  - Automate the execution of key Rhai test scripts in CI.
    * **Solution:** If a test harness and mock `faux_mgs` are developed (see Testing section), run these tests in CI. For tests requiring real hardware, integrate them into a hardware-in-the-loop (HIL) testing rig if available.

## Future/Deferred

  - When there is a new baseline image that does have the transient boot feature, it will change the success criteria for the `upgrade-rollback-transient.rhai` test.
    * **Solution:** This is an expected future change. The script should be updated to assert successful use of transient boot once the baseline supports it. This might involve version checking or feature detection of the baseline RoT.
