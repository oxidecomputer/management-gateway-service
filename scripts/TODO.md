# TODO List for Rhai Test Suite

This document tracks known issues, planned features, and refactoring opportunities for the `upgrade-rollback` test suite.

## High Priority / Bugs & Workarounds

* **Remove `--hubris-2093` Workaround**
    * **Issue**: The `lpc55-update-server` firmware has a bug where setting a persistent preference does not correctly clear a pre-existing pending preference. This is tracked as "Hubris issue #2093".
    * **Workaround**: The `sanitize_boot_preferences` function in `update-helper.rhai` uses a reset to reliably clear a pending preference when the `--hubris-2093` flag is active.
    * **Action**: Once the firmware bug is fixed, the workaround logic should be removed from `sanitize_boot_preferences` and the `--hubris-2093` flag should be removed from `upgrade-rollback.rhai`. The "ideal" logic path should become the only path.

* **Fix `faux-mgs` Error Reporting for `reset-component`**
    * **Issue**: When the SP debugger is attached, the `reset-component sp` command fails. However, the `faux-mgs` Rust code does not gracefully package the detailed error message (`watchdog: RoT error: the SP programming dongle is connected`) into the JSON passed to Rhai. It returns a generic error.
    * **Action**: Modify the error handling in `faux-mgs/src/rhaiscript.rs` to ensure the full, detailed error string from a failed `run_command` is always serialized into the JSON message passed to the Rhai script. *(Self-correction: We have since fixed this by changing the error formatting to `{:?}`, but this note is kept for historical context).*

## Feature Enhancements & New Tests

* **Implement Image Corruption Fault Injection**
    * **Goal**: Add a fault injection test to simulate an incomplete image write, as might happen during a power failure.
    * **Blocker**: This is difficult with the current script API. It would likely require a new `faux-mgs` command to be added in Rust, for example: `faux-mgs update-partial <slot> <image> --bytes <N>`.
    * **Action**:
        1.  Add the new debug command to `faux-mgs`.
        2.  Create a corresponding wrapper in `util.rhai`.
        3.  Add `inject_incomplete_update_fault()` to `update-helper.rhai`.
        4.  Add `"incomplete-write"` to the `--inject-fault` options in `upgrade-rollback.rhai` and implement the test case.

* **Add a Definitive Debugger Check**
    * **Issue**: The current `check_for_sp_debugger` function is heuristic and only works if an update is pending on the SP.
    * **Action**: Investigate if there is a more reliable, deterministic command or register read that can definitively report the presence of an attached and powered-on SWD probe, and update the function accordingly.

* **Add Configuration Schema Validation**
    * **Goal**: Improve robustness by validating the structure of the `targets.json` file when it is parsed in `process_cli`.
    * **Action**: Add checks in `process_cli` to ensure required keys (`images`, `base`, `ut`, etc.) exist to prevent runtime errors later in the script.

## Code Refactoring & Cleanup

* **Improve `util::getopts` for Long Options**
    * **Issue**: The `getopts` function does not support space-separated arguments for long options (e.g., `--option value`), only the `--option=value` format.
    * **Action**: Refactor the long-option parsing logic in `util::getopts` to handle space-separated arguments, which would make it behave more like the standard GNU getopt.

* **Validate Transient Boot with Bootloader Log**
    * **Context**: The `update_rot_hubris` function has a `TODO` referencing "Hubris issue #2066".
    * **Action**: When the bootloader provides a decision log in `RotBootInfo`, update the `rot_validate_initial_transient_boot_state` function to parse this log and confirm that the boot was a result of the transient preference, not a fallback.
