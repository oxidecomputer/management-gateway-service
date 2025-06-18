# Scripting in faux-mgs

The `faux-mgs` utility is useful for testing the APIs and protocols used
between the control plane and service processor (SP) on Oxide hardware.

Testing complex scenarios involving multiple commands, conditional logic based
on hardware state, and interactions across resets can be challenging when
using individual `faux-mgs` commands manually or via simple shell scripts.

`faux-mgs` can be extended with new commands in Rust. For code of
general utility, that is encouraged.

However, it is sometimes desirable to code in a scripting language.
This directory provides the ability to use the embedded **Rhai**
scripting language to automate one-off procedures, test sequences,
and personal workflows.

## Benefits of Rhai Scripting

* **Stateful Interaction:** Scripts maintain the connection (discovery, etc.)
    to the SP across multiple command invocations within the same `faux-mgs`
    process, leading to faster execution compared to separate calls.
* **Structured Data:** Command output (using the required `--json=pretty`
    internal format) is automatically available to scripts as native Rhai maps
    or other types, simplifying data extraction and conditional logic.
* **Portability:** Test logic is contained within Rhai scripts, which are
    as portable as the `faux-mgs` binary itself.
* **Multi-Target Execution:** Scripts can leverage `faux-mgs`'s ability to
    run against multiple SPs simultaneously by providing multiple `--target`
    arguments to `faux-mgs`.
* **Extensibility:** Provides access to file system, environment variables,
    and time functions within the script.

## Rhai Integration Details

* **Entry Point:** These Rhai scripts must define a `main()` function that
    returns an integer (`fn main() -> i64`), typically `0` for success and
    non-zero for failure.
* **Available Globals:** The following globals are available within the
    script's scope:
    * `argv`: An array of string arguments passed to the script after `--`
        on the `faux-mgs` command line (e.g., `["script_name", "arg1", ...]`)
    * `interface`: The value of the `faux-mgs --interface` argument (string).
    * `reset_watchdog_timeout_ms`: The configured watchdog timeout (integer).
    * `rbi_default`: The highest known RoT Boot Info version (integer string).
    * `script_dir`: The canonical path to the directory containing the
        main script file (string).
* **Extra Rhai Packages:** The following packages are enabled:
    * `rhai_env::EnvironmentPackage`: Access user environment variables (`env`, `envs`).
    * `rhai_fs::FilesystemPackage`: Access the file system (`open_file`, `path`, etc.).
    * `rhai_chrono::ChronoPackage`: Standard time/date functions (`timestamp`, `datetime_local`, `sleep`).
* **Logging:** The standard Rhai `debug()` function is routed to the `faux-mgs`
    logging system (`slog`). Prefixing the message with `"level|"` (e.g.,
    `"warn|Message"`, `"info|Message"`, `"error|Message"`, `"trace|Message"`)
    logs at the corresponding level. Unprefixed messages default to `info`.
* **Custom Functions/Types (Built-in):** Core functions provided by the
    `faux-mgs` Rust integration:
    * `faux_mgs(["arg0", .., "argN"]) -> map`: Runs any `faux-mgs` command
        internally (using `--json=pretty`) and returns the result as a Rhai map.
        *Do not call this directly in test scripts; use wrappers from `util.rhai`.*
    * `new_archive(path) -> ArchiveInspector`: Loads a Hubris archive (.zip).
    * `ArchiveInspector[<zip_path>]`: Access files within the archive (returns
        string/blob based on extension). Use `.caboose` property to get a
        `CabooseInspector`.
    * `ArchiveInspector.verify_rot_image(cmpa_blob, cfpa_blob) -> bool`:
        Verifies RoT image signature against provided CMPA/CFPA blobs.
    * `CabooseInspector[<TAG>]`: Access caboose tags (e.g., `GITC`, `VERS`).
    * `json_to_map(string) -> map`: Converts a JSON string to a Rhai map.
    * `system(["cmd", .., "argN"]) -> map`: Runs an external OS command
        (no shell expansion) and returns `#{ exit_code: i64, stdout: str, stderr: str }`.
        *Use with caution.*

## Utility Scripts (`scripts/util.rhai`)

Common helper functions, constants, and wrappers around direct `faux_mgs` calls
are placed in `scripts/util.rhai`. Scripts should import this using:

```rhai
import `${script_dir}/util` as util;
```

### Key utilities provided:

-   **Constants:** `ROT_FLASH_PAGE_SIZE`.
-   **Formatting:** `to_hexstring`, `cstring_to_string`, `array_to_mac`.
-   **Data Handling:** `env_expand`, `array_to_blob`, `ab_to_01`.
-   **Hardware Info:** `get_cmpa`, `get_cfpa`, `get_rot_keyset`, `state`,
    `caboose_value`, `get_device_cabooses`.
-   **`faux_mgs` Wrappers:**
    -   `rot_boot_info()`: Gets formatted RoT Boot Info.
    -   `check_update_in_progress(component)`: Checks SP/RoT update status.
    -   `update_rot_image_file(slot, path, label)`: Updates RoT image.
    -   `set_rot_boot_preference(slot, use_transient, label)`: Sets RoT pref.
    -   `reset_rot_and_get_rbi(desc, label)`: Resets RoT and gets RBI.
    -   `update_sp_image(path)`: Updates SP image.
    -   `reset_sp()`: Resets SP.
    -   *(More wrappers can be added for other commands like `update-abort`,*
        *`reset-component`, etc.)*
-   **Argument Parsing:** `getopts(argv, options_string)`: Parses script arguments.

## Example Script (`scripts/upgrade-rollback.rhai`)

This script automates testing firmware upgrades and subsequent rollbacks between
two specified sets of firmware builds (a "baseline" and an "under-test" version).

### Configuration:

-   Uses `scripts/targets.json` to define paths to firmware repositories,
    specific image zip files, board names, and potentially other settings like
    IPCC or power control commands.
-   Supports `${VAR}` expansion in paths within `targets.json`, referencing
    environment variables or other keys within the JSON file itself via
    `util::env_expand`.

### Key Command-Line Options:

-   `-b <path>`: **Optional.** Path to the baseline Hubris repo`
-   `-c <path>`: **Required.** Path to the JSON configuration file
    (e.g., `scripts/targets.json`).
-   `-t`: Enable testing using the RoT "transient boot preference" feature.
    The script attempts to use this mechanism if the active RoT supports it
    and handles differences in behavior when targeting older "baseline" RoTs
    that may not fully support the feature.
-   `-u <path>`: **Optional.** Path to the under-test Hubris repo`
-   `-v`: Verbose output (enables more `debug("info|...")` messages).
-   `-h`: Show help message.

### Example Invocation:

Assumes `faux-mgs` is built with `rhaiscript` feature enabled.

```bash
# Set environment variable used in targets.json for the 'under-test' repo, e.g.
export UT_WORKTREE=my-feature-branch

# Run faux-mgs, targeting the script, providing config and transient flag,
# and overriding repo paths via positional arguments after '--'
# Ensure the shell expands UT_WORKTREE in the path argument
cargo run --bin faux-mgs --features=rhaiscript -- \
  --interface=enp5s0 \
  --log-level=info \
  rhai scripts/upgrade-rollback.rhai \
  -c scripts/targets.json -t \
  -b $HOME/Oxide/src/hubris/master \
  -u $HOME/Oxide/src/hubris/${UT_WORKTREE}

# Check exit code
echo $?
```

## Running Scripts Generally

Use the `rhai` subcommand of `faux_mgs`:

```bash
faux-mgs [faux-mgs options] rhai <script_path.rhai> [script options] -- [script arguments]
```

-   **`faux-mgs options`**: Standard options like `--interface`, `--target`,
    `--log-level`. Note that `--json=pretty` is used *internally* for commands
    called via the `faux_mgs()` function within Rhai, but you might set
    `--log-level` for the overall execution.
-   **`script_path.rhai`**: Path to the main Rhai script.
-   **`script options`**: Currently none defined globally, but scripts might parse
    their own using `util::getopts`.
-   **`--`**: Separates `faux_mgs` options from arguments intended for the script.
-   **`script arguments`**: Arguments passed to the script's `argv` global array.

## Contributing / TODO

See [`scripts/TODO.md`](TODO.md) for more details.

## SP and RoT Update/Rollback test plan

See [`scripts/TEST_PLAN.md`](TEST_PLAN.md) for more details.
