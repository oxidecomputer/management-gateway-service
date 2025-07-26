# Validation Test Plan

This document outlines a full set of tests to validate the `upgrade-rollback.rhai` test harness. It is split into two parts:
1.  **Part 1**: Tests the current, real-world scenario where the new `under-test` firmware has features that the older `baseline` firmware lacks.
2.  **Part 2**: Describes tests for a future state where both `baseline` and `under-test` firmware are fully compliant with the transient boot preference feature.

## Prerequisites and Setup

### 1. Environment Variables

Before running these tests, for convenience, set environment variables to point to your local Hubris build repositories. For example:
```bash
export REPO_BL=/path/to/your/baseline/hubris
export REPO_UT=/path/to/your/under-test/hubris
export UT_WORKTREE=${REPO_UT}
```

These repositories must have SP and RoT Hubris build products in their
respective `target/` directories.

**Note for other users**: The `scripts/targets.json` file uses these environment variables (e.g., `UT_WORKTREE`) to locate firmware images. If simple environment variable overrides are not convenient, then you will want your own configuration file like `scripts/targets.json` that reflects your local test environment.

### 2. The `FMR` Wrapper Script

The test commands use a helper script named `FMR` (faux-mgs with Rhai scripting), which is a wrapper around the main `cargo run --bin faux-mgs` command. Its purpose is to simplify running tests by automatically including common arguments.

* **Functionality**: The script automatically adds required arguments like `--features=rhaiscript`, `--json=pretty`, timeouts, and attempts to discover the correct network `--interface` setting.
* **Log Levels**: The name used to call the script sets the log level for the test run. For example, `FMR-info` sets `--log-level=info`, while `FMR-trace` sets `--log-level=trace`.
* **Setup**: To create the convenient `FMR-info`, `FMR-debug`, etc. symlinks in your working directory, you can run the following command from the repository root:
    ```bash
    ./scripts/FMR link
    ```

### 3. Clean State

Each numbered test case should be run from a known-clean state. Before starting a test, please perform two RoT resets:
```bash
FMR-info reset-component rot
FMR-info reset-component rot

This ensures that any version of RoT firmware being used has no pending Hubris
image preferences in effect.

### 3. Copy and customize `scripts/targets.json` for your environment

```bash
TARGETS=targets-$(uname-n).json
cp scripts/targets.json $TARGETS
# Edit $TARGETS appropriately
```

Note that the `upgrade-rollback.rhai` script has a `-b` and `-u` options to
override the baseline and under-test paths in `scripts/targets.json`, so if that
is the only thing you want to change you can just use those CLI flags.


---

## Version Compatibility and Graceful Degradation

The test scripts include robust version compatibility handling for the `--cancel-pending` feature:

* **Preferred Method**: When supported, the scripts use `faux-mgs component-active-slot -c` to directly clear pending persistent preferences.
* **Fallback Method**: When the SP firmware doesn't support the command (indicated by a "WrongVersion" error), the scripts automatically fall back to the RoT reset workaround.
* **Seamless Operation**: This compatibility layer ensures tests work across different firmware versions without manual intervention.

During the transition period where some devices have updated firmware and others don't, the test suite will automatically use the appropriate method for each device.

---

## Part 1: Testing Asymmetric Feature Support (Current State)

**Assumption**: For this set of tests, `$REPO_BL` points to an **old** firmware build that **does not** support the transient boot preference feature, and `$REPO_UT` points to a **new** build that does.

### Test 1.1: Standard Workflow (Golden Path)

* **Purpose**: To verify that the primary upgrade and rollback functionality works correctly without using any of the new features.
* **Command**:
    ```bash
    ./FMR-info rhai scripts/upgrade-rollback.rhai -c $TARGETS
    ```
* **Expected Outcome**: The script should complete successfully with an exit code of 0. It will upgrade to the `under-test` image and then roll back to the `baseline` image using persistent updates.

### Test 1.2: Transient Boot Path (`-t` flag)

* **Purpose**: To verify the script correctly handles the feature asymmetry when the transient update path is requested.
* **Command**:
    ```bash
    ./FMR-info rhai scripts/upgrade-rollback.rhai -c $TARGETS -t
    ```
* **Expected Outcome**: The script should complete successfully with an exit code of 0. The log should show:
    * **Upgrade**: The active `baseline` firmware does not support the feature. The script will log a warning and use a persistent update.
    * **Rollback**: The now-active `under-test` firmware supports the feature. The script will correctly use a transient update for the rollback.

### Test 1.3: Negative Test (`-N`) Workflow

* **Purpose**: To verify the logic that runs (or skips) the `test_and_recover...` negative test based on feature support.
* **Command**:
    ```bash
    ./FMR-info rhai scripts/upgrade-rollback.rhai -c $TARGETS -N
    ```
* **Expected Outcome**: The script will **fail with exit code 1**. This is the correct behavior.
    * **Upgrade**: The `baseline` firmware is active and does not support the transient feature. The script will detect this and, because the test is for the `ut` branch, it will log a `FATAL` error stating the `under-test` image must support the feature. This check is known to be flawed for this specific asymmetric case but correctly protects against regressions.

### Test 1.4: Fault Injection - Conflicting `pending` Preference

* **Purpose**: To verify that the test harness can recover from a pre-existing `pending_persistent` preference fault.
* **Command**:
    ```bash
    ./FMR-info rhai scripts/upgrade-rollback.rhai -c $TARGETS --inject-fault=pending
    ```
* **Expected Outcome**: The script should run the "pending" fault injection test and exit with code 0. The log will show the sanitizer detecting the fault and attempting to use the `faux-mgs component-active-slot -c` command to clear it. If the firmware supports the command, it will clear the fault directly. If there's a version mismatch (e.g., "WrongVersion { sp: 19, request: 20 }"), the system will fall back to the RoT reset workaround and still complete successfully.

### Test 1.5: Fault Injection - Conflicting `transient` Preference

* **Purpose**: To verify the test harness correctly handles the inability to inject a fault into non-compliant firmware.
* **Command**:
    ```bash
    ./FMR-info rhai scripts/upgrade-rollback.rhai -c $TARGETS --inject-fault=transient
    ```
* **Expected Outcome**: The script is **expected to fail with exit code 1**. This is the correct outcome. The log will show:
    1. The script first installs the `baseline` (`master`) firmware.
    2. It then attempts to run the `transient` fault injection test.
    3. The `helper::inject_conflicting_transient_preference()` function will fail because the active `baseline` firmware does not support the transient preference command.
    4. The script will log an error like "Failed to inject transient preference fault" and exit. This proves the test harness correctly identifies that the fault cannot be created.

---

## Part 2: Testing Symmetric Feature Support (Future State)

**Assumption**: For this set of tests, assume **both** `$REPO_BL` and `$REPO_UT` point to firmware builds that support the transient boot preference feature.

### Test 2.1: Transient Boot Path (`-t` flag)

* **Purpose**: To verify that when both images are compliant, the script uses the transient update path for both the upgrade and the rollback.
* **Command**:
    ```bash
    ./FMR-info rhai scripts/upgrade-rollback.rhai -c $TARGETS -t
    ```
* **Expected Outcome**: The script should complete successfully with an exit code of 0. The log should show a transient update is used for **both** the upgrade to `ut` and the subsequent rollback to `base`.

### Test 2.2: Negative Test (`-N`) Workflow

* **Purpose**: To verify that the negative test runs successfully in both directions when all firmware is compliant.
* **Command**:
    ```bash
    ./FMR-info rhai scripts/upgrade-rollback.rhai -c $TARGETS -N
    ```
* **Expected Outcome**: The script should complete successfully with an exit code of 0. The `test_and_recover_from_preferred_slot_update_failure` function should be executed and pass for the `ut` branch during the upgrade, and then be executed and pass **again** for the `base` branch during the rollback.
