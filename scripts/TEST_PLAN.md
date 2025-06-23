# Validation Test Plan

This document outlines a full set of tests to validate the `upgrade-rollback.rhai` test harness. It is split into two parts:
1.  **Part 1**: Tests the current, real-world scenario where the new `baseline` firmware has features that the older `under-test` firmware lacks.
2.  **Part 2**: Describes tests for a future state where both `baseline` and `under-test` firmware are fully compliant with the transient boot preference feature.

## Prerequisites and Setup

### 1. Environment Variables

Before running these tests, for convenience, set two environment variables to point to your local Hubris build repositories:
```bash
export REPO_BL=/path/to/your/baseline/hubris
export REPO_UT=/path/to/your/under-test/hubris
```

These repositories must have SP and RoT Hubris build products in their
respective `target/` directories.

Examine and edit the `scripts/targets.json` file or make your own if you need
to use images from other locations.

### 2. The `FMR` Wrapper Script

The test commands use a helper script named `FMR`, which is a wrapper around the main `cargo run --bin faux-mgs` command. Its purpose is to simplify running tests by automatically including common arguments.

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
```

---

## Part 1: Testing Asymmetric Feature Support (Current State)

**Assumption**: For this set of tests, `$REPO_BL` points to an **old** firmware build that **does not** support the transient boot preference feature, and `$REPO_UT` points to a **new** build that does.

### Test 1.1: Standard Workflow (Golden Path)

* **Purpose**: To verify that the primary upgrade and rollback functionality works correctly without using any of the new features.
* **Command**:
    ```bash
    FMR-info rhai scripts/upgrade-rollback.rhai -c scripts/targets.json \
      -b $REPO_BL -u $REPO_UT
    ```
* **Expected Outcome**: The script should complete successfully with an exit code of 0. It will upgrade to the `under-test` image and then roll back to the `baseline` image using persistent updates.

### Test 1.2: Transient Boot Path (`-t` flag)

* **Purpose**: To verify the script correctly handles the feature asymmetry when the transient update path is requested.
* **Command**:
    ```bash
    FMR-info rhai scripts/upgrade-rollback.rhai -c scripts/targets.json \
      -b $REPO_BL -u $REPO_UT -t
    ```
* **Expected Outcome**: The script should complete successfully with an exit code of 0. The log should show:
    * **Upgrade**: The active `baseline` firmware does not support the feature. The script will log a warning and use a persistent update.
    * **Rollback**: The now-active `under-test` firmware supports the feature. The script will correctly use a transient update for the rollback.

### Test 1.3: Negative Test (`-N`) Workflow

* **Purpose**: To verify the logic that runs (or skips) the `test_and_recover...` negative test based on feature support.
* **Command**:
    ```bash
    FMR-info rhai scripts/upgrade-rollback.rhai -c scripts/targets.json \
      -b $REPO_BL -u $REPO_UT -N
    ```
* **Expected Outcome**: The script will **fail with exit code 1**. This is the correct behavior.
    * **Upgrade**: The `baseline` firmware is active and does not support the transient feature. The script will detect this and, because the test is for the `ut` branch, it will log a `FATAL` error stating the `under-test` image must support the feature. This check is known to be flawed for this specific asymmetric case but correctly protects against regressions.

### Test 1.4: Fault Injection - Conflicting `pending` Preference

* **Purpose**: To verify that the test harness can recover from a pre-existing `pending_persistent` preference fault.
* **Command**:
    ```bash
    FMR-info rhai scripts/upgrade-rollback.rhai -c scripts/targets.json \
      -b $REPO_BL -u $REPO_UT \
      --inject-fault=pending --hubris-2093
    ```
* **Expected Outcome**: The script should run the "pending" fault injection test and exit with code 0. The log will show the sanitizer detecting the fault and using the reset-based workaround to clear it before the main test flow runs successfully.

### Test 1.5: Fault Injection - Conflicting `transient` Preference

* **Purpose**: To verify the test harness correctly handles the inability to inject a fault into non-compliant firmware.
* **Command**:
    ```bash
    FMR-info rhai scripts/upgrade-rollback.rhai -c scripts/targets.json \
      -b $REPO_BL -u $REPO_UT \
      --inject-fault=transient
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
    FMR-info rhai scripts/upgrade-rollback.rhai -c scripts/targets.json \
      -b $REPO_BL -u $REPO_UT -t
    ```
* **Expected Outcome**: The script should complete successfully with an exit code of 0. The log should show a transient update is used for **both** the upgrade to `ut` and the subsequent rollback to `base`.

### Test 2.2: Negative Test (`-N`) Workflow

* **Purpose**: To verify that the negative test runs successfully in both directions when all firmware is compliant.
* **Command**:
    ```bash
    FMR-info rhai scripts/upgrade-rollback.rhai -c scripts/targets.json \
      -b $REPO_BL -u $REPO_UT -N
    ```
* **Expected Outcome**: The script should complete successfully with an exit code of 0. The `test_and_recover_from_preferred_slot_update_failure` function should be executed and pass for the `ut` branch during the upgrade, and then be executed and pass **again** for the `base` branch during the rollback.
