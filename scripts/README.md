# Scripting in faux-mgs

The `faux-mgs` utility is useful for testing the APIs and protocols used
between the control plane and service processor.

The choices for testing over multiple messages with behavior conditional
on results against real hardware becomes more challenging.

`Faux-mgs` itself can be extended to include any new command or
test. But for one-off scripting, personal development bench tests, or
other contexts, such as tying a CI test to a certain set of hardware,
the mix of scripts and faux-mgs commands can quickly become unwieldy.

`Faux-mgs` supports a `--json pretty` output format for all commands. So,
using any scripting language, including bash, becomes much easier with
the language's JSON libraries or use of the `jq` program.

Here, another option is provided; the embedded Rhai scripting language
is used to extend `faux-mgs`.

The JSON output from `Faux-mgs` means that all commands already produce
an easy to parse output format. That format is easily translated to a Rhai
`map`.

The `clap` parser used by `faux-mgs` isn't limited to parsing the `argv`
from the OS command line interface. It can also be called internal to
`faux-mgs` on an arbitrary string array.

This standardized command I/O means that the interpreter integration
does not have to be aware of any particular `faux-mgs` command. The
exception being itself in order to prevent recursive calls.

Nice attributes:
  - Faster, because the "connection" (discovery, etc.) to the SP is
    reused between commands and multiple commands are run from the same
    faux-mgs process.
  - Command output is made available to scripts in a Rhai native format
  - the script is as portable as `faux-mgs`
  - The feature of faux-mgs of being able to run the same command
    against multiple SPs means that a script can also be run that way.

## Rhai Integration

Rhai calls the script's `main() -> i64 {}`.

### Globals available to the script are the:

  - `argv` array of string arguments that trail the `clap`/OS CLI `rhai` command.
  - `interface` the value of the `faux-mgs` `--interface` argument.
  - `reset_watchdog_timeout_ms`
  - `rbi_default` is RotBootInfo::HIGHEST_KNOWN_VERSION
  - `script_dir` is the canonical path to the directory of the main
     script file.

### Extra Rhai Packages used include:

  - rhai_env::EnvironmentPackage - user environment variables
  - rhai_fs::FilesystemPackage - file system access
  - [rhai_chrono::ChronoPackage](https://github.com/iganev/rhai-chrono) - standard time formats.

### Modified Rhai behavior
  - The `debug("message")` function is routed to the faux-mgs slog logging.
    Prefixing a message with "crit|", "trace|", "error|", "warn|", "error|", or "debug|"
    will log at that corresponding level. Leaving off the prefix or using some other
    prefix will log at the debug level.

### Custom functions:

  - faux_mgs(["arg0", .., "argN"]) -> #{} // Run any faux-mgs command -> map
  - RawHubrisArchive
      - new_archive(path) -> ArchiveInspector // RawHubrisArchive inspection
      - indexer (get via var["index"]) for ArchiveInspector
          - zip path name to blob or string as appropriate according to
            internal rules (e.g. .bin, elf/*, etc are blobs)
  - verify_rot_image(image_blob, cmpa, cfpa) -> bool // verify RoT image signature
  - json_to_map(string) -> #{} // convert any JSON to a Rhai map
  - system(["argv0", .., "argvN"]) -> #{"exit_code": i64, "stdout": str, "stderr": str}
      - run any command. Note: no shell expansion, this is std::process::Command

### Script utility functions

See `scripts/util.rhai` for additional utility functions.

## Running a script

In this example, we use bash wrapper "FM" to save typing.
`faux-mgs` command against a particular SP (Grapefruit).

```bash
#!/usr/bin/bash
if [[ "${1:-}" == "--too-quick" ]]
then
  shift
  # too fast for update to succeed. Used to trigger update watchdog.
  MAXATTEMPTS=5
  MAXATTEMPTS_RESET=1
  PER_ATTEMPT_MS=2000
else
  # Normal values
  MAXATTEMPTS=5
  MAXATTEMPTS_RESET=30
  # PER_ATTEMPT_MS=2000
  # 2165 is on the edge
  PER_ATTEMPT_MS=2200
fi

cargo -q run --bin faux-mgs --features=rhaiscript -- \
  --log-level=crit \
  --interface=enp5s0 \
  --json=pretty \
  --max-attempts=${MAXATTEMPTS} \
  --max-attempts-reset=${MAXATTEMPTS_RESET} \
  --per-attempt-timeout-millis=${PER_ATTEMPT_MS} \
  "$@"
```


A `getops` utility function provides command line parsing within
the script.

### An update/rollback test

For the upgrade-rollback script, a JSON configuration file supplies
paths or other parameters needed to configure the script.

For convenience, it is assumed that there are two repos with there
respective Grapefruit SP and RoT images built.

#### Running update-rollback between the master branch and your new code:

```bash
BASELINE=$HOME/Oxide/src/hubris/master
UNDER_TEST=$HOME/Oxide/src/hubris/my-new-branch
./FM rhai scripts/upgrade-rollback.rhai -- \
    -c scripts/targets.json ${BASELINE} ${UNDER_TEST}
```

See the scripts themselves for further information.
