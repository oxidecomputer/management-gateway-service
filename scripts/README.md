# Scripting in faux-mgs

The `faux-mgs` utility is useful for testing the APIs and protocols used
between the control plane and service processor.

The choices for testing over multiple messages with behavior conditional
on results against real hardware becomes more challenging.

`Faux-mgs` itself can be extended to include any new command or test. But
for one-offs, personal, or other contexts, such as tying a CI test to
a certain set of hardware, the mix of scripts and faux-mgs commands can
quickly become unweildy.

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
  - Faster, because the connection to the SP is reused between commands
  - command output is made available to scripts in a Rhai native format
  - the script is as portable as `faux-mgs`

## Rhai Integraion

Rhai calls the script's `main() -> i64 {}` function.

Globals available to the script are the:
  - `argv` array of string arguments that trail the `clap`/OS CLI `rhai` command.
  - `interface` the value of the `faux-mgs` `--interface` argument.
  - `reset_watchdog_timeout_ms`

TODO: a numeric exit code from the script should be propagated to some useful place.

TODO: Integrate humility in some way. Probably just running it in a shell and collecting
stdout, stderr, and its exit code, passing those back to the Rhai script in a map.
e.g.:
```json
{
    "stdout": "program output",
    "stderr": "error messages",
    "exit_code": 0
}
```

## Running a script

A bash wrapper in a file called `FM` to run any `faux-mgs` command
against a particular SP (Grapefruit).

```bash
#!/usr/bin/bash
INTERFACE="--interface $(ip -br a | awk '$2 == "UP" {print $1}' -)"
DISCOVERY_ADDR=--discovery-addr='[fe80::0c1d:7fff:fe49:5641]:11111'
cargo run --bin faux-mgs -- --log-level=crit $INTERFACE $DISCOVERY_ADDR "$@"
```

then for instance:
```bash
./FM rhai scripts/update.rhai /gimlet/env/lurch.json sidecar-sp
```

The script `update.rhai` will read the device under
test configurations from `lurch.json` and run the update test on
`sidecar-sp`. Another JSON file could specify the various images to use
for the tests.
