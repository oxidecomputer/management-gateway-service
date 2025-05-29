## Prototype Wireshark LUA Plugin

This directory contains a prototype to dissect the control-plane-agent / MGS
protocol. To install on Linux, create a symlink to this directory in
`$HOME/.local/lib/wireshark/plugins`. It attempts to dissect UDP traffic on
ports 11111 and 22222.

Most of the messages in this protocol are left undissected and reported as
`TODO`s in Wireshark. Expanding any of the TODOs you find yourself needing
should be _relatively_ straightforward. To add new hubpack-encoded enum
variants, update `../compose-wireshark-plugin/src/main.rs` to include the enum,
rerun `../compose-wireshark-plugin`, and make use of the newly-generated details
(following existing hubpack enums by way of example). To handle "leaf" nodes
that don't recurse further into more hubpack enums, implement the appropriate
dissector Lua function.
