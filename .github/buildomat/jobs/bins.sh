#!/bin/bash
#:
#: name = "bins"
#: variety = "basic"
#: target = "helios-latest"
#: rust_toolchain = "stable"
#: output_rules = [
#:	"=/out/faux-mgs.gz",
#:	"=/out/faux-mgs.sha256.txt",
#:	"=/out/faux-mgs.gz.sha256.txt",
#:	"=/out/omicron-faux-mgs.tar.gz",
#:	"=/out/omicron-faux-mgs.tar.gz.sha256.txt",
#: ]
#:
#: [[publish]]
#: from_output = "/out/faux-mgs.gz"
#: series = "bins"
#: name = "faux-mgs.gz"
#:
#: [[publish]]
#: from_output = "/out/faux-mgs.gz.sha256.txt"
#: series = "bins"
#: name = "faux-mgs.gz.sha256.txt"
#:
#: [[publish]]
#: from_output = "/out/omicron-faux-mgs.tar.gz"
#: series = "image"
#: name = "omicron-faux-mgs.tar.gz"
#:
#: [[publish]]
#: from_output = "/out/omicron-faux-mgs.tar.gz.sha256.txt"
#: series = "image"
#: name = "omicron-faux-mgs.tar.gz.sha256.txt"
#:

set -o errexit
set -o pipefail
set -o xtrace

cargo --version
rustc --version

pfexec mkdir -p /out
pfexec chown "$LOGNAME" /out

banner build
ptime -m cargo build --release --bin faux-mgs

banner omicron-zone-package
cargo xtask zone-package target/out/

banner output

mv target/release/faux-mgs /out/faux-mgs
digest -a sha256 /out/faux-mgs > /out/faux-mgs.sha256.txt
gzip /out/faux-mgs
digest -a sha256 /out/faux-mgs.gz > /out/faux-mgs.gz.sha256.txt

mv target/out/omicron-faux-mgs.tar.gz /out/omicron-faux-mgs.tar.gz
digest -a sha256 /out/omicron-faux-mgs.tar.gz > /out/omicron-faux-mgs.tar.gz.sha256.txt
