## Overview

The Management Gateway Service (MGS) is the [control
plane](https://github.com/oxidecomputer/omicron) service that communications
with Service Processors (SPs) running
[hubris](https://github.com/oxidecomputer/hubris).

MGS itself lives in the omicron repo, and there is a corresponding agent task in
hubris with which it communicates.

## Navigating

* `gateway-messages` - no_std code that defines the messages exchanged between
  MGS and SPs and provides serialization/deserialization support. This is used
  by the hubris task on the real SPs, by MGS proper for messaging, and by the
  simulated SPs we use for testing. Sharing this crate between hubris and
  omicron is the primary motivation for the existence of this repository.

* `gateway-sp-comms` - std code used by MGS and `faux-mgs` for communicating
  with a set of SPs.

* `faux-mgs` - command line application intended for debug and development work;
  it can pretend to be MGS to communicate with a single target SP (either
  directly via IP address or discovered via UDP multicast similarily to how
  MGS's general discovery process works).
