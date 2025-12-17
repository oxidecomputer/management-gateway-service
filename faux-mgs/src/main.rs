// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use camino::Utf8PathBuf;
use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;
use futures::stream::FuturesOrdered;
use futures::FutureExt;
use futures::StreamExt;
use gateway_messages::ignition::TransceiverSelect;
use gateway_messages::ComponentAction;
use gateway_messages::ComponentActionResponse;
use gateway_messages::EcdsaSha2Nistp256Challenge;
use gateway_messages::IgnitionCommand;
use gateway_messages::LedComponentAction;
use gateway_messages::MonorailComponentAction;
use gateway_messages::MonorailComponentActionResponse;
use gateway_messages::PowerState;
use gateway_messages::RotBootInfo;
use gateway_messages::SpComponent;
use gateway_messages::StartupOptions;
use gateway_messages::UnlockChallenge;
use gateway_messages::UnlockResponse;
use gateway_messages::UpdateId;
use gateway_messages::UpdateStatus;
use gateway_messages::ROT_PAGE_SIZE;
use gateway_sp_comms::ereport;
use gateway_sp_comms::shared_socket;
use gateway_sp_comms::InMemoryHostPhase2Provider;
use gateway_sp_comms::SharedSocket;
use gateway_sp_comms::SingleSp;
use gateway_sp_comms::SpComponentDetails;
use gateway_sp_comms::SpRetryConfig;
use gateway_sp_comms::SwitchPortConfig;
use gateway_sp_comms::VersionedSpState;
use gateway_sp_comms::MGS_PORT;
use indicatif::ProgressBar;
use indicatif::ProgressStyle;
use serde_json::json;
use slog::debug;
use slog::info;
use slog::o;
use slog::warn;
use slog::Drain;
use slog::Level;
use slog::Logger;
use slog_async::AsyncGuard;
use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::IsTerminal;
use std::io::Write;
use std::mem;
use std::net::Ipv6Addr;
use std::net::SocketAddrV6;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use uuid::Uuid;
use zerocopy::IntoBytes;

mod picocom_map;
mod usart;

/// Command line program that can send MGS messages to a single SP.
#[derive(Parser, Debug)]
struct Args {
    #[clap(
        short,
        long,
        default_value = "info",
        value_parser = level_from_str,
        help = "Log level for MGS client: {off,critical,error,warn,info,debug,trace}",
    )]
    log_level: Level,

    /// Write logs to a file instead of stderr.
    #[clap(long)]
    logfile: Option<PathBuf>,

    /// Emit parseable JSON on stdout instead of "human-readable" (often
    /// `Debug`-formatted) data.
    #[clap(long, value_names = ["pretty"], value_parser = json_pretty_from_str)]
    json: Option<Option<JsonPretty>>,

    /// Port to bind to locally [default: 0 for client commands, 22222 for
    /// server commands]
    #[clap(long)]
    listen_port: Option<u16>,

    /// Ereport port to bind to locally
    // Note that, unlike `listen_port`, this always defaults to 0, because we
    // don't need to act as a server with a known port for the ereport
    // protocol.
    #[clap(long, default_value_t = 0)]
    ereport_port: u16,

    /// Address to use to discover the SP. May be a specific SP's address to
    /// bypass multicast discovery.
    #[clap(long, default_value_t = gateway_sp_comms::default_discovery_addr())]
    discovery_addr: SocketAddrV6,

    /// Interface(s) to use to communicate with target SP(s).
    ///
    /// Supports shell-like glob patterns (e.g., "gimlet*"). May be specified
    /// multiple times.
    #[clap(long, required = true)]
    interface: Vec<String>,

    /// Address to talk to an `sp-sim` instance.
    ///
    /// Bypasses the normal mechanism of IPv6 scope ID-based packet
    /// identification supported by `--interface`.
    #[clap(long, conflicts_with_all = ["discovery_addr", "interface"])]
    sp_sim_addr: Option<SocketAddrV6>,

    /// Maximum number of attempts to make when sending general (non-reset)
    /// requests to the SP.
    #[clap(long, default_value = "5")]
    max_attempts: usize,

    /// Maximum number of attempts to make when sending reset requests to the
    /// SP.
    #[clap(long, default_value = "30")]
    max_attempts_reset: usize,

    /// Timeout (in milliseconds) for each attempt.
    #[clap(long, default_value = "2000")]
    per_attempt_timeout_millis: u64,

    #[clap(subcommand)]
    command: Command,
}

fn level_from_str(s: &str) -> Result<Level> {
    if let Ok(level) = s.parse() {
        Ok(level)
    } else {
        bail!(format!("Invalid log level: {}", s))
    }
}

#[derive(Debug, Clone, Copy)]
struct JsonPretty;

fn json_pretty_from_str(s: &str) -> Result<JsonPretty> {
    if s == "pretty" {
        Ok(JsonPretty)
    } else {
        bail!("expected \"pretty\"")
    }
}

#[derive(Subcommand, Debug, Clone)]
#[allow(clippy::enum_variant_names)]
enum Command {
    /// Discover a connected SP.
    Discover,

    /// Ask SP for its current state.
    State,

    /// Get the ignition state for a port (only valid if the SP is an ignition
    /// controller).
    Ignition {
        #[clap(flatten)]
        sel: IgnitionBulkSelectorWithCompatibilityShim,
    },

    /// Send an ignition command for a single target port (only valid if the SP
    /// is an ignition controller).
    IgnitionCommand {
        // We can't use the compatibility shim here because it has an optional
        // positional argument, which can't be followed by `command`
        #[clap(flatten)]
        sel: IgnitionSingleSelector,
        #[clap(
            help = "'power-[on,off,reset]' or '[set,clear]-always-transmit'",
            value_parser = ignition_command_from_str,
        )]
        command: IgnitionCommand,
    },

    /// Get bulk ignition link events (only valid if the SP is an ignition
    /// controller).
    IgnitionLinkEvents {
        #[clap(flatten)]
        sel: IgnitionBulkSelectorWithCompatibilityShim,
    },

    /// Clear all ignition link events (only valid if the SP is an ignition
    /// controller).
    ClearIgnitionLinkEvents {
        // We can't use the compatibility shim here because it has an optional
        // positional argument, which can't be followed by `transceiver_select`
        #[clap(flatten)]
        sel: IgnitionBulkSelector,
        #[clap(
            help = "'controller', 'target-link0', 'target-link1', or 'all'",
            value_parser = IgnitionLinkEventsTransceiverSelect::parse,
        )]
        transceiver_select: IgnitionLinkEventsTransceiverSelect,
    },

    /// Get or set the active slot of a component (e.g., `host-boot-flash`).
    ///
    /// Except for component "stage0", setting the active slot can be
    /// viewed as an atomic operation.
    ///
    /// Setting "stage0" slot 1 as the active slot initiates a copy from
    /// slot 1 to slot 0 if the contents of slot 1 still match those seen
    /// at last RoT reset and the contents are properly signed.
    ///
    /// Power failures during the copy can disable the RoT. Only one stage0
    /// update should be in process in a rack at any time.
    ComponentActiveSlot {
        #[clap(value_parser = parse_sp_component)]
        component: SpComponent,
        #[clap(short, long, value_name = "SLOT", help = "set the active slot")]
        set: Option<u16>,
        #[clap(
            short,
            long,
            requires = "set",
            help = "persist the active slot to non-volatile memory"
        )]
        persist: bool,
        /// Prefer the specified slot on the next soft reset.
        #[clap(short, long, requires = "set", conflicts_with = "persist")]
        transient: bool,
    },

    /// Get or set startup options on an SP.
    StartupOptions {
        options: Option<u64>,
    },

    /// Ask SP for its inventory.
    Inventory,

    /// Ask SP for details of a component.
    ComponentDetails {
        #[clap(value_parser = parse_sp_component)]
        component: SpComponent,
    },

    /// Ask SP to clear the state (e.g., reset counters) on a component.
    ComponentClearStatus {
        #[clap(value_parser = parse_sp_component)]
        component: SpComponent,
    },

    /// Ask the SP for its current system time (interpreted as human time or as
    /// a raw value).
    CurrentTime {
        #[clap(short, long, help = "do not interpret returned value")]
        raw: bool,
    },

    /// Attach to the SP's USART.
    UsartAttach {
        /// Put the local terminal in raw mode.
        #[clap(
            long = "no-raw",
            help = "do not put terminal in raw mode",
            action = clap::ArgAction::SetFalse,
        )]
        raw: bool,

        /// Amount of time to buffer input from stdin before forwarding to SP.
        #[clap(long, default_value = "500")]
        stdin_buffer_time_millis: u64,

        /// Specifies the input character map (i.e., special characters to be
        /// replaced when reading from the serial port). See picocom's manpage.
        #[clap(long)]
        imap: Option<String>,

        /// Specifies the output character map (i.e., special characters to be
        /// replaced when writing to the serial port). See picocom's manpage.
        #[clap(long)]
        omap: Option<String>,

        /// Record all input read from the serial port to this logfile (before
        /// any remapping).
        #[clap(long)]
        uart_logfile: Option<PathBuf>,
    },

    /// Detach any other attached USART connection.
    UsartDetach,

    /// Serve host phase 2 images.
    ServeHostPhase2 {
        directory: PathBuf,
    },

    /// Upload a new image to the SP or one of its components.
    ///
    /// To update the SP itself:
    ///
    /// 1. Use the component name "sp"
    /// 2. Specify slot 0 (the SP only has a single updateable slot: its
    ///    alternate bank).
    /// 3. Pass the path to a hubris archive as `image`.
    Update {
        #[clap(long)]
        allow_multiple_update: bool,

        #[clap(value_parser = parse_sp_component)]
        component: SpComponent,
        slot: u16,
        image: PathBuf,
    },

    /// Get the status of an update to the specified component.
    UpdateStatus {
        #[clap(value_parser = parse_sp_component)]
        component: SpComponent,
    },

    /// Abort an in-progress update.
    UpdateAbort {
        /// Component with an update-in-progress to be aborted. Omit to abort
        /// updates to the SP itself.
        #[clap(value_parser = parse_sp_component)]
        component: SpComponent,
        /// ID of the update to abort.
        update_id: Uuid,
    },

    /// Get or set the power state.
    PowerState {
        /// If present, instruct the SP to set this power state. If not present,
        /// get the current power state instead.
        #[clap(value_parser = power_state_from_str)]
        new_power_state: Option<PowerState>,
    },

    /// Sends an NMI to the host (SP3) CPU by toggling a GPIO
    SendHostNmi,

    /// Set an IPCC key/value
    SetIpccKeyValue {
        key: u8,

        /// Path to a file containing the value
        value_path: PathBuf,
    },

    /// Read a single key from the caboose
    ReadCaboose {
        /// 4-character ASCII string
        #[arg(value_parser = parse_tlvc_key)]
        key: [u8; 4],
    },

    /// Read a single key from the caboose
    ReadComponentCaboose {
        /// Component from which to read; must be `sp` or `rot`
        #[clap(short, long, value_parser = parse_sp_component)]
        component: SpComponent,

        /// Target slot from which to read the caboose.
        ///
        /// The SP accepts `active` or `inactive`; the RoT accepts `A` or `B`
        #[clap(short, long)]
        slot: Option<String>,

        /// 4-character ASCII string
        #[arg(value_parser = parse_tlvc_key)]
        key: [u8; 4],
    },

    /// Instruct the SP to reset.
    Reset {
        /// Reset without the automatic safety rollback watchdog
        #[clap(long)]
        disable_watchdog: bool,
    },

    /// Reset a component.
    ///
    /// This command is implemented for the component "rot" but may be
    /// expanded to other components in the future.
    ResetComponent {
        #[clap(value_parser = parse_sp_component)]
        component: SpComponent,
        /// Reset without the automatic safety rollback watchdog (if applicable)
        #[clap(long)]
        disable_watchdog: bool,
    },

    /// Controls the system LED
    SystemLed {
        #[clap(subcommand)]
        cmd: LedCommand,
    },

    /// Reads a single sensor by `SensorId`, returning a `f32`
    ReadSensorValue {
        /// Sensor ID
        id: u32,
    },

    /// Reads the CMPA from an attached Root of Trust
    ReadCmpa {
        /// Output file (by default, pretty-printed to `stdout`)
        #[clap(short, long)]
        out: Option<PathBuf>,
    },

    /// Reads a CFPA slot from an attached Root of Trust
    ReadCfpa {
        /// Output file (by default, pretty-printed to `stdout`)
        #[clap(short, long)]
        out: Option<PathBuf>,

        #[clap(short, long, default_value_t = CfpaSlot::Active)]
        slot: CfpaSlot,
    },

    /// Reads the lock status of any VPD in the system
    VpdLockStatus,

    /// Read the RoT's boot-time information.
    RotBootInfo {
        /// Return highest version of RotBootInfo less then or equal to our
        /// highest known version.
        #[clap(long, short, default_value_t = RotBootInfo::HIGHEST_KNOWN_VERSION)]
        version: u8,
    },

    /// Control the management network switch
    Monorail {
        #[clap(subcommand)]
        cmd: MonorailCommand,
    },

    /// List and read per-task crash dumps
    Dump {
        #[clap(subcommand)]
        cmd: DumpCommand,
    },

    /// Read ereports
    ///
    /// This command sends an ereport request to the service processor for the
    /// provided `--restart-id`, starting at the requested `--start-ena`.
    ///
    /// If the `--committed-ena` argument is provided, the SP will be asked to
    /// flush (discard from memory) ereports up to that ENA. provided that
    /// the requested `--restart-id` matches the SP's current restart ID.
    Ereports {
        /// Starting ENA to read from.
        ///
        /// If this value has a leading '0x' prefix, it will be parsed as
        /// hexadecimal, otherwise, it will be parsed as a decimal number.
        #[clap(
            long,
            short,
            default_value_t = 0,
            value_parser = parse_int::parse::<u64>
        )]
        start_ena: u64,

        /// ENA to commit (flush ereports prior to).
        ///
        /// If this value has a leading '0x' prefix, it will be parsed as
        /// hexadecimal, otherwise, it will be parsed as a decimal number.
        ///
        /// Note that if this value is provided, this command becomes a
        /// destructive operation! Ereports prior to this ENA will be
        /// permanently discarded by the service processor!
        #[clap(long, short, value_parser = parse_int::parse::<u64>)]
        committed_ena: Option<u64>,

        /// Expected SP restart ID.
        ///
        /// This should be formatted as a UUID.
        #[clap(long, short, default_value_t = Uuid::nil())]
        restart_id: Uuid,

        /// Maximum number of ereports to request.
        #[clap(long, short)]
        limit: Option<std::num::NonZeroU8>,
    },

    /// Read Host flash at address
    ReadHostFlash {
        slot: u16,
        // Giving addresses in hex is nice and the default clap parser
        // does not support that
        #[clap(value_parser = parse_int::parse::<u32>)]
        addr: u32,
    },
    /// Dump the entire contents of the host flash, up to a specified size
    DumpHostFlash {
        slot: u16,
        #[clap(value_parser = parse_int::parse::<u32>)]
        size: u32,
        output: Utf8PathBuf,
        #[clap(
            long,
            default_value_t = 0,
            value_parser = parse_int::parse::<u32>,
        )]
        start_address: u32,
    },
    StartHostFlashHash {
        slot: u16,
    },
    GetHostFlashHash {
        slot: u16,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum LedCommand {
    /// Turns the LED on
    On,
    /// Turns the LED off
    Off,
    /// Enables blinking
    Blink,
}

#[derive(Subcommand, Debug, Clone)]
enum MonorailCommand {
    /// Unlock the technician port, allowing access to other SPs
    Unlock {
        #[clap(flatten)]
        cmd: UnlockGroup,

        /// Name of the signing key for producing unlock challenge responses
        ///
        /// This is either a path to an SSH public key file (ending in `.pub`),
        /// or a substring to match against known SSH keys (which can be printed
        /// with `faux-mgs monorail unlock --list`), or a permslip key name (see
        /// `permslip list-keys -t`).
        #[clap(short, long, conflicts_with = "list")]
        key: Option<String>,

        /// Path to the SSH agent socket
        #[clap(long, env)]
        ssh_auth_sock: Option<PathBuf>,

        /// Use the Online Signing Service with `permslip`
        #[clap(
            short,
            long,
            alias = "online",
            conflicts_with = "list",
            requires = "key"
        )]
        permslip: bool,
    },

    /// Lock the technician port
    Lock,
}

#[derive(Subcommand, Debug, Clone)]
enum DumpCommand {
    /// List the number of task crash dumps available
    Count,

    /// Read a single dump
    Read {
        /// Index of the dump to read (in the range `0..count`)
        ///
        /// The total dump count can be printed with `faux-mgs dump count`
        #[clap(long, short)]
        index: u32,

        /// File to write the dump
        ///
        /// If not provided, the dump is written to `hubris.dry.X`, where `X` is
        /// the next available integer.
        #[clap(long, short)]
        output: Option<PathBuf>,
    },
}

#[derive(Clone, Debug, clap::Args)]
#[group(required = true, multiple = false)]
pub struct UnlockGroup {
    /// How long to unlock for
    #[clap(short, long)]
    time: Option<humantime::Duration>,

    /// List available keys
    #[clap(short, long)]
    list: bool,
}

#[derive(ValueEnum, Debug, Clone)]
enum CfpaSlot {
    Active,
    Inactive,
    Scratch,
}

impl std::fmt::Display for CfpaSlot {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "{}",
            match self {
                CfpaSlot::Active => "active",
                CfpaSlot::Inactive => "inactive",
                CfpaSlot::Scratch => "scratch",
            }
        )
    }
}

#[derive(Copy, Clone, Debug, clap::Args)]
pub struct IgnitionSelector {
    /// Ignition target
    #[clap(short, long)]
    target: Option<u8>,

    /// Sled cubby (0-31)
    #[clap(short, long, conflicts_with_all = ["target"])]
    cubby: Option<u8>,

    /// Sidecar ('local' or 'peer')
    #[clap(
        short, long, conflicts_with_all = ["target", "cubby"],
        value_parser = parse_sidecar_selector
    )]
    sidecar: Option<SidecarSelector>,

    /// PSC index (0-1)
    #[clap(short, long, conflicts_with_all = ["target", "cubby", "sidecar"])]
    psc: Option<u8>,
}

#[derive(Clone, Debug, clap::Args)]
#[clap(group(clap::ArgGroup::new("select")
    .required(true)
    .args(&["target", "cubby", "sidecar", "psc"]))
)]
pub struct IgnitionSingleSelector {
    #[clap(flatten)]
    sel: IgnitionSelector,
}

impl IgnitionSingleSelector {
    fn get_target(&self, log: &Logger) -> Result<u8> {
        // presence of at least one is enforced by clap
        Ok(self.sel.get_target(log)?.unwrap())
    }
}

impl IgnitionSelector {
    /// Decodes CLI arguments to an ignition target
    fn get_target(&self, log: &Logger) -> Result<Option<u8>> {
        // At this point, we assume that the various `Option` values are
        // mutually exclusive (enforced by `clap`).
        let t = if let Some(t) = self.target {
            t
        } else if let Some(c) = self.cubby {
            // See RFD 144 § 6.1 (Switch Port Map) for this mapping
            let t = match c {
                0 => 14,
                1 => 30,
                2 => 15,
                3 => 31,
                4 => 13,
                5 => 29,
                6 => 12,
                7 => 28,
                8 => 10,
                9 => 26,
                10 => 11,
                11 => 27,
                12 => 9,
                13 => 25,
                14 => 8,
                15 => 24,
                16 => 4,
                17 => 20,
                18 => 5,
                19 => 21,
                20 => 7,
                22 => 6,
                24 => 0,
                25 => 16,
                26 => 1,
                27 => 17,
                28 => 3,
                29 => 19,
                30 => 2,
                31 => 18,
                i => bail!("cubby must be in the range 0-31, not {i}"),
            };
            debug!(log, "decoded cubby {c} => target {t}");
            t
        } else if let Some(s) = self.sidecar {
            let t = match s {
                SidecarSelector::Peer => 34,
                SidecarSelector::Local => 35,
            };
            debug!(log, "decoded {s:?} => target {t}");
            t
        } else if let Some(p) = self.psc {
            let t = match p {
                0 => 32,
                1 => 33,
                i => bail!("psc must be in the range 0-1, not {i}"),
            };
            debug!(log, "decoded psc {p} => target {t}");
            t
        } else {
            return Ok(None);
        };
        Ok(Some(t))
    }
}

/// `IgnitionSelector` that also supports `--all`
#[derive(Clone, Debug, clap::Args)]
#[clap(group(clap::ArgGroup::new("select")
    .required(true)
    .args(&["target", "cubby", "sidecar", "psc", "all"]))
)]
pub struct IgnitionBulkSelector {
    #[clap(flatten)]
    sel: IgnitionSelector,

    /// All targets
    #[clap(short, long)]
    all: bool,
}

impl IgnitionBulkSelector {
    fn get_targets(&self, log: &Logger) -> Result<IgnitionBulkTargets> {
        // Delegate to the fancier representation
        IgnitionBulkSelectorWithCompatibilityShim {
            sel: self.sel,
            all: self.all,
            compat: None,
        }
        .get_targets(log)
    }
}

/// `IgnitionBulkSelector` that also supports a positional argument
///
/// This is for backwards compatibility. However, it can't be used in
/// combination with later positional arguments, because optional positional
/// arguments are only allowed at the end of an argument list.
#[derive(Clone, Debug, clap::Args)]
#[clap(group(clap::ArgGroup::new("select")
    .required(true)
    .args(&["target", "cubby", "sidecar", "psc", "all", "compat"]))
)]
pub struct IgnitionBulkSelectorWithCompatibilityShim {
    #[clap(flatten)]
    sel: IgnitionSelector,

    /// All targets
    #[clap(short, long)]
    all: bool,

    /// 'all' or a target number
    /// (deprecated, present for backwards-compatibility)
    #[clap(value_parser = parse_bulk_targets_shim)]
    compat: Option<IgnitionBulkTargets>,
}

impl IgnitionBulkSelectorWithCompatibilityShim {
    fn get_targets(&self, log: &Logger) -> Result<IgnitionBulkTargets> {
        match (self.sel.get_target(log)?, self.all, self.compat) {
            (Some(_), true, _) | (_, true, Some(_)) => {
                bail!("cannot specify a target and `--all`")
            }
            (Some(_), _, Some(_)) => {
                bail!(
                    "cannot specify a target with both flags \
                     and positional arguments"
                )
            }
            (Some(target), false, None) => {
                Ok(IgnitionBulkTargets::Single(target))
            }
            (None, false, Some(t)) => {
                match t {
                    IgnitionBulkTargets::All => warn!(
                        log,
                        "positional `all` argument is deprecated, \
                         please switch to `--all`"
                    ),
                    IgnitionBulkTargets::Single(..) => warn!(
                        log,
                        "positional target argument is deprecated, \
                         please switch to `--target`, `--cubby`, \
                         `--sidecar`, or `--psc`"
                    ),
                }
                Ok(t)
            }
            (None, true, None) => Ok(IgnitionBulkTargets::All),
            (None, false, None) => {
                // enforced by clap
                panic!("must specify either a target or `--all`")
            }
        }
    }
}

#[derive(Copy, Clone, Debug)]
enum IgnitionBulkTargets {
    Single(u8),
    All,
}

#[derive(Copy, Clone, Debug)]
enum SidecarSelector {
    Local,
    Peer,
}

fn parse_sidecar_selector(s: &str) -> Result<SidecarSelector> {
    let out = match s.to_ascii_lowercase().as_str() {
        "local" => SidecarSelector::Local,
        "peer" => SidecarSelector::Peer,
        _ => bail!("invalid sidecar selector '{s}', must be 'local' or 'peer'"),
    };
    Ok(out)
}

impl Command {
    // If the user didn't specify a listening port, what should we use? We
    // allow this to vary by command so that client commands (most of them) can
    // pick port 0 (i.e., let the OS choose an arbitrary available port), but
    // server commands can still default to the port on which the SP expects to
    // find MGS.
    fn default_listen_port(&self) -> u16 {
        match self {
            // Server commands; use standard MGS port
            Command::ServeHostPhase2 { .. } => MGS_PORT,
            // Client commands: use port 0
            _ => 0,
        }
    }
}

fn parse_tlvc_key(key: &str) -> Result<[u8; 4]> {
    if !key.is_ascii() {
        bail!("key must be an ASCII string");
    } else if key.len() != 4 {
        bail!("key must be 4 characters");
    }

    Ok(key.as_bytes().try_into().unwrap())
}

fn parse_sp_component(component: &str) -> Result<SpComponent> {
    SpComponent::try_from(component)
        .map_err(|_| anyhow!("invalid component name: {component}"))
}

fn parse_bulk_targets_shim(s: &str) -> Result<IgnitionBulkTargets> {
    match s {
        "all" | "ALL" => Ok(IgnitionBulkTargets::All),
        _ => {
            let target = s
                .parse()
                .with_context(|| "must be an integer (0..256) or 'all'")?;
            Ok(IgnitionBulkTargets::Single(target))
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct IgnitionLinkEventsTransceiverSelect(Option<TransceiverSelect>);

impl IgnitionLinkEventsTransceiverSelect {
    fn parse(s: &str) -> Result<Self> {
        match s {
            "all" | "ALL" => Ok(Self(None)),
            "controller" => Ok(Self(Some(TransceiverSelect::Controller))),
            "target-link0" => Ok(Self(Some(TransceiverSelect::TargetLink0))),
            "target-link1" => Ok(Self(Some(TransceiverSelect::TargetLink1))),
            _ => {
                bail!("transceiver selection must be one of 'all', 'controller', 'target-link0', 'target-link1'")
            }
        }
    }
}

fn power_state_from_str(s: &str) -> Result<PowerState> {
    match s {
        "a0" | "A0" => Ok(PowerState::A0),
        "a1" | "A1" => Ok(PowerState::A1),
        "a2" | "A2" => Ok(PowerState::A2),
        _ => Err(anyhow!("Invalid power state: {s}")),
    }
}

fn ignition_command_from_str(s: &str) -> Result<IgnitionCommand> {
    match s {
        "power-on" => Ok(IgnitionCommand::PowerOn),
        "power-off" => Ok(IgnitionCommand::PowerOff),
        "power-reset" => Ok(IgnitionCommand::PowerReset),
        "set-always-transmit" => {
            Ok(IgnitionCommand::AlwaysTransmit { enabled: true })
        }
        "clear-always-transmit" => {
            Ok(IgnitionCommand::AlwaysTransmit { enabled: false })
        }
        _ => Err(anyhow!("Invalid ignition command: {s}")),
    }
}

fn build_logger(
    level: Level,
    path: Option<&Path>,
) -> Result<(Logger, AsyncGuard)> {
    fn make_drain<D: slog_term::Decorator + Send + 'static>(
        level: Level,
        decorator: D,
    ) -> (slog::Fuse<slog_async::Async>, AsyncGuard) {
        let drain = slog_term::FullFormat::new(decorator)
            .build()
            .filter_level(level)
            .fuse();
        let (drain, guard) = slog_async::Async::new(drain).build_with_guard();
        (drain.fuse(), guard)
    }

    let (drain, guard) = if let Some(path) = path {
        let file = File::create(path).with_context(|| {
            format!("failed to create logfile {}", path.display())
        })?;
        make_drain(level, slog_term::PlainDecorator::new(file))
    } else {
        make_drain(level, slog_term::TermDecorator::new().build())
    };

    Ok((Logger::root(drain, o!("component" => "faux-mgs")), guard))
}

fn build_requested_interfaces(patterns: Vec<String>) -> Result<Vec<String>> {
    let mut sys_ifaces = Vec::new();
    let ifaddrs = nix::ifaddrs::getifaddrs().context("getifaddrs() failed")?;
    for ifaddr in ifaddrs {
        sys_ifaces.push(ifaddr.interface_name);
    }

    let mut requested_ifaces = Vec::new();
    for pattern in patterns {
        let pattern = glob::Pattern::new(&pattern).with_context(|| {
            format!("failed to build glob pattern for {pattern}")
        })?;

        let prev_count = requested_ifaces.len();
        let mut matched_existing = false;
        for sys_iface in &sys_ifaces {
            if pattern.matches(sys_iface) {
                if requested_ifaces.contains(sys_iface) {
                    matched_existing = true;
                } else {
                    requested_ifaces.push(sys_iface.clone());
                }
            }
        }
        if requested_ifaces.len() == prev_count {
            if matched_existing {
                bail!("`--interface {pattern}` did not match any interfaces not already covered by previous `--interface` arguments");
            } else {
                bail!("`--interface {pattern}` did not match any interfaces");
            }
        }
    }

    Ok(requested_ifaces)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let (log, log_guard) =
        build_logger(args.log_level, args.logfile.as_deref())?;

    let retry_config = SpRetryConfig {
        per_attempt_timeout: Duration::from_millis(
            args.per_attempt_timeout_millis,
        ),
        max_attempts_reset: args.max_attempts_reset,
        max_attempts_general: args.max_attempts,
    };

    let listen_port =
        args.listen_port.unwrap_or_else(|| args.command.default_listen_port());

    // For faux-mgs, we'll serve all images present in the directory the user
    // requests, so don't cap the LRU cache size.
    let host_phase2_provider =
        Arc::new(InMemoryHostPhase2Provider::with_capacity(usize::MAX));

    let shared_socket = SharedSocket::bind(
        listen_port,
        shared_socket::ControlPlaneAgentHandler::new(&host_phase2_provider),
        log.new(slog::o!("socket" => "control-plane-agent")),
    )
    .await
    .context("SharedSocket:bind() failed")?;
    let ereport_socket = {
        SharedSocket::bind(
            args.ereport_port,
            ereport::EreportHandler::default(),
            log.new(slog::o!("socket" => "ereport")),
        )
        .await
        .context("SharedSocket::bind() for ereport socket failed")?
    };

    let mut sps = Vec::new();

    if let Some(sp_sim_addr) = args.sp_sim_addr {
        info!(
            log,
            "creating SP handle on to talk to SP simulator at {sp_sim_addr}"
        );
        // Bind a new socket for each simulated switch port.
        let bind_addr: SocketAddrV6 =
            SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0);
        let socket = UdpSocket::bind(bind_addr)
            .await
            .with_context(|| format!("failed to bind to {bind_addr}"))?;
        let ereport_bind_addr: SocketAddrV6 =
            SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0);
        let ereport_socket =
            UdpSocket::bind(ereport_bind_addr).await.with_context(|| {
                format!("failed to bind to {ereport_bind_addr}")
            })?;
        sps.push(SingleSp::new_direct_socket_for_testing(
            socket,
            sp_sim_addr,
            ereport_socket,
            SocketAddrV6::new(
                *sp_sim_addr.ip(),
                gateway_sp_comms::ereport::SP_PORT,
                0,
                0,
            ),
            retry_config,
            log.clone(),
        ));
    } else {
        let interfaces = build_requested_interfaces(args.interface)?;

        let mut ereport_addr = args.discovery_addr;
        ereport_addr.set_port(gateway_sp_comms::ereport::SP_PORT);
        for interface in interfaces {
            info!(log, "creating SP handle on interface {interface}");
            sps.push(
                SingleSp::new(
                    &shared_socket,
                    &ereport_socket,
                    SwitchPortConfig {
                        discovery_addr: args.discovery_addr,
                        ereport_addr,
                        interface,
                    },
                    retry_config,
                )
                .await,
            );
        }
    }

    let num_sps = sps.len();

    // Special case commands that do not make sense to run against multiple SPs:
    //
    // 1. usart-attach takes over the terminal, and we should reject multiple
    //    SPs.
    // 2. serve-host-phase2 runs forever; we _should_ accept multiple SPs (all
    //    the SPs to serve) but only need to run the command once.
    // 3. update: ensure the user passed `--allow-multiple-update` if they gave
    //    us multiple SPs to avoid accidentally trying to update many SPs
    //    simultaneously. (Actually peforming the update is still handled
    //    below.)
    //
    // All other commands can be run on any number of SPs; we'll handle those
    // below.
    match args.command.clone() {
        Command::UsartAttach {
            raw,
            stdin_buffer_time_millis,
            imap,
            omap,
            uart_logfile,
        } => {
            assert!(
                args.json.is_none(),
                "--json not supported for serial console"
            );
            assert_eq!(
                num_sps, 1,
                "cannot specify multiple interfaces for usart-attach"
            );
            usart::run(
                sps.remove(0),
                raw,
                Duration::from_millis(stdin_buffer_time_millis),
                imap,
                omap,
                uart_logfile,
                log,
            )
            .await?;

            // If usart::run() returns, the user detached; exit.
            //
            // We don't just `return Ok(())` here because we'll bump into
            // https://github.com/tokio-rs/tokio/issues/2466: `usart::run()`
            // reads from stdin, which means we end up with a task blocked in a
            // system call, preventing tokio from shutting down the runtime
            // created via `tokio::main`. We could create an explicit `Runtime`
            // and call `shutdown_background`; instead, we explicitly exit to
            // bypass tokio's shutdown. We first drop our `log_guard` to ensure
            // any messages have been flushed.
            mem::drop(log_guard);
            std::process::exit(0);
        }
        Command::ServeHostPhase2 { directory } => {
            populate_phase2_images(&host_phase2_provider, &directory, &log)
                .await?;
            info!(log, "serving host phase 2 images (ctrl-c to stop)");

            // Loop forever. If we have multiple `sps`, we'll never actually
            // iterate and move on to the next, but that's fine - the
            // underlying `SharedSocket` will respond to requests from any
            // of our created SPs.
            loop {
                tokio::time::sleep(Duration::from_secs(1024)).await;
            }
        }
        Command::Update { allow_multiple_update, .. } => {
            if num_sps > 1 && !allow_multiple_update {
                bail!("Did you mean to attempt to update multiple SPs? If so, add `--allow-multiple-updates`.");
            }
        }

        _ => (),
    }

    let maxwidth = sps.iter().map(|sp| sp.interface().len()).max().unwrap_or(0);

    let mut all_results = sps
        .into_iter()
        .map(|sp| {
            let interface = sp.interface().to_string();
            run_command(
                sp,
                args.command.clone(),
                args.json.is_some(),
                log.clone(),
            )
            .map(|result| (interface, result))
        })
        .collect::<FuturesOrdered<_>>();

    let mut by_interface = BTreeMap::new();
    let mut did_fail = false;
    while let Some((interface, result)) = all_results.next().await {
        let prefix = if args.json.is_none() && num_sps > 1 {
            format!("{interface:maxwidth$} ")
        } else {
            String::new()
        };
        match result {
            Ok(Output::Json(value)) => {
                by_interface.insert(interface, Ok(value));
            }
            Ok(Output::Lines(lines)) => {
                for line in lines {
                    println!("{prefix}{line}");
                }
            }
            Err(err) => {
                did_fail = true;
                if args.json.is_some() {
                    by_interface.insert(interface, Err(format!("{err:#}")));
                } else {
                    println!("{prefix}Error: {err:#}");
                }
            }
        }
    }

    match args.json {
        Some(Some(JsonPretty)) => {
            serde_json::to_writer_pretty(io::stdout().lock(), &by_interface)
                .context("failed to write to stdout")?;
        }
        Some(None) => {
            serde_json::to_writer(io::stdout().lock(), &by_interface)
                .context("failed to write to stdout")?;
        }
        None => {
            // nothing to do; already preinted in the loop above
        }
    }

    if did_fail {
        std::process::exit(1);
    }

    Ok(())
}

fn get_ssh_client<P: AsRef<Path> + std::fmt::Debug>(
    socket: P,
) -> Result<ssh_agent_client_rs::Client> {
    let client = ssh_agent_client_rs::Client::connect(socket.as_ref())
        .with_context(|| {
            format!("failed to connect to SSH agent on {socket:?}")
        })?;
    Ok(client)
}

fn ssh_list_keys(socket: &PathBuf) -> Result<Vec<ssh_key::PublicKey>> {
    let mut client = get_ssh_client(socket)?;
    client.list_identities().context("failed to list identities")
}

async fn run_command(
    sp: SingleSp,
    command: Command,
    json: bool,
    log: Logger,
) -> Result<Output> {
    match command {
        // Skip special commands handled by `main()` above.
        Command::UsartAttach { .. } | Command::ServeHostPhase2 { .. } => {
            unreachable!()
        }

        // Remainder of commands.
        Command::Discover => {
            const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);
            let mut addr_watch = sp.sp_addr_watch().clone();
            loop {
                let current = *addr_watch.borrow();
                match current {
                    Some((addr, port)) => {
                        info!(
                            log, "SP discovered";
                            "interface" => sp.interface(),
                            "addr" => %addr,
                            "port" => ?port,
                        );
                        if json {
                            break Ok(Output::Json(json!({
                                "addr": addr,
                                "port": port,
                            })));
                        } else {
                            break Ok(Output::Lines(vec![format!(
                                "addr={addr}, port={port:?}"
                            )]));
                        }
                    }
                    None => match tokio::time::timeout(
                        DISCOVERY_TIMEOUT,
                        addr_watch.changed(),
                    )
                    .await
                    {
                        Ok(recv_result) => recv_result.unwrap(),
                        Err(_) => bail!(
                            "discovery failed (waited {DISCOVERY_TIMEOUT:?})"
                        ),
                    },
                }
            }
        }
        Command::State => {
            let state = sp.state().await?;
            info!(log, "{state:?}");
            if json {
                return Ok(Output::Json(serde_json::to_value(state).unwrap()));
            }
            let mut lines = Vec::new();
            let zero_padded_to_str = |bytes: [u8; 32]| {
                let stop =
                    bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                String::from_utf8_lossy(&bytes[..stop]).to_string()
            };

            match state {
                VersionedSpState::V1(state) => {
                    lines.push(format!(
                        "hubris archive: {}",
                        hex::encode(state.hubris_archive_id)
                    ));

                    lines.push(format!(
                        "serial number: {}",
                        zero_padded_to_str(state.serial_number)
                    ));
                    lines.push(format!(
                        "model: {}",
                        zero_padded_to_str(state.model)
                    ));
                    lines.push(format!("revision: {}", state.revision));
                    lines.push(format!(
                        "base MAC address: {}",
                        state
                            .base_mac_address
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<Vec<_>>()
                            .join(":")
                    ));
                    lines.push(format!("hubris version: {:?}", state.version));
                    lines.push(format!("power state: {:?}", state.power_state));
                    match state.rot {
                        Ok(rot) => {
                            lines.push(format!("rot: Ok({})", rot.display()))
                        }
                        Err(err) => lines.push(format!("rot: Err({})", err)),
                    }
                    Ok(Output::Lines(lines))
                }
                VersionedSpState::V2(state) => {
                    lines.push(format!(
                        "hubris archive: {}",
                        hex::encode(state.hubris_archive_id)
                    ));

                    lines.push(format!(
                        "serial number: {}",
                        zero_padded_to_str(state.serial_number)
                    ));
                    lines.push(format!(
                        "model: {}",
                        zero_padded_to_str(state.model)
                    ));
                    lines.push(format!("revision: {}", state.revision));
                    lines.push(format!(
                        "base MAC address: {}",
                        state
                            .base_mac_address
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<Vec<_>>()
                            .join(":")
                    ));
                    lines.push(format!("power state: {:?}", state.power_state));
                    match state.rot {
                        Ok(rot) => lines.push(format!("rot: Ok({})", rot)),
                        Err(err) => lines.push(format!("rot: Err({})", err)),
                    }
                    Ok(Output::Lines(lines))
                }
                VersionedSpState::V3(state) => {
                    lines.push(format!(
                        "hubris archive: {}",
                        hex::encode(state.hubris_archive_id)
                    ));

                    lines.push(format!(
                        "serial number: {}",
                        zero_padded_to_str(state.serial_number)
                    ));
                    lines.push(format!(
                        "model: {}",
                        zero_padded_to_str(state.model)
                    ));
                    lines.push(format!("revision: {}", state.revision));
                    lines.push(format!(
                        "base MAC address: {}",
                        state
                            .base_mac_address
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<Vec<_>>()
                            .join(":")
                    ));
                    lines.push(format!("power state: {:?}", state.power_state));
                    Ok(Output::Lines(lines))
                }
            }
        }
        Command::RotBootInfo { version } => {
            let rot_state = sp.rot_state(version).await?;
            info!(log, "{rot_state:x?}");
            if json {
                Ok(Output::Json(serde_json::to_value(rot_state).unwrap()))
            } else {
                let mut lines = Vec::new();
                lines.push(format!("{}", rot_state.display()));
                Ok(Output::Lines(lines))
            }
        }
        Command::Ignition { sel } => {
            let mut by_target = BTreeMap::new();
            match sel.get_targets(&log)? {
                IgnitionBulkTargets::Single(target) => {
                    let state = sp.ignition_state(target).await?;
                    by_target.insert(usize::from(target), state);
                }
                IgnitionBulkTargets::All => {
                    let states = sp.bulk_ignition_state().await?;
                    for (i, state) in states.into_iter().enumerate() {
                        by_target.insert(i, state);
                    }
                }
            };
            if json {
                Ok(Output::Json(serde_json::to_value(by_target).unwrap()))
            } else {
                let mut lines = Vec::new();
                for (target, state) in by_target {
                    lines.push(format!("target {target}: {state:?}"));
                }
                Ok(Output::Lines(lines))
            }
        }
        Command::IgnitionCommand { sel, command } => {
            let target = sel.get_target(&log)?;
            sp.ignition_command(target, command).await?;
            info!(log, "ignition command {command:?} send to target {target}");
            if json {
                Ok(Output::Json(json!({ "ack": command })))
            } else {
                Ok(Output::Lines(vec![format!(
                    "successfully sent {command:?}"
                )]))
            }
        }
        Command::IgnitionLinkEvents { sel } => {
            let mut by_target = BTreeMap::new();
            match sel.get_targets(&log)? {
                IgnitionBulkTargets::Single(target) => {
                    let events = sp.ignition_link_events(target).await?;
                    by_target.insert(usize::from(target), events);
                }
                IgnitionBulkTargets::All => {
                    let events = sp.bulk_ignition_link_events().await?;
                    for (i, events) in events.into_iter().enumerate() {
                        by_target.insert(i, events);
                    }
                }
            }
            if json {
                Ok(Output::Json(serde_json::to_value(by_target).unwrap()))
            } else {
                let mut lines = Vec::new();
                for (target, events) in by_target {
                    lines.push(format!("target {target}: {events:?}"));
                }
                Ok(Output::Lines(lines))
            }
        }
        Command::ClearIgnitionLinkEvents { sel, transceiver_select } => {
            let target = match sel.get_targets(&log)? {
                IgnitionBulkTargets::Single(t) => Some(t),
                IgnitionBulkTargets::All => None,
            };
            sp.clear_ignition_link_events(target, transceiver_select.0).await?;
            info!(log, "ignition link events cleared");
            if json {
                Ok(Output::Json(json!({ "ack": "cleared" })))
            } else {
                Ok(Output::Lines(vec![
                    "ignition link events cleared".to_string()
                ]))
            }
        }
        Command::ComponentActiveSlot {
            component,
            set,
            persist,
            transient: _,
        } => {
            if let Some(slot) = set {
                sp.set_component_active_slot(component, slot, persist).await?;
                if json {
                    Ok(Output::Json(json!({ "ack": "set", "slot": slot })))
                } else {
                    Ok(Output::Lines(vec![format!(
                        "set active slot for {component:?} to {slot}"
                    )]))
                }
            } else {
                let slot = sp.component_active_slot(component).await?;
                info!(log, "active slot for {component:?}: {slot}");
                if json {
                    Ok(Output::Json(json!({ "slot": slot })))
                } else {
                    Ok(Output::Lines(vec![format!("{slot}")]))
                }
            }
        }
        Command::StartupOptions { options } => {
            if let Some(options) = options {
                let options =
                    StartupOptions::from_bits(options).with_context(|| {
                        format!("invalid startup options bits: {options:#x}")
                    })?;
                sp.set_startup_options(options).await?;
                if json {
                    Ok(Output::Json(
                        json!({ "ack": "set", "options": options }),
                    ))
                } else {
                    Ok(Output::Lines(vec![format!(
                        "successfully set startup options to {options:?}"
                    )]))
                }
            } else {
                let options = sp.get_startup_options().await?;
                if json {
                    Ok(Output::Json(json!({ "options": options })))
                } else {
                    Ok(Output::Lines(vec![format!(
                        "startup options: {options:?}"
                    )]))
                }
            }
        }
        Command::Inventory => {
            let inventory = sp.inventory().await?;

            if json {
                return Ok(Output::Json(
                    serde_json::to_value(inventory).unwrap(),
                ));
            }

            let mut lines = Vec::new();
            lines.push(format!(
                "{:<16} {:<12} {:<16} {:<}",
                "COMPONENT", "STATUS", "DEVICE", "DESCRIPTION (CAPABILITIES)"
            ));
            for d in inventory.devices {
                lines.push(format!(
                    "{:<16} {:<12} {:<16} {} ({:?})",
                    d.component.as_str().unwrap_or("???"),
                    format!("{:?}", d.presence),
                    d.device,
                    d.description,
                    d.capabilities,
                ));
            }
            Ok(Output::Lines(lines))
        }
        Command::ComponentDetails { component } => {
            let details = sp.component_details(component).await?;
            if json {
                return Ok(Output::Json(component_details_to_json(details)));
            }

            /// Helper `struct` to pretty-print component details
            ///
            /// This normally delegates to `Debug`, but prints `LastPostCode` as
            /// a hex value for convenience.
            struct ComponentDetailPrinter(gateway_messages::ComponentDetails);
            impl std::fmt::Display for ComponentDetailPrinter {
                fn fmt(
                    &self,
                    f: &mut std::fmt::Formatter<'_>,
                ) -> std::fmt::Result {
                    use gateway_messages::ComponentDetails;
                    match &self.0 {
                        ComponentDetails::LastPostCode(p) => {
                            write!(f, "LastPostCode({:#x})", p.0)
                        }
                        d => write!(f, "{d:?}"),
                    }
                }
            }

            let mut lines = Vec::new();
            for entry in details.entries {
                let d = ComponentDetailPrinter(entry);
                lines.push(format!("{d}"));
            }
            Ok(Output::Lines(lines))
        }
        Command::ComponentClearStatus { component } => {
            sp.component_clear_status(component).await?;
            info!(log, "status cleared for component {component}");
            if json {
                Ok(Output::Json(json!({ "ack": "cleared" })))
            } else {
                Ok(Output::Lines(vec!["status cleared".to_string()]))
            }
        }
        Command::CurrentTime { raw } => {
            if raw {
                let t = sp.current_time_raw().await?;
                if json {
                    Ok(Output::Json(json!({"time-raw": t})))
                } else {
                    Ok(Output::Lines(vec![format!("current time (raw): {t}")]))
                }
            } else {
                let t = sp.current_time().await?;
                if json {
                    Ok(Output::Json(json!({"time": t})))
                } else {
                    let t = humantime::format_duration(t);
                    Ok(Output::Lines(vec![format!("current time: {t}")]))
                }
            }
        }
        Command::UsartDetach => {
            sp.serial_console_detach().await?;
            info!(log, "SP serial console detached");
            if json {
                Ok(Output::Json(json!({ "ack": "detached" })))
            } else {
                Ok(Output::Lines(
                    vec!["SP serial console detached".to_string()],
                ))
            }
        }
        Command::Update { component, slot, image, .. } => {
            let data = fs::read(&image).with_context(|| {
                format!("failed to read {}", image.display())
            })?;
            update(&log, &sp, component, slot, data).await.with_context(
                || {
                    format!(
                        "updating {} slot {} to {} failed",
                        component,
                        slot,
                        image.display()
                    )
                },
            )?;
            if json {
                Ok(Output::Json(json!({ "ack": "updated" })))
            } else {
                Ok(Output::Lines(vec!["update complete".to_string()]))
            }
        }
        Command::UpdateStatus { component } => {
            let status =
                sp.update_status(component).await.with_context(|| {
                    format!(
                        "failed to get update status to component {component}"
                    )
                })?;
            if json {
                return Ok(Output::Json(serde_json::to_value(status).unwrap()));
            }
            let status = match status {
                UpdateStatus::Preparing(sub_status) => {
                    let id = Uuid::from(sub_status.id);
                    if let Some(progress) = sub_status.progress {
                        format!(
                            "update {id} preparing (progress: {}/{})",
                            progress.current, progress.total
                        )
                    } else {
                        format!("update {id} preparing (no progress available)")
                    }
                }
                UpdateStatus::SpUpdateAuxFlashChckScan {
                    id,
                    found_match,
                    ..
                } => {
                    let id = Uuid::from(id);
                    format!("update {id} aux flash scan complete (found_match={found_match})")
                }
                UpdateStatus::InProgress(sub_status) => {
                    let id = Uuid::from(sub_status.id);
                    format!(
                        "update {id} in progress ({} of {} received)",
                        sub_status.bytes_received, sub_status.total_size,
                    )
                }
                UpdateStatus::Complete(id) => {
                    let id = Uuid::from(id);
                    format!("update {id} complete")
                }
                UpdateStatus::Aborted(id) => {
                    let id = Uuid::from(id);
                    format!("update {id} aborted")
                }
                UpdateStatus::Failed { id, code } => {
                    let id = Uuid::from(id);
                    format!("update {id} failed (code={code})")
                }
                UpdateStatus::RotError { id, error } => {
                    let id = Uuid::from(id);
                    format!("update {id} failed (rot error={error:?})")
                }
                UpdateStatus::None => "no update status available".to_string(),
            };
            info!(log, "{status}");
            Ok(Output::Lines(vec![status]))
        }
        Command::UpdateAbort { component, update_id } => {
            sp.update_abort(component, update_id).await.with_context(|| {
                format!("aborting update to {} failed", component)
            })?;
            if json {
                Ok(Output::Json(json!({ "ack": "aborted" })))
            } else {
                Ok(Output::Lines(vec![format!("update {update_id} aborted")]))
            }
        }
        Command::PowerState { new_power_state } => {
            if let Some(state) = new_power_state {
                let transition =
                    sp.set_power_state(state).await.with_context(|| {
                        format!("failed to set power state to {state:?}")
                    })?;
                info!(
                    log,
                    "successfully set SP power state to {state:?} \
                     ({transition:?})"
                );
                if json {
                    let changed = transition
                        == gateway_messages::PowerStateTransition::Changed;
                    Ok(Output::Json(json!({
                        "ack": "set",
                        "state": state,
                        "changed": changed,
                    })))
                } else {
                    Ok(Output::Lines(vec![format!(
                        "successfully set SP power state to {state:?}\
                         ({transition:?})"
                    )]))
                }
            } else {
                let state = sp
                    .power_state()
                    .await
                    .context("failed to get power state")?;
                info!(log, "SP power state = {state:?}");
                if json {
                    Ok(Output::Json(json!({ "state": state })))
                } else {
                    Ok(Output::Lines(vec![format!("{state:?}")]))
                }
            }
        }
        Command::Reset { disable_watchdog } => {
            sp.reset_component_prepare(SpComponent::SP_ITSELF).await?;
            info!(log, "SP is prepared to reset");
            sp.reset_component_trigger(
                SpComponent::SP_ITSELF,
                disable_watchdog,
            )
            .await?;
            info!(log, "SP reset complete");
            if json {
                Ok(Output::Json(json!({ "ack": "reset" })))
            } else {
                Ok(Output::Lines(vec!["reset complete".to_string()]))
            }
        }

        Command::ResetComponent { component, disable_watchdog } => {
            sp.reset_component_prepare(component).await?;
            info!(log, "SP is prepared to reset component {component}",);
            sp.reset_component_trigger(component, disable_watchdog).await?;
            info!(log, "SP reset component {component} complete");
            if json {
                Ok(Output::Json(json!({ "ack": "reset" })))
            } else {
                Ok(Output::Lines(vec!["reset complete".to_string()]))
            }
        }
        Command::SendHostNmi => {
            sp.send_host_nmi().await?;
            if json {
                Ok(Output::Json(json!({ "ack": "nmi" })))
            } else {
                Ok(Output::Lines(vec!["done".to_string()]))
            }
        }
        Command::SetIpccKeyValue { key, value_path } => {
            let value = fs::read(&value_path).with_context(|| {
                format!("failed to read {}", value_path.display())
            })?;
            sp.set_ipcc_key_lookup_value(key, value).await?;
            if json {
                Ok(Output::Json(json!({ "ack": "ipcc" })))
            } else {
                Ok(Output::Lines(vec!["done".to_string()]))
            }
        }

        Command::ReadCaboose { key } => {
            let value = sp.get_caboose_value(key).await?;
            let out = if value.is_ascii() {
                String::from_utf8(value).unwrap()
            } else {
                hex::encode(value)
            };
            if json {
                Ok(Output::Json(json!({ "value": out })))
            } else {
                Ok(Output::Lines(vec![out]))
            }
        }
        Command::SystemLed { cmd } => {
            sp.component_action(
                SpComponent::SYSTEM_LED,
                ComponentAction::Led(match cmd {
                    LedCommand::On => LedComponentAction::TurnOn,
                    LedCommand::Off => LedComponentAction::TurnOff,
                    LedCommand::Blink => LedComponentAction::Blink,
                }),
            )
            .await?;
            if json {
                Ok(Output::Json(json!({ "ack": "led" })))
            } else {
                Ok(Output::Lines(vec!["done".to_string()]))
            }
        }
        Command::Monorail { cmd } => {
            match cmd {
                MonorailCommand::Lock => {
                    sp.component_action(
                        SpComponent::MONORAIL,
                        ComponentAction::Monorail(
                            MonorailComponentAction::Lock,
                        ),
                    )
                    .await?
                }
                MonorailCommand::Unlock {
                    cmd: UnlockGroup { time, list },
                    key,
                    ssh_auth_sock,
                    permslip,
                } => {
                    if list {
                        let Some(ssh_auth_sock) = ssh_auth_sock else {
                            bail!("must provide --ssh-auth-sock");
                        };
                        for k in ssh_list_keys(&ssh_auth_sock)? {
                            println!("{}", k.to_openssh()?);
                        }
                    } else {
                        let time_sec = time.unwrap().as_secs_f32() as u32;
                        if time_sec == 0 {
                            bail!("--time must be >= 1 second");
                        }
                        monorail_unlock(
                            &log,
                            &sp,
                            time_sec,
                            ssh_auth_sock,
                            key,
                            permslip,
                        )
                        .await?;
                    }
                }
            }
            if json {
                Ok(Output::Json(json!({ "ack": "monorail" })))
            } else {
                Ok(Output::Lines(vec!["done".to_string()]))
            }
        }
        Command::ReadComponentCaboose { component, slot, key } => {
            let slot = match (component, slot.as_deref()) {
                (SpComponent::SP_ITSELF, Some("active" | "0") | None) => 0,
                (SpComponent::SP_ITSELF, Some("inactive" | "1")) => 1,
                (SpComponent::SP_ITSELF, v) => {
                    bail!(
                        "invalid slot '{}' for SP; \
                         must be 'active' or 'inactive'",
                        v.unwrap(),
                    )
                }
                (SpComponent::ROT, Some("A" | "a" | "0")) => 0,
                (SpComponent::ROT, Some("B" | "b" | "1")) => 1,
                (SpComponent::ROT, None) => {
                    bail!("must provide slot ('A' or 'B') for RoT")
                }
                (SpComponent::ROT, v) => {
                    bail!(
                        "invalid slot '{}' for ROT, must be 'A' or 'B'",
                        v.unwrap()
                    );
                }
                (SpComponent::STAGE0, Some("A" | "a" | "0")) => 0,
                (SpComponent::STAGE0, Some("B" | "b" | "1")) => 1,
                (SpComponent::STAGE0, None) => {
                    bail!("must provide slot ('A' or 'B') for Stage0")
                }
                (SpComponent::STAGE0, v) => {
                    bail!(
                        "invalid slot '{}' for Stage0, must be 'A' or 'B'",
                        v.unwrap()
                    );
                }
                (c, _) => {
                    bail!("invalid component {c} for caboose")
                }
            };
            let out =
                sp.read_component_caboose_string(component, slot, key).await?;
            if json {
                Ok(Output::Json(json!({ "value": out })))
            } else {
                Ok(Output::Lines(vec![out]))
            }
        }
        Command::ReadSensorValue { id } => {
            let out = sp.read_sensor_value(id).await?;
            Ok(if json {
                Output::Json(match out.value {
                    Ok(v) => json!({
                        "value": format!("{v}"),
                        "timestamp": out.timestamp
                    }),
                    Err(e) => json!({
                        "error": format!("{e:?}"),
                        "timestamp": out.timestamp
                    }),
                })
            } else {
                Output::Lines(match out.value {
                    Ok(v) => vec![
                        format!("value:     {v}"),
                        format!("timestamp: {}", out.timestamp),
                    ],
                    Err(e) => vec![
                        format!("error:     {e:?}"),
                        format!("timestamp: {}", out.timestamp),
                    ],
                })
            })
        }
        Command::ReadCmpa { out } => {
            let data = sp.read_rot_cmpa().await?;
            handle_cxpa("cmpa", data, out, json)
        }
        Command::ReadCfpa { out, slot } => {
            let data = match slot {
                CfpaSlot::Active => sp.read_rot_active_cfpa().await,
                CfpaSlot::Inactive => sp.read_rot_inactive_cfpa().await,
                CfpaSlot::Scratch => sp.read_rot_scratch_cfpa().await,
            }?;
            handle_cxpa("cfpa", data, out, json)
        }
        Command::VpdLockStatus => {
            let data = sp.vpd_lock_status_all().await?;

            if json {
                Ok(Output::Json(json!({ "vpd_lock_status": data })))
            } else {
                let mut out = vec![];
                for b in data {
                    out.push(format!("{b:x?}"));
                }
                Ok(Output::Lines(out))
            }
        }
        Command::Dump { cmd } => match cmd {
            DumpCommand::Count => {
                let n = sp.task_dump_count().await?;

                if json {
                    Ok(Output::Json(json!({"count": n})))
                } else {
                    Ok(Output::Lines(vec![format!("count: {n}")]))
                }
            }
            DumpCommand::Read { index, output } => {
                let task = sp.task_dump_read(index).await?;

                let output = output.unwrap_or_else(|| {
                    (0..)
                        .map(|i| PathBuf::from(format!("hubris.dry.{i}")))
                        .find(|p| !p.exists())
                        .unwrap()
                });
                task.write_zip(std::fs::File::create(&output)?)?;

                if json {
                    let regions = task
                        .memory
                        .iter()
                        .map(|(k, v)| (*k, v.len()))
                        .collect::<Vec<(u32, usize)>>();
                    Ok(Output::Json(json!({
                        "task_index": task.task_index,
                        "crashed_at": task.timestamp,
                        "gitc": task.gitc,
                        "bord": task.bord,
                        "regions": regions,
                        "written_to": output,
                    })))
                } else {
                    let mut lines = vec![
                        format!(
                            "task {}: crashed at {}",
                            task.task_index, task.timestamp
                        ),
                        format!("gitc: {}", task.gitc),
                        format!("bord: {}", task.bord),
                        format!("{} memory regions:", task.memory.len()),
                    ];
                    for (k, v) in task.memory {
                        lines.push(format!("  {k:#08x}: {:#08x}", v.len()));
                    }
                    lines.push(format!("written to {output:?}"));
                    Ok(Output::Lines(lines))
                }
            }
        },
        Command::Ereports {
            start_ena,
            committed_ena,
            restart_id: req_restart_id,
            limit,
        } => {
            anyhow::ensure!(
                committed_ena <= Some(start_ena),
                "`--committed-ena` argument must be less than or equal to \
                 `--start-ena`",
            );

            let tranche = sp
                .ereports(
                    req_restart_id,
                    ereport::Ena::new(start_ena),
                    limit,
                    committed_ena.map(ereport::Ena::new),
                )
                .await?;

            if json {
                return Ok(Output::Json(json!(tranche)));
            }

            let gateway_sp_comms::ereport::EreportTranche {
                ereports,
                restart_id,
            } = tranche;

            let mut lines = vec![format!("restart ID: {restart_id}")];
            if req_restart_id != restart_id {
                lines.push(format!(
                    "restart IDs did not match (requested {req_restart_id})",
                ));
            }
            lines.push(format!("count: {}", ereports.len()));
            lines.push(String::new());
            lines.push("ereports:".to_string());

            for ereport in ereports {
                lines.push(format!(
                    "{:#x}: {:#?}\n",
                    ereport.ena.into_u64(),
                    ereport.data
                ));
            }

            Ok(Output::Lines(lines))
        }
        Command::ReadHostFlash { slot, addr } => {
            let result = sp.read_host_flash(slot, addr).await?;
            Ok(Output::Lines(vec![format!("{result:x?}")]))
        }
        Command::DumpHostFlash { slot, size, output, start_address } => {
            let mut fh = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output)
                .with_context(|| format!("failed to create `{output}`"))?;
            let progress_bar = if std::io::stderr().is_terminal() {
                Some(
                    ProgressBar::new(u64::from(size)).with_style(
                        ProgressStyle::default_bar()
                            .template(
                                "dumping [{bar:30}] \
                                 {bytes}/{total_bytes} ({bytes_per_sec})",
                            )
                            .expect("template should be valid"),
                    ),
                )
            } else {
                None
            };

            let mut addr = start_address;
            let mut bytes_dumped = 0;

            while bytes_dumped < size {
                let data = sp.read_host_flash(slot, addr).await.with_context(
                    || format!("failed to read data at offset {addr}"),
                )?;

                let to_write =
                    usize::min(data.len(), (size - bytes_dumped) as usize);
                fh.write_all(&data[..to_write])
                    .with_context(|| format!("failed writing to `{output}`"))?;

                let to_write = to_write as u32;
                addr += to_write;
                bytes_dumped += to_write;
                if let Some(bar) = &progress_bar {
                    bar.inc(u64::from(to_write));
                }
            }
            if json {
                Ok(Output::Json(json!({"file-written": output.to_string()})))
            } else {
                Ok(Output::Lines(vec![format!("wrote {output}")]))
            }
        }
        Command::StartHostFlashHash { slot } => {
            sp.start_host_flash_hash(slot).await?;
            Ok(Output::Lines(vec!["hash started".to_string()]))
        }
        Command::GetHostFlashHash { slot } => {
            let result = sp.get_host_flash_hash(slot).await?;
            Ok(Output::Lines(vec![format!("{result:x?}")]))
        }
    }
}

async fn monorail_unlock(
    log: &Logger,
    sp: &SingleSp,
    time_sec: u32,
    ssh_sock: Option<PathBuf>,
    pub_key: Option<String>,
    permslip: bool,
) -> Result<()> {
    let r = sp
        .component_action_with_response(
            SpComponent::MONORAIL,
            ComponentAction::Monorail(
                MonorailComponentAction::RequestChallenge,
            ),
        )
        .await?;

    let ComponentActionResponse::Monorail(
        MonorailComponentActionResponse::RequestChallenge(challenge),
    ) = r
    else {
        bail!("unexpected response: {r:?}");
    };
    info!(log, "received challenge {challenge:?}");

    let response = match challenge {
        UnlockChallenge::Trivial { timestamp } => {
            UnlockResponse::Trivial { timestamp }
        }
        UnlockChallenge::EcdsaSha2Nistp256(ecdsa_challenge) => {
            if pub_key.is_some() && permslip {
                unlock_permslip(log, pub_key.unwrap(), challenge)?
            } else if let Some(socket) = ssh_sock {
                unlock_ssh(log, socket, pub_key, ecdsa_challenge)?
            } else {
                bail!("don't know how to unlock tech port without ssh or permslip")
            }
        }
    };
    sp.component_action(
        SpComponent::MONORAIL,
        ComponentAction::Monorail(MonorailComponentAction::Unlock {
            challenge,
            response,
            time_sec,
        }),
    )
    .await?;

    Ok(())
}

fn unlock_permslip(
    log: &Logger,
    key_name: String,
    challenge: UnlockChallenge,
) -> Result<UnlockResponse> {
    use std::env;
    use std::process::{Command, Stdio};

    let mut permslip = Command::new(
        env::var("PERMSLIP").unwrap_or_else(|_| String::from("permslip")),
    )
    .arg("sign")
    .arg(key_name)
    .arg("--sshauth")
    .arg("--kind=tech-port-unlock-challenge")
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::inherit())
    .spawn()
    .map_err(|_| {
        anyhow!(
            "Unable to execute `permslip`, is it in your PATH and executable? \
             You may also override it with the PERMSLIP environment variable."
        )
    })?;

    let mut input =
        permslip.stdin.take().context("can't get permslip input")?;
    input.write_all(serde_json::to_string(&challenge)?.as_bytes())?;
    input.flush()?;
    drop(input);

    let output =
        permslip.wait_with_output().context("can't read permslip output")?;
    if output.status.success() {
        let response =
            serde_json::from_slice::<UnlockResponse>(&output.stdout)?;
        debug!(log, "got response from permslip"; "response" => ?response);
        Ok(response)
    } else {
        bail!("online signing with permslip failed");
    }
}

fn unlock_ssh(
    log: &Logger,
    socket: PathBuf,
    pub_key: Option<String>,
    challenge: EcdsaSha2Nistp256Challenge,
) -> Result<UnlockResponse> {
    let keys = ssh_list_keys(&socket)?;
    let pub_key = if keys.len() == 1 && pub_key.is_none() {
        keys[0].clone()
    } else {
        let Some(pub_key) = pub_key else {
            bail!(
                "need --key for ECDSA challenge; \
                 multiple keys are available"
            );
        };
        if pub_key.ends_with(".pub") {
            ssh_key::PublicKey::read_openssh_file(Path::new(&pub_key))
                .with_context(|| {
                    format!("could not read key from {pub_key:?}")
                })?
        } else {
            let mut found = None;
            for k in keys.iter() {
                if k.to_openssh()?.contains(&pub_key) {
                    if found.is_some() {
                        bail!("multiple keys contain '{pub_key}'");
                    }
                    found = Some(k);
                }
            }
            let Some(found) = found else {
                bail!(
                    "could not match '{pub_key}'; \
                     use `faux-mgs monorail unlock --list` \
                     to print keys"
                );
            };
            found.clone()
        }
    };

    let mut data = challenge.as_bytes().to_vec();
    let signer_nonce: [u8; 8] = rand::random();
    data.extend(signer_nonce);

    let signed = ssh_keygen_sign(socket, pub_key, &data)?;
    debug!(log, "got signature {signed:?}");

    let key_bytes = signed.public_key().ecdsa().unwrap().as_sec1_bytes();
    assert_eq!(key_bytes.len(), 65, "invalid key length");
    let mut key = [0u8; 65];
    key.copy_from_slice(key_bytes);

    // Signature bytes are encoded per
    // https://datatracker.ietf.org/doc/html/rfc5656#section-3.1.2
    //
    // They are a pair of `mpint` values, per
    // https://datatracker.ietf.org/doc/html/rfc4251
    //
    // Each one is either 32 bytes or 33 bytes with a leading zero, so
    // we'll awkwardly allow for both cases.
    let mut r = std::io::Cursor::new(signed.signature_bytes());
    use std::io::Read;
    let mut signature = [0u8; 64];
    for i in 0..2 {
        let mut size = [0u8; 4];
        r.read_exact(&mut size)?;
        match u32::from_be_bytes(size) {
            32 => (),
            33 => r.read_exact(&mut [0u8])?, // eat the leading byte
            _ => bail!("invalid length {i}"),
        }
        r.read_exact(&mut signature[i * 32..][..32])?;
    }

    Ok(UnlockResponse::EcdsaSha2Nistp256 { key, signer_nonce, signature })
}

fn ssh_keygen_sign(
    socket: PathBuf,
    pub_key: ssh_key::PublicKey,
    data: &[u8],
) -> Result<ssh_key::SshSig> {
    use ssh_key::{Algorithm, EcdsaCurve, HashAlg, SshSig};

    let mut client = get_ssh_client(socket)?;

    const NAMESPACE: &str = "monorail-unlock";
    const HASH: HashAlg = HashAlg::Sha256;
    let blob = SshSig::signed_data(NAMESPACE, HASH, data)?;

    let sig = client.sign(&pub_key, &blob)?;
    let sig = SshSig::new(pub_key.into(), NAMESPACE, HASH, sig)?;

    // Confirm that the signature is of the expected form
    match sig.algorithm() {
        Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 } => {}
        h => bail!("invalid signature algorithm {h:?}"),
    }
    match sig.hash_alg() {
        HashAlg::Sha256 => {}
        h => bail!("invalid hash algorithm {h:?}"),
    }
    Ok(sig)
}

fn handle_cxpa(
    name: &str,
    data: [u8; ROT_PAGE_SIZE],
    out: Option<PathBuf>,
    json: bool,
) -> Result<Output> {
    Ok(if let Some(f) = &out {
        std::fs::write(f, data).context(format!(
            "failed to write {} to {f:?}",
            name.to_uppercase()
        ))?;
        if json {
            Output::Json(json!({ "ok": true }))
        } else {
            Output::Lines(vec!["ok".to_string()])
        }
    } else if json {
        Output::Json(json!({ name: data.to_vec() }))
    } else {
        Output::Lines(vec![format!("{data:x?}")])
    })
}

async fn update(
    log: &Logger,
    sp: &SingleSp,
    component: SpComponent,
    slot: u16,
    data: Vec<u8>,
) -> Result<()> {
    let update_id = Uuid::new_v4();
    info!(log, "generated update ID"; "id" => %update_id);
    let mut update_driver = Some(
        sp.start_update(component, update_id, slot, data)
            .await
            .context("failed to start update")?,
    );

    let sp_update_id = UpdateId::from(update_id);
    loop {
        // Bail if the update driver task has failed.
        if update_driver.as_ref().is_some_and(|driver| driver.is_finished()) {
            let update_driver = update_driver.take().unwrap();
            update_driver
                .await
                .context("update driver task died")?
                .context("update driver task failed")?;
        }

        let status = sp
            .update_status(component)
            .await
            .context("failed to get update status")?;
        match status {
            UpdateStatus::None => {
                bail!("no update status returned by SP (did it reset?)");
            }
            UpdateStatus::Preparing(sub_status) => {
                if sub_status.id != sp_update_id {
                    bail!("different update preparing ({:?})", sub_status.id);
                }
                if let Some(progress) = sub_status.progress {
                    info!(
                        log,
                        "update preparing: {}/{}",
                        progress.current,
                        progress.total,
                    );
                } else {
                    info!(log, "update preparing (no progress available)");
                }
            }
            UpdateStatus::SpUpdateAuxFlashChckScan {
                id,
                found_match,
                total_size,
            } => {
                if id != sp_update_id {
                    bail!("different update in progress ({:?})", id);
                }
                info!(
                    log, "aux flash scan complete";
                    "found_match" => found_match,
                    "total_size" => total_size,
                );
            }
            UpdateStatus::InProgress(sub_status) => {
                if sub_status.id != sp_update_id {
                    bail!("different update in progress ({:?})", sub_status.id);
                }
                info!(
                    log, "update in progress";
                    "bytes_received" => sub_status.bytes_received,
                    "total_size" => sub_status.total_size,
                );
            }
            UpdateStatus::Complete(id) => {
                if id != sp_update_id {
                    bail!("different update complete ({id:?})");
                }
                return Ok(());
            }
            UpdateStatus::Aborted(id) => {
                if id != sp_update_id {
                    bail!("different update aborted ({id:?})");
                }
                bail!("update aborted");
            }
            UpdateStatus::Failed { id, code } => {
                if id != sp_update_id {
                    bail!("different update failed ({id:?}, code {code})");
                }
                bail!("update failed (code {code})");
            }
            UpdateStatus::RotError { id, error } => {
                if id != sp_update_id {
                    bail!("different update failed ({id:?}, error {error:?})");
                }
                bail!("update failed (error {error:?})");
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn populate_phase2_images(
    cache: &InMemoryHostPhase2Provider,
    path: &Path,
    log: &Logger,
) -> Result<()> {
    let dir_iter = fs::read_dir(path).with_context(|| {
        format!("failed to open directory for reading: {}", path.display())
    })?;

    for entry in dir_iter {
        let entry = entry.with_context(|| {
            format!("failed to read directory entry in {}", path.display())
        })?;
        let entry_path = entry.path();

        let file_type = entry.file_type().with_context(|| {
            format!("failed to read file type of {}", entry_path.display())
        })?;

        if file_type.is_symlink() {
            let meta = fs::metadata(&entry_path).with_context(|| {
                format!("failed to metadata of {}", entry_path.display())
            })?;
            if !meta.file_type().is_file() {
                continue;
            }
        } else if !file_type.is_file() {
            continue;
        }

        let data = fs::read(&entry_path).with_context(|| {
            format!("failed to read {}", entry_path.display())
        })?;

        match cache.insert(data).await {
            Ok(hash) => {
                info!(
                    log, "added phase2 image to server cache";
                    "hash" => hex::encode(hash),
                    "path" => entry_path.display(),
                );
            }
            Err(err) => {
                warn!(
                    log, "skipping file (not a phase2 image?)";
                    "path" => entry_path.display(),
                    err,
                );
            }
        }
    }

    Ok(())
}

enum Output {
    Json(serde_json::Value),
    Lines(Vec<String>),
}

fn component_details_to_json(details: SpComponentDetails) -> serde_json::Value {
    use gateway_messages::measurement::{MeasurementError, MeasurementKind};
    use gateway_messages::monorail_port_status::{PortStatus, PortStatusError};

    // SpComponentDetails and Measurement from gateway_messages intentionally do
    // not derive `Serialize` to avoid accidental misuse in MGS / the SP, so we
    // do a little work here to map them to something that does.
    #[derive(serde::Serialize)]
    #[serde(tag = "kind")]
    enum ComponentDetails {
        PortStatus(Result<PortStatus, PortStatusError>),
        Measurement(Measurement),
        LastPostCode(u32),
        GpioToggleCount { edge_count: u32, cycles_since_last_edge: u32 },
    }

    #[derive(serde::Serialize)]
    struct Measurement {
        pub name: String,
        pub kind: MeasurementKind,
        pub value: Result<f32, MeasurementError>,
    }

    let entries = details
        .entries
        .into_iter()
        .map(|d| match d {
            gateway_messages::ComponentDetails::PortStatus(r) => {
                ComponentDetails::PortStatus(r)
            }
            gateway_messages::ComponentDetails::Measurement(m) => {
                ComponentDetails::Measurement(Measurement {
                    name: m.name,
                    kind: m.kind,
                    value: m.value,
                })
            }
            gateway_messages::ComponentDetails::LastPostCode(code) => {
                ComponentDetails::LastPostCode(code.0)
            }
            gateway_messages::ComponentDetails::GpioToggleCount(n) => {
                ComponentDetails::GpioToggleCount {
                    edge_count: n.edge_count,
                    cycles_since_last_edge: n.cycles_since_last_edge,
                }
            }
        })
        .collect::<Vec<_>>();

    json!({ "entries": entries })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// Helper to parse args, prefixing with required global args.
    fn parse_args(args: &[&str]) -> Result<Args, clap::Error> {
        let mut full_args = vec!["faux-mgs", "--interface", "test0"];
        full_args.extend(args);
        Args::try_parse_from(full_args)
    }

    /// Helper to check that parsing succeeds and extract the Command.
    fn parse_command(args: &[&str]) -> Command {
        parse_args(args).expect("should parse successfully").command
    }

    /// Helper to check that parsing fails.
    fn parse_should_fail(args: &[&str]) {
        assert!(
            parse_args(args).is_err(),
            "expected parsing to fail for args: {:?}",
            args
        );
    }

    //
    // Tests for pilot compatibility (these were broken by #385)
    //

    /// Pilot uses `component-active-slot host-boot-flash -s {slot}` for
    /// transient updates. This must work without requiring --persist or
    /// --transient.
    #[test]
    fn pilot_host_boot_flash_set_slot_transient_default() {
        let cmd = parse_command(&[
            "component-active-slot",
            "host-boot-flash",
            "-s",
            "0",
        ]);
        match cmd {
            Command::ComponentActiveSlot {
                component,
                set,
                persist,
                transient,
            } => {
                assert_eq!(component, SpComponent::HOST_CPU_BOOT_FLASH);
                assert_eq!(set, Some(0));
                assert!(
                    !persist,
                    "should default to non-persistent (transient)"
                );
                assert!(!transient, "transient flag should not be set");
            }
            _ => panic!("expected ComponentActiveSlot command"),
        }
    }

    /// Pilot uses `component-active-slot host-boot-flash -s {slot} --persist`
    /// for persistent updates.
    #[test]
    fn pilot_host_boot_flash_set_slot_persistent() {
        let cmd = parse_command(&[
            "component-active-slot",
            "host-boot-flash",
            "-s",
            "1",
            "--persist",
        ]);
        match cmd {
            Command::ComponentActiveSlot {
                component,
                set,
                persist,
                transient,
            } => {
                assert_eq!(component, SpComponent::HOST_CPU_BOOT_FLASH);
                assert_eq!(set, Some(1));
                assert!(persist, "persist flag should be set");
                assert!(!transient);
            }
            _ => panic!("expected ComponentActiveSlot command"),
        }
    }

    /// Pilot's operate.rs uses `component-active-slot {component} --set {slot}
    /// --persist` with various components.
    #[test]
    fn pilot_operate_set_slot_persistent() {
        for component_name in ["rot", "sp", "host-boot-flash", "stage0"] {
            let cmd = parse_command(&[
                "component-active-slot",
                component_name,
                "--set",
                "0",
                "--persist",
            ]);
            match cmd {
                Command::ComponentActiveSlot { set, persist, .. } => {
                    assert_eq!(set, Some(0));
                    assert!(persist);
                }
                _ => panic!("expected ComponentActiveSlot command"),
            }
        }
    }

    //
    // Tests for getting active slot (no -s flag)
    //

    #[test]
    fn get_active_slot_rot() {
        let cmd = parse_command(&["component-active-slot", "rot"]);
        match cmd {
            Command::ComponentActiveSlot {
                component,
                set,
                persist,
                transient,
            } => {
                assert_eq!(component, SpComponent::ROT);
                assert_eq!(set, None);
                assert!(!persist);
                assert!(!transient);
            }
            _ => panic!("expected ComponentActiveSlot command"),
        }
    }

    #[test]
    fn get_active_slot_host_boot_flash() {
        let cmd = parse_command(&["component-active-slot", "host-boot-flash"]);
        match cmd {
            Command::ComponentActiveSlot { component, set, .. } => {
                assert_eq!(component, SpComponent::HOST_CPU_BOOT_FLASH);
                assert_eq!(set, None);
            }
            _ => panic!("expected ComponentActiveSlot command"),
        }
    }

    #[test]
    fn get_active_slot_sp() {
        let cmd = parse_command(&["component-active-slot", "sp"]);
        match cmd {
            Command::ComponentActiveSlot { component, set, .. } => {
                assert_eq!(component, SpComponent::SP_ITSELF);
                assert_eq!(set, None);
            }
            _ => panic!("expected ComponentActiveSlot command"),
        }
    }

    //
    // Tests for setting active slot with --transient
    // (was broken: only allowed for 'rot' component)
    //

    #[test]
    fn set_slot_transient_rot() {
        let cmd = parse_command(&[
            "component-active-slot",
            "rot",
            "-s",
            "0",
            "--transient",
        ]);
        match cmd {
            Command::ComponentActiveSlot {
                component,
                set,
                persist,
                transient,
            } => {
                assert_eq!(component, SpComponent::ROT);
                assert_eq!(set, Some(0));
                assert!(!persist);
                assert!(transient);
            }
            _ => panic!("expected ComponentActiveSlot command"),
        }
    }

    #[test]
    fn set_slot_transient_host_boot_flash() {
        let cmd = parse_command(&[
            "component-active-slot",
            "host-boot-flash",
            "-s",
            "1",
            "-t",
        ]);
        match cmd {
            Command::ComponentActiveSlot {
                component,
                set,
                persist,
                transient,
            } => {
                assert_eq!(component, SpComponent::HOST_CPU_BOOT_FLASH);
                assert_eq!(set, Some(1));
                assert!(!persist);
                assert!(transient);
            }
            _ => panic!("expected ComponentActiveSlot command"),
        }
    }

    #[test]
    fn set_slot_transient_sp() {
        let cmd = parse_command(&[
            "component-active-slot",
            "sp",
            "-s",
            "0",
            "--transient",
        ]);
        match cmd {
            Command::ComponentActiveSlot { component, transient, .. } => {
                assert_eq!(component, SpComponent::SP_ITSELF);
                assert!(transient);
            }
            _ => panic!("expected ComponentActiveSlot command"),
        }
    }

    //
    // Tests for invalid argument combinations
    //

    /// --transient requires --set
    #[test]
    fn transient_requires_set() {
        parse_should_fail(&["component-active-slot", "rot", "--transient"]);
        parse_should_fail(&["component-active-slot", "host-boot-flash", "-t"]);
    }

    /// --persist requires --set
    #[test]
    fn persist_requires_set() {
        parse_should_fail(&["component-active-slot", "rot", "--persist"]);
        parse_should_fail(&["component-active-slot", "host-boot-flash", "-p"]);
    }

    /// --persist and --transient are mutually exclusive
    #[test]
    fn persist_and_transient_conflict() {
        parse_should_fail(&[
            "component-active-slot",
            "rot",
            "-s",
            "0",
            "--persist",
            "--transient",
        ]);
        parse_should_fail(&[
            "component-active-slot",
            "host-boot-flash",
            "-s",
            "0",
            "-p",
            "-t",
        ]);
    }

    /// Cannot specify the same flag twice
    #[test]
    fn no_duplicate_flags() {
        parse_should_fail(&[
            "component-active-slot",
            "rot",
            "-s",
            "0",
            "-p",
            "-p",
        ]);
        parse_should_fail(&[
            "component-active-slot",
            "rot",
            "-s",
            "0",
            "-t",
            "-t",
        ]);
    }
}
