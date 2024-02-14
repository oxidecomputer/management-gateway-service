// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;
use futures::stream::FuturesOrdered;
use futures::FutureExt;
use futures::StreamExt;
use gateway_messages::ignition::TransceiverSelect;
use gateway_messages::ComponentAction;
use gateway_messages::IgnitionCommand;
use gateway_messages::LedComponentAction;
use gateway_messages::PowerState;
use gateway_messages::SpComponent;
use gateway_messages::StartupOptions;
use gateway_messages::UpdateId;
use gateway_messages::UpdateStatus;
use gateway_messages::ROT_PAGE_SIZE;
use gateway_sp_comms::InMemoryHostPhase2Provider;
use gateway_sp_comms::SharedSocket;
use gateway_sp_comms::SingleSp;
use gateway_sp_comms::SpComponentDetails;
use gateway_sp_comms::SwitchPortConfig;
use gateway_sp_comms::VersionedSpState;
use gateway_sp_comms::MGS_PORT;
use serde_json::json;
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
use std::io;
use std::mem;
use std::net::SocketAddrV6;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

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

    /// Maximum number of attempts to make when sending requests to the SP.
    #[clap(long, default_value = "5")]
    max_attempts: usize,

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
enum Command {
    /// Discover a connected SP.
    Discover,

    /// Ask SP for its current state.
    State,

    /// Ask RoT via SP for its current boot-time information represented by
    /// a particular struct.
    RotBootInfo {
        /// RotStateV2 is the default verion
        #[clap(long, short, default_value = "3")]
        version: u8,
    },

    /// Get the ignition state for a single target port (only valid if the SP is
    /// an ignition controller).
    Ignition {
        #[clap(
            help = "integer of a target, or 'all' for all targets",
            value_parser = IgnitionLinkEventsTarget::parse,
        )]
        target: IgnitionLinkEventsTarget,
    },

    /// Send an ignition command for a single target port (only valid if the SP
    /// is an ignition controller).
    IgnitionCommand {
        target: u8,
        #[clap(
            help = "'power-on', 'power-off', or 'power-reset'",
            value_parser = ignition_command_from_str,
        )]
        command: IgnitionCommand,
    },

    /// Get bulk ignition link events (only valid if the SP is an ignition
    /// controller).
    IgnitionLinkEvents {
        #[clap(
            help = "integer of a target, or 'all' for all targets",
            value_parser = IgnitionLinkEventsTarget::parse,
        )]
        target: IgnitionLinkEventsTarget,
    },

    /// Clear all ignition link events (only valid if the SP is an ignition
    /// controller).
    ClearIgnitionLinkEvents {
        #[clap(
            help = "integer of a target, or 'all' for all targets",
            value_parser = IgnitionLinkEventsTarget::parse,
        )]
        target: IgnitionLinkEventsTarget,
        #[clap(
            help = "'controller', 'target-link0', 'target-link1', or 'all'",
            value_parser = IgnitionLinkEventsTransceiverSelect::parse,
        )]
        transceiver_select: IgnitionLinkEventsTransceiverSelect,
    },

    /// Get or set the active slot of a component (e.g., `host-boot-flash`).
    ///
    /// In the case of the bootloader flash banks, there is no atomic switching
    /// from stage0next (bank 1), to stage0 (bank 0). Instead, contents are copied.
    ///
    /// The copy is only performed if the signature on stage0next was valid at boot time
    /// and the current contents still match the boot-time contents.
    ///
    /// Power failures during the copy can disable the RoT. Only one stage0 update
    /// should be in process in a rack at any time.
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
    },

    /// Get or set startup options on an SP.
    StartupOptions { options: Option<u64> },

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
    ServeHostPhase2 { directory: PathBuf },

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
    Reset,

    /// Reset a component.
    ///
    /// This command is implemented for the component "rot" but may be
    /// expanded to other components in the future.
    ResetComponent {
        #[clap(value_parser = parse_sp_component)]
        component: SpComponent,
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

#[derive(Debug, Clone, Copy)]
struct IgnitionLinkEventsTarget(Option<u8>);

impl IgnitionLinkEventsTarget {
    fn parse(s: &str) -> Result<Self> {
        match s {
            "all" | "ALL" => Ok(Self(None)),
            _ => {
                let target = s
                    .parse()
                    .with_context(|| "must be an integer (0..256) or 'all'")?;
                Ok(Self(Some(target)))
            }
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

    let per_attempt_timeout =
        Duration::from_millis(args.per_attempt_timeout_millis);

    let listen_port =
        args.listen_port.unwrap_or_else(|| args.command.default_listen_port());

    // For faux-mgs, we'll serve all images present in the directory the user
    // requests, so don't cap the LRU cache size.
    let host_phase2_provider =
        Arc::new(InMemoryHostPhase2Provider::with_capacity(usize::MAX));

    let shared_socket = SharedSocket::bind(
        listen_port,
        Arc::clone(&host_phase2_provider),
        log.clone(),
    )
    .await
    .context("SharedSocket:bind() failed")?;

    let interfaces = build_requested_interfaces(args.interface)?;
    let mut sps = Vec::with_capacity(interfaces.len());
    for interface in interfaces {
        info!(log, "creating SP handle on interface {interface}");
        sps.push(
            SingleSp::new(
                &shared_socket,
                SwitchPortConfig {
                    discovery_addr: args.discovery_addr,
                    interface,
                },
                args.max_attempts,
                per_attempt_timeout,
            )
            .await,
        );
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

    Ok(())
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
                        Ok(rotstate) => lines.push(format!("{}", &rotstate)),
                        Err(err) => lines.push(format!("RoT state: {:?}", err)),
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
                        Ok(rotstate) => lines.push(format!("{}", &rotstate)),
                        Err(err) => lines.push(format!("RoT state: {:?}", err)),
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
            let state = sp.rot_state(version).await?;
            info!(log, "{state:x?}");
            if json {
                return Ok(Output::Json(serde_json::to_value(state).unwrap()));
            }
            let mut lines = Vec::new();
            lines.push(format!("{}", state));
            Ok(Output::Lines(lines))
        }
        Command::Ignition { target } => {
            let mut by_target = BTreeMap::new();
            if let Some(target) = target.0 {
                let state = sp.ignition_state(target).await?;
                by_target.insert(usize::from(target), state);
            } else {
                let states = sp.bulk_ignition_state().await?;
                for (i, state) in states.into_iter().enumerate() {
                    by_target.insert(i, state);
                }
            }
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
        Command::IgnitionCommand { target, command } => {
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
        Command::IgnitionLinkEvents { target } => {
            let mut by_target = BTreeMap::new();
            if let Some(target) = target.0 {
                let events = sp.ignition_link_events(target).await?;
                by_target.insert(usize::from(target), events);
            } else {
                let events = sp.bulk_ignition_link_events().await?;
                for (i, events) in events.into_iter().enumerate() {
                    by_target.insert(i, events);
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
        Command::ClearIgnitionLinkEvents { target, transceiver_select } => {
            sp.clear_ignition_link_events(target.0, transceiver_select.0)
                .await?;
            info!(log, "ignition link events cleared");
            if json {
                Ok(Output::Json(json!({ "ack": "cleared" })))
            } else {
                Ok(Output::Lines(vec![
                    "ignition link events cleared".to_string()
                ]))
            }
        }
        Command::ComponentActiveSlot { component, set, persist } => {
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
            let mut lines = Vec::new();
            for entry in details.entries {
                lines.push(format!("{entry:?}"));
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
                    format!("update {id} aux flash scan complete (found_match={found_match}")
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
                sp.set_power_state(state).await.with_context(|| {
                    format!("failed to set power state to {state:?}")
                })?;
                info!(log, "successfully set SP power state to {state:?}");
                if json {
                    Ok(Output::Json(json!({ "ack": "set", "state": state })))
                } else {
                    Ok(Output::Lines(vec![format!(
                        "successfully set SP power state to {state:?}"
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
        Command::Reset => {
            sp.reset_component_prepare(SpComponent::SP_ITSELF).await?;
            info!(log, "SP is prepared to reset");
            sp.reset_component_trigger(SpComponent::SP_ITSELF).await?;
            info!(log, "SP reset complete");
            if json {
                Ok(Output::Json(json!({ "ack": "reset" })))
            } else {
                Ok(Output::Lines(vec!["reset complete".to_string()]))
            }
        }

        Command::ResetComponent { component } => {
            sp.reset_component_prepare(component).await?;
            info!(log, "SP is prepared to reset component {component}",);
            sp.reset_component_trigger(component).await?;
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
                (c, _) => {
                    bail!("invalid component {c} for caboose")
                }
            };
            let value = sp.read_component_caboose(component, slot, key).await?;
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
    }
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
    sp.start_update(component, update_id, slot, data)
        .await
        .context("failed to start update")?;

    let sp_update_id = UpdateId::from(update_id);
    loop {
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
        })
        .collect::<Vec<_>>();

    json!({ "entries": entries })
}
