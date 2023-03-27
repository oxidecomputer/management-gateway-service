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
use futures::stream::FuturesOrdered;
use futures::FutureExt;
use futures::StreamExt;
use gateway_messages::ignition::TransceiverSelect;
use gateway_messages::IgnitionCommand;
use gateway_messages::PowerState;
use gateway_messages::ResetIntent;
use gateway_messages::SpComponent;
use gateway_messages::StartupOptions;
use gateway_messages::UpdateId;
use gateway_messages::UpdateStatus;
use gateway_sp_comms::InMemoryHostPhase2Provider;
use gateway_sp_comms::SharedSocket;
use gateway_sp_comms::SingleSp;
use gateway_sp_comms::SwitchPortConfig;
use gateway_sp_comms::MGS_PORT;
use slog::info;
use slog::o;
use slog::warn;
use slog::Drain;
use slog::Level;
use slog::Logger;
use std::fs;
use std::fs::File;
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

#[derive(Subcommand, Debug, Clone)]
enum Command {
    /// Discover a connected SP.
    Discover,

    /// Ask SP for its current state.
    State,

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
    ComponentActiveSlot {
        component: String,
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
    ComponentDetails { component: String },

    /// Ask SP to clear the state (e.g., reset counters) on a component.
    ComponentClearStatus { component: String },

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

        component: String,
        slot: u16,
        image: PathBuf,
    },

    /// Get the status of an update to the specified component.
    UpdateStatus { component: String },

    /// Abort an in-progress update.
    UpdateAbort {
        /// Component with an update-in-progress to be aborted. Omit to abort
        /// updates to the SP itself.
        component: String,
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

    /// Instruct the SP to reset.
    Reset,

    /// Reset a component.
    ///
    /// This command is implemented for the component "rot" but may be
    /// expanded to other components in the future.
    //
    // TODO: RoT boot image selection.
    // TODO: revoke RoT Prod keys.
    ResetComponent {
        /// "rot" and "stage0" are equivalent since they are different firmware images on the same
        /// physical part.
        component: String,
        #[clap(
             default_value = "normal",
             help = "'normal'(default) perform a simple reset of the component.{n}\
                     'persistent' changes the CFPA image selection to `slot`.{n}\
                     'transient' overrides the CFPA selection to `slot` for the next reset only.{n}\
                     Selecting a slot with a lower image epoch will be refused by the RoT.",
                     // TODO: ExpensiveAndIrrevocableProdToDev with auth_data
             value_parser = reset_intent_from_str,
        )]
        intent: ResetIntent,

        // RoT ImageA=0, ImageB=1
        #[clap(
            default_value = None,
            help = "Image slot selection for Persistent and Transient intents",
        )]
        slot: Option<u16>,
        // TODO: Authorization for ExpensiveAndIrrevocableProdToDev
        // auth: [u8; EAIPTD_MAX_SIZE],
        // // Path to authentication blob
        // auth: Option<PathBuf>,
    },
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

fn reset_intent_from_str(s: &str) -> Result<ResetIntent> {
    match s {
        "normal" | "n" => Ok(ResetIntent::Normal),
        "persistent" | "p" => Ok(ResetIntent::Persistent),
        "transient" | "t" => Ok(ResetIntent::Transient),
        // "expensive_and_irrevocable_prod_to_dev" => Ok(ResetIntent::ExpensiveAndIrrevocableProdToDev),
        _ => Err(anyhow!("Invalid reset intent: {s}")),
    }
}

fn build_logger(level: Level, path: Option<&Path>) -> Result<Logger> {
    fn make_drain<D: slog_term::Decorator + Send + 'static>(
        level: Level,
        decorator: D,
    ) -> slog::Fuse<slog_async::Async> {
        let drain = slog_term::FullFormat::new(decorator)
            .build()
            .filter_level(level)
            .fuse();
        slog_async::Async::new(drain).build().fuse()
    }

    let drain = if let Some(path) = path {
        // Special case /dev/null - don't even bother with slog_async, just
        // return a discarding logger.
        if path == Path::new("/dev/null") {
            return Ok(Logger::root(slog::Discard, o!()));
        }

        let file = File::create(path).with_context(|| {
            format!("failed to create logfile {}", path.display())
        })?;
        make_drain(level, slog_term::PlainDecorator::new(file))
    } else {
        make_drain(level, slog_term::TermDecorator::new().build())
    };

    Ok(Logger::root(drain, o!("component" => "faux-mgs")))
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

    let log = build_logger(args.log_level, args.logfile.as_deref())?;

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
            )
            .await?;

            // If usart::run() returns, the user detached; exit.
            return Ok(());
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
            run_command(sp, args.command.clone(), log.clone())
                .map(|result| (interface, result))
        })
        .collect::<FuturesOrdered<_>>();

    while let Some((interface, result)) = all_results.next().await {
        let prefix = if num_sps > 1 {
            format!("{interface:maxwidth$} ")
        } else {
            String::new()
        };
        match result {
            Ok(lines) => {
                for line in lines {
                    println!("{prefix}{line}");
                }
            }
            Err(err) => println!("{prefix}Error: {err}"),
        }
    }

    Ok(())
}

async fn run_command(
    sp: SingleSp,
    command: Command,
    log: Logger,
) -> Result<Vec<String>> {
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
                        break Ok(vec![format!("addr={addr}, port={port:?}")]);
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
            let mut lines = Vec::new();
            lines.push(format!(
                "hubris archive: {}",
                hex::encode(state.hubris_archive_id)
            ));

            let zero_padded_to_str = |bytes: [u8; 32]| {
                let stop =
                    bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                String::from_utf8_lossy(&bytes[..stop]).to_string()
            };

            lines.push(format!(
                "serial number: {}",
                zero_padded_to_str(state.serial_number)
            ));
            lines.push(format!("model: {}", zero_padded_to_str(state.model)));
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

            // TODO: pretty print RoT state?
            lines.push(format!("RoT state: {:?}", state.rot));
            Ok(lines)
        }
        Command::Ignition { target } => {
            let mut lines = Vec::new();
            if let Some(target) = target.0 {
                let state = sp.ignition_state(target).await?;
                lines.push(format!("target {target}: {state:?}"));
            } else {
                let states = sp.bulk_ignition_state().await?;
                for (i, state) in states.into_iter().enumerate() {
                    lines.push(format!("target {i}: {state:?}"));
                }
            }
            Ok(lines)
        }
        Command::IgnitionCommand { target, command } => {
            sp.ignition_command(target, command).await?;
            info!(log, "ignition command {command:?} send to target {target}");
            Ok(vec![format!("successfully send {command:?}")])
        }
        Command::IgnitionLinkEvents { target } => {
            let mut lines = Vec::new();
            if let Some(target) = target.0 {
                let events = sp.ignition_link_events(target).await;
                lines.push(format!("target {target}: {events:?}"));
            } else {
                let events = sp.bulk_ignition_link_events().await?;
                for (i, events) in events.into_iter().enumerate() {
                    lines.push(format!("target {i}: {events:?}"));
                }
            }
            Ok(lines)
        }
        Command::ClearIgnitionLinkEvents { target, transceiver_select } => {
            sp.clear_ignition_link_events(target.0, transceiver_select.0)
                .await?;
            info!(log, "ignition link events cleared");
            Ok(vec!["ignition link events cleared".to_string()])
        }
        Command::ComponentActiveSlot { component, set, persist } => {
            let sp_component = SpComponent::try_from(component.as_str())
                .map_err(|_| {
                    anyhow!("invalid component name: {}", component)
                })?;
            if let Some(slot) = set {
                sp.set_component_active_slot(sp_component, slot, persist)
                    .await?;
                Ok(vec![format!("set active slot for {component:?} to {slot}")])
            } else {
                let slot = sp.component_active_slot(sp_component).await?;
                info!(log, "active slot for {component:?}: {slot}");
                Ok(vec![format!("{slot}")])
            }
        }
        Command::StartupOptions { options } => {
            if let Some(options) = options {
                let options =
                    StartupOptions::from_bits(options).with_context(|| {
                        format!("invalid startup options bits: {options:#x}")
                    })?;
                sp.set_startup_options(options).await?;
                Ok(vec![format!(
                    "successfully set startup options to {options:?}"
                )])
            } else {
                let options = sp.get_startup_options().await?;
                Ok(vec![format!("startup options: {options:?}")])
            }
        }
        Command::Inventory => {
            let mut lines = Vec::new();
            let inventory = sp.inventory().await?;
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
            Ok(lines)
        }
        Command::ComponentDetails { component } => {
            let sp_component = SpComponent::try_from(component.as_str())
                .map_err(|_| {
                    anyhow!("invalid component name: {}", component)
                })?;
            let details = sp.component_details(sp_component).await?;
            let mut lines = Vec::new();
            for entry in details.entries {
                lines.push(format!("{entry:?}"));
            }
            Ok(lines)
        }
        Command::ComponentClearStatus { component } => {
            let sp_component = SpComponent::try_from(component.as_str())
                .map_err(|_| {
                    anyhow!("invalid component name: {}", component)
                })?;
            sp.component_clear_status(sp_component).await?;
            info!(log, "status cleared for component {component}");
            Ok(vec!["status cleared".to_string()])
        }
        Command::UsartDetach => {
            sp.serial_console_detach().await?;
            info!(log, "SP serial console detached");
            Ok(vec!["SP serial console detached".to_string()])
        }
        Command::Update { component, slot, image, .. } => {
            let sp_component = SpComponent::try_from(component.as_str())
                .map_err(|_| {
                    anyhow!("invalid component name: {}", component)
                })?;
            let data = fs::read(&image).with_context(|| {
                format!("failed to read {}", image.display())
            })?;
            update(&log, &sp, sp_component, slot, data).await.with_context(
                || {
                    format!(
                        "updating {} slot {} to {} failed",
                        component,
                        slot,
                        image.display()
                    )
                },
            )?;
            Ok(vec!["update complete".to_string()])
        }
        Command::UpdateStatus { component } => {
            let sp_component = SpComponent::try_from(component.as_str())
                .map_err(|_| anyhow!("invalid component name: {component}"))?;
            let status =
                sp.update_status(sp_component).await.with_context(|| {
                    format!(
                        "failed to get update status to component {component}"
                    )
                })?;
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
                UpdateStatus::None => "no update status available".to_string(),
            };
            info!(log, "{status}");
            Ok(vec![status])
        }
        Command::UpdateAbort { component, update_id } => {
            let sp_component = SpComponent::try_from(component.as_str())
                .map_err(|_| anyhow!("invalid component name: {component}"))?;
            sp.update_abort(sp_component, update_id).await.with_context(
                || format!("aborting update to {} failed", component),
            )?;
            Ok(vec!["update {update_id} aborted".to_string()])
        }
        Command::PowerState { new_power_state } => {
            if let Some(state) = new_power_state {
                sp.set_power_state(state).await.with_context(|| {
                    format!("failed to set power state to {state:?}")
                })?;
                info!(log, "successfully set SP power state to {state:?}");
                Ok(vec![format!(
                    "successfully set SP power state to {state:?}"
                )])
            } else {
                let state = sp
                    .power_state()
                    .await
                    .context("failed to get power state")?;
                info!(log, "SP power state = {state:?}");
                Ok(vec![format!("{state:?}")])
            }
        }
        Command::Reset => {
            sp.reset_prepare().await?;
            info!(log, "SP is prepared to reset");
            sp.reset_trigger().await?;
            info!(log, "SP reset complete");
            Ok(vec!["reset complete".to_string()])
        }
        // TODO: Add slot, intent, and PathBuf to auth blob
        Command::ResetComponent {
            component,
            intent: _intents,
            slot: _slot,
        } => {
            let sp_component = SpComponent::try_from(component.as_str())
                .map_err(|_| anyhow!("invalid component name: {component}"))?;
            sp.reset_component_prepare(sp_component).await?;
            info!(
                log,
                "SP is repared to reset component {}",
                component.as_str()
            );
            sp.reset_component_trigger(
                sp_component,
                None,
                ResetIntent::Normal,
            )
            .await?;
            info!(log, "SP reset component {} complete", component.as_str());
            Ok(vec!["reset complete".to_string()])
        }
        Command::SendHostNmi => {
            sp.send_host_nmi().await?;
            Ok(vec!["done".to_string()])
        }
        Command::SetIpccKeyValue { key, value_path } => {
            let value = fs::read(&value_path).with_context(|| {
                format!("failed to read {}", value_path.display())
            })?;
            sp.set_ipcc_key_lookup_value(key, value).await?;
            Ok(vec!["done".to_string()])
        }

        Command::ReadCaboose { key } => {
            let value = sp.get_caboose_value(key).await?;
            let out = if value.is_ascii() {
                String::from_utf8(value).unwrap()
            } else {
                format!("{value:?}")
            };
            Ok(vec![out])
        }
    }
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
                    "err" => %err,
                );
            }
        }
    }

    Ok(())
}
