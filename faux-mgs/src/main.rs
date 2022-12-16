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
use gateway_messages::ignition::TransceiverSelect;
use gateway_messages::IgnitionCommand;
use gateway_messages::PowerState;
use gateway_messages::SpComponent;
use gateway_messages::StartupOptions;
use gateway_messages::UpdateId;
use gateway_messages::UpdateStatus;
use gateway_sp_comms::SingleSp;
use gateway_sp_comms::SwitchPortConfig;
use host_phase2::DirectoryHostPhase2Provider;
use slog::info;
use slog::o;
use slog::Drain;
use slog::Level;
use slog::Logger;
use std::fs;
use std::fs::File;
use std::net::SocketAddrV6;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use uuid::Uuid;

mod host_phase2;
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
        help = "Log level for MGS client",
    )]
    log_level: Level,

    /// Write logs to a file instead of stderr.
    #[clap(long)]
    logfile: Option<PathBuf>,

    /// Address to bind to locally.
    #[clap(long, default_value_t = gateway_sp_comms::default_listen_addr())]
    listen_addr: SocketAddrV6,

    /// Address to use to discover the SP. May be a specific SP's address to
    /// bypass multicast discovery.
    #[clap(long, default_value_t = gateway_sp_comms::default_discovery_addr())]
    discovery_addr: SocketAddrV6,

    /// Interface to specify as the scope ID for both `listen_addr` and
    /// `discovery_addr`.
    #[clap(long)]
    interface: Option<String>,

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

#[derive(Subcommand, Debug)]
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
    Update { component: String, slot: u16, image: PathBuf },

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

    /// Instruct the SP to reset.
    Reset,
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

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let log = build_logger(args.log_level, args.logfile.as_deref())?;

    let per_attempt_timeout =
        Duration::from_millis(args.per_attempt_timeout_millis);

    if let Some(interface) = args.interface.as_ref() {
        info!(log, "binding to {} on {}", args.listen_addr, interface);
    } else {
        info!(log, "binding to {}", args.listen_addr);
    }

    let host_phase2_provider =
        if let Command::ServeHostPhase2 { directory } = &args.command {
            DirectoryHostPhase2Provider::new(directory, &log).await?
        } else {
            DirectoryHostPhase2Provider::default()
        };

    let sp = SingleSp::new(
        SwitchPortConfig {
            listen_addr: args.listen_addr,
            discovery_addr: args.discovery_addr,
            interface: args.interface,
        },
        args.max_attempts,
        per_attempt_timeout,
        host_phase2_provider,
        log.clone(),
    );

    // Wait for `sp` to finish starting up.
    sp.wait_for_startup_completion()
        .await
        .with_context(|| "SP communicator startup failed")?;

    match args.command {
        Command::Discover => {
            info!(log, "attempting SP discovery");

            // `sp_addr_watch()` can only fail if startup fails, which we waited
            // for and checked above; this is safe to unwrap.
            let mut addr_watch = sp.sp_addr_watch().unwrap().clone();

            // "None" command indicates only discovery was requested; loop until
            // discovery completes, then log the result.
            loop {
                let current = *addr_watch.borrow();
                match current {
                    Some((addr, port)) => {
                        info!(
                            log, "SP discovered";
                            "addr" => %addr,
                            "port" => ?port,
                        );
                        break;
                    }
                    None => {
                        addr_watch.changed().await.unwrap();
                    }
                }
            }
        }
        Command::State => {
            info!(log, "{:?}", sp.state().await?);
        }
        Command::Ignition { target } => {
            if let Some(target) = target.0 {
                let state = sp.ignition_state(target).await?;
                println!("target {target}: {state:?}");
            } else {
                let states = sp.bulk_ignition_state().await?;
                for (i, state) in states.into_iter().enumerate() {
                    println!("target {i}: {state:?}");
                }
            }
        }
        Command::IgnitionCommand { target, command } => {
            sp.ignition_command(target, command).await?;
            info!(log, "ignition command {command:?} send to target {target}");
        }
        Command::IgnitionLinkEvents { target } => {
            if let Some(target) = target.0 {
                let events = sp.ignition_link_events(target).await;
                println!("target {target}: {events:?}");
            } else {
                let events = sp.bulk_ignition_link_events().await?;
                for (i, events) in events.into_iter().enumerate() {
                    println!("target {i}: {events:?}");
                }
            }
        }
        Command::ClearIgnitionLinkEvents { target, transceiver_select } => {
            sp.clear_ignition_link_events(target.0, transceiver_select.0)
                .await?;
            info!(log, "ignition link events cleared");
        }
        Command::ComponentActiveSlot { component, set } => {
            let sp_component = SpComponent::try_from(component.as_str())
                .map_err(|_| {
                    anyhow!("invalid component name: {}", component)
                })?;
            if let Some(slot) = set {
                sp.set_component_active_slot(sp_component, slot).await?;
                println!("set active slot for {component:?} to {slot}");
            } else {
                let slot = sp.component_active_slot(sp_component).await?;
                info!(log, "active slot for {component:?}: {slot}");
                println!("{slot}");
            }
        }
        Command::StartupOptions { options } => {
            if let Some(options) = options {
                let options =
                    StartupOptions::from_bits(options).with_context(|| {
                        format!("invalid startup options bits: {options:#x}")
                    })?;
                sp.set_startup_options(options).await?;
                println!("successfully set startup options to {options:?}");
            } else {
                let options = sp.get_startup_options().await?;
                println!("startup options: {options:?}");
            }
        }
        Command::Inventory => {
            let inventory = sp.inventory().await?;
            println!(
                "{:<16} {:<12} {:<16} {:<}",
                "COMPONENT", "STATUS", "DEVICE", "DESCRIPTION (CAPABILITIES)"
            );
            for d in inventory.devices {
                println!(
                    "{:<16} {:<12} {:<16} {} ({:?})",
                    d.component.as_str().unwrap_or("???"),
                    format!("{:?}", d.presence),
                    d.device,
                    d.description,
                    d.capabilities,
                );
            }
        }
        Command::ComponentDetails { component } => {
            let sp_component = SpComponent::try_from(component.as_str())
                .map_err(|_| {
                    anyhow!("invalid component name: {}", component)
                })?;
            let details = sp.component_details(sp_component).await?;
            for entry in details.entries {
                println!("{entry:?}");
            }
        }
        Command::ComponentClearStatus { component } => {
            let sp_component = SpComponent::try_from(component.as_str())
                .map_err(|_| {
                    anyhow!("invalid component name: {}", component)
                })?;
            sp.component_clear_status(sp_component).await?;
            info!(log, "status cleared for component {component}");
        }
        Command::UsartAttach {
            raw,
            stdin_buffer_time_millis,
            imap,
            omap,
            uart_logfile,
        } => {
            usart::run(
                sp,
                raw,
                Duration::from_millis(stdin_buffer_time_millis),
                imap,
                omap,
                uart_logfile,
            )
            .await?;
        }
        Command::UsartDetach => {
            sp.serial_console_detach().await?;
            info!(log, "SP serial console detached");
        }
        Command::ServeHostPhase2 { .. } => {
            info!(log, "serving host phase 2 images (ctrl-c to stop)");
            loop {
                tokio::time::sleep(Duration::from_secs(1024)).await;
            }
        }
        Command::Update { component, slot, image } => {
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
            match status {
                UpdateStatus::Preparing(sub_status) => {
                    let id = Uuid::from(sub_status.id);
                    if let Some(progress) = sub_status.progress {
                        info!(
                            log, "update still preparing (progress: {}/{})",
                            progress.current, progress.total;
                            "id" => %id,
                        );
                    } else {
                        info!(
                            log, "update still preparing (no progress available)";
                            "id" => %id,
                        );
                    }
                }
                UpdateStatus::SpUpdateAuxFlashChckScan {
                    id,
                    found_match,
                    ..
                } => {
                    let id = Uuid::from(id);
                    info!(
                        log, "aux flash scan complete";
                        "id" => %id,
                        "found_match" => found_match,
                    );
                }
                UpdateStatus::InProgress(sub_status) => {
                    let id = Uuid::from(sub_status.id);
                    info!(
                        log, "update in progress";
                        "id" => %id,
                        "bytes_received" => sub_status.bytes_received,
                        "total_size" => sub_status.total_size,
                    );
                }
                UpdateStatus::Complete(id) => {
                    let id = Uuid::from(id);
                    info!(log, "update complete"; "id" => %id);
                }
                UpdateStatus::Aborted(id) => {
                    let id = Uuid::from(id);
                    info!(log, "update aborted"; "id" => %id);
                }
                UpdateStatus::Failed { id, code } => {
                    let id = Uuid::from(id);
                    info!(log, "update failed"; "id" => %id, "code" => code);
                }
                UpdateStatus::None => {
                    info!(log, "no update status available");
                }
            }
        }
        Command::UpdateAbort { component, update_id } => {
            let sp_component = SpComponent::try_from(component.as_str())
                .map_err(|_| anyhow!("invalid component name: {component}"))?;
            sp.update_abort(sp_component, update_id).await.with_context(
                || format!("aborting update to {} failed", component),
            )?;
        }
        Command::PowerState { new_power_state } => {
            if let Some(state) = new_power_state {
                sp.set_power_state(state).await.with_context(|| {
                    format!("failed to set power state to {state:?}")
                })?;
                info!(log, "successfully set SP power state to {state:?}");
            } else {
                let state = sp
                    .power_state()
                    .await
                    .context("failed to get power state")?;
                info!(log, "SP power state = {state:?}");
                println!("{state:?}");
            }
        }
        Command::Reset => {
            sp.reset_prepare().await?;
            info!(log, "SP is prepared to reset");
            sp.reset_trigger().await?;
            info!(log, "SP reset complete");
        }
    }

    Ok(())
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
