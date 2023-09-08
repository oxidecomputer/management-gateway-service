// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

use anyhow::Context;
use anyhow::Result;
use gateway_messages::BadRequestReason;
use gateway_messages::SpComponent;
use gateway_messages::SpError;
use gateway_messages::SERIAL_CONSOLE_IDLE_TIMEOUT;
use gateway_sp_comms::error::CommunicationError;
use gateway_sp_comms::AttachedSerialConsoleSend;
use gateway_sp_comms::SingleSp;
use slog::error;
use slog::info;
use slog::warn;
use std::collections::VecDeque;
use std::fs::File;
use std::io;
use std::io::Write;
use std::mem;
use std::os::unix::prelude::AsRawFd;
use std::path::PathBuf;
use std::time::Duration;
use termios::Termios;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::time;
use tokio::time::Interval;
use tokio::time::MissedTickBehavior;

use crate::picocom_map::RemapRules;

const CTRL_A: u8 = b'\x01';
const CTRL_X: u8 = b'\x18';
const CTRL_BACKSLASH: u8 = b'\x1c';

pub(crate) async fn run(
    sp: SingleSp,
    raw: bool,
    stdin_buffer_time: Duration,
    imap: Option<String>,
    omap: Option<String>,
    uart_logfile: Option<PathBuf>,
    log: slog::Logger,
) -> Result<()> {
    // Put terminal in raw mode, if requested, with a guard to restore it on
    // drop or when we return.
    let termios_guard =
        if raw { Some(UnrawTermiosGuard::make_stdout_raw()?) } else { None };

    // Parse imap/omap strings.
    let imap = match imap {
        Some(s) => s.parse().context("invalid imap rules")?,
        None => RemapRules::default(),
    };
    let omap = match omap {
        Some(s) => s.parse().context("invalid omap rules")?,
        None => RemapRules::default(),
    };

    // Open uart logfile, if requested.
    let mut uart_logfile = match uart_logfile {
        Some(path) => {
            let f = File::options()
                .append(true)
                .create(true)
                .open(&path)
                .with_context(|| {
                    format!("failed to open {}", path.display())
                })?;
            Some(f)
        }
        None => None,
    };

    let mut stdin = tokio::io::stdin();
    let mut stdin_buf = Vec::with_capacity(64);
    let mut out_buf = StdinOutBuf::new(omap, raw);
    let mut flush_delay = FlushDelay::new(stdin_buffer_time);
    let console = sp
        .serial_console_attach(SpComponent::SP3_HOST_CPU)
        .await
        .with_context(|| "failed to attach to serial console")?;

    let (console_tx, mut console_rx) = console.split();
    let (fatal_err_tx, mut fatal_err_rx) = oneshot::channel();
    let (send_tx, send_rx) = mpsc::channel(8);
    let tx_to_sp_handle = tokio::spawn(relay_data_to_sp(
        console_tx,
        send_rx,
        fatal_err_tx,
        log.clone(),
    ));

    let mut encountered_fatal_error = false;
    loop {
        tokio::select! {
            result = stdin.read_buf(&mut stdin_buf) => {
                let n = result.context("failed to read from stdin")?;
                if n == 0 {
                    break;
                }

                match out_buf.ingest(&mut stdin_buf) {
                    IngestResult::Ok => (),
                    IngestResult::Exit => {
                        break;
                    }
                    IngestResult::Break => {
                        send_tx.send(SendTxData::Break)
                            .await
                            .context("failed to send data (task shutdown?)")?;
                        println!("\n\r*** break sent ***\r");
                    }
                }

                flush_delay.start_if_unstarted().await;
            }

            fatal_err_result = &mut fatal_err_rx => {
                // The sending half of `fatal_err_rx` is held by our
                // `relay_data_to_sp` task; it should only exit if we tell it to
                // (which we do _below_ this select loop if we break out due to
                // the user exiting) or if it encounters a fatal error (in which
                // case it first sends a message on this channel).
                let fatal_err = fatal_err_result
                    .expect("tx_to_sp task panicked");
                error!(
                    log, "fatal communication error with SP";
                    "err" => #%fatal_err,
                );
                encountered_fatal_error = true;
                break;
            }

            chunk = console_rx.recv() => {
                // The sending half of `console_rx` is held by the task spawned
                // when `sp` was created; it should not exit until we drop `sp`.
                let chunk = chunk.expect("internal SP task panicked");

                if let Some(uart_logfile) = uart_logfile.as_mut() {
                    uart_logfile
                        .write_all(&chunk)
                        .context("failed to write to logfile")?;
                }

                let data = imap.apply(chunk).collect::<Vec<_>>();

                let mut stdout = io::stdout().lock();
                stdout.write_all(&data).context("failed to write to stdout")?;
                stdout.flush().context("failed to flush stdout")?;
            }

            _ = flush_delay.ready() => {
                send_tx
                    .send(SendTxData::Buf(out_buf.steal_buf()))
                    .await
                    .with_context(|| "failed to send data (task shutdown?)")?;
            }
        }
    }

    // Drop the sending half of this channel to signal our tx-to-sp task to
    // exit.
    mem::drop(send_tx);
    let console_tx = tx_to_sp_handle.await.expect("tx_to_sp task panicked");

    // If we encountered a fatal error, we will not attempt to detach from the
    // SP. One possible fatal error is _someone else detached us_, and they
    // might have attached themselves in the meantime. Other fatal errors
    // indicate a serious problem communicating with the SP, and it's likely
    // detaching will fail anyway.
    if !encountered_fatal_error {
        console_tx
            .detach()
            .await
            .context("failed to detach from SP console")?;
    }

    // Restore termios settings, if we put the terminal into raw mode. (This
    // would happen automatically when the guard is dropped, but doing it
    // explicitly lets us check for errors.)
    if let Some(guard) = termios_guard {
        guard.restore()?;
    }

    Ok(())
}

async fn relay_data_to_sp(
    mut console_tx: AttachedSerialConsoleSend,
    mut data_rx: mpsc::Receiver<SendTxData>,
    fatal_err_tx: oneshot::Sender<CommunicationError>,
    log: slog::Logger,
) -> AttachedSerialConsoleSend {
    let mut keepalive = time::interval(SERIAL_CONSOLE_IDLE_TIMEOUT / 4);
    keepalive.set_missed_tick_behavior(MissedTickBehavior::Delay);

    // If we fail to send a message, we need to resend it; we'll keep a running
    // ticker and check for messages-to-send every second.
    let mut check_for_resend = time::interval(Duration::from_secs(1));
    check_for_resend.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut messages_to_send = VecDeque::new();

    // If we warn the user that we've failed to communicate with the SP, we will
    // also inform them if we later succeed.
    let mut recently_warned = false;

    loop {
        tokio::select! {
            maybe_data = data_rx.recv() => {
                match maybe_data {
                    Some(message) => {
                        messages_to_send.push_front(message);
                        if let Err(fatal_err) = drain_messages_to_send(
                            &mut messages_to_send,
                            &mut console_tx,
                            &mut keepalive,
                            &mut recently_warned,
                            &log,
                        ).await {
                            fatal_err_tx
                                .send(fatal_err)
                                .expect("parent task exited");
                            return console_tx;
                        }
                    }
                    None => return console_tx,
                }
            }

            _ = check_for_resend.tick() => {
                if let Err(fatal_err) = drain_messages_to_send(
                    &mut messages_to_send,
                    &mut console_tx,
                    &mut keepalive,
                    &mut recently_warned,
                    &log,
                ).await {
                    fatal_err_tx.send(fatal_err).expect("parent task exited");
                    return console_tx;
                }
            }

            _ = keepalive.tick() => {
                match console_tx.keepalive().await {
                    Ok(()) => (),
                    // Temporary stopgap that allows us to continue talking to
                    // SPs that don't yet have the keepalive update.
                    Err(CommunicationError::SpError(SpError::BadRequest(
                        BadRequestReason::DeserializationError,
                    ))) => {
                        warn!(
                            log,
                            "This SP does not support console keepalives! \
                             Please update it at your earliest convenience.",
                        );
                        // Change our keepalive timer to only tick once ever 4
                        // hours (i.e., probably never, unless someone leaves
                        // the console open.)
                        keepalive = time::interval(
                            Duration::from_secs(4 * 3600)
                        );
                        keepalive.reset();
                    }
                    Err(err) => {
                        warn!(
                            log, "failed to send console keepalive";
                            "err" => #%err,
                        );
                    }
                }
            }
        }
    }
}

async fn drain_messages_to_send(
    messages: &mut VecDeque<SendTxData>,
    tx: &mut AttachedSerialConsoleSend,
    keepalive: &mut Interval,
    recently_warned: &mut bool,
    log: &slog::Logger,
) -> Result<(), CommunicationError> {
    while let Some(message) = messages.front().cloned() {
        let result = match message {
            SendTxData::Buf(data) => tx.write(data).await,
            SendTxData::Break => tx.send_break().await,
        };

        match result {
            Ok(()) => {
                if *recently_warned {
                    info!(log, "communication with SP reestablished");
                    *recently_warned = false;
                }
                messages.pop_front();
                keepalive.reset();
            }
            // These error cases are fatal: if we get this response, we do not
            // expect any future writes to succeed.
            Err(
                fatal_err @ (CommunicationError::SpError(
                    SpError::BadRequest(_)
                    | SpError::RequestUnsupportedForSp
                    | SpError::RequestUnsupportedForComponent
                    | SpError::SerialConsoleNotAttached
                    | SpError::SerialConsoleAlreadyAttached,
                )
                | CommunicationError::BogusSerialConsoleState
                | CommunicationError::VersionMismatch { .. }),
            ) => {
                return Err(fatal_err);
            }
            Err(non_fatal_err) => {
                warn!(
                    log, "communication error with SP (will retry)";
                    "err" => #%non_fatal_err,
                );
                *recently_warned = true;
                return Ok(());
            }
        }
    }

    Ok(())
}

#[derive(Debug, Clone)]
enum SendTxData {
    Buf(Vec<u8>),
    Break,
}

struct UnrawTermiosGuard {
    stdout: i32,
    ios: Termios,
    restored: bool,
}

impl Drop for UnrawTermiosGuard {
    fn drop(&mut self) {
        if !self.restored {
            _ = termios::tcsetattr(self.stdout, termios::TCSAFLUSH, &self.ios);
        }
    }
}

impl UnrawTermiosGuard {
    fn make_stdout_raw() -> Result<Self> {
        let stdout = io::stdout().as_raw_fd();
        let mut ios = Termios::from_fd(stdout)
            .with_context(|| "could not get termios for stdout")?;
        let orig_ios = ios;
        termios::cfmakeraw(&mut ios);
        termios::tcsetattr(stdout, termios::TCSANOW, &ios)
            .with_context(|| "failed to set TCSANOW on stdout")?;
        termios::tcflush(stdout, termios::TCIOFLUSH)
            .with_context(|| "failed to set TCIOFLUSH on stdout")?;
        Ok(Self { stdout, ios: orig_ios, restored: false })
    }

    fn restore(mut self) -> Result<()> {
        termios::tcsetattr(self.stdout, termios::TCSAFLUSH, &self.ios)
            .context("failed to restore stdout termios settings")?;
        self.restored = true;
        Ok(())
    }
}

struct FlushDelay {
    started: bool,
    tx: mpsc::Sender<()>,
    rx: mpsc::Receiver<()>,
}

impl FlushDelay {
    fn new(duration: Duration) -> Self {
        let (tx0, mut rx0) = mpsc::channel(1);
        let (tx1, rx1) = mpsc::channel(1);
        tokio::spawn(async move {
            loop {
                match rx0.recv().await {
                    Some(()) => (),
                    None => return,
                }

                tokio::time::sleep(duration).await;

                let _ = tx1.send(()).await;
            }
        });
        Self { started: false, tx: tx0, rx: rx1 }
    }

    async fn start_if_unstarted(&mut self) {
        if !self.started {
            self.started = true;
            self.tx.send(()).await.expect("inner task panicked");
        }
    }

    async fn ready(&mut self) {
        self.rx.recv().await.expect("inner task panicked");
        self.started = false;
    }
}

struct StdinOutBuf {
    raw_mode: bool,
    in_prefix: bool,
    remap: RemapRules,
    buf: Vec<u8>,
}

enum IngestResult {
    Ok,
    Exit,

    /// Send a break on the UART
    Break,
}

impl StdinOutBuf {
    fn new(remap: RemapRules, raw_mode: bool) -> Self {
        Self { raw_mode, in_prefix: false, remap, buf: Vec::new() }
    }

    fn ingest(&mut self, buf: &mut Vec<u8>) -> IngestResult {
        let buf = self.remap.apply(buf.drain(..));

        if !self.raw_mode {
            self.buf.extend(buf);
            return IngestResult::Ok;
        }

        let mut result = IngestResult::Ok;
        for c in buf {
            match c {
                CTRL_A => {
                    if self.in_prefix {
                        // Ctrl-A Ctrl-A should be sent as Ctrl-A
                        self.buf.push(c);
                        self.in_prefix = false;
                    } else {
                        self.in_prefix = true;
                    }
                }
                CTRL_X => {
                    if self.in_prefix {
                        // Exit on Ctrl-A Ctrl-X
                        return IngestResult::Exit;
                    } else {
                        self.buf.push(c);
                    }
                }
                CTRL_BACKSLASH => {
                    if self.in_prefix {
                        // Keep processing the buffer, but return a flag
                        // indicating that the host wants a USART break to be
                        // sent.
                        result = IngestResult::Break;
                        self.in_prefix = false;
                    } else {
                        self.buf.push(c);
                    }
                }
                _ => {
                    self.buf.push(c);
                    self.in_prefix = false;
                }
            }
        }

        result
    }

    fn steal_buf(&mut self) -> Vec<u8> {
        let mut stolen = Vec::new();
        mem::swap(&mut stolen, &mut self.buf);
        stolen
    }
}
