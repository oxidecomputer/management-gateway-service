// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

use anyhow::Context;
use anyhow::Result;
use gateway_messages::SpComponent;
use gateway_sp_comms::AttachedSerialConsoleSend;
use gateway_sp_comms::SingleSp;
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
) -> Result<()> {
    // Put terminal in raw mode, if requested, with a guard to restore it.
    let _guard =
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
    let (send_tx, send_rx) = mpsc::channel(8);
    let tx_to_sp_handle = tokio::spawn(async move {
        relay_data_to_sp(console_tx, send_rx).await.unwrap();
    });

    loop {
        tokio::select! {
            result = stdin.read_buf(&mut stdin_buf) => {
                let n = result.context("failed to read from stdin")?;
                if n == 0 {
                    mem::drop(send_tx);
                    tx_to_sp_handle.await.unwrap();
                    return Ok(());
                }

                match out_buf.ingest(&mut stdin_buf) {
                    IngestResult::Ok => (),
                    IngestResult::Exit => {
                        mem::drop(send_tx);
                        tx_to_sp_handle.await.unwrap();
                        return Ok(());
                    }
                    IngestResult::Break => {
                        send_tx.send(SendTxData::Break)
                            .await
                            .with_context(|| "failed to send data (task shutdown?)")?;
                    }
                }

                flush_delay.start_if_unstarted().await;
            }

            chunk = console_rx.recv() => {
                let chunk = chunk.unwrap();

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
}

async fn relay_data_to_sp(
    mut console_tx: AttachedSerialConsoleSend,
    mut data_rx: mpsc::Receiver<SendTxData>,
) -> Result<()> {
    while let Some(data) = data_rx.recv().await {
        match data {
            SendTxData::Buf(buf) => console_tx.write(buf).await?,
            SendTxData::Break => console_tx.send_break().await?,
        }
    }
    console_tx.detach().await?;

    Ok(())
}

#[derive(Debug)]
enum SendTxData {
    Buf(Vec<u8>),
    Break,
}

struct UnrawTermiosGuard {
    stdout: i32,
    ios: Termios,
}

impl Drop for UnrawTermiosGuard {
    fn drop(&mut self) {
        termios::tcsetattr(self.stdout, termios::TCSAFLUSH, &self.ios).unwrap();
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
        Ok(Self { stdout, ios: orig_ios })
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
            self.tx.send(()).await.unwrap();
        }
    }

    async fn ready(&mut self) {
        self.rx.recv().await.unwrap();
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
                        return IngestResult::Break;
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

        IngestResult::Ok
    }

    fn steal_buf(&mut self) -> Vec<u8> {
        let mut stolen = Vec::new();
        mem::swap(&mut stolen, &mut self.buf);
        stolen
    }
}
