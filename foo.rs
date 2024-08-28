#![feature(prelude_import)]
#[prelude_import]
use std::prelude::rust_2021::*;
#[macro_use]
extern crate std;
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
use gateway_messages::ComponentActionResponse;
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
use gateway_sp_comms::InMemoryHostPhase2Provider;
use gateway_sp_comms::SharedSocket;
use gateway_sp_comms::SingleSp;
use gateway_sp_comms::SpComponentDetails;
use gateway_sp_comms::SwitchPortConfig;
use gateway_sp_comms::VersionedSpState;
use gateway_sp_comms::MGS_PORT;
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
use std::io;
use std::mem;
use std::net::SocketAddrV6;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;
use zerocopy::AsBytes;
mod picocom_map {
    //! picocom-style character remapping; does not support the "... to hex" rules.
    use std::{collections::VecDeque, str::FromStr};
    use anyhow::{bail, ensure, Error, Result};
    pub struct RemapRules {
        cr: Option<&'static [u8]>,
        lf: Option<&'static [u8]>,
        bsdel: bool,
        delbs: bool,
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for RemapRules {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field4_finish(
                f,
                "RemapRules",
                "cr",
                &self.cr,
                "lf",
                &self.lf,
                "bsdel",
                &self.bsdel,
                "delbs",
                &&self.delbs,
            )
        }
    }
    #[automatically_derived]
    impl ::core::default::Default for RemapRules {
        #[inline]
        fn default() -> RemapRules {
            RemapRules {
                cr: ::core::default::Default::default(),
                lf: ::core::default::Default::default(),
                bsdel: ::core::default::Default::default(),
                delbs: ::core::default::Default::default(),
            }
        }
    }
    #[automatically_derived]
    impl ::core::clone::Clone for RemapRules {
        #[inline]
        fn clone(&self) -> RemapRules {
            let _: ::core::clone::AssertParamIsClone<Option<&'static [u8]>>;
            let _: ::core::clone::AssertParamIsClone<Option<&'static [u8]>>;
            let _: ::core::clone::AssertParamIsClone<bool>;
            *self
        }
    }
    #[automatically_derived]
    impl ::core::marker::Copy for RemapRules {}
    impl FromStr for RemapRules {
        type Err = Error;
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let mut rules = Self::default();
            for rule in s.split(',') {
                match rule {
                    "crlf" => {
                        if ::anyhow::__private::not(rules.cr.is_none()) {
                            return ::anyhow::__private::Err({
                                let error = ::anyhow::__private::format_err(
                                    format_args!("multiple rules remapping cr"),
                                );
                                error
                            });
                        }
                        rules.cr = Some(&[raw::LF]);
                    }
                    "crcrlf" => {
                        if ::anyhow::__private::not(rules.cr.is_none()) {
                            return ::anyhow::__private::Err({
                                let error = ::anyhow::__private::format_err(
                                    format_args!("multiple rules remapping cr"),
                                );
                                error
                            });
                        }
                        rules.cr = Some(&[raw::CR, raw::LF]);
                    }
                    "igncr" => {
                        if ::anyhow::__private::not(rules.cr.is_none()) {
                            return ::anyhow::__private::Err({
                                let error = ::anyhow::__private::format_err(
                                    format_args!("multiple rules remapping cr"),
                                );
                                error
                            });
                        }
                        rules.cr = Some(&[]);
                    }
                    "lfcr" => {
                        if ::anyhow::__private::not(rules.lf.is_none()) {
                            return ::anyhow::__private::Err({
                                let error = ::anyhow::__private::format_err(
                                    format_args!("multiple rules remapping lf"),
                                );
                                error
                            });
                        }
                        rules.lf = Some(&[raw::CR]);
                    }
                    "lfcrlf" => {
                        if ::anyhow::__private::not(rules.lf.is_none()) {
                            return ::anyhow::__private::Err({
                                let error = ::anyhow::__private::format_err(
                                    format_args!("multiple rules remapping lf"),
                                );
                                error
                            });
                        }
                        rules.lf = Some(&[raw::CR, raw::LF]);
                    }
                    "ignlf" => {
                        if ::anyhow::__private::not(rules.lf.is_none()) {
                            return ::anyhow::__private::Err({
                                let error = ::anyhow::__private::format_err(
                                    format_args!("multiple rules remapping lf"),
                                );
                                error
                            });
                        }
                        rules.lf = Some(&[]);
                    }
                    "bsdel" => {
                        rules.bsdel = true;
                    }
                    "delbs" => {
                        rules.delbs = true;
                    }
                    _ => {
                        return ::anyhow::__private::Err({
                            let error = ::anyhow::__private::format_err(
                                format_args!(
                                    "unknown or unsupported remap rule: {0:?}",
                                    rule,
                                ),
                            );
                            error
                        });
                    }
                }
            }
            Ok(rules)
        }
    }
    impl RemapRules {
        pub fn apply<I>(&self, bytes: I) -> RemapIter<I::IntoIter>
        where
            I: IntoIterator<Item = u8>,
        {
            RemapIter {
                inner: bytes.into_iter(),
                prev: VecDeque::new(),
                rules: *self,
            }
        }
    }
    pub struct RemapIter<I> {
        inner: I,
        prev: VecDeque<u8>,
        rules: RemapRules,
    }
    impl<I> Iterator for RemapIter<I>
    where
        I: Iterator<Item = u8>,
    {
        type Item = u8;
        fn next(&mut self) -> Option<Self::Item> {
            loop {
                if let Some(b) = self.prev.pop_front() {
                    return Some(b);
                }
                match self.inner.next()? {
                    raw::CR => {
                        if let Some(repl) = self.rules.cr {
                            self.prev.extend(repl);
                            continue;
                        } else {
                            return Some(raw::CR);
                        }
                    }
                    raw::LF => {
                        if let Some(repl) = self.rules.lf {
                            self.prev.extend(repl);
                            continue;
                        } else {
                            return Some(raw::LF);
                        }
                    }
                    raw::BS if self.rules.bsdel => return Some(raw::DEL),
                    raw::DEL if self.rules.delbs => return Some(raw::BS),
                    b => return Some(b),
                }
            }
        }
    }
    mod raw {
        pub(super) const CR: u8 = b'\r';
        pub(super) const LF: u8 = b'\n';
        pub(super) const BS: u8 = 0x08;
        pub(super) const DEL: u8 = 0x7f;
    }
}
mod usart {
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
        let termios_guard = if raw {
            Some(UnrawTermiosGuard::make_stdout_raw()?)
        } else {
            None
        };
        let imap = match imap {
            Some(s) => s.parse().context("invalid imap rules")?,
            None => RemapRules::default(),
        };
        let omap = match omap {
            Some(s) => s.parse().context("invalid omap rules")?,
            None => RemapRules::default(),
        };
        let mut uart_logfile = match uart_logfile {
            Some(path) => {
                let f = File::options()
                    .append(true)
                    .create(true)
                    .open(&path)
                    .with_context(|| {
                        {
                            let res = ::alloc::fmt::format(
                                format_args!("failed to open {0}", path.display()),
                            );
                            res
                        }
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
        let tx_to_sp_handle = tokio::spawn(
            relay_data_to_sp(console_tx, send_rx, fatal_err_tx, log.clone()),
        );
        let mut encountered_fatal_error = false;
        loop {
            {
                #[doc(hidden)]
                mod __tokio_select_util {
                    pub(super) enum Out<_0, _1, _2, _3> {
                        _0(_0),
                        _1(_1),
                        _2(_2),
                        _3(_3),
                        Disabled,
                    }
                    pub(super) type Mask = u8;
                }
                use ::tokio::macros::support::Future;
                use ::tokio::macros::support::Pin;
                use ::tokio::macros::support::Poll::{Ready, Pending};
                const BRANCHES: u32 = 4;
                let mut disabled: __tokio_select_util::Mask = Default::default();
                if !true {
                    let mask: __tokio_select_util::Mask = 1 << 0;
                    disabled |= mask;
                }
                if !true {
                    let mask: __tokio_select_util::Mask = 1 << 1;
                    disabled |= mask;
                }
                if !true {
                    let mask: __tokio_select_util::Mask = 1 << 2;
                    disabled |= mask;
                }
                if !true {
                    let mask: __tokio_select_util::Mask = 1 << 3;
                    disabled |= mask;
                }
                let mut output = {
                    let mut futures = (
                        stdin.read_buf(&mut stdin_buf),
                        &mut fatal_err_rx,
                        console_rx.recv(),
                        flush_delay.ready(),
                    );
                    let mut futures = &mut futures;
                    ::tokio::macros::support::poll_fn(|cx| {
                            let mut is_pending = false;
                            let start = {
                                ::tokio::macros::support::thread_rng_n(BRANCHES)
                            };
                            for i in 0..BRANCHES {
                                let branch;
                                #[allow(clippy::modulo_one)]
                                {
                                    branch = (start + i) % BRANCHES;
                                }
                                match branch {
                                    #[allow(unreachable_code)]
                                    0 => {
                                        let mask = 1 << branch;
                                        if disabled & mask == mask {
                                            continue;
                                        }
                                        let (fut, ..) = &mut *futures;
                                        let mut fut = unsafe { Pin::new_unchecked(fut) };
                                        let out = match Future::poll(fut, cx) {
                                            Ready(out) => out,
                                            Pending => {
                                                is_pending = true;
                                                continue;
                                            }
                                        };
                                        disabled |= mask;
                                        #[allow(unused_variables)] #[allow(unused_mut)]
                                        match &out {
                                            result => {}
                                            _ => continue,
                                        }
                                        return Ready(__tokio_select_util::Out::_0(out));
                                    }
                                    #[allow(unreachable_code)]
                                    1 => {
                                        let mask = 1 << branch;
                                        if disabled & mask == mask {
                                            continue;
                                        }
                                        let (_, fut, ..) = &mut *futures;
                                        let mut fut = unsafe { Pin::new_unchecked(fut) };
                                        let out = match Future::poll(fut, cx) {
                                            Ready(out) => out,
                                            Pending => {
                                                is_pending = true;
                                                continue;
                                            }
                                        };
                                        disabled |= mask;
                                        #[allow(unused_variables)] #[allow(unused_mut)]
                                        match &out {
                                            fatal_err_result => {}
                                            _ => continue,
                                        }
                                        return Ready(__tokio_select_util::Out::_1(out));
                                    }
                                    #[allow(unreachable_code)]
                                    2 => {
                                        let mask = 1 << branch;
                                        if disabled & mask == mask {
                                            continue;
                                        }
                                        let (_, _, fut, ..) = &mut *futures;
                                        let mut fut = unsafe { Pin::new_unchecked(fut) };
                                        let out = match Future::poll(fut, cx) {
                                            Ready(out) => out,
                                            Pending => {
                                                is_pending = true;
                                                continue;
                                            }
                                        };
                                        disabled |= mask;
                                        #[allow(unused_variables)] #[allow(unused_mut)]
                                        match &out {
                                            chunk => {}
                                            _ => continue,
                                        }
                                        return Ready(__tokio_select_util::Out::_2(out));
                                    }
                                    #[allow(unreachable_code)]
                                    3 => {
                                        let mask = 1 << branch;
                                        if disabled & mask == mask {
                                            continue;
                                        }
                                        let (_, _, _, fut, ..) = &mut *futures;
                                        let mut fut = unsafe { Pin::new_unchecked(fut) };
                                        let out = match Future::poll(fut, cx) {
                                            Ready(out) => out,
                                            Pending => {
                                                is_pending = true;
                                                continue;
                                            }
                                        };
                                        disabled |= mask;
                                        #[allow(unused_variables)] #[allow(unused_mut)]
                                        match &out {
                                            _ => {}
                                            _ => continue,
                                        }
                                        return Ready(__tokio_select_util::Out::_3(out));
                                    }
                                    _ => {
                                        ::core::panicking::panic_fmt(
                                            format_args!(
                                                "internal error: entered unreachable code: {0}",
                                                format_args!(
                                                    "reaching this means there probably is an off by one bug",
                                                ),
                                            ),
                                        );
                                    }
                                }
                            }
                            if is_pending {
                                Pending
                            } else {
                                Ready(__tokio_select_util::Out::Disabled)
                            }
                        })
                        .await
                };
                match output {
                    __tokio_select_util::Out::_0(result) => {
                        let n = result.context("failed to read from stdin")?;
                        if n == 0 {
                            break;
                        }
                        match out_buf.ingest(&mut stdin_buf) {
                            IngestResult::Ok => {}
                            IngestResult::Exit => {
                                break;
                            }
                            IngestResult::Break => {
                                send_tx
                                    .send(SendTxData::Break)
                                    .await
                                    .context("failed to send data (task shutdown?)")?;
                                {
                                    ::std::io::_print(
                                        format_args!("\n\r*** break sent ***\r\n"),
                                    );
                                };
                            }
                        }
                        flush_delay.start_if_unstarted().await;
                    }
                    __tokio_select_util::Out::_1(fatal_err_result) => {
                        let fatal_err = fatal_err_result
                            .expect("tx_to_sp task panicked");
                        if ::slog::Level::Error.as_usize()
                            <= ::slog::__slog_static_max_level().as_usize()
                        {
                            ::slog::Logger::log(
                                &log,
                                &{
                                    #[allow(dead_code)]
                                    static RS: ::slog::RecordStatic<'static> = {
                                        static LOC: ::slog::RecordLocation = ::slog::RecordLocation {
                                            file: "faux-mgs/src/usart.rs",
                                            line: 132u32,
                                            column: 17u32,
                                            function: "",
                                            module: "faux_mgs::usart",
                                        };
                                        ::slog::RecordStatic {
                                            location: &LOC,
                                            level: ::slog::Level::Error,
                                            tag: "",
                                        }
                                    };
                                    ::slog::Record::new(
                                        &RS,
                                        &format_args!("fatal communication error with SP"),
                                        ::slog::BorrowedKV(&(fatal_err, ())),
                                    )
                                },
                            )
                        }
                        encountered_fatal_error = true;
                        break;
                    }
                    __tokio_select_util::Out::_2(chunk) => {
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
                    __tokio_select_util::Out::_3(_) => {
                        send_tx
                            .send(SendTxData::Buf(out_buf.steal_buf()))
                            .await
                            .with_context(|| "failed to send data (task shutdown?)")?;
                    }
                    __tokio_select_util::Out::Disabled => {
                        ::core::panicking::panic_fmt(
                            format_args!(
                                "all branches are disabled and there is no else branch",
                            ),
                        );
                    }
                    _ => {
                        ::core::panicking::panic_fmt(
                            format_args!(
                                "internal error: entered unreachable code: {0}",
                                format_args!("failed to match bind"),
                            ),
                        );
                    }
                }
            }
        }
        mem::drop(send_tx);
        let console_tx = tx_to_sp_handle.await.expect("tx_to_sp task panicked");
        if !encountered_fatal_error {
            console_tx.detach().await.context("failed to detach from SP console")?;
        }
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
        let mut check_for_resend = time::interval(Duration::from_secs(1));
        check_for_resend.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut messages_to_send = VecDeque::new();
        let mut recently_warned = false;
        loop {
            {
                #[doc(hidden)]
                mod __tokio_select_util {
                    pub(super) enum Out<_0, _1, _2> {
                        _0(_0),
                        _1(_1),
                        _2(_2),
                        Disabled,
                    }
                    pub(super) type Mask = u8;
                }
                use ::tokio::macros::support::Future;
                use ::tokio::macros::support::Pin;
                use ::tokio::macros::support::Poll::{Ready, Pending};
                const BRANCHES: u32 = 3;
                let mut disabled: __tokio_select_util::Mask = Default::default();
                if !true {
                    let mask: __tokio_select_util::Mask = 1 << 0;
                    disabled |= mask;
                }
                if !true {
                    let mask: __tokio_select_util::Mask = 1 << 1;
                    disabled |= mask;
                }
                if !true {
                    let mask: __tokio_select_util::Mask = 1 << 2;
                    disabled |= mask;
                }
                let mut output = {
                    let mut futures = (
                        data_rx.recv(),
                        check_for_resend.tick(),
                        keepalive.tick(),
                    );
                    let mut futures = &mut futures;
                    ::tokio::macros::support::poll_fn(|cx| {
                            let mut is_pending = false;
                            let start = {
                                ::tokio::macros::support::thread_rng_n(BRANCHES)
                            };
                            for i in 0..BRANCHES {
                                let branch;
                                #[allow(clippy::modulo_one)]
                                {
                                    branch = (start + i) % BRANCHES;
                                }
                                match branch {
                                    #[allow(unreachable_code)]
                                    0 => {
                                        let mask = 1 << branch;
                                        if disabled & mask == mask {
                                            continue;
                                        }
                                        let (fut, ..) = &mut *futures;
                                        let mut fut = unsafe { Pin::new_unchecked(fut) };
                                        let out = match Future::poll(fut, cx) {
                                            Ready(out) => out,
                                            Pending => {
                                                is_pending = true;
                                                continue;
                                            }
                                        };
                                        disabled |= mask;
                                        #[allow(unused_variables)] #[allow(unused_mut)]
                                        match &out {
                                            maybe_data => {}
                                            _ => continue,
                                        }
                                        return Ready(__tokio_select_util::Out::_0(out));
                                    }
                                    #[allow(unreachable_code)]
                                    1 => {
                                        let mask = 1 << branch;
                                        if disabled & mask == mask {
                                            continue;
                                        }
                                        let (_, fut, ..) = &mut *futures;
                                        let mut fut = unsafe { Pin::new_unchecked(fut) };
                                        let out = match Future::poll(fut, cx) {
                                            Ready(out) => out,
                                            Pending => {
                                                is_pending = true;
                                                continue;
                                            }
                                        };
                                        disabled |= mask;
                                        #[allow(unused_variables)] #[allow(unused_mut)]
                                        match &out {
                                            _ => {}
                                            _ => continue,
                                        }
                                        return Ready(__tokio_select_util::Out::_1(out));
                                    }
                                    #[allow(unreachable_code)]
                                    2 => {
                                        let mask = 1 << branch;
                                        if disabled & mask == mask {
                                            continue;
                                        }
                                        let (_, _, fut, ..) = &mut *futures;
                                        let mut fut = unsafe { Pin::new_unchecked(fut) };
                                        let out = match Future::poll(fut, cx) {
                                            Ready(out) => out,
                                            Pending => {
                                                is_pending = true;
                                                continue;
                                            }
                                        };
                                        disabled |= mask;
                                        #[allow(unused_variables)] #[allow(unused_mut)]
                                        match &out {
                                            _ => {}
                                            _ => continue,
                                        }
                                        return Ready(__tokio_select_util::Out::_2(out));
                                    }
                                    _ => {
                                        ::core::panicking::panic_fmt(
                                            format_args!(
                                                "internal error: entered unreachable code: {0}",
                                                format_args!(
                                                    "reaching this means there probably is an off by one bug",
                                                ),
                                            ),
                                        );
                                    }
                                }
                            }
                            if is_pending {
                                Pending
                            } else {
                                Ready(__tokio_select_util::Out::Disabled)
                            }
                        })
                        .await
                };
                match output {
                    __tokio_select_util::Out::_0(maybe_data) => {
                        match maybe_data {
                            Some(message) => {
                                messages_to_send.push_front(message);
                                if let Err(fatal_err) = drain_messages_to_send(
                                        &mut messages_to_send,
                                        &mut console_tx,
                                        &mut keepalive,
                                        &mut recently_warned,
                                        &log,
                                    )
                                    .await
                                {
                                    fatal_err_tx.send(fatal_err).expect("parent task exited");
                                    return console_tx;
                                }
                            }
                            None => return console_tx,
                        }
                    }
                    __tokio_select_util::Out::_1(_) => {
                        if let Err(fatal_err) = drain_messages_to_send(
                                &mut messages_to_send,
                                &mut console_tx,
                                &mut keepalive,
                                &mut recently_warned,
                                &log,
                            )
                            .await
                        {
                            fatal_err_tx.send(fatal_err).expect("parent task exited");
                            return console_tx;
                        }
                    }
                    __tokio_select_util::Out::_2(_) => {
                        match console_tx.keepalive().await {
                            Ok(()) => {}
                            Err(
                                CommunicationError::SpError(
                                    SpError::BadRequest(BadRequestReason::DeserializationError),
                                ),
                            ) => {
                                if ::slog::Level::Warning.as_usize()
                                    <= ::slog::__slog_static_max_level().as_usize()
                                {
                                    ::slog::Logger::log(
                                        &log,
                                        &{
                                            #[allow(dead_code)]
                                            static RS: ::slog::RecordStatic<'static> = {
                                                static LOC: ::slog::RecordLocation = ::slog::RecordLocation {
                                                    file: "faux-mgs/src/usart.rs",
                                                    line: 255u32,
                                                    column: 25u32,
                                                    function: "",
                                                    module: "faux_mgs::usart",
                                                };
                                                ::slog::RecordStatic {
                                                    location: &LOC,
                                                    level: ::slog::Level::Warning,
                                                    tag: "",
                                                }
                                            };
                                            ::slog::Record::new(
                                                &RS,
                                                &format_args!(
                                                    "This SP does not support console keepalives! Please update it at your earliest convenience.",
                                                ),
                                                ::slog::BorrowedKV(&()),
                                            )
                                        },
                                    )
                                }
                                keepalive = time::interval(Duration::from_secs(4 * 3600));
                                keepalive.reset();
                            }
                            Err(err) => {
                                if ::slog::Level::Warning.as_usize()
                                    <= ::slog::__slog_static_max_level().as_usize()
                                {
                                    ::slog::Logger::log(
                                        &log,
                                        &{
                                            #[allow(dead_code)]
                                            static RS: ::slog::RecordStatic<'static> = {
                                                static LOC: ::slog::RecordLocation = ::slog::RecordLocation {
                                                    file: "faux-mgs/src/usart.rs",
                                                    line: 269u32,
                                                    column: 25u32,
                                                    function: "",
                                                    module: "faux_mgs::usart",
                                                };
                                                ::slog::RecordStatic {
                                                    location: &LOC,
                                                    level: ::slog::Level::Warning,
                                                    tag: "",
                                                }
                                            };
                                            ::slog::Record::new(
                                                &RS,
                                                &format_args!("failed to send console keepalive"),
                                                ::slog::BorrowedKV(&(err, ())),
                                            )
                                        },
                                    )
                                }
                            }
                        }
                    }
                    __tokio_select_util::Out::Disabled => {
                        ::core::panicking::panic_fmt(
                            format_args!(
                                "all branches are disabled and there is no else branch",
                            ),
                        );
                    }
                    _ => {
                        ::core::panicking::panic_fmt(
                            format_args!(
                                "internal error: entered unreachable code: {0}",
                                format_args!("failed to match bind"),
                            ),
                        );
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
                        if ::slog::Level::Info.as_usize()
                            <= ::slog::__slog_static_max_level().as_usize()
                        {
                            ::slog::Logger::log(
                                &log,
                                &{
                                    #[allow(dead_code)]
                                    static RS: ::slog::RecordStatic<'static> = {
                                        static LOC: ::slog::RecordLocation = ::slog::RecordLocation {
                                            file: "faux-mgs/src/usart.rs",
                                            line: 293u32,
                                            column: 21u32,
                                            function: "",
                                            module: "faux_mgs::usart",
                                        };
                                        ::slog::RecordStatic {
                                            location: &LOC,
                                            level: ::slog::Level::Info,
                                            tag: "",
                                        }
                                    };
                                    ::slog::Record::new(
                                        &RS,
                                        &format_args!("communication with SP reestablished"),
                                        ::slog::BorrowedKV(&()),
                                    )
                                },
                            )
                        }
                        *recently_warned = false;
                    }
                    messages.pop_front();
                    keepalive.reset();
                }
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
                    if ::slog::Level::Warning.as_usize()
                        <= ::slog::__slog_static_max_level().as_usize()
                    {
                        ::slog::Logger::log(
                            &log,
                            &{
                                #[allow(dead_code)]
                                static RS: ::slog::RecordStatic<'static> = {
                                    static LOC: ::slog::RecordLocation = ::slog::RecordLocation {
                                        file: "faux-mgs/src/usart.rs",
                                        line: 315u32,
                                        column: 17u32,
                                        function: "",
                                        module: "faux_mgs::usart",
                                    };
                                    ::slog::RecordStatic {
                                        location: &LOC,
                                        level: ::slog::Level::Warning,
                                        tag: "",
                                    }
                                };
                                ::slog::Record::new(
                                    &RS,
                                    &format_args!("communication error with SP (will retry)"),
                                    ::slog::BorrowedKV(&(non_fatal_err, ())),
                                )
                            },
                        )
                    }
                    *recently_warned = true;
                    return Ok(());
                }
            }
        }
        Ok(())
    }
    enum SendTxData {
        Buf(Vec<u8>),
        Break,
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for SendTxData {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match self {
                SendTxData::Buf(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "Buf",
                        &__self_0,
                    )
                }
                SendTxData::Break => ::core::fmt::Formatter::write_str(f, "Break"),
            }
        }
    }
    #[automatically_derived]
    impl ::core::clone::Clone for SendTxData {
        #[inline]
        fn clone(&self) -> SendTxData {
            match self {
                SendTxData::Buf(__self_0) => {
                    SendTxData::Buf(::core::clone::Clone::clone(__self_0))
                }
                SendTxData::Break => SendTxData::Break,
            }
        }
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
            Ok(Self {
                stdout,
                ios: orig_ios,
                restored: false,
            })
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
                        Some(()) => {}
                        None => return,
                    }
                    tokio::time::sleep(duration).await;
                    let _ = tx1.send(()).await;
                }
            });
            Self {
                started: false,
                tx: tx0,
                rx: rx1,
            }
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
            Self {
                raw_mode,
                in_prefix: false,
                remap,
                buf: Vec::new(),
            }
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
                            self.buf.push(c);
                            self.in_prefix = false;
                        } else {
                            self.in_prefix = true;
                        }
                    }
                    CTRL_X => {
                        if self.in_prefix {
                            return IngestResult::Exit;
                        } else {
                            self.buf.push(c);
                        }
                    }
                    CTRL_BACKSLASH => {
                        if self.in_prefix {
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
}
/// Command line program that can send MGS messages to a single SP.
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
#[automatically_derived]
#[allow(unused_qualifications, clippy::redundant_locals)]
impl clap::Parser for Args {}
#[allow(
    dead_code,
    unreachable_code,
    unused_variables,
    unused_braces,
    unused_qualifications,
)]
#[allow(
    clippy::style,
    clippy::complexity,
    clippy::pedantic,
    clippy::restriction,
    clippy::perf,
    clippy::deprecated,
    clippy::nursery,
    clippy::cargo,
    clippy::suspicious_else_formatting,
    clippy::almost_swapped,
    clippy::redundant_locals,
)]
#[automatically_derived]
impl clap::CommandFactory for Args {
    fn command<'b>() -> clap::Command {
        let __clap_app = clap::Command::new("faux-mgs");
        <Self as clap::Args>::augment_args(__clap_app)
    }
    fn command_for_update<'b>() -> clap::Command {
        let __clap_app = clap::Command::new("faux-mgs");
        <Self as clap::Args>::augment_args_for_update(__clap_app)
    }
}
#[allow(
    dead_code,
    unreachable_code,
    unused_variables,
    unused_braces,
    unused_qualifications,
)]
#[allow(
    clippy::style,
    clippy::complexity,
    clippy::pedantic,
    clippy::restriction,
    clippy::perf,
    clippy::deprecated,
    clippy::nursery,
    clippy::cargo,
    clippy::suspicious_else_formatting,
    clippy::almost_swapped,
    clippy::redundant_locals,
)]
#[automatically_derived]
impl clap::FromArgMatches for Args {
    fn from_arg_matches(
        __clap_arg_matches: &clap::ArgMatches,
    ) -> ::std::result::Result<Self, clap::Error> {
        Self::from_arg_matches_mut(&mut __clap_arg_matches.clone())
    }
    fn from_arg_matches_mut(
        __clap_arg_matches: &mut clap::ArgMatches,
    ) -> ::std::result::Result<Self, clap::Error> {
        #![allow(deprecated)]
        let v = Args {
            log_level: __clap_arg_matches
                .remove_one::<Level>("log_level")
                .ok_or_else(|| clap::Error::raw(
                    clap::error::ErrorKind::MissingRequiredArgument,
                    "The following required argument was not provided: log_level",
                ))?,
            logfile: __clap_arg_matches.remove_one::<PathBuf>("logfile"),
            json: if __clap_arg_matches.contains_id("json") {
                Some(__clap_arg_matches.remove_one::<JsonPretty>("json"))
            } else {
                None
            },
            listen_port: __clap_arg_matches.remove_one::<u16>("listen_port"),
            discovery_addr: __clap_arg_matches
                .remove_one::<SocketAddrV6>("discovery_addr")
                .ok_or_else(|| clap::Error::raw(
                    clap::error::ErrorKind::MissingRequiredArgument,
                    "The following required argument was not provided: discovery_addr",
                ))?,
            interface: __clap_arg_matches
                .remove_many::<String>("interface")
                .map(|v| v.collect::<Vec<_>>())
                .unwrap_or_else(Vec::new),
            max_attempts: __clap_arg_matches
                .remove_one::<usize>("max_attempts")
                .ok_or_else(|| clap::Error::raw(
                    clap::error::ErrorKind::MissingRequiredArgument,
                    "The following required argument was not provided: max_attempts",
                ))?,
            per_attempt_timeout_millis: __clap_arg_matches
                .remove_one::<u64>("per_attempt_timeout_millis")
                .ok_or_else(|| clap::Error::raw(
                    clap::error::ErrorKind::MissingRequiredArgument,
                    "The following required argument was not provided: per_attempt_timeout_millis",
                ))?,
            command: {
                <Command as clap::FromArgMatches>::from_arg_matches_mut(
                    __clap_arg_matches,
                )?
            },
        };
        ::std::result::Result::Ok(v)
    }
    fn update_from_arg_matches(
        &mut self,
        __clap_arg_matches: &clap::ArgMatches,
    ) -> ::std::result::Result<(), clap::Error> {
        self.update_from_arg_matches_mut(&mut __clap_arg_matches.clone())
    }
    fn update_from_arg_matches_mut(
        &mut self,
        __clap_arg_matches: &mut clap::ArgMatches,
    ) -> ::std::result::Result<(), clap::Error> {
        #![allow(deprecated)]
        if __clap_arg_matches.contains_id("log_level") {
            #[allow(non_snake_case)]
            let log_level = &mut self.log_level;
            *log_level = __clap_arg_matches
                .remove_one::<Level>("log_level")
                .ok_or_else(|| clap::Error::raw(
                    clap::error::ErrorKind::MissingRequiredArgument,
                    "The following required argument was not provided: log_level",
                ))?;
        }
        if __clap_arg_matches.contains_id("logfile") {
            #[allow(non_snake_case)]
            let logfile = &mut self.logfile;
            *logfile = __clap_arg_matches.remove_one::<PathBuf>("logfile");
        }
        if __clap_arg_matches.contains_id("json") {
            #[allow(non_snake_case)]
            let json = &mut self.json;
            *json = if __clap_arg_matches.contains_id("json") {
                Some(__clap_arg_matches.remove_one::<JsonPretty>("json"))
            } else {
                None
            };
        }
        if __clap_arg_matches.contains_id("listen_port") {
            #[allow(non_snake_case)]
            let listen_port = &mut self.listen_port;
            *listen_port = __clap_arg_matches.remove_one::<u16>("listen_port");
        }
        if __clap_arg_matches.contains_id("discovery_addr") {
            #[allow(non_snake_case)]
            let discovery_addr = &mut self.discovery_addr;
            *discovery_addr = __clap_arg_matches
                .remove_one::<SocketAddrV6>("discovery_addr")
                .ok_or_else(|| clap::Error::raw(
                    clap::error::ErrorKind::MissingRequiredArgument,
                    "The following required argument was not provided: discovery_addr",
                ))?;
        }
        if __clap_arg_matches.contains_id("interface") {
            #[allow(non_snake_case)]
            let interface = &mut self.interface;
            *interface = __clap_arg_matches
                .remove_many::<String>("interface")
                .map(|v| v.collect::<Vec<_>>())
                .unwrap_or_else(Vec::new);
        }
        if __clap_arg_matches.contains_id("max_attempts") {
            #[allow(non_snake_case)]
            let max_attempts = &mut self.max_attempts;
            *max_attempts = __clap_arg_matches
                .remove_one::<usize>("max_attempts")
                .ok_or_else(|| clap::Error::raw(
                    clap::error::ErrorKind::MissingRequiredArgument,
                    "The following required argument was not provided: max_attempts",
                ))?;
        }
        if __clap_arg_matches.contains_id("per_attempt_timeout_millis") {
            #[allow(non_snake_case)]
            let per_attempt_timeout_millis = &mut self.per_attempt_timeout_millis;
            *per_attempt_timeout_millis = __clap_arg_matches
                .remove_one::<u64>("per_attempt_timeout_millis")
                .ok_or_else(|| clap::Error::raw(
                    clap::error::ErrorKind::MissingRequiredArgument,
                    "The following required argument was not provided: per_attempt_timeout_millis",
                ))?;
        }
        {
            #[allow(non_snake_case)]
            let command = &mut self.command;
            <Command as clap::FromArgMatches>::update_from_arg_matches_mut(
                command,
                __clap_arg_matches,
            )?;
        }
        ::std::result::Result::Ok(())
    }
}
#[allow(
    dead_code,
    unreachable_code,
    unused_variables,
    unused_braces,
    unused_qualifications,
)]
#[allow(
    clippy::style,
    clippy::complexity,
    clippy::pedantic,
    clippy::restriction,
    clippy::perf,
    clippy::deprecated,
    clippy::nursery,
    clippy::cargo,
    clippy::suspicious_else_formatting,
    clippy::almost_swapped,
    clippy::redundant_locals,
)]
#[automatically_derived]
impl clap::Args for Args {
    fn group_id() -> Option<clap::Id> {
        Some(clap::Id::from("Args"))
    }
    fn augment_args<'b>(__clap_app: clap::Command) -> clap::Command {
        {
            let __clap_app = __clap_app
                .group(
                    clap::ArgGroup::new("Args")
                        .multiple(true)
                        .args({
                            let members: [clap::Id; 8usize] = [
                                clap::Id::from("log_level"),
                                clap::Id::from("logfile"),
                                clap::Id::from("json"),
                                clap::Id::from("listen_port"),
                                clap::Id::from("discovery_addr"),
                                clap::Id::from("interface"),
                                clap::Id::from("max_attempts"),
                                clap::Id::from("per_attempt_timeout_millis"),
                            ];
                            members
                        }),
                );
            let __clap_app = __clap_app
                .arg({
                    #[allow(deprecated)]
                    let arg = clap::Arg::new("log_level")
                        .value_name("LOG_LEVEL")
                        .required(false && clap::ArgAction::Set.takes_values())
                        .value_parser(level_from_str)
                        .action(clap::ArgAction::Set);
                    let arg = arg
                        .short('l')
                        .long("log-level")
                        .default_value("info")
                        .help(
                            "Log level for MGS client: {off,critical,error,warn,info,debug,trace}",
                        );
                    let arg = arg;
                    arg
                });
            let __clap_app = __clap_app
                .arg({
                    #[allow(deprecated)]
                    let arg = clap::Arg::new("logfile")
                        .value_name("LOGFILE")
                        .value_parser({
                            use ::clap_builder::builder::via_prelude::*;
                            let auto = ::clap_builder::builder::_AutoValueParser::<
                                PathBuf,
                            >::new();
                            (&&&&&&auto).value_parser()
                        })
                        .action(clap::ArgAction::Set);
                    let arg = arg
                        .help("Write logs to a file instead of stderr")
                        .long_help(None)
                        .long("logfile");
                    let arg = arg;
                    arg
                });
            let __clap_app = __clap_app
                .arg({
                    #[allow(deprecated)]
                    let arg = clap::Arg::new("json")
                        .value_name("JSON")
                        .num_args(0..=1)
                        .value_parser(json_pretty_from_str)
                        .action(clap::ArgAction::Set);
                    let arg = arg
                        .help(
                            "Emit parseable JSON on stdout instead of \"human-readable\" (often `Debug`-formatted) data",
                        )
                        .long_help(None)
                        .long("json")
                        .value_names(["pretty"]);
                    let arg = arg;
                    arg
                });
            let __clap_app = __clap_app
                .arg({
                    #[allow(deprecated)]
                    let arg = clap::Arg::new("listen_port")
                        .value_name("LISTEN_PORT")
                        .value_parser({
                            use ::clap_builder::builder::via_prelude::*;
                            let auto = ::clap_builder::builder::_AutoValueParser::<
                                u16,
                            >::new();
                            (&&&&&&auto).value_parser()
                        })
                        .action(clap::ArgAction::Set);
                    let arg = arg
                        .help(
                            "Port to bind to locally [default: 0 for client commands, 22222 for server commands]",
                        )
                        .long_help(None)
                        .long("listen-port");
                    let arg = arg;
                    arg
                });
            let __clap_app = __clap_app
                .arg({
                    #[allow(deprecated)]
                    let arg = clap::Arg::new("discovery_addr")
                        .value_name("DISCOVERY_ADDR")
                        .required(false && clap::ArgAction::Set.takes_values())
                        .value_parser({
                            use ::clap_builder::builder::via_prelude::*;
                            let auto = ::clap_builder::builder::_AutoValueParser::<
                                SocketAddrV6,
                            >::new();
                            (&&&&&&auto).value_parser()
                        })
                        .action(clap::ArgAction::Set);
                    let arg = arg
                        .help(
                            "Address to use to discover the SP. May be a specific SP's address to bypass multicast discovery",
                        )
                        .long_help(None)
                        .long("discovery-addr")
                        .default_value({
                            static DEFAULT_VALUE: ::std::sync::OnceLock<String> = ::std::sync::OnceLock::new();
                            let s = DEFAULT_VALUE
                                .get_or_init(|| {
                                    let val: SocketAddrV6 = gateway_sp_comms::default_discovery_addr();
                                    ::std::string::ToString::to_string(&val)
                                });
                            let s: &'static str = &*s;
                            s
                        });
                    let arg = arg;
                    arg
                });
            let __clap_app = __clap_app
                .arg({
                    #[allow(deprecated)]
                    let arg = clap::Arg::new("interface")
                        .value_name("INTERFACE")
                        .value_parser({
                            use ::clap_builder::builder::via_prelude::*;
                            let auto = ::clap_builder::builder::_AutoValueParser::<
                                String,
                            >::new();
                            (&&&&&&auto).value_parser()
                        })
                        .action(clap::ArgAction::Append);
                    let arg = arg
                        .help("Interface(s) to use to communicate with target SP(s)")
                        .long_help(
                            "Interface(s) to use to communicate with target SP(s).\n\nSupports shell-like glob patterns (e.g., \"gimlet*\"). May be specified multiple times.",
                        )
                        .long("interface")
                        .required(true);
                    let arg = arg;
                    arg
                });
            let __clap_app = __clap_app
                .arg({
                    #[allow(deprecated)]
                    let arg = clap::Arg::new("max_attempts")
                        .value_name("MAX_ATTEMPTS")
                        .required(false && clap::ArgAction::Set.takes_values())
                        .value_parser({
                            use ::clap_builder::builder::via_prelude::*;
                            let auto = ::clap_builder::builder::_AutoValueParser::<
                                usize,
                            >::new();
                            (&&&&&&auto).value_parser()
                        })
                        .action(clap::ArgAction::Set);
                    let arg = arg
                        .help(
                            "Maximum number of attempts to make when sending requests to the SP",
                        )
                        .long_help(None)
                        .long("max-attempts")
                        .default_value("5");
                    let arg = arg;
                    arg
                });
            let __clap_app = __clap_app
                .arg({
                    #[allow(deprecated)]
                    let arg = clap::Arg::new("per_attempt_timeout_millis")
                        .value_name("PER_ATTEMPT_TIMEOUT_MILLIS")
                        .required(false && clap::ArgAction::Set.takes_values())
                        .value_parser({
                            use ::clap_builder::builder::via_prelude::*;
                            let auto = ::clap_builder::builder::_AutoValueParser::<
                                u64,
                            >::new();
                            (&&&&&&auto).value_parser()
                        })
                        .action(clap::ArgAction::Set);
                    let arg = arg
                        .help("Timeout (in milliseconds) for each attempt")
                        .long_help(None)
                        .long("per-attempt-timeout-millis")
                        .default_value("2000");
                    let arg = arg;
                    arg
                });
            let __clap_app = <Command as clap::Subcommand>::augment_subcommands(
                __clap_app,
            );
            let __clap_app = __clap_app
                .subcommand_required(true)
                .arg_required_else_help(true);
            __clap_app
                .about("Command line program that can send MGS messages to a single SP")
                .long_about(None)
        }
    }
    fn augment_args_for_update<'b>(__clap_app: clap::Command) -> clap::Command {
        {
            let __clap_app = __clap_app
                .group(
                    clap::ArgGroup::new("Args")
                        .multiple(true)
                        .args({
                            let members: [clap::Id; 8usize] = [
                                clap::Id::from("log_level"),
                                clap::Id::from("logfile"),
                                clap::Id::from("json"),
                                clap::Id::from("listen_port"),
                                clap::Id::from("discovery_addr"),
                                clap::Id::from("interface"),
                                clap::Id::from("max_attempts"),
                                clap::Id::from("per_attempt_timeout_millis"),
                            ];
                            members
                        }),
                );
            let __clap_app = __clap_app
                .arg({
                    #[allow(deprecated)]
                    let arg = clap::Arg::new("log_level")
                        .value_name("LOG_LEVEL")
                        .required(false && clap::ArgAction::Set.takes_values())
                        .value_parser(level_from_str)
                        .action(clap::ArgAction::Set);
                    let arg = arg
                        .short('l')
                        .long("log-level")
                        .default_value("info")
                        .help(
                            "Log level for MGS client: {off,critical,error,warn,info,debug,trace}",
                        );
                    let arg = arg.required(false);
                    arg
                });
            let __clap_app = __clap_app
                .arg({
                    #[allow(deprecated)]
                    let arg = clap::Arg::new("logfile")
                        .value_name("LOGFILE")
                        .value_parser({
                            use ::clap_builder::builder::via_prelude::*;
                            let auto = ::clap_builder::builder::_AutoValueParser::<
                                PathBuf,
                            >::new();
                            (&&&&&&auto).value_parser()
                        })
                        .action(clap::ArgAction::Set);
                    let arg = arg
                        .help("Write logs to a file instead of stderr")
                        .long_help(None)
                        .long("logfile");
                    let arg = arg.required(false);
                    arg
                });
            let __clap_app = __clap_app
                .arg({
                    #[allow(deprecated)]
                    let arg = clap::Arg::new("json")
                        .value_name("JSON")
                        .num_args(0..=1)
                        .value_parser(json_pretty_from_str)
                        .action(clap::ArgAction::Set);
                    let arg = arg
                        .help(
                            "Emit parseable JSON on stdout instead of \"human-readable\" (often `Debug`-formatted) data",
                        )
                        .long_help(None)
                        .long("json")
                        .value_names(["pretty"]);
                    let arg = arg.required(false);
                    arg
                });
            let __clap_app = __clap_app
                .arg({
                    #[allow(deprecated)]
                    let arg = clap::Arg::new("listen_port")
                        .value_name("LISTEN_PORT")
                        .value_parser({
                            use ::clap_builder::builder::via_prelude::*;
                            let auto = ::clap_builder::builder::_AutoValueParser::<
                                u16,
                            >::new();
                            (&&&&&&auto).value_parser()
                        })
                        .action(clap::ArgAction::Set);
                    let arg = arg
                        .help(
                            "Port to bind to locally [default: 0 for client commands, 22222 for server commands]",
                        )
                        .long_help(None)
                        .long("listen-port");
                    let arg = arg.required(false);
                    arg
                });
            let __clap_app = __clap_app
                .arg({
                    #[allow(deprecated)]
                    let arg = clap::Arg::new("discovery_addr")
                        .value_name("DISCOVERY_ADDR")
                        .required(false && clap::ArgAction::Set.takes_values())
                        .value_parser({
                            use ::clap_builder::builder::via_prelude::*;
                            let auto = ::clap_builder::builder::_AutoValueParser::<
                                SocketAddrV6,
                            >::new();
                            (&&&&&&auto).value_parser()
                        })
                        .action(clap::ArgAction::Set);
                    let arg = arg
                        .help(
                            "Address to use to discover the SP. May be a specific SP's address to bypass multicast discovery",
                        )
                        .long_help(None)
                        .long("discovery-addr")
                        .default_value({
                            static DEFAULT_VALUE: ::std::sync::OnceLock<String> = ::std::sync::OnceLock::new();
                            let s = DEFAULT_VALUE
                                .get_or_init(|| {
                                    let val: SocketAddrV6 = gateway_sp_comms::default_discovery_addr();
                                    ::std::string::ToString::to_string(&val)
                                });
                            let s: &'static str = &*s;
                            s
                        });
                    let arg = arg.required(false);
                    arg
                });
            let __clap_app = __clap_app
                .arg({
                    #[allow(deprecated)]
                    let arg = clap::Arg::new("interface")
                        .value_name("INTERFACE")
                        .value_parser({
                            use ::clap_builder::builder::via_prelude::*;
                            let auto = ::clap_builder::builder::_AutoValueParser::<
                                String,
                            >::new();
                            (&&&&&&auto).value_parser()
                        })
                        .action(clap::ArgAction::Append);
                    let arg = arg
                        .help("Interface(s) to use to communicate with target SP(s)")
                        .long_help(
                            "Interface(s) to use to communicate with target SP(s).\n\nSupports shell-like glob patterns (e.g., \"gimlet*\"). May be specified multiple times.",
                        )
                        .long("interface")
                        .required(true);
                    let arg = arg.required(false);
                    arg
                });
            let __clap_app = __clap_app
                .arg({
                    #[allow(deprecated)]
                    let arg = clap::Arg::new("max_attempts")
                        .value_name("MAX_ATTEMPTS")
                        .required(false && clap::ArgAction::Set.takes_values())
                        .value_parser({
                            use ::clap_builder::builder::via_prelude::*;
                            let auto = ::clap_builder::builder::_AutoValueParser::<
                                usize,
                            >::new();
                            (&&&&&&auto).value_parser()
                        })
                        .action(clap::ArgAction::Set);
                    let arg = arg
                        .help(
                            "Maximum number of attempts to make when sending requests to the SP",
                        )
                        .long_help(None)
                        .long("max-attempts")
                        .default_value("5");
                    let arg = arg.required(false);
                    arg
                });
            let __clap_app = __clap_app
                .arg({
                    #[allow(deprecated)]
                    let arg = clap::Arg::new("per_attempt_timeout_millis")
                        .value_name("PER_ATTEMPT_TIMEOUT_MILLIS")
                        .required(false && clap::ArgAction::Set.takes_values())
                        .value_parser({
                            use ::clap_builder::builder::via_prelude::*;
                            let auto = ::clap_builder::builder::_AutoValueParser::<
                                u64,
                            >::new();
                            (&&&&&&auto).value_parser()
                        })
                        .action(clap::ArgAction::Set);
                    let arg = arg
                        .help("Timeout (in milliseconds) for each attempt")
                        .long_help(None)
                        .long("per-attempt-timeout-millis")
                        .default_value("2000");
                    let arg = arg.required(false);
                    arg
                });
            let __clap_app = <Command as clap::Subcommand>::augment_subcommands(
                __clap_app,
            );
            let __clap_app = __clap_app
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand_required(false)
                .arg_required_else_help(false);
            __clap_app
                .about("Command line program that can send MGS messages to a single SP")
                .long_about(None)
        }
    }
}
#[automatically_derived]
impl ::core::fmt::Debug for Args {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        let names: &'static _ = &[
            "log_level",
            "logfile",
            "json",
            "listen_port",
            "discovery_addr",
            "interface",
            "max_attempts",
            "per_attempt_timeout_millis",
            "command",
        ];
        let values: &[&dyn ::core::fmt::Debug] = &[
            &self.log_level,
            &self.logfile,
            &self.json,
            &self.listen_port,
            &self.discovery_addr,
            &self.interface,
            &self.max_attempts,
            &self.per_attempt_timeout_millis,
            &&self.command,
        ];
        ::core::fmt::Formatter::debug_struct_fields_finish(f, "Args", names, values)
    }
}
fn level_from_str(s: &str) -> Result<Level> {
    if let Ok(level) = s.parse() {
        Ok(level)
    } else {
        return ::anyhow::__private::Err({
            use ::anyhow::__private::kind::*;
            let error = match {
                let res = ::alloc::fmt::format(
                    format_args!("Invalid log level: {0}", s),
                );
                res
            } {
                error => (&error).anyhow_kind().new(error),
            };
            error
        })
    }
}
struct JsonPretty;
#[automatically_derived]
impl ::core::fmt::Debug for JsonPretty {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        ::core::fmt::Formatter::write_str(f, "JsonPretty")
    }
}
#[automatically_derived]
impl ::core::clone::Clone for JsonPretty {
    #[inline]
    fn clone(&self) -> JsonPretty {
        *self
    }
}
#[automatically_derived]
impl ::core::marker::Copy for JsonPretty {}
fn json_pretty_from_str(s: &str) -> Result<JsonPretty> {
    if s == "pretty" {
        Ok(JsonPretty)
    } else {
        return ::anyhow::__private::Err({
            let error = ::anyhow::__private::format_err(
                format_args!("expected \"pretty\""),
            );
            error
        })
    }
}
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
    UpdateStatus { #[clap(value_parser = parse_sp_component)] component: SpComponent },
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
    SystemLed { #[clap(subcommand)] cmd: LedCommand },
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
    Monorail { #[clap(subcommand)] cmd: MonorailCommand },
}
#[allow(
    dead_code,
    unreachable_code,
    unused_variables,
    unused_braces,
    unused_qualifications,
)]
#[allow(
    clippy::style,
    clippy::complexity,
    clippy::pedantic,
    clippy::restriction,
    clippy::perf,
    clippy::deprecated,
    clippy::nursery,
    clippy::cargo,
    clippy::suspicious_else_formatting,
    clippy::almost_swapped,
    clippy::redundant_locals,
)]
#[automatically_derived]
impl clap::FromArgMatches for Command {
    fn from_arg_matches(
        __clap_arg_matches: &clap::ArgMatches,
    ) -> ::std::result::Result<Self, clap::Error> {
        Self::from_arg_matches_mut(&mut __clap_arg_matches.clone())
    }
    fn from_arg_matches_mut(
        __clap_arg_matches: &mut clap::ArgMatches,
    ) -> ::std::result::Result<Self, clap::Error> {
        #![allow(deprecated)]
        if let Some((__clap_name, mut __clap_arg_sub_matches)) = __clap_arg_matches
            .remove_subcommand()
        {
            let __clap_arg_matches = &mut __clap_arg_sub_matches;
            if __clap_name == "discover" && !__clap_arg_matches.contains_id("") {
                return ::std::result::Result::Ok(Self::Discover);
            }
            if __clap_name == "state" && !__clap_arg_matches.contains_id("") {
                return ::std::result::Result::Ok(Self::State);
            }
            if __clap_name == "ignition" && !__clap_arg_matches.contains_id("") {
                return ::std::result::Result::Ok(Self::Ignition {
                    target: __clap_arg_matches
                        .remove_one::<IgnitionLinkEventsTarget>("target")
                        .ok_or_else(|| clap::Error::raw(
                            clap::error::ErrorKind::MissingRequiredArgument,
                            "The following required argument was not provided: target",
                        ))?,
                });
            }
            if __clap_name == "ignition-command" && !__clap_arg_matches.contains_id("") {
                return ::std::result::Result::Ok(Self::IgnitionCommand {
                    target: __clap_arg_matches
                        .remove_one::<u8>("target")
                        .ok_or_else(|| clap::Error::raw(
                            clap::error::ErrorKind::MissingRequiredArgument,
                            "The following required argument was not provided: target",
                        ))?,
                    command: __clap_arg_matches
                        .remove_one::<IgnitionCommand>("command")
                        .ok_or_else(|| clap::Error::raw(
                            clap::error::ErrorKind::MissingRequiredArgument,
                            "The following required argument was not provided: command",
                        ))?,
                });
            }
            if __clap_name == "ignition-link-events"
                && !__clap_arg_matches.contains_id("")
            {
                return ::std::result::Result::Ok(Self::IgnitionLinkEvents {
                    target: __clap_arg_matches
                        .remove_one::<IgnitionLinkEventsTarget>("target")
                        .ok_or_else(|| clap::Error::raw(
                            clap::error::ErrorKind::MissingRequiredArgument,
                            "The following required argument was not provided: target",
                        ))?,
                });
            }
            if __clap_name == "clear-ignition-link-events"
                && !__clap_arg_matches.contains_id("")
            {
                return ::std::result::Result::Ok(Self::ClearIgnitionLinkEvents {
                    target: __clap_arg_matches
                        .remove_one::<IgnitionLinkEventsTarget>("target")
                        .ok_or_else(|| clap::Error::raw(
                            clap::error::ErrorKind::MissingRequiredArgument,
                            "The following required argument was not provided: target",
                        ))?,
                    transceiver_select: __clap_arg_matches
                        .remove_one::<
                            IgnitionLinkEventsTransceiverSelect,
                        >("transceiver_select")
                        .ok_or_else(|| clap::Error::raw(
                            clap::error::ErrorKind::MissingRequiredArgument,
                            "The following required argument was not provided: transceiver_select",
                        ))?,
                });
            }
            if __clap_name == "component-active-slot"
                && !__clap_arg_matches.contains_id("")
            {
                return ::std::result::Result::Ok(Self::ComponentActiveSlot {
                    component: __clap_arg_matches
                        .remove_one::<SpComponent>("component")
                        .ok_or_else(|| clap::Error::raw(
                            clap::error::ErrorKind::MissingRequiredArgument,
                            "The following required argument was not provided: component",
                        ))?,
                    set: __clap_arg_matches.remove_one::<u16>("set"),
                    persist: __clap_arg_matches
                        .remove_one::<bool>("persist")
                        .ok_or_else(|| clap::Error::raw(
                            clap::error::ErrorKind::MissingRequiredArgument,
                            "The following required argument was not provided: persist",
                        ))?,
                });
            }
            if __clap_name == "startup-options" && !__clap_arg_matches.contains_id("") {
                return ::std::result::Result::Ok(Self::StartupOptions {
                    options: __clap_arg_matches.remove_one::<u64>("options"),
                });
            }
            if __clap_name == "inventory" && !__clap_arg_matches.contains_id("") {
                return ::std::result::Result::Ok(Self::Inventory);
            }
            if __clap_name == "component-details" && !__clap_arg_matches.contains_id("")
            {
                return ::std::result::Result::Ok(Self::ComponentDetails {
                    component: __clap_arg_matches
                        .remove_one::<SpComponent>("component")
                        .ok_or_else(|| clap::Error::raw(
                            clap::error::ErrorKind::MissingRequiredArgument,
                            "The following required argument was not provided: component",
                        ))?,
                });
            }
            if __clap_name == "component-clear-status"
                && !__clap_arg_matches.contains_id("")
            {
                return ::std::result::Result::Ok(Self::ComponentClearStatus {
                    component: __clap_arg_matches
                        .remove_one::<SpComponent>("component")
                        .ok_or_else(|| clap::Error::raw(
                            clap::error::ErrorKind::MissingRequiredArgument,
                            "The following required argument was not provided: component",
                        ))?,
                });
            }
            if __clap_name == "usart-attach" && !__clap_arg_matches.contains_id("") {
                return ::std::result::Result::Ok(Self::UsartAttach {
                    raw: __clap_arg_matches
                        .remove_one::<bool>("raw")
                        .ok_or_else(|| clap::Error::raw(
                            clap::error::ErrorKind::MissingRequiredArgument,
                            "The following required argument was not provided: raw",
                        ))?,
                    stdin_buffer_time_millis: __clap_arg_matches
                        .remove_one::<u64>("stdin_buffer_time_millis")
                        .ok_or_else(|| clap::Error::raw(
                            clap::error::ErrorKind::MissingRequiredArgument,
                            "The following required argument was not provided: stdin_buffer_time_millis",
                        ))?,
                    imap: __clap_arg_matches.remove_one::<String>("imap"),
                    omap: __clap_arg_matches.remove_one::<String>("omap"),
                    uart_logfile: __clap_arg_matches
                        .remove_one::<PathBuf>("uart_logfile"),
                });
            }
            if __clap_name == "usart-detach" && !__clap_arg_matches.contains_id("") {
                return ::std::result::Result::Ok(Self::UsartDetach);
            }
            if __clap_name == "serve-host-phase2" && !__clap_arg_matches.contains_id("")
            {
                return ::std::result::Result::Ok(Self::ServeHostPhase2 {
                    directory: __clap_arg_matches
                        .remove_one::<PathBuf>("directory")
                        .ok_or_else(|| clap::Error::raw(
                            clap::error::ErrorKind::MissingRequiredArgument,
                            "The following required argument was not provided: directory",
                        ))?,
                });
            }
            if __clap_name == "update" && !__clap_arg_matches.contains_id("") {
                return ::std::result::Result::Ok(Self::Update {
                    allow_multiple_update: __clap_arg_matches
                        .remove_one::<bool>("allow_multiple_update")
                        .ok_or_else(|| clap::Error::raw(
                            clap::error::ErrorKind::MissingRequiredArgument,
                            "The following required argument was not provided: allow_multiple_update",
                        ))?,
                    component: __clap_arg_matches
                        .remove_one::<SpComponent>("component")
                        .ok_or_else(|| clap::Error::raw(
                            clap::error::ErrorKind::MissingRequiredArgument,
                            "The following required argument was not provided: component",
                        ))?,
                    slot: __clap_arg_matches
                        .remove_one::<u16>("slot")
                        .ok_or_else(|| clap::Error::raw(
                            clap::error::ErrorKind::MissingRequiredArgument,
                            "The following required argument was not provided: slot",
                        ))?,
                    image: __clap_arg_matches
                        .remove_one::<PathBuf>("image")
                        .ok_or_else(|| clap::Error::raw(
                            clap::error::ErrorKind::MissingRequiredArgument,
                            "The following required argument was not provided: image",
                        ))?,
                });
            }
            if __clap_name == "update-status" && !__clap_arg_matches.contains_id("") {
                return ::std::result::Result::Ok(Self::UpdateStatus {
                    component: __clap_arg_matches
                        .remove_one::<SpComponent>("component")
                        .ok_or_else(|| clap::Error::raw(
                            clap::error::ErrorKind::MissingRequiredArgument,
                            "The following required argument was not provided: component",
                        ))?,
                });
            }
            if __clap_name == "update-abort" && !__clap_arg_matches.contains_id("") {
                return ::std::result::Result::Ok(Self::UpdateAbort {
                    component: __clap_arg_matches
                        .remove_one::<SpComponent>("component")
                        .ok_or_else(|| clap::Error::raw(
                            clap::error::ErrorKind::MissingRequiredArgument,
                            "The following required argument was not provided: component",
                        ))?,
                    update_id: __clap_arg_matches
                        .remove_one::<Uuid>("update_id")
                        .ok_or_else(|| clap::Error::raw(
                            clap::error::ErrorKind::MissingRequiredArgument,
                            "The following required argument was not provided: update_id",
                        ))?,
                });
            }
            if __clap_name == "power-state" && !__clap_arg_matches.contains_id("") {
                return ::std::result::Result::Ok(Self::PowerState {
                    new_power_state: __clap_arg_matches
                        .remove_one::<PowerState>("new_power_state"),
                });
            }
            if __clap_name == "send-host-nmi" && !__clap_arg_matches.contains_id("") {
                return ::std::result::Result::Ok(Self::SendHostNmi);
            }
            if __clap_name == "set-ipcc-key-value" && !__clap_arg_matches.contains_id("")
            {
                return ::std::result::Result::Ok(Self::SetIpccKeyValue {
                    key: __clap_arg_matches
                        .remove_one::<u8>("key")
                        .ok_or_else(|| clap::Error::raw(
                            clap::error::ErrorKind::MissingRequiredArgument,
                            "The following required argument was not provided: key",
                        ))?,
                    value_path: __clap_arg_matches
                        .remove_one::<PathBuf>("value_path")
                        .ok_or_else(|| clap::Error::raw(
                            clap::error::ErrorKind::MissingRequiredArgument,
                            "The following required argument was not provided: value_path",
                        ))?,
                });
            }
            if __clap_name == "read-caboose" && !__clap_arg_matches.contains_id("") {
                return ::std::result::Result::Ok(Self::ReadCaboose {
                    key: __clap_arg_matches
                        .remove_one::<[u8; 4]>("key")
                        .ok_or_else(|| clap::Error::raw(
                            clap::error::ErrorKind::MissingRequiredArgument,
                            "The following required argument was not provided: key",
                        ))?,
                });
            }
            if __clap_name == "read-component-caboose"
                && !__clap_arg_matches.contains_id("")
            {
                return ::std::result::Result::Ok(Self::ReadComponentCaboose {
                    component: __clap_arg_matches
                        .remove_one::<SpComponent>("component")
                        .ok_or_else(|| clap::Error::raw(
                            clap::error::ErrorKind::MissingRequiredArgument,
                            "The following required argument was not provided: component",
                        ))?,
                    slot: __clap_arg_matches.remove_one::<String>("slot"),
                    key: __clap_arg_matches
                        .remove_one::<[u8; 4]>("key")
                        .ok_or_else(|| clap::Error::raw(
                            clap::error::ErrorKind::MissingRequiredArgument,
                            "The following required argument was not provided: key",
                        ))?,
                });
            }
            if __clap_name == "reset" && !__clap_arg_matches.contains_id("") {
                return ::std::result::Result::Ok(Self::Reset {
                    disable_watchdog: __clap_arg_matches
                        .remove_one::<bool>("disable_watchdog")
                        .ok_or_else(|| clap::Error::raw(
                            clap::error::ErrorKind::MissingRequiredArgument,
                            "The following required argument was not provided: disable_watchdog",
                        ))?,
                });
            }
            if __clap_name == "reset-component" && !__clap_arg_matches.contains_id("") {
                return ::std::result::Result::Ok(Self::ResetComponent {
                    component: __clap_arg_matches
                        .remove_one::<SpComponent>("component")
                        .ok_or_else(|| clap::Error::raw(
                            clap::error::ErrorKind::MissingRequiredArgument,
                            "The following required argument was not provided: component",
                        ))?,
                    disable_watchdog: __clap_arg_matches
                        .remove_one::<bool>("disable_watchdog")
                        .ok_or_else(|| clap::Error::raw(
                            clap::error::ErrorKind::MissingRequiredArgument,
                            "The following required argument was not provided: disable_watchdog",
                        ))?,
                });
            }
            if __clap_name == "system-led" && !__clap_arg_matches.contains_id("") {
                return ::std::result::Result::Ok(Self::SystemLed {
                    cmd: {
                        <LedCommand as clap::FromArgMatches>::from_arg_matches_mut(
                            __clap_arg_matches,
                        )?
                    },
                });
            }
            if __clap_name == "read-sensor-value" && !__clap_arg_matches.contains_id("")
            {
                return ::std::result::Result::Ok(Self::ReadSensorValue {
                    id: __clap_arg_matches
                        .remove_one::<u32>("id")
                        .ok_or_else(|| clap::Error::raw(
                            clap::error::ErrorKind::MissingRequiredArgument,
                            "The following required argument was not provided: id",
                        ))?,
                });
            }
            if __clap_name == "read-cmpa" && !__clap_arg_matches.contains_id("") {
                return ::std::result::Result::Ok(Self::ReadCmpa {
                    out: __clap_arg_matches.remove_one::<PathBuf>("out"),
                });
            }
            if __clap_name == "read-cfpa" && !__clap_arg_matches.contains_id("") {
                return ::std::result::Result::Ok(Self::ReadCfpa {
                    out: __clap_arg_matches.remove_one::<PathBuf>("out"),
                    slot: __clap_arg_matches
                        .remove_one::<CfpaSlot>("slot")
                        .ok_or_else(|| clap::Error::raw(
                            clap::error::ErrorKind::MissingRequiredArgument,
                            "The following required argument was not provided: slot",
                        ))?,
                });
            }
            if __clap_name == "vpd-lock-status" && !__clap_arg_matches.contains_id("") {
                return ::std::result::Result::Ok(Self::VpdLockStatus);
            }
            if __clap_name == "rot-boot-info" && !__clap_arg_matches.contains_id("") {
                return ::std::result::Result::Ok(Self::RotBootInfo {
                    version: __clap_arg_matches
                        .remove_one::<u8>("version")
                        .ok_or_else(|| clap::Error::raw(
                            clap::error::ErrorKind::MissingRequiredArgument,
                            "The following required argument was not provided: version",
                        ))?,
                });
            }
            if __clap_name == "monorail" && !__clap_arg_matches.contains_id("") {
                return ::std::result::Result::Ok(Self::Monorail {
                    cmd: {
                        <MonorailCommand as clap::FromArgMatches>::from_arg_matches_mut(
                            __clap_arg_matches,
                        )?
                    },
                });
            }
            ::std::result::Result::Err(
                clap::Error::raw(
                    clap::error::ErrorKind::InvalidSubcommand,
                    {
                        let res = ::alloc::fmt::format(
                            format_args!(
                                "The subcommand \'{0}\' wasn\'t recognized",
                                __clap_name,
                            ),
                        );
                        res
                    },
                ),
            )
        } else {
            ::std::result::Result::Err(
                clap::Error::raw(
                    clap::error::ErrorKind::MissingSubcommand,
                    "A subcommand is required but one was not provided.",
                ),
            )
        }
    }
    fn update_from_arg_matches(
        &mut self,
        __clap_arg_matches: &clap::ArgMatches,
    ) -> ::std::result::Result<(), clap::Error> {
        self.update_from_arg_matches_mut(&mut __clap_arg_matches.clone())
    }
    fn update_from_arg_matches_mut<'b>(
        &mut self,
        __clap_arg_matches: &mut clap::ArgMatches,
    ) -> ::std::result::Result<(), clap::Error> {
        #![allow(deprecated)]
        if let Some(__clap_name) = __clap_arg_matches.subcommand_name() {
            match self {
                Self::Discover if "discover" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {}
                }
                Self::State if "state" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {}
                }
                Self::Ignition { target } if "ignition" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {
                        if __clap_arg_matches.contains_id("target") {
                            *target = __clap_arg_matches
                                .remove_one::<IgnitionLinkEventsTarget>("target")
                                .ok_or_else(|| clap::Error::raw(
                                    clap::error::ErrorKind::MissingRequiredArgument,
                                    "The following required argument was not provided: target",
                                ))?;
                        }
                    }
                }
                Self::IgnitionCommand {
                    target,
                    command,
                } if "ignition-command" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {
                        if __clap_arg_matches.contains_id("target") {
                            *target = __clap_arg_matches
                                .remove_one::<u8>("target")
                                .ok_or_else(|| clap::Error::raw(
                                    clap::error::ErrorKind::MissingRequiredArgument,
                                    "The following required argument was not provided: target",
                                ))?;
                        }
                        if __clap_arg_matches.contains_id("command") {
                            *command = __clap_arg_matches
                                .remove_one::<IgnitionCommand>("command")
                                .ok_or_else(|| clap::Error::raw(
                                    clap::error::ErrorKind::MissingRequiredArgument,
                                    "The following required argument was not provided: command",
                                ))?;
                        }
                    }
                }
                Self::IgnitionLinkEvents {
                    target,
                } if "ignition-link-events" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {
                        if __clap_arg_matches.contains_id("target") {
                            *target = __clap_arg_matches
                                .remove_one::<IgnitionLinkEventsTarget>("target")
                                .ok_or_else(|| clap::Error::raw(
                                    clap::error::ErrorKind::MissingRequiredArgument,
                                    "The following required argument was not provided: target",
                                ))?;
                        }
                    }
                }
                Self::ClearIgnitionLinkEvents {
                    target,
                    transceiver_select,
                } if "clear-ignition-link-events" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {
                        if __clap_arg_matches.contains_id("target") {
                            *target = __clap_arg_matches
                                .remove_one::<IgnitionLinkEventsTarget>("target")
                                .ok_or_else(|| clap::Error::raw(
                                    clap::error::ErrorKind::MissingRequiredArgument,
                                    "The following required argument was not provided: target",
                                ))?;
                        }
                        if __clap_arg_matches.contains_id("transceiver_select") {
                            *transceiver_select = __clap_arg_matches
                                .remove_one::<
                                    IgnitionLinkEventsTransceiverSelect,
                                >("transceiver_select")
                                .ok_or_else(|| clap::Error::raw(
                                    clap::error::ErrorKind::MissingRequiredArgument,
                                    "The following required argument was not provided: transceiver_select",
                                ))?;
                        }
                    }
                }
                Self::ComponentActiveSlot {
                    component,
                    set,
                    persist,
                } if "component-active-slot" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {
                        if __clap_arg_matches.contains_id("component") {
                            *component = __clap_arg_matches
                                .remove_one::<SpComponent>("component")
                                .ok_or_else(|| clap::Error::raw(
                                    clap::error::ErrorKind::MissingRequiredArgument,
                                    "The following required argument was not provided: component",
                                ))?;
                        }
                        if __clap_arg_matches.contains_id("set") {
                            *set = __clap_arg_matches.remove_one::<u16>("set");
                        }
                        if __clap_arg_matches.contains_id("persist") {
                            *persist = __clap_arg_matches
                                .remove_one::<bool>("persist")
                                .ok_or_else(|| clap::Error::raw(
                                    clap::error::ErrorKind::MissingRequiredArgument,
                                    "The following required argument was not provided: persist",
                                ))?;
                        }
                    }
                }
                Self::StartupOptions { options } if "startup-options" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {
                        if __clap_arg_matches.contains_id("options") {
                            *options = __clap_arg_matches.remove_one::<u64>("options");
                        }
                    }
                }
                Self::Inventory if "inventory" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {}
                }
                Self::ComponentDetails {
                    component,
                } if "component-details" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {
                        if __clap_arg_matches.contains_id("component") {
                            *component = __clap_arg_matches
                                .remove_one::<SpComponent>("component")
                                .ok_or_else(|| clap::Error::raw(
                                    clap::error::ErrorKind::MissingRequiredArgument,
                                    "The following required argument was not provided: component",
                                ))?;
                        }
                    }
                }
                Self::ComponentClearStatus {
                    component,
                } if "component-clear-status" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {
                        if __clap_arg_matches.contains_id("component") {
                            *component = __clap_arg_matches
                                .remove_one::<SpComponent>("component")
                                .ok_or_else(|| clap::Error::raw(
                                    clap::error::ErrorKind::MissingRequiredArgument,
                                    "The following required argument was not provided: component",
                                ))?;
                        }
                    }
                }
                Self::UsartAttach {
                    raw,
                    stdin_buffer_time_millis,
                    imap,
                    omap,
                    uart_logfile,
                } if "usart-attach" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {
                        if __clap_arg_matches.contains_id("raw") {
                            *raw = __clap_arg_matches
                                .remove_one::<bool>("raw")
                                .ok_or_else(|| clap::Error::raw(
                                    clap::error::ErrorKind::MissingRequiredArgument,
                                    "The following required argument was not provided: raw",
                                ))?;
                        }
                        if __clap_arg_matches.contains_id("stdin_buffer_time_millis") {
                            *stdin_buffer_time_millis = __clap_arg_matches
                                .remove_one::<u64>("stdin_buffer_time_millis")
                                .ok_or_else(|| clap::Error::raw(
                                    clap::error::ErrorKind::MissingRequiredArgument,
                                    "The following required argument was not provided: stdin_buffer_time_millis",
                                ))?;
                        }
                        if __clap_arg_matches.contains_id("imap") {
                            *imap = __clap_arg_matches.remove_one::<String>("imap");
                        }
                        if __clap_arg_matches.contains_id("omap") {
                            *omap = __clap_arg_matches.remove_one::<String>("omap");
                        }
                        if __clap_arg_matches.contains_id("uart_logfile") {
                            *uart_logfile = __clap_arg_matches
                                .remove_one::<PathBuf>("uart_logfile");
                        }
                    }
                }
                Self::UsartDetach if "usart-detach" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {}
                }
                Self::ServeHostPhase2 {
                    directory,
                } if "serve-host-phase2" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {
                        if __clap_arg_matches.contains_id("directory") {
                            *directory = __clap_arg_matches
                                .remove_one::<PathBuf>("directory")
                                .ok_or_else(|| clap::Error::raw(
                                    clap::error::ErrorKind::MissingRequiredArgument,
                                    "The following required argument was not provided: directory",
                                ))?;
                        }
                    }
                }
                Self::Update {
                    allow_multiple_update,
                    component,
                    slot,
                    image,
                } if "update" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {
                        if __clap_arg_matches.contains_id("allow_multiple_update") {
                            *allow_multiple_update = __clap_arg_matches
                                .remove_one::<bool>("allow_multiple_update")
                                .ok_or_else(|| clap::Error::raw(
                                    clap::error::ErrorKind::MissingRequiredArgument,
                                    "The following required argument was not provided: allow_multiple_update",
                                ))?;
                        }
                        if __clap_arg_matches.contains_id("component") {
                            *component = __clap_arg_matches
                                .remove_one::<SpComponent>("component")
                                .ok_or_else(|| clap::Error::raw(
                                    clap::error::ErrorKind::MissingRequiredArgument,
                                    "The following required argument was not provided: component",
                                ))?;
                        }
                        if __clap_arg_matches.contains_id("slot") {
                            *slot = __clap_arg_matches
                                .remove_one::<u16>("slot")
                                .ok_or_else(|| clap::Error::raw(
                                    clap::error::ErrorKind::MissingRequiredArgument,
                                    "The following required argument was not provided: slot",
                                ))?;
                        }
                        if __clap_arg_matches.contains_id("image") {
                            *image = __clap_arg_matches
                                .remove_one::<PathBuf>("image")
                                .ok_or_else(|| clap::Error::raw(
                                    clap::error::ErrorKind::MissingRequiredArgument,
                                    "The following required argument was not provided: image",
                                ))?;
                        }
                    }
                }
                Self::UpdateStatus { component } if "update-status" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {
                        if __clap_arg_matches.contains_id("component") {
                            *component = __clap_arg_matches
                                .remove_one::<SpComponent>("component")
                                .ok_or_else(|| clap::Error::raw(
                                    clap::error::ErrorKind::MissingRequiredArgument,
                                    "The following required argument was not provided: component",
                                ))?;
                        }
                    }
                }
                Self::UpdateAbort {
                    component,
                    update_id,
                } if "update-abort" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {
                        if __clap_arg_matches.contains_id("component") {
                            *component = __clap_arg_matches
                                .remove_one::<SpComponent>("component")
                                .ok_or_else(|| clap::Error::raw(
                                    clap::error::ErrorKind::MissingRequiredArgument,
                                    "The following required argument was not provided: component",
                                ))?;
                        }
                        if __clap_arg_matches.contains_id("update_id") {
                            *update_id = __clap_arg_matches
                                .remove_one::<Uuid>("update_id")
                                .ok_or_else(|| clap::Error::raw(
                                    clap::error::ErrorKind::MissingRequiredArgument,
                                    "The following required argument was not provided: update_id",
                                ))?;
                        }
                    }
                }
                Self::PowerState { new_power_state } if "power-state" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {
                        if __clap_arg_matches.contains_id("new_power_state") {
                            *new_power_state = __clap_arg_matches
                                .remove_one::<PowerState>("new_power_state");
                        }
                    }
                }
                Self::SendHostNmi if "send-host-nmi" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {}
                }
                Self::SetIpccKeyValue {
                    key,
                    value_path,
                } if "set-ipcc-key-value" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {
                        if __clap_arg_matches.contains_id("key") {
                            *key = __clap_arg_matches
                                .remove_one::<u8>("key")
                                .ok_or_else(|| clap::Error::raw(
                                    clap::error::ErrorKind::MissingRequiredArgument,
                                    "The following required argument was not provided: key",
                                ))?;
                        }
                        if __clap_arg_matches.contains_id("value_path") {
                            *value_path = __clap_arg_matches
                                .remove_one::<PathBuf>("value_path")
                                .ok_or_else(|| clap::Error::raw(
                                    clap::error::ErrorKind::MissingRequiredArgument,
                                    "The following required argument was not provided: value_path",
                                ))?;
                        }
                    }
                }
                Self::ReadCaboose { key } if "read-caboose" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {
                        if __clap_arg_matches.contains_id("key") {
                            *key = __clap_arg_matches
                                .remove_one::<[u8; 4]>("key")
                                .ok_or_else(|| clap::Error::raw(
                                    clap::error::ErrorKind::MissingRequiredArgument,
                                    "The following required argument was not provided: key",
                                ))?;
                        }
                    }
                }
                Self::ReadComponentCaboose {
                    component,
                    slot,
                    key,
                } if "read-component-caboose" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {
                        if __clap_arg_matches.contains_id("component") {
                            *component = __clap_arg_matches
                                .remove_one::<SpComponent>("component")
                                .ok_or_else(|| clap::Error::raw(
                                    clap::error::ErrorKind::MissingRequiredArgument,
                                    "The following required argument was not provided: component",
                                ))?;
                        }
                        if __clap_arg_matches.contains_id("slot") {
                            *slot = __clap_arg_matches.remove_one::<String>("slot");
                        }
                        if __clap_arg_matches.contains_id("key") {
                            *key = __clap_arg_matches
                                .remove_one::<[u8; 4]>("key")
                                .ok_or_else(|| clap::Error::raw(
                                    clap::error::ErrorKind::MissingRequiredArgument,
                                    "The following required argument was not provided: key",
                                ))?;
                        }
                    }
                }
                Self::Reset { disable_watchdog } if "reset" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {
                        if __clap_arg_matches.contains_id("disable_watchdog") {
                            *disable_watchdog = __clap_arg_matches
                                .remove_one::<bool>("disable_watchdog")
                                .ok_or_else(|| clap::Error::raw(
                                    clap::error::ErrorKind::MissingRequiredArgument,
                                    "The following required argument was not provided: disable_watchdog",
                                ))?;
                        }
                    }
                }
                Self::ResetComponent {
                    component,
                    disable_watchdog,
                } if "reset-component" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {
                        if __clap_arg_matches.contains_id("component") {
                            *component = __clap_arg_matches
                                .remove_one::<SpComponent>("component")
                                .ok_or_else(|| clap::Error::raw(
                                    clap::error::ErrorKind::MissingRequiredArgument,
                                    "The following required argument was not provided: component",
                                ))?;
                        }
                        if __clap_arg_matches.contains_id("disable_watchdog") {
                            *disable_watchdog = __clap_arg_matches
                                .remove_one::<bool>("disable_watchdog")
                                .ok_or_else(|| clap::Error::raw(
                                    clap::error::ErrorKind::MissingRequiredArgument,
                                    "The following required argument was not provided: disable_watchdog",
                                ))?;
                        }
                    }
                }
                Self::SystemLed { cmd } if "system-led" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {
                        {
                            <LedCommand as clap::FromArgMatches>::update_from_arg_matches_mut(
                                cmd,
                                __clap_arg_matches,
                            )?;
                        }
                    }
                }
                Self::ReadSensorValue { id } if "read-sensor-value" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {
                        if __clap_arg_matches.contains_id("id") {
                            *id = __clap_arg_matches
                                .remove_one::<u32>("id")
                                .ok_or_else(|| clap::Error::raw(
                                    clap::error::ErrorKind::MissingRequiredArgument,
                                    "The following required argument was not provided: id",
                                ))?;
                        }
                    }
                }
                Self::ReadCmpa { out } if "read-cmpa" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {
                        if __clap_arg_matches.contains_id("out") {
                            *out = __clap_arg_matches.remove_one::<PathBuf>("out");
                        }
                    }
                }
                Self::ReadCfpa { out, slot } if "read-cfpa" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {
                        if __clap_arg_matches.contains_id("out") {
                            *out = __clap_arg_matches.remove_one::<PathBuf>("out");
                        }
                        if __clap_arg_matches.contains_id("slot") {
                            *slot = __clap_arg_matches
                                .remove_one::<CfpaSlot>("slot")
                                .ok_or_else(|| clap::Error::raw(
                                    clap::error::ErrorKind::MissingRequiredArgument,
                                    "The following required argument was not provided: slot",
                                ))?;
                        }
                    }
                }
                Self::VpdLockStatus if "vpd-lock-status" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {}
                }
                Self::RotBootInfo { version } if "rot-boot-info" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {
                        if __clap_arg_matches.contains_id("version") {
                            *version = __clap_arg_matches
                                .remove_one::<u8>("version")
                                .ok_or_else(|| clap::Error::raw(
                                    clap::error::ErrorKind::MissingRequiredArgument,
                                    "The following required argument was not provided: version",
                                ))?;
                        }
                    }
                }
                Self::Monorail { cmd } if "monorail" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {
                        {
                            <MonorailCommand as clap::FromArgMatches>::update_from_arg_matches_mut(
                                cmd,
                                __clap_arg_matches,
                            )?;
                        }
                    }
                }
                s => {
                    *s = <Self as clap::FromArgMatches>::from_arg_matches_mut(
                        __clap_arg_matches,
                    )?;
                }
            }
        }
        ::std::result::Result::Ok(())
    }
}
#[allow(
    dead_code,
    unreachable_code,
    unused_variables,
    unused_braces,
    unused_qualifications,
)]
#[allow(
    clippy::style,
    clippy::complexity,
    clippy::pedantic,
    clippy::restriction,
    clippy::perf,
    clippy::deprecated,
    clippy::nursery,
    clippy::cargo,
    clippy::suspicious_else_formatting,
    clippy::almost_swapped,
    clippy::redundant_locals,
)]
#[automatically_derived]
impl clap::Subcommand for Command {
    fn augment_subcommands<'b>(__clap_app: clap::Command) -> clap::Command {
        let __clap_app = __clap_app;
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("discover");
                let __clap_subcommand = __clap_subcommand;
                let __clap_subcommand = __clap_subcommand;
                __clap_subcommand.about("Discover a connected SP").long_about(None)
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("state");
                let __clap_subcommand = __clap_subcommand;
                let __clap_subcommand = __clap_subcommand;
                __clap_subcommand.about("Ask SP for its current state").long_about(None)
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("ignition");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("Ignition")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 1usize] = [
                                        clap::Id::from("target"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("target")
                                .value_name("TARGET")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser(IgnitionLinkEventsTarget::parse)
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help("integer of a target, or 'all' for all targets");
                            let arg = arg;
                            arg
                        });
                    __clap_subcommand
                        .about(
                            "Get the ignition state for a single target port (only valid if the SP is an ignition controller)",
                        )
                        .long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("ignition-command");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("IgnitionCommand")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 2usize] = [
                                        clap::Id::from("target"),
                                        clap::Id::from("command"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("target")
                                .value_name("TARGET")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        u8,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg;
                            let arg = arg;
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("command")
                                .value_name("COMMAND")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser(ignition_command_from_str)
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help("'power-on', 'power-off', or 'power-reset'");
                            let arg = arg;
                            arg
                        });
                    __clap_subcommand
                        .about(
                            "Send an ignition command for a single target port (only valid if the SP is an ignition controller)",
                        )
                        .long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("ignition-link-events");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("IgnitionLinkEvents")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 1usize] = [
                                        clap::Id::from("target"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("target")
                                .value_name("TARGET")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser(IgnitionLinkEventsTarget::parse)
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help("integer of a target, or 'all' for all targets");
                            let arg = arg;
                            arg
                        });
                    __clap_subcommand
                        .about(
                            "Get bulk ignition link events (only valid if the SP is an ignition controller)",
                        )
                        .long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("clear-ignition-link-events");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("ClearIgnitionLinkEvents")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 2usize] = [
                                        clap::Id::from("target"),
                                        clap::Id::from("transceiver_select"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("target")
                                .value_name("TARGET")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser(IgnitionLinkEventsTarget::parse)
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help("integer of a target, or 'all' for all targets");
                            let arg = arg;
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("transceiver_select")
                                .value_name("TRANSCEIVER_SELECT")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser(IgnitionLinkEventsTransceiverSelect::parse)
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help(
                                    "'controller', 'target-link0', 'target-link1', or 'all'",
                                );
                            let arg = arg;
                            arg
                        });
                    __clap_subcommand
                        .about(
                            "Clear all ignition link events (only valid if the SP is an ignition controller)",
                        )
                        .long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("component-active-slot");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("ComponentActiveSlot")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 3usize] = [
                                        clap::Id::from("component"),
                                        clap::Id::from("set"),
                                        clap::Id::from("persist"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("component")
                                .value_name("COMPONENT")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser(parse_sp_component)
                                .action(clap::ArgAction::Set);
                            let arg = arg;
                            let arg = arg;
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("set")
                                .value_name("SET")
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        u16,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .short('s')
                                .long("set")
                                .value_name("SLOT")
                                .help("set the active slot");
                            let arg = arg;
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("persist")
                                .value_name("PERSIST")
                                .required(true && clap::ArgAction::SetTrue.takes_values())
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        bool,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::SetTrue);
                            let arg = arg
                                .short('p')
                                .long("persist")
                                .requires("set")
                                .help("persist the active slot to non-volatile memory");
                            let arg = arg;
                            arg
                        });
                    __clap_subcommand
                        .about(
                            "Get or set the active slot of a component (e.g., `host-boot-flash`)",
                        )
                        .long_about(
                            "Get or set the active slot of a component (e.g., `host-boot-flash`).\n\nExcept for component \"stage0\", setting the active slot can be viewed as an atomic operation.\n\nSetting \"stage0\" slot 1 as the active slot initiates a copy from slot 1 to slot 0 if the contents of slot 1 still match those seen at last RoT reset and the contents are properly signed.\n\nPower failures during the copy can disable the RoT. Only one stage0 update should be in process in a rack at any time.",
                        )
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("startup-options");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("StartupOptions")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 1usize] = [
                                        clap::Id::from("options"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("options")
                                .value_name("OPTIONS")
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        u64,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg;
                            let arg = arg;
                            arg
                        });
                    __clap_subcommand
                        .about("Get or set startup options on an SP")
                        .long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("inventory");
                let __clap_subcommand = __clap_subcommand;
                let __clap_subcommand = __clap_subcommand;
                __clap_subcommand.about("Ask SP for its inventory").long_about(None)
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("component-details");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("ComponentDetails")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 1usize] = [
                                        clap::Id::from("component"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("component")
                                .value_name("COMPONENT")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser(parse_sp_component)
                                .action(clap::ArgAction::Set);
                            let arg = arg;
                            let arg = arg;
                            arg
                        });
                    __clap_subcommand
                        .about("Ask SP for details of a component")
                        .long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("component-clear-status");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("ComponentClearStatus")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 1usize] = [
                                        clap::Id::from("component"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("component")
                                .value_name("COMPONENT")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser(parse_sp_component)
                                .action(clap::ArgAction::Set);
                            let arg = arg;
                            let arg = arg;
                            arg
                        });
                    __clap_subcommand
                        .about(
                            "Ask SP to clear the state (e.g., reset counters) on a component",
                        )
                        .long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("usart-attach");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("UsartAttach")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 5usize] = [
                                        clap::Id::from("raw"),
                                        clap::Id::from("stdin_buffer_time_millis"),
                                        clap::Id::from("imap"),
                                        clap::Id::from("omap"),
                                        clap::Id::from("uart_logfile"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("raw")
                                .value_name("RAW")
                                .required(true && clap::ArgAction::SetFalse.takes_values())
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        bool,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::SetFalse);
                            let arg = arg
                                .help("Put the local terminal in raw mode")
                                .long_help(None)
                                .long("no-raw")
                                .help("do not put terminal in raw mode");
                            let arg = arg;
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("stdin_buffer_time_millis")
                                .value_name("STDIN_BUFFER_TIME_MILLIS")
                                .required(false && clap::ArgAction::Set.takes_values())
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        u64,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help(
                                    "Amount of time to buffer input from stdin before forwarding to SP",
                                )
                                .long_help(None)
                                .long("stdin-buffer-time-millis")
                                .default_value("500");
                            let arg = arg;
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("imap")
                                .value_name("IMAP")
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        String,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help(
                                    "Specifies the input character map (i.e., special characters to be replaced when reading from the serial port). See picocom's manpage",
                                )
                                .long_help(None)
                                .long("imap");
                            let arg = arg;
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("omap")
                                .value_name("OMAP")
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        String,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help(
                                    "Specifies the output character map (i.e., special characters to be replaced when writing to the serial port). See picocom's manpage",
                                )
                                .long_help(None)
                                .long("omap");
                            let arg = arg;
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("uart_logfile")
                                .value_name("UART_LOGFILE")
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        PathBuf,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help(
                                    "Record all input read from the serial port to this logfile (before any remapping)",
                                )
                                .long_help(None)
                                .long("uart-logfile");
                            let arg = arg;
                            arg
                        });
                    __clap_subcommand.about("Attach to the SP's USART").long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("usart-detach");
                let __clap_subcommand = __clap_subcommand;
                let __clap_subcommand = __clap_subcommand;
                __clap_subcommand
                    .about("Detach any other attached USART connection")
                    .long_about(None)
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("serve-host-phase2");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("ServeHostPhase2")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 1usize] = [
                                        clap::Id::from("directory"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("directory")
                                .value_name("DIRECTORY")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        PathBuf,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg;
                            let arg = arg;
                            arg
                        });
                    __clap_subcommand.about("Serve host phase 2 images").long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("update");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("Update")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 4usize] = [
                                        clap::Id::from("allow_multiple_update"),
                                        clap::Id::from("component"),
                                        clap::Id::from("slot"),
                                        clap::Id::from("image"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("allow_multiple_update")
                                .value_name("ALLOW_MULTIPLE_UPDATE")
                                .required(true && clap::ArgAction::SetTrue.takes_values())
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        bool,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::SetTrue);
                            let arg = arg.long("allow-multiple-update");
                            let arg = arg;
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("component")
                                .value_name("COMPONENT")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser(parse_sp_component)
                                .action(clap::ArgAction::Set);
                            let arg = arg;
                            let arg = arg;
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("slot")
                                .value_name("SLOT")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        u16,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg;
                            let arg = arg;
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("image")
                                .value_name("IMAGE")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        PathBuf,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg;
                            let arg = arg;
                            arg
                        });
                    __clap_subcommand
                        .about("Upload a new image to the SP or one of its components")
                        .long_about(
                            "Upload a new image to the SP or one of its components.\n\nTo update the SP itself:\n\n1. Use the component name \"sp\" 2. Specify slot 0 (the SP only has a single updateable slot: its alternate bank). 3. Pass the path to a hubris archive as `image`.",
                        )
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("update-status");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("UpdateStatus")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 1usize] = [
                                        clap::Id::from("component"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("component")
                                .value_name("COMPONENT")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser(parse_sp_component)
                                .action(clap::ArgAction::Set);
                            let arg = arg;
                            let arg = arg;
                            arg
                        });
                    __clap_subcommand
                        .about("Get the status of an update to the specified component")
                        .long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("update-abort");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("UpdateAbort")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 2usize] = [
                                        clap::Id::from("component"),
                                        clap::Id::from("update_id"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("component")
                                .value_name("COMPONENT")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser(parse_sp_component)
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help(
                                    "Component with an update-in-progress to be aborted. Omit to abort updates to the SP itself",
                                )
                                .long_help(None);
                            let arg = arg;
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("update_id")
                                .value_name("UPDATE_ID")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        Uuid,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help("ID of the update to abort")
                                .long_help(None);
                            let arg = arg;
                            arg
                        });
                    __clap_subcommand
                        .about("Abort an in-progress update")
                        .long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("power-state");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("PowerState")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 1usize] = [
                                        clap::Id::from("new_power_state"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("new_power_state")
                                .value_name("NEW_POWER_STATE")
                                .value_parser(power_state_from_str)
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help(
                                    "If present, instruct the SP to set this power state. If not present, get the current power state instead",
                                )
                                .long_help(None);
                            let arg = arg;
                            arg
                        });
                    __clap_subcommand
                        .about("Get or set the power state")
                        .long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("send-host-nmi");
                let __clap_subcommand = __clap_subcommand;
                let __clap_subcommand = __clap_subcommand;
                __clap_subcommand
                    .about("Sends an NMI to the host (SP3) CPU by toggling a GPIO")
                    .long_about(None)
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("set-ipcc-key-value");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("SetIpccKeyValue")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 2usize] = [
                                        clap::Id::from("key"),
                                        clap::Id::from("value_path"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("key")
                                .value_name("KEY")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        u8,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg;
                            let arg = arg;
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("value_path")
                                .value_name("VALUE_PATH")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        PathBuf,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help("Path to a file containing the value")
                                .long_help(None);
                            let arg = arg;
                            arg
                        });
                    __clap_subcommand.about("Set an IPCC key/value").long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("read-caboose");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("ReadCaboose")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 1usize] = [clap::Id::from("key")];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("key")
                                .value_name("KEY")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser(parse_tlvc_key)
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help("4-character ASCII string")
                                .long_help(None);
                            let arg = arg;
                            arg
                        });
                    __clap_subcommand
                        .about("Read a single key from the caboose")
                        .long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("read-component-caboose");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("ReadComponentCaboose")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 3usize] = [
                                        clap::Id::from("component"),
                                        clap::Id::from("slot"),
                                        clap::Id::from("key"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("component")
                                .value_name("COMPONENT")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser(parse_sp_component)
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help("Component from which to read; must be `sp` or `rot`")
                                .long_help(None)
                                .short('c')
                                .long("component");
                            let arg = arg;
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("slot")
                                .value_name("SLOT")
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        String,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help("Target slot from which to read the caboose")
                                .long_help(
                                    "Target slot from which to read the caboose.\n\nThe SP accepts `active` or `inactive`; the RoT accepts `A` or `B`",
                                )
                                .short('s')
                                .long("slot");
                            let arg = arg;
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("key")
                                .value_name("KEY")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser(parse_tlvc_key)
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help("4-character ASCII string")
                                .long_help(None);
                            let arg = arg;
                            arg
                        });
                    __clap_subcommand
                        .about("Read a single key from the caboose")
                        .long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("reset");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("Reset")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 1usize] = [
                                        clap::Id::from("disable_watchdog"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("disable_watchdog")
                                .value_name("DISABLE_WATCHDOG")
                                .required(true && clap::ArgAction::SetTrue.takes_values())
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        bool,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::SetTrue);
                            let arg = arg
                                .help(
                                    "Reset without the automatic safety rollback watchdog",
                                )
                                .long_help(None)
                                .long("disable-watchdog");
                            let arg = arg;
                            arg
                        });
                    __clap_subcommand.about("Instruct the SP to reset").long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("reset-component");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("ResetComponent")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 2usize] = [
                                        clap::Id::from("component"),
                                        clap::Id::from("disable_watchdog"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("component")
                                .value_name("COMPONENT")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser(parse_sp_component)
                                .action(clap::ArgAction::Set);
                            let arg = arg;
                            let arg = arg;
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("disable_watchdog")
                                .value_name("DISABLE_WATCHDOG")
                                .required(true && clap::ArgAction::SetTrue.takes_values())
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        bool,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::SetTrue);
                            let arg = arg
                                .help(
                                    "Reset without the automatic safety rollback watchdog (if applicable)",
                                )
                                .long_help(None)
                                .long("disable-watchdog");
                            let arg = arg;
                            arg
                        });
                    __clap_subcommand
                        .about("Reset a component")
                        .long_about(
                            "Reset a component.\n\nThis command is implemented for the component \"rot\" but may be expanded to other components in the future.",
                        )
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("system-led");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("SystemLed")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 0usize] = [];
                                    members
                                }),
                        );
                    let __clap_subcommand = <LedCommand as clap::Subcommand>::augment_subcommands(
                        __clap_subcommand,
                    );
                    let __clap_subcommand = __clap_subcommand
                        .subcommand_required(true)
                        .arg_required_else_help(true);
                    __clap_subcommand.about("Controls the system LED").long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("read-sensor-value");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("ReadSensorValue")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 1usize] = [clap::Id::from("id")];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("id")
                                .value_name("ID")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        u32,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg.help("Sensor ID").long_help(None);
                            let arg = arg;
                            arg
                        });
                    __clap_subcommand
                        .about("Reads a single sensor by `SensorId`, returning a `f32`")
                        .long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("read-cmpa");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("ReadCmpa")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 1usize] = [clap::Id::from("out")];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("out")
                                .value_name("OUT")
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        PathBuf,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help(
                                    "Output file (by default, pretty-printed to `stdout`)",
                                )
                                .long_help(None)
                                .short('o')
                                .long("out");
                            let arg = arg;
                            arg
                        });
                    __clap_subcommand
                        .about("Reads the CMPA from an attached Root of Trust")
                        .long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("read-cfpa");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("ReadCfpa")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 2usize] = [
                                        clap::Id::from("out"),
                                        clap::Id::from("slot"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("out")
                                .value_name("OUT")
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        PathBuf,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help(
                                    "Output file (by default, pretty-printed to `stdout`)",
                                )
                                .long_help(None)
                                .short('o')
                                .long("out");
                            let arg = arg;
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("slot")
                                .value_name("SLOT")
                                .required(false && clap::ArgAction::Set.takes_values())
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        CfpaSlot,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .short('s')
                                .long("slot")
                                .default_value({
                                    static DEFAULT_VALUE: ::std::sync::OnceLock<String> = ::std::sync::OnceLock::new();
                                    let s = DEFAULT_VALUE
                                        .get_or_init(|| {
                                            let val: CfpaSlot = CfpaSlot::Active;
                                            ::std::string::ToString::to_string(&val)
                                        });
                                    let s: &'static str = &*s;
                                    s
                                });
                            let arg = arg;
                            arg
                        });
                    __clap_subcommand
                        .about("Reads a CFPA slot from an attached Root of Trust")
                        .long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("vpd-lock-status");
                let __clap_subcommand = __clap_subcommand;
                let __clap_subcommand = __clap_subcommand;
                __clap_subcommand
                    .about("Reads the lock status of any VPD in the system")
                    .long_about(None)
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("rot-boot-info");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("RotBootInfo")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 1usize] = [
                                        clap::Id::from("version"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("version")
                                .value_name("VERSION")
                                .required(false && clap::ArgAction::Set.takes_values())
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        u8,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help(
                                    "Return highest version of RotBootInfo less then or equal to our highest known version",
                                )
                                .long_help(None)
                                .long("version")
                                .short('v')
                                .default_value({
                                    static DEFAULT_VALUE: ::std::sync::OnceLock<String> = ::std::sync::OnceLock::new();
                                    let s = DEFAULT_VALUE
                                        .get_or_init(|| {
                                            let val: u8 = RotBootInfo::HIGHEST_KNOWN_VERSION;
                                            ::std::string::ToString::to_string(&val)
                                        });
                                    let s: &'static str = &*s;
                                    s
                                });
                            let arg = arg;
                            arg
                        });
                    __clap_subcommand
                        .about("Read the RoT's boot-time information")
                        .long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("monorail");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("Monorail")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 0usize] = [];
                                    members
                                }),
                        );
                    let __clap_subcommand = <MonorailCommand as clap::Subcommand>::augment_subcommands(
                        __clap_subcommand,
                    );
                    let __clap_subcommand = __clap_subcommand
                        .subcommand_required(true)
                        .arg_required_else_help(true);
                    __clap_subcommand
                        .about("Control the management network switch")
                        .long_about(None)
                }
            });
        __clap_app
    }
    fn augment_subcommands_for_update<'b>(__clap_app: clap::Command) -> clap::Command {
        let __clap_app = __clap_app;
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("discover");
                let __clap_subcommand = __clap_subcommand;
                let __clap_subcommand = __clap_subcommand;
                __clap_subcommand.about("Discover a connected SP").long_about(None)
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("state");
                let __clap_subcommand = __clap_subcommand;
                let __clap_subcommand = __clap_subcommand;
                __clap_subcommand.about("Ask SP for its current state").long_about(None)
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("ignition");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("Ignition")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 1usize] = [
                                        clap::Id::from("target"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("target")
                                .value_name("TARGET")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser(IgnitionLinkEventsTarget::parse)
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help("integer of a target, or 'all' for all targets");
                            let arg = arg.required(false);
                            arg
                        });
                    __clap_subcommand
                        .about(
                            "Get the ignition state for a single target port (only valid if the SP is an ignition controller)",
                        )
                        .long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("ignition-command");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("IgnitionCommand")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 2usize] = [
                                        clap::Id::from("target"),
                                        clap::Id::from("command"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("target")
                                .value_name("TARGET")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        u8,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg;
                            let arg = arg.required(false);
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("command")
                                .value_name("COMMAND")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser(ignition_command_from_str)
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help("'power-on', 'power-off', or 'power-reset'");
                            let arg = arg.required(false);
                            arg
                        });
                    __clap_subcommand
                        .about(
                            "Send an ignition command for a single target port (only valid if the SP is an ignition controller)",
                        )
                        .long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("ignition-link-events");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("IgnitionLinkEvents")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 1usize] = [
                                        clap::Id::from("target"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("target")
                                .value_name("TARGET")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser(IgnitionLinkEventsTarget::parse)
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help("integer of a target, or 'all' for all targets");
                            let arg = arg.required(false);
                            arg
                        });
                    __clap_subcommand
                        .about(
                            "Get bulk ignition link events (only valid if the SP is an ignition controller)",
                        )
                        .long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("clear-ignition-link-events");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("ClearIgnitionLinkEvents")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 2usize] = [
                                        clap::Id::from("target"),
                                        clap::Id::from("transceiver_select"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("target")
                                .value_name("TARGET")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser(IgnitionLinkEventsTarget::parse)
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help("integer of a target, or 'all' for all targets");
                            let arg = arg.required(false);
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("transceiver_select")
                                .value_name("TRANSCEIVER_SELECT")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser(IgnitionLinkEventsTransceiverSelect::parse)
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help(
                                    "'controller', 'target-link0', 'target-link1', or 'all'",
                                );
                            let arg = arg.required(false);
                            arg
                        });
                    __clap_subcommand
                        .about(
                            "Clear all ignition link events (only valid if the SP is an ignition controller)",
                        )
                        .long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("component-active-slot");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("ComponentActiveSlot")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 3usize] = [
                                        clap::Id::from("component"),
                                        clap::Id::from("set"),
                                        clap::Id::from("persist"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("component")
                                .value_name("COMPONENT")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser(parse_sp_component)
                                .action(clap::ArgAction::Set);
                            let arg = arg;
                            let arg = arg.required(false);
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("set")
                                .value_name("SET")
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        u16,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .short('s')
                                .long("set")
                                .value_name("SLOT")
                                .help("set the active slot");
                            let arg = arg.required(false);
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("persist")
                                .value_name("PERSIST")
                                .required(true && clap::ArgAction::SetTrue.takes_values())
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        bool,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::SetTrue);
                            let arg = arg
                                .short('p')
                                .long("persist")
                                .requires("set")
                                .help("persist the active slot to non-volatile memory");
                            let arg = arg.required(false);
                            arg
                        });
                    __clap_subcommand
                        .about(
                            "Get or set the active slot of a component (e.g., `host-boot-flash`)",
                        )
                        .long_about(
                            "Get or set the active slot of a component (e.g., `host-boot-flash`).\n\nExcept for component \"stage0\", setting the active slot can be viewed as an atomic operation.\n\nSetting \"stage0\" slot 1 as the active slot initiates a copy from slot 1 to slot 0 if the contents of slot 1 still match those seen at last RoT reset and the contents are properly signed.\n\nPower failures during the copy can disable the RoT. Only one stage0 update should be in process in a rack at any time.",
                        )
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("startup-options");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("StartupOptions")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 1usize] = [
                                        clap::Id::from("options"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("options")
                                .value_name("OPTIONS")
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        u64,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg;
                            let arg = arg.required(false);
                            arg
                        });
                    __clap_subcommand
                        .about("Get or set startup options on an SP")
                        .long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("inventory");
                let __clap_subcommand = __clap_subcommand;
                let __clap_subcommand = __clap_subcommand;
                __clap_subcommand.about("Ask SP for its inventory").long_about(None)
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("component-details");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("ComponentDetails")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 1usize] = [
                                        clap::Id::from("component"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("component")
                                .value_name("COMPONENT")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser(parse_sp_component)
                                .action(clap::ArgAction::Set);
                            let arg = arg;
                            let arg = arg.required(false);
                            arg
                        });
                    __clap_subcommand
                        .about("Ask SP for details of a component")
                        .long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("component-clear-status");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("ComponentClearStatus")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 1usize] = [
                                        clap::Id::from("component"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("component")
                                .value_name("COMPONENT")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser(parse_sp_component)
                                .action(clap::ArgAction::Set);
                            let arg = arg;
                            let arg = arg.required(false);
                            arg
                        });
                    __clap_subcommand
                        .about(
                            "Ask SP to clear the state (e.g., reset counters) on a component",
                        )
                        .long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("usart-attach");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("UsartAttach")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 5usize] = [
                                        clap::Id::from("raw"),
                                        clap::Id::from("stdin_buffer_time_millis"),
                                        clap::Id::from("imap"),
                                        clap::Id::from("omap"),
                                        clap::Id::from("uart_logfile"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("raw")
                                .value_name("RAW")
                                .required(true && clap::ArgAction::SetFalse.takes_values())
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        bool,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::SetFalse);
                            let arg = arg
                                .help("Put the local terminal in raw mode")
                                .long_help(None)
                                .long("no-raw")
                                .help("do not put terminal in raw mode");
                            let arg = arg.required(false);
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("stdin_buffer_time_millis")
                                .value_name("STDIN_BUFFER_TIME_MILLIS")
                                .required(false && clap::ArgAction::Set.takes_values())
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        u64,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help(
                                    "Amount of time to buffer input from stdin before forwarding to SP",
                                )
                                .long_help(None)
                                .long("stdin-buffer-time-millis")
                                .default_value("500");
                            let arg = arg.required(false);
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("imap")
                                .value_name("IMAP")
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        String,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help(
                                    "Specifies the input character map (i.e., special characters to be replaced when reading from the serial port). See picocom's manpage",
                                )
                                .long_help(None)
                                .long("imap");
                            let arg = arg.required(false);
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("omap")
                                .value_name("OMAP")
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        String,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help(
                                    "Specifies the output character map (i.e., special characters to be replaced when writing to the serial port). See picocom's manpage",
                                )
                                .long_help(None)
                                .long("omap");
                            let arg = arg.required(false);
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("uart_logfile")
                                .value_name("UART_LOGFILE")
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        PathBuf,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help(
                                    "Record all input read from the serial port to this logfile (before any remapping)",
                                )
                                .long_help(None)
                                .long("uart-logfile");
                            let arg = arg.required(false);
                            arg
                        });
                    __clap_subcommand.about("Attach to the SP's USART").long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("usart-detach");
                let __clap_subcommand = __clap_subcommand;
                let __clap_subcommand = __clap_subcommand;
                __clap_subcommand
                    .about("Detach any other attached USART connection")
                    .long_about(None)
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("serve-host-phase2");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("ServeHostPhase2")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 1usize] = [
                                        clap::Id::from("directory"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("directory")
                                .value_name("DIRECTORY")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        PathBuf,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg;
                            let arg = arg.required(false);
                            arg
                        });
                    __clap_subcommand.about("Serve host phase 2 images").long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("update");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("Update")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 4usize] = [
                                        clap::Id::from("allow_multiple_update"),
                                        clap::Id::from("component"),
                                        clap::Id::from("slot"),
                                        clap::Id::from("image"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("allow_multiple_update")
                                .value_name("ALLOW_MULTIPLE_UPDATE")
                                .required(true && clap::ArgAction::SetTrue.takes_values())
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        bool,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::SetTrue);
                            let arg = arg.long("allow-multiple-update");
                            let arg = arg.required(false);
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("component")
                                .value_name("COMPONENT")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser(parse_sp_component)
                                .action(clap::ArgAction::Set);
                            let arg = arg;
                            let arg = arg.required(false);
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("slot")
                                .value_name("SLOT")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        u16,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg;
                            let arg = arg.required(false);
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("image")
                                .value_name("IMAGE")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        PathBuf,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg;
                            let arg = arg.required(false);
                            arg
                        });
                    __clap_subcommand
                        .about("Upload a new image to the SP or one of its components")
                        .long_about(
                            "Upload a new image to the SP or one of its components.\n\nTo update the SP itself:\n\n1. Use the component name \"sp\" 2. Specify slot 0 (the SP only has a single updateable slot: its alternate bank). 3. Pass the path to a hubris archive as `image`.",
                        )
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("update-status");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("UpdateStatus")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 1usize] = [
                                        clap::Id::from("component"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("component")
                                .value_name("COMPONENT")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser(parse_sp_component)
                                .action(clap::ArgAction::Set);
                            let arg = arg;
                            let arg = arg.required(false);
                            arg
                        });
                    __clap_subcommand
                        .about("Get the status of an update to the specified component")
                        .long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("update-abort");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("UpdateAbort")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 2usize] = [
                                        clap::Id::from("component"),
                                        clap::Id::from("update_id"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("component")
                                .value_name("COMPONENT")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser(parse_sp_component)
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help(
                                    "Component with an update-in-progress to be aborted. Omit to abort updates to the SP itself",
                                )
                                .long_help(None);
                            let arg = arg.required(false);
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("update_id")
                                .value_name("UPDATE_ID")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        Uuid,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help("ID of the update to abort")
                                .long_help(None);
                            let arg = arg.required(false);
                            arg
                        });
                    __clap_subcommand
                        .about("Abort an in-progress update")
                        .long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("power-state");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("PowerState")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 1usize] = [
                                        clap::Id::from("new_power_state"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("new_power_state")
                                .value_name("NEW_POWER_STATE")
                                .value_parser(power_state_from_str)
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help(
                                    "If present, instruct the SP to set this power state. If not present, get the current power state instead",
                                )
                                .long_help(None);
                            let arg = arg.required(false);
                            arg
                        });
                    __clap_subcommand
                        .about("Get or set the power state")
                        .long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("send-host-nmi");
                let __clap_subcommand = __clap_subcommand;
                let __clap_subcommand = __clap_subcommand;
                __clap_subcommand
                    .about("Sends an NMI to the host (SP3) CPU by toggling a GPIO")
                    .long_about(None)
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("set-ipcc-key-value");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("SetIpccKeyValue")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 2usize] = [
                                        clap::Id::from("key"),
                                        clap::Id::from("value_path"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("key")
                                .value_name("KEY")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        u8,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg;
                            let arg = arg.required(false);
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("value_path")
                                .value_name("VALUE_PATH")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        PathBuf,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help("Path to a file containing the value")
                                .long_help(None);
                            let arg = arg.required(false);
                            arg
                        });
                    __clap_subcommand.about("Set an IPCC key/value").long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("read-caboose");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("ReadCaboose")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 1usize] = [clap::Id::from("key")];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("key")
                                .value_name("KEY")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser(parse_tlvc_key)
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help("4-character ASCII string")
                                .long_help(None);
                            let arg = arg.required(false);
                            arg
                        });
                    __clap_subcommand
                        .about("Read a single key from the caboose")
                        .long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("read-component-caboose");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("ReadComponentCaboose")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 3usize] = [
                                        clap::Id::from("component"),
                                        clap::Id::from("slot"),
                                        clap::Id::from("key"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("component")
                                .value_name("COMPONENT")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser(parse_sp_component)
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help("Component from which to read; must be `sp` or `rot`")
                                .long_help(None)
                                .short('c')
                                .long("component");
                            let arg = arg.required(false);
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("slot")
                                .value_name("SLOT")
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        String,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help("Target slot from which to read the caboose")
                                .long_help(
                                    "Target slot from which to read the caboose.\n\nThe SP accepts `active` or `inactive`; the RoT accepts `A` or `B`",
                                )
                                .short('s')
                                .long("slot");
                            let arg = arg.required(false);
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("key")
                                .value_name("KEY")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser(parse_tlvc_key)
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help("4-character ASCII string")
                                .long_help(None);
                            let arg = arg.required(false);
                            arg
                        });
                    __clap_subcommand
                        .about("Read a single key from the caboose")
                        .long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("reset");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("Reset")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 1usize] = [
                                        clap::Id::from("disable_watchdog"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("disable_watchdog")
                                .value_name("DISABLE_WATCHDOG")
                                .required(true && clap::ArgAction::SetTrue.takes_values())
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        bool,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::SetTrue);
                            let arg = arg
                                .help(
                                    "Reset without the automatic safety rollback watchdog",
                                )
                                .long_help(None)
                                .long("disable-watchdog");
                            let arg = arg.required(false);
                            arg
                        });
                    __clap_subcommand.about("Instruct the SP to reset").long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("reset-component");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("ResetComponent")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 2usize] = [
                                        clap::Id::from("component"),
                                        clap::Id::from("disable_watchdog"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("component")
                                .value_name("COMPONENT")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser(parse_sp_component)
                                .action(clap::ArgAction::Set);
                            let arg = arg;
                            let arg = arg.required(false);
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("disable_watchdog")
                                .value_name("DISABLE_WATCHDOG")
                                .required(true && clap::ArgAction::SetTrue.takes_values())
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        bool,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::SetTrue);
                            let arg = arg
                                .help(
                                    "Reset without the automatic safety rollback watchdog (if applicable)",
                                )
                                .long_help(None)
                                .long("disable-watchdog");
                            let arg = arg.required(false);
                            arg
                        });
                    __clap_subcommand
                        .about("Reset a component")
                        .long_about(
                            "Reset a component.\n\nThis command is implemented for the component \"rot\" but may be expanded to other components in the future.",
                        )
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("system-led");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("SystemLed")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 0usize] = [];
                                    members
                                }),
                        );
                    let __clap_subcommand = <LedCommand as clap::Subcommand>::augment_subcommands(
                        __clap_subcommand,
                    );
                    let __clap_subcommand = __clap_subcommand
                        .subcommand_required(true)
                        .arg_required_else_help(true)
                        .subcommand_required(false)
                        .arg_required_else_help(false);
                    __clap_subcommand.about("Controls the system LED").long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("read-sensor-value");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("ReadSensorValue")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 1usize] = [clap::Id::from("id")];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("id")
                                .value_name("ID")
                                .required(true && clap::ArgAction::Set.takes_values())
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        u32,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg.help("Sensor ID").long_help(None);
                            let arg = arg.required(false);
                            arg
                        });
                    __clap_subcommand
                        .about("Reads a single sensor by `SensorId`, returning a `f32`")
                        .long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("read-cmpa");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("ReadCmpa")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 1usize] = [clap::Id::from("out")];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("out")
                                .value_name("OUT")
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        PathBuf,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help(
                                    "Output file (by default, pretty-printed to `stdout`)",
                                )
                                .long_help(None)
                                .short('o')
                                .long("out");
                            let arg = arg.required(false);
                            arg
                        });
                    __clap_subcommand
                        .about("Reads the CMPA from an attached Root of Trust")
                        .long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("read-cfpa");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("ReadCfpa")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 2usize] = [
                                        clap::Id::from("out"),
                                        clap::Id::from("slot"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("out")
                                .value_name("OUT")
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        PathBuf,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help(
                                    "Output file (by default, pretty-printed to `stdout`)",
                                )
                                .long_help(None)
                                .short('o')
                                .long("out");
                            let arg = arg.required(false);
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("slot")
                                .value_name("SLOT")
                                .required(false && clap::ArgAction::Set.takes_values())
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        CfpaSlot,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .short('s')
                                .long("slot")
                                .default_value({
                                    static DEFAULT_VALUE: ::std::sync::OnceLock<String> = ::std::sync::OnceLock::new();
                                    let s = DEFAULT_VALUE
                                        .get_or_init(|| {
                                            let val: CfpaSlot = CfpaSlot::Active;
                                            ::std::string::ToString::to_string(&val)
                                        });
                                    let s: &'static str = &*s;
                                    s
                                });
                            let arg = arg.required(false);
                            arg
                        });
                    __clap_subcommand
                        .about("Reads a CFPA slot from an attached Root of Trust")
                        .long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("vpd-lock-status");
                let __clap_subcommand = __clap_subcommand;
                let __clap_subcommand = __clap_subcommand;
                __clap_subcommand
                    .about("Reads the lock status of any VPD in the system")
                    .long_about(None)
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("rot-boot-info");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("RotBootInfo")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 1usize] = [
                                        clap::Id::from("version"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("version")
                                .value_name("VERSION")
                                .required(false && clap::ArgAction::Set.takes_values())
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        u8,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help(
                                    "Return highest version of RotBootInfo less then or equal to our highest known version",
                                )
                                .long_help(None)
                                .long("version")
                                .short('v')
                                .default_value({
                                    static DEFAULT_VALUE: ::std::sync::OnceLock<String> = ::std::sync::OnceLock::new();
                                    let s = DEFAULT_VALUE
                                        .get_or_init(|| {
                                            let val: u8 = RotBootInfo::HIGHEST_KNOWN_VERSION;
                                            ::std::string::ToString::to_string(&val)
                                        });
                                    let s: &'static str = &*s;
                                    s
                                });
                            let arg = arg.required(false);
                            arg
                        });
                    __clap_subcommand
                        .about("Read the RoT's boot-time information")
                        .long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("monorail");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("Monorail")
                                .multiple(true)
                                .args({
                                    let members: [clap::Id; 0usize] = [];
                                    members
                                }),
                        );
                    let __clap_subcommand = <MonorailCommand as clap::Subcommand>::augment_subcommands(
                        __clap_subcommand,
                    );
                    let __clap_subcommand = __clap_subcommand
                        .subcommand_required(true)
                        .arg_required_else_help(true)
                        .subcommand_required(false)
                        .arg_required_else_help(false);
                    __clap_subcommand
                        .about("Control the management network switch")
                        .long_about(None)
                }
            });
        __clap_app
    }
    fn has_subcommand(__clap_name: &str) -> bool {
        if "discover" == __clap_name {
            return true;
        }
        if "state" == __clap_name {
            return true;
        }
        if "ignition" == __clap_name {
            return true;
        }
        if "ignition-command" == __clap_name {
            return true;
        }
        if "ignition-link-events" == __clap_name {
            return true;
        }
        if "clear-ignition-link-events" == __clap_name {
            return true;
        }
        if "component-active-slot" == __clap_name {
            return true;
        }
        if "startup-options" == __clap_name {
            return true;
        }
        if "inventory" == __clap_name {
            return true;
        }
        if "component-details" == __clap_name {
            return true;
        }
        if "component-clear-status" == __clap_name {
            return true;
        }
        if "usart-attach" == __clap_name {
            return true;
        }
        if "usart-detach" == __clap_name {
            return true;
        }
        if "serve-host-phase2" == __clap_name {
            return true;
        }
        if "update" == __clap_name {
            return true;
        }
        if "update-status" == __clap_name {
            return true;
        }
        if "update-abort" == __clap_name {
            return true;
        }
        if "power-state" == __clap_name {
            return true;
        }
        if "send-host-nmi" == __clap_name {
            return true;
        }
        if "set-ipcc-key-value" == __clap_name {
            return true;
        }
        if "read-caboose" == __clap_name {
            return true;
        }
        if "read-component-caboose" == __clap_name {
            return true;
        }
        if "reset" == __clap_name {
            return true;
        }
        if "reset-component" == __clap_name {
            return true;
        }
        if "system-led" == __clap_name {
            return true;
        }
        if "read-sensor-value" == __clap_name {
            return true;
        }
        if "read-cmpa" == __clap_name {
            return true;
        }
        if "read-cfpa" == __clap_name {
            return true;
        }
        if "vpd-lock-status" == __clap_name {
            return true;
        }
        if "rot-boot-info" == __clap_name {
            return true;
        }
        if "monorail" == __clap_name {
            return true;
        }
        false
    }
}
#[automatically_derived]
impl ::core::fmt::Debug for Command {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        match self {
            Command::Discover => ::core::fmt::Formatter::write_str(f, "Discover"),
            Command::State => ::core::fmt::Formatter::write_str(f, "State"),
            Command::Ignition { target: __self_0 } => {
                ::core::fmt::Formatter::debug_struct_field1_finish(
                    f,
                    "Ignition",
                    "target",
                    &__self_0,
                )
            }
            Command::IgnitionCommand { target: __self_0, command: __self_1 } => {
                ::core::fmt::Formatter::debug_struct_field2_finish(
                    f,
                    "IgnitionCommand",
                    "target",
                    __self_0,
                    "command",
                    &__self_1,
                )
            }
            Command::IgnitionLinkEvents { target: __self_0 } => {
                ::core::fmt::Formatter::debug_struct_field1_finish(
                    f,
                    "IgnitionLinkEvents",
                    "target",
                    &__self_0,
                )
            }
            Command::ClearIgnitionLinkEvents {
                target: __self_0,
                transceiver_select: __self_1,
            } => {
                ::core::fmt::Formatter::debug_struct_field2_finish(
                    f,
                    "ClearIgnitionLinkEvents",
                    "target",
                    __self_0,
                    "transceiver_select",
                    &__self_1,
                )
            }
            Command::ComponentActiveSlot {
                component: __self_0,
                set: __self_1,
                persist: __self_2,
            } => {
                ::core::fmt::Formatter::debug_struct_field3_finish(
                    f,
                    "ComponentActiveSlot",
                    "component",
                    __self_0,
                    "set",
                    __self_1,
                    "persist",
                    &__self_2,
                )
            }
            Command::StartupOptions { options: __self_0 } => {
                ::core::fmt::Formatter::debug_struct_field1_finish(
                    f,
                    "StartupOptions",
                    "options",
                    &__self_0,
                )
            }
            Command::Inventory => ::core::fmt::Formatter::write_str(f, "Inventory"),
            Command::ComponentDetails { component: __self_0 } => {
                ::core::fmt::Formatter::debug_struct_field1_finish(
                    f,
                    "ComponentDetails",
                    "component",
                    &__self_0,
                )
            }
            Command::ComponentClearStatus { component: __self_0 } => {
                ::core::fmt::Formatter::debug_struct_field1_finish(
                    f,
                    "ComponentClearStatus",
                    "component",
                    &__self_0,
                )
            }
            Command::UsartAttach {
                raw: __self_0,
                stdin_buffer_time_millis: __self_1,
                imap: __self_2,
                omap: __self_3,
                uart_logfile: __self_4,
            } => {
                ::core::fmt::Formatter::debug_struct_field5_finish(
                    f,
                    "UsartAttach",
                    "raw",
                    __self_0,
                    "stdin_buffer_time_millis",
                    __self_1,
                    "imap",
                    __self_2,
                    "omap",
                    __self_3,
                    "uart_logfile",
                    &__self_4,
                )
            }
            Command::UsartDetach => ::core::fmt::Formatter::write_str(f, "UsartDetach"),
            Command::ServeHostPhase2 { directory: __self_0 } => {
                ::core::fmt::Formatter::debug_struct_field1_finish(
                    f,
                    "ServeHostPhase2",
                    "directory",
                    &__self_0,
                )
            }
            Command::Update {
                allow_multiple_update: __self_0,
                component: __self_1,
                slot: __self_2,
                image: __self_3,
            } => {
                ::core::fmt::Formatter::debug_struct_field4_finish(
                    f,
                    "Update",
                    "allow_multiple_update",
                    __self_0,
                    "component",
                    __self_1,
                    "slot",
                    __self_2,
                    "image",
                    &__self_3,
                )
            }
            Command::UpdateStatus { component: __self_0 } => {
                ::core::fmt::Formatter::debug_struct_field1_finish(
                    f,
                    "UpdateStatus",
                    "component",
                    &__self_0,
                )
            }
            Command::UpdateAbort { component: __self_0, update_id: __self_1 } => {
                ::core::fmt::Formatter::debug_struct_field2_finish(
                    f,
                    "UpdateAbort",
                    "component",
                    __self_0,
                    "update_id",
                    &__self_1,
                )
            }
            Command::PowerState { new_power_state: __self_0 } => {
                ::core::fmt::Formatter::debug_struct_field1_finish(
                    f,
                    "PowerState",
                    "new_power_state",
                    &__self_0,
                )
            }
            Command::SendHostNmi => ::core::fmt::Formatter::write_str(f, "SendHostNmi"),
            Command::SetIpccKeyValue { key: __self_0, value_path: __self_1 } => {
                ::core::fmt::Formatter::debug_struct_field2_finish(
                    f,
                    "SetIpccKeyValue",
                    "key",
                    __self_0,
                    "value_path",
                    &__self_1,
                )
            }
            Command::ReadCaboose { key: __self_0 } => {
                ::core::fmt::Formatter::debug_struct_field1_finish(
                    f,
                    "ReadCaboose",
                    "key",
                    &__self_0,
                )
            }
            Command::ReadComponentCaboose {
                component: __self_0,
                slot: __self_1,
                key: __self_2,
            } => {
                ::core::fmt::Formatter::debug_struct_field3_finish(
                    f,
                    "ReadComponentCaboose",
                    "component",
                    __self_0,
                    "slot",
                    __self_1,
                    "key",
                    &__self_2,
                )
            }
            Command::Reset { disable_watchdog: __self_0 } => {
                ::core::fmt::Formatter::debug_struct_field1_finish(
                    f,
                    "Reset",
                    "disable_watchdog",
                    &__self_0,
                )
            }
            Command::ResetComponent {
                component: __self_0,
                disable_watchdog: __self_1,
            } => {
                ::core::fmt::Formatter::debug_struct_field2_finish(
                    f,
                    "ResetComponent",
                    "component",
                    __self_0,
                    "disable_watchdog",
                    &__self_1,
                )
            }
            Command::SystemLed { cmd: __self_0 } => {
                ::core::fmt::Formatter::debug_struct_field1_finish(
                    f,
                    "SystemLed",
                    "cmd",
                    &__self_0,
                )
            }
            Command::ReadSensorValue { id: __self_0 } => {
                ::core::fmt::Formatter::debug_struct_field1_finish(
                    f,
                    "ReadSensorValue",
                    "id",
                    &__self_0,
                )
            }
            Command::ReadCmpa { out: __self_0 } => {
                ::core::fmt::Formatter::debug_struct_field1_finish(
                    f,
                    "ReadCmpa",
                    "out",
                    &__self_0,
                )
            }
            Command::ReadCfpa { out: __self_0, slot: __self_1 } => {
                ::core::fmt::Formatter::debug_struct_field2_finish(
                    f,
                    "ReadCfpa",
                    "out",
                    __self_0,
                    "slot",
                    &__self_1,
                )
            }
            Command::VpdLockStatus => {
                ::core::fmt::Formatter::write_str(f, "VpdLockStatus")
            }
            Command::RotBootInfo { version: __self_0 } => {
                ::core::fmt::Formatter::debug_struct_field1_finish(
                    f,
                    "RotBootInfo",
                    "version",
                    &__self_0,
                )
            }
            Command::Monorail { cmd: __self_0 } => {
                ::core::fmt::Formatter::debug_struct_field1_finish(
                    f,
                    "Monorail",
                    "cmd",
                    &__self_0,
                )
            }
        }
    }
}
#[automatically_derived]
impl ::core::clone::Clone for Command {
    #[inline]
    fn clone(&self) -> Command {
        match self {
            Command::Discover => Command::Discover,
            Command::State => Command::State,
            Command::Ignition { target: __self_0 } => {
                Command::Ignition {
                    target: ::core::clone::Clone::clone(__self_0),
                }
            }
            Command::IgnitionCommand { target: __self_0, command: __self_1 } => {
                Command::IgnitionCommand {
                    target: ::core::clone::Clone::clone(__self_0),
                    command: ::core::clone::Clone::clone(__self_1),
                }
            }
            Command::IgnitionLinkEvents { target: __self_0 } => {
                Command::IgnitionLinkEvents {
                    target: ::core::clone::Clone::clone(__self_0),
                }
            }
            Command::ClearIgnitionLinkEvents {
                target: __self_0,
                transceiver_select: __self_1,
            } => {
                Command::ClearIgnitionLinkEvents {
                    target: ::core::clone::Clone::clone(__self_0),
                    transceiver_select: ::core::clone::Clone::clone(__self_1),
                }
            }
            Command::ComponentActiveSlot {
                component: __self_0,
                set: __self_1,
                persist: __self_2,
            } => {
                Command::ComponentActiveSlot {
                    component: ::core::clone::Clone::clone(__self_0),
                    set: ::core::clone::Clone::clone(__self_1),
                    persist: ::core::clone::Clone::clone(__self_2),
                }
            }
            Command::StartupOptions { options: __self_0 } => {
                Command::StartupOptions {
                    options: ::core::clone::Clone::clone(__self_0),
                }
            }
            Command::Inventory => Command::Inventory,
            Command::ComponentDetails { component: __self_0 } => {
                Command::ComponentDetails {
                    component: ::core::clone::Clone::clone(__self_0),
                }
            }
            Command::ComponentClearStatus { component: __self_0 } => {
                Command::ComponentClearStatus {
                    component: ::core::clone::Clone::clone(__self_0),
                }
            }
            Command::UsartAttach {
                raw: __self_0,
                stdin_buffer_time_millis: __self_1,
                imap: __self_2,
                omap: __self_3,
                uart_logfile: __self_4,
            } => {
                Command::UsartAttach {
                    raw: ::core::clone::Clone::clone(__self_0),
                    stdin_buffer_time_millis: ::core::clone::Clone::clone(__self_1),
                    imap: ::core::clone::Clone::clone(__self_2),
                    omap: ::core::clone::Clone::clone(__self_3),
                    uart_logfile: ::core::clone::Clone::clone(__self_4),
                }
            }
            Command::UsartDetach => Command::UsartDetach,
            Command::ServeHostPhase2 { directory: __self_0 } => {
                Command::ServeHostPhase2 {
                    directory: ::core::clone::Clone::clone(__self_0),
                }
            }
            Command::Update {
                allow_multiple_update: __self_0,
                component: __self_1,
                slot: __self_2,
                image: __self_3,
            } => {
                Command::Update {
                    allow_multiple_update: ::core::clone::Clone::clone(__self_0),
                    component: ::core::clone::Clone::clone(__self_1),
                    slot: ::core::clone::Clone::clone(__self_2),
                    image: ::core::clone::Clone::clone(__self_3),
                }
            }
            Command::UpdateStatus { component: __self_0 } => {
                Command::UpdateStatus {
                    component: ::core::clone::Clone::clone(__self_0),
                }
            }
            Command::UpdateAbort { component: __self_0, update_id: __self_1 } => {
                Command::UpdateAbort {
                    component: ::core::clone::Clone::clone(__self_0),
                    update_id: ::core::clone::Clone::clone(__self_1),
                }
            }
            Command::PowerState { new_power_state: __self_0 } => {
                Command::PowerState {
                    new_power_state: ::core::clone::Clone::clone(__self_0),
                }
            }
            Command::SendHostNmi => Command::SendHostNmi,
            Command::SetIpccKeyValue { key: __self_0, value_path: __self_1 } => {
                Command::SetIpccKeyValue {
                    key: ::core::clone::Clone::clone(__self_0),
                    value_path: ::core::clone::Clone::clone(__self_1),
                }
            }
            Command::ReadCaboose { key: __self_0 } => {
                Command::ReadCaboose {
                    key: ::core::clone::Clone::clone(__self_0),
                }
            }
            Command::ReadComponentCaboose {
                component: __self_0,
                slot: __self_1,
                key: __self_2,
            } => {
                Command::ReadComponentCaboose {
                    component: ::core::clone::Clone::clone(__self_0),
                    slot: ::core::clone::Clone::clone(__self_1),
                    key: ::core::clone::Clone::clone(__self_2),
                }
            }
            Command::Reset { disable_watchdog: __self_0 } => {
                Command::Reset {
                    disable_watchdog: ::core::clone::Clone::clone(__self_0),
                }
            }
            Command::ResetComponent {
                component: __self_0,
                disable_watchdog: __self_1,
            } => {
                Command::ResetComponent {
                    component: ::core::clone::Clone::clone(__self_0),
                    disable_watchdog: ::core::clone::Clone::clone(__self_1),
                }
            }
            Command::SystemLed { cmd: __self_0 } => {
                Command::SystemLed {
                    cmd: ::core::clone::Clone::clone(__self_0),
                }
            }
            Command::ReadSensorValue { id: __self_0 } => {
                Command::ReadSensorValue {
                    id: ::core::clone::Clone::clone(__self_0),
                }
            }
            Command::ReadCmpa { out: __self_0 } => {
                Command::ReadCmpa {
                    out: ::core::clone::Clone::clone(__self_0),
                }
            }
            Command::ReadCfpa { out: __self_0, slot: __self_1 } => {
                Command::ReadCfpa {
                    out: ::core::clone::Clone::clone(__self_0),
                    slot: ::core::clone::Clone::clone(__self_1),
                }
            }
            Command::VpdLockStatus => Command::VpdLockStatus,
            Command::RotBootInfo { version: __self_0 } => {
                Command::RotBootInfo {
                    version: ::core::clone::Clone::clone(__self_0),
                }
            }
            Command::Monorail { cmd: __self_0 } => {
                Command::Monorail {
                    cmd: ::core::clone::Clone::clone(__self_0),
                }
            }
        }
    }
}
enum LedCommand {
    /// Turns the LED on
    On,
    /// Turns the LED off
    Off,
    /// Enables blinking
    Blink,
}
#[allow(
    dead_code,
    unreachable_code,
    unused_variables,
    unused_braces,
    unused_qualifications,
)]
#[allow(
    clippy::style,
    clippy::complexity,
    clippy::pedantic,
    clippy::restriction,
    clippy::perf,
    clippy::deprecated,
    clippy::nursery,
    clippy::cargo,
    clippy::suspicious_else_formatting,
    clippy::almost_swapped,
    clippy::redundant_locals,
)]
#[automatically_derived]
impl clap::FromArgMatches for LedCommand {
    fn from_arg_matches(
        __clap_arg_matches: &clap::ArgMatches,
    ) -> ::std::result::Result<Self, clap::Error> {
        Self::from_arg_matches_mut(&mut __clap_arg_matches.clone())
    }
    fn from_arg_matches_mut(
        __clap_arg_matches: &mut clap::ArgMatches,
    ) -> ::std::result::Result<Self, clap::Error> {
        #![allow(deprecated)]
        if let Some((__clap_name, mut __clap_arg_sub_matches)) = __clap_arg_matches
            .remove_subcommand()
        {
            let __clap_arg_matches = &mut __clap_arg_sub_matches;
            if __clap_name == "on" && !__clap_arg_matches.contains_id("") {
                return ::std::result::Result::Ok(Self::On);
            }
            if __clap_name == "off" && !__clap_arg_matches.contains_id("") {
                return ::std::result::Result::Ok(Self::Off);
            }
            if __clap_name == "blink" && !__clap_arg_matches.contains_id("") {
                return ::std::result::Result::Ok(Self::Blink);
            }
            ::std::result::Result::Err(
                clap::Error::raw(
                    clap::error::ErrorKind::InvalidSubcommand,
                    {
                        let res = ::alloc::fmt::format(
                            format_args!(
                                "The subcommand \'{0}\' wasn\'t recognized",
                                __clap_name,
                            ),
                        );
                        res
                    },
                ),
            )
        } else {
            ::std::result::Result::Err(
                clap::Error::raw(
                    clap::error::ErrorKind::MissingSubcommand,
                    "A subcommand is required but one was not provided.",
                ),
            )
        }
    }
    fn update_from_arg_matches(
        &mut self,
        __clap_arg_matches: &clap::ArgMatches,
    ) -> ::std::result::Result<(), clap::Error> {
        self.update_from_arg_matches_mut(&mut __clap_arg_matches.clone())
    }
    fn update_from_arg_matches_mut<'b>(
        &mut self,
        __clap_arg_matches: &mut clap::ArgMatches,
    ) -> ::std::result::Result<(), clap::Error> {
        #![allow(deprecated)]
        if let Some(__clap_name) = __clap_arg_matches.subcommand_name() {
            match self {
                Self::On if "on" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {}
                }
                Self::Off if "off" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {}
                }
                Self::Blink if "blink" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {}
                }
                s => {
                    *s = <Self as clap::FromArgMatches>::from_arg_matches_mut(
                        __clap_arg_matches,
                    )?;
                }
            }
        }
        ::std::result::Result::Ok(())
    }
}
#[allow(
    dead_code,
    unreachable_code,
    unused_variables,
    unused_braces,
    unused_qualifications,
)]
#[allow(
    clippy::style,
    clippy::complexity,
    clippy::pedantic,
    clippy::restriction,
    clippy::perf,
    clippy::deprecated,
    clippy::nursery,
    clippy::cargo,
    clippy::suspicious_else_formatting,
    clippy::almost_swapped,
    clippy::redundant_locals,
)]
#[automatically_derived]
impl clap::Subcommand for LedCommand {
    fn augment_subcommands<'b>(__clap_app: clap::Command) -> clap::Command {
        let __clap_app = __clap_app;
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("on");
                let __clap_subcommand = __clap_subcommand;
                let __clap_subcommand = __clap_subcommand;
                __clap_subcommand.about("Turns the LED on").long_about(None)
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("off");
                let __clap_subcommand = __clap_subcommand;
                let __clap_subcommand = __clap_subcommand;
                __clap_subcommand.about("Turns the LED off").long_about(None)
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("blink");
                let __clap_subcommand = __clap_subcommand;
                let __clap_subcommand = __clap_subcommand;
                __clap_subcommand.about("Enables blinking").long_about(None)
            });
        __clap_app
    }
    fn augment_subcommands_for_update<'b>(__clap_app: clap::Command) -> clap::Command {
        let __clap_app = __clap_app;
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("on");
                let __clap_subcommand = __clap_subcommand;
                let __clap_subcommand = __clap_subcommand;
                __clap_subcommand.about("Turns the LED on").long_about(None)
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("off");
                let __clap_subcommand = __clap_subcommand;
                let __clap_subcommand = __clap_subcommand;
                __clap_subcommand.about("Turns the LED off").long_about(None)
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("blink");
                let __clap_subcommand = __clap_subcommand;
                let __clap_subcommand = __clap_subcommand;
                __clap_subcommand.about("Enables blinking").long_about(None)
            });
        __clap_app
    }
    fn has_subcommand(__clap_name: &str) -> bool {
        if "on" == __clap_name {
            return true;
        }
        if "off" == __clap_name {
            return true;
        }
        if "blink" == __clap_name {
            return true;
        }
        false
    }
}
#[automatically_derived]
impl ::core::fmt::Debug for LedCommand {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        ::core::fmt::Formatter::write_str(
            f,
            match self {
                LedCommand::On => "On",
                LedCommand::Off => "Off",
                LedCommand::Blink => "Blink",
            },
        )
    }
}
#[automatically_derived]
impl ::core::clone::Clone for LedCommand {
    #[inline]
    fn clone(&self) -> LedCommand {
        match self {
            LedCommand::On => LedCommand::On,
            LedCommand::Off => LedCommand::Off,
            LedCommand::Blink => LedCommand::Blink,
        }
    }
}
enum MonorailCommand {
    /// Unlock the technician port, allowing access to other SPs
    #[group(id = "unlock", required = true, multiple = false)]
    Unlock {
        /// How long to unlock for
        #[clap(short, long, group = "unlock")]
        time: Option<humantime::Duration>,
        /// Public key for SSH signing challenge
        ///
        /// This is either a path to a public key (ending in `.pub`), or a
        /// substring to match against known keys (which can be printed with
        /// `faux-mgs monorail unlock --list`).
        #[clap(short, long, conflicts_with = "list")]
        key: Option<String>,
        /// List available keys
        #[clap(short, long, group = "unlock")]
        list: bool,
    },
    /// Lock the technician port
    Lock,
}
#[allow(
    dead_code,
    unreachable_code,
    unused_variables,
    unused_braces,
    unused_qualifications,
)]
#[allow(
    clippy::style,
    clippy::complexity,
    clippy::pedantic,
    clippy::restriction,
    clippy::perf,
    clippy::deprecated,
    clippy::nursery,
    clippy::cargo,
    clippy::suspicious_else_formatting,
    clippy::almost_swapped,
    clippy::redundant_locals,
)]
#[automatically_derived]
impl clap::FromArgMatches for MonorailCommand {
    fn from_arg_matches(
        __clap_arg_matches: &clap::ArgMatches,
    ) -> ::std::result::Result<Self, clap::Error> {
        Self::from_arg_matches_mut(&mut __clap_arg_matches.clone())
    }
    fn from_arg_matches_mut(
        __clap_arg_matches: &mut clap::ArgMatches,
    ) -> ::std::result::Result<Self, clap::Error> {
        #![allow(deprecated)]
        if let Some((__clap_name, mut __clap_arg_sub_matches)) = __clap_arg_matches
            .remove_subcommand()
        {
            let __clap_arg_matches = &mut __clap_arg_sub_matches;
            if __clap_name == "unlock" && !__clap_arg_matches.contains_id("") {
                return ::std::result::Result::Ok(Self::Unlock {
                    time: __clap_arg_matches.remove_one::<humantime::Duration>("time"),
                    key: __clap_arg_matches.remove_one::<String>("key"),
                    list: __clap_arg_matches
                        .remove_one::<bool>("list")
                        .ok_or_else(|| clap::Error::raw(
                            clap::error::ErrorKind::MissingRequiredArgument,
                            "The following required argument was not provided: list",
                        ))?,
                });
            }
            if __clap_name == "lock" && !__clap_arg_matches.contains_id("") {
                return ::std::result::Result::Ok(Self::Lock);
            }
            ::std::result::Result::Err(
                clap::Error::raw(
                    clap::error::ErrorKind::InvalidSubcommand,
                    {
                        let res = ::alloc::fmt::format(
                            format_args!(
                                "The subcommand \'{0}\' wasn\'t recognized",
                                __clap_name,
                            ),
                        );
                        res
                    },
                ),
            )
        } else {
            ::std::result::Result::Err(
                clap::Error::raw(
                    clap::error::ErrorKind::MissingSubcommand,
                    "A subcommand is required but one was not provided.",
                ),
            )
        }
    }
    fn update_from_arg_matches(
        &mut self,
        __clap_arg_matches: &clap::ArgMatches,
    ) -> ::std::result::Result<(), clap::Error> {
        self.update_from_arg_matches_mut(&mut __clap_arg_matches.clone())
    }
    fn update_from_arg_matches_mut<'b>(
        &mut self,
        __clap_arg_matches: &mut clap::ArgMatches,
    ) -> ::std::result::Result<(), clap::Error> {
        #![allow(deprecated)]
        if let Some(__clap_name) = __clap_arg_matches.subcommand_name() {
            match self {
                Self::Unlock { time, key, list } if "unlock" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {
                        if __clap_arg_matches.contains_id("time") {
                            *time = __clap_arg_matches
                                .remove_one::<humantime::Duration>("time");
                        }
                        if __clap_arg_matches.contains_id("key") {
                            *key = __clap_arg_matches.remove_one::<String>("key");
                        }
                        if __clap_arg_matches.contains_id("list") {
                            *list = __clap_arg_matches
                                .remove_one::<bool>("list")
                                .ok_or_else(|| clap::Error::raw(
                                    clap::error::ErrorKind::MissingRequiredArgument,
                                    "The following required argument was not provided: list",
                                ))?;
                        }
                    }
                }
                Self::Lock if "lock" == __clap_name => {
                    let (_, mut __clap_arg_sub_matches) = __clap_arg_matches
                        .remove_subcommand()
                        .unwrap();
                    let __clap_arg_matches = &mut __clap_arg_sub_matches;
                    {}
                }
                s => {
                    *s = <Self as clap::FromArgMatches>::from_arg_matches_mut(
                        __clap_arg_matches,
                    )?;
                }
            }
        }
        ::std::result::Result::Ok(())
    }
}
#[allow(
    dead_code,
    unreachable_code,
    unused_variables,
    unused_braces,
    unused_qualifications,
)]
#[allow(
    clippy::style,
    clippy::complexity,
    clippy::pedantic,
    clippy::restriction,
    clippy::perf,
    clippy::deprecated,
    clippy::nursery,
    clippy::cargo,
    clippy::suspicious_else_formatting,
    clippy::almost_swapped,
    clippy::redundant_locals,
)]
#[automatically_derived]
impl clap::Subcommand for MonorailCommand {
    fn augment_subcommands<'b>(__clap_app: clap::Command) -> clap::Command {
        let __clap_app = __clap_app;
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("unlock");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("unlock")
                                .multiple(true)
                                .required(true)
                                .multiple(false)
                                .args({
                                    let members: [clap::Id; 3usize] = [
                                        clap::Id::from("time"),
                                        clap::Id::from("key"),
                                        clap::Id::from("list"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("time")
                                .value_name("TIME")
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        humantime::Duration,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help("How long to unlock for")
                                .long_help(None)
                                .short('t')
                                .long("time")
                                .group("unlock");
                            let arg = arg;
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("key")
                                .value_name("KEY")
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        String,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help("Public key for SSH signing challenge")
                                .long_help(
                                    "Public key for SSH signing challenge\n\nThis is either a path to a public key (ending in `.pub`), or a substring to match against known keys (which can be printed with `faux-mgs monorail unlock --list`).",
                                )
                                .short('k')
                                .long("key")
                                .conflicts_with("list");
                            let arg = arg;
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("list")
                                .value_name("LIST")
                                .required(true && clap::ArgAction::SetTrue.takes_values())
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        bool,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::SetTrue);
                            let arg = arg
                                .help("List available keys")
                                .long_help(None)
                                .short('l')
                                .long("list")
                                .group("unlock");
                            let arg = arg;
                            arg
                        });
                    __clap_subcommand
                        .about(
                            "Unlock the technician port, allowing access to other SPs",
                        )
                        .long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("lock");
                let __clap_subcommand = __clap_subcommand;
                let __clap_subcommand = __clap_subcommand;
                __clap_subcommand.about("Lock the technician port").long_about(None)
            });
        __clap_app
    }
    fn augment_subcommands_for_update<'b>(__clap_app: clap::Command) -> clap::Command {
        let __clap_app = __clap_app;
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("unlock");
                {
                    let __clap_subcommand = __clap_subcommand
                        .group(
                            clap::ArgGroup::new("unlock")
                                .multiple(true)
                                .required(true)
                                .multiple(false)
                                .args({
                                    let members: [clap::Id; 3usize] = [
                                        clap::Id::from("time"),
                                        clap::Id::from("key"),
                                        clap::Id::from("list"),
                                    ];
                                    members
                                }),
                        );
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("time")
                                .value_name("TIME")
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        humantime::Duration,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help("How long to unlock for")
                                .long_help(None)
                                .short('t')
                                .long("time")
                                .group("unlock");
                            let arg = arg.required(false);
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("key")
                                .value_name("KEY")
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        String,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::Set);
                            let arg = arg
                                .help("Public key for SSH signing challenge")
                                .long_help(
                                    "Public key for SSH signing challenge\n\nThis is either a path to a public key (ending in `.pub`), or a substring to match against known keys (which can be printed with `faux-mgs monorail unlock --list`).",
                                )
                                .short('k')
                                .long("key")
                                .conflicts_with("list");
                            let arg = arg.required(false);
                            arg
                        });
                    let __clap_subcommand = __clap_subcommand
                        .arg({
                            #[allow(deprecated)]
                            let arg = clap::Arg::new("list")
                                .value_name("LIST")
                                .required(true && clap::ArgAction::SetTrue.takes_values())
                                .value_parser({
                                    use ::clap_builder::builder::via_prelude::*;
                                    let auto = ::clap_builder::builder::_AutoValueParser::<
                                        bool,
                                    >::new();
                                    (&&&&&&auto).value_parser()
                                })
                                .action(clap::ArgAction::SetTrue);
                            let arg = arg
                                .help("List available keys")
                                .long_help(None)
                                .short('l')
                                .long("list")
                                .group("unlock");
                            let arg = arg.required(false);
                            arg
                        });
                    __clap_subcommand
                        .about(
                            "Unlock the technician port, allowing access to other SPs",
                        )
                        .long_about(None)
                }
            });
        let __clap_app = __clap_app
            .subcommand({
                let __clap_subcommand = clap::Command::new("lock");
                let __clap_subcommand = __clap_subcommand;
                let __clap_subcommand = __clap_subcommand;
                __clap_subcommand.about("Lock the technician port").long_about(None)
            });
        __clap_app
    }
    fn has_subcommand(__clap_name: &str) -> bool {
        if "unlock" == __clap_name {
            return true;
        }
        if "lock" == __clap_name {
            return true;
        }
        false
    }
}
#[automatically_derived]
impl ::core::fmt::Debug for MonorailCommand {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        match self {
            MonorailCommand::Unlock { time: __self_0, key: __self_1, list: __self_2 } => {
                ::core::fmt::Formatter::debug_struct_field3_finish(
                    f,
                    "Unlock",
                    "time",
                    __self_0,
                    "key",
                    __self_1,
                    "list",
                    &__self_2,
                )
            }
            MonorailCommand::Lock => ::core::fmt::Formatter::write_str(f, "Lock"),
        }
    }
}
#[automatically_derived]
impl ::core::clone::Clone for MonorailCommand {
    #[inline]
    fn clone(&self) -> MonorailCommand {
        match self {
            MonorailCommand::Unlock { time: __self_0, key: __self_1, list: __self_2 } => {
                MonorailCommand::Unlock {
                    time: ::core::clone::Clone::clone(__self_0),
                    key: ::core::clone::Clone::clone(__self_1),
                    list: ::core::clone::Clone::clone(__self_2),
                }
            }
            MonorailCommand::Lock => MonorailCommand::Lock,
        }
    }
}
enum CfpaSlot {
    Active,
    Inactive,
    Scratch,
}
#[allow(
    dead_code,
    unreachable_code,
    unused_variables,
    unused_braces,
    unused_qualifications,
)]
#[allow(
    clippy::style,
    clippy::complexity,
    clippy::pedantic,
    clippy::restriction,
    clippy::perf,
    clippy::deprecated,
    clippy::nursery,
    clippy::cargo,
    clippy::suspicious_else_formatting,
    clippy::almost_swapped,
    clippy::redundant_locals,
)]
#[automatically_derived]
impl clap::ValueEnum for CfpaSlot {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Active, Self::Inactive, Self::Scratch]
    }
    fn to_possible_value<'a>(
        &self,
    ) -> ::std::option::Option<clap::builder::PossibleValue> {
        match self {
            Self::Active => Some({ clap::builder::PossibleValue::new("active") }),
            Self::Inactive => Some({ clap::builder::PossibleValue::new("inactive") }),
            Self::Scratch => Some({ clap::builder::PossibleValue::new("scratch") }),
            _ => None,
        }
    }
}
#[automatically_derived]
impl ::core::fmt::Debug for CfpaSlot {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        ::core::fmt::Formatter::write_str(
            f,
            match self {
                CfpaSlot::Active => "Active",
                CfpaSlot::Inactive => "Inactive",
                CfpaSlot::Scratch => "Scratch",
            },
        )
    }
}
#[automatically_derived]
impl ::core::clone::Clone for CfpaSlot {
    #[inline]
    fn clone(&self) -> CfpaSlot {
        match self {
            CfpaSlot::Active => CfpaSlot::Active,
            CfpaSlot::Inactive => CfpaSlot::Inactive,
            CfpaSlot::Scratch => CfpaSlot::Scratch,
        }
    }
}
impl std::fmt::Display for CfpaSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.write_fmt(
            format_args!(
                "{0}",
                match self {
                    CfpaSlot::Active => "active",
                    CfpaSlot::Inactive => "inactive",
                    CfpaSlot::Scratch => "scratch",
                },
            ),
        )
    }
}
impl Command {
    fn default_listen_port(&self) -> u16 {
        match self {
            Command::ServeHostPhase2 { .. } => MGS_PORT,
            _ => 0,
        }
    }
}
fn parse_tlvc_key(key: &str) -> Result<[u8; 4]> {
    if !key.is_ascii() {
        return ::anyhow::__private::Err({
            let error = ::anyhow::__private::format_err(
                format_args!("key must be an ASCII string"),
            );
            error
        });
    } else if key.len() != 4 {
        return ::anyhow::__private::Err({
            let error = ::anyhow::__private::format_err(
                format_args!("key must be 4 characters"),
            );
            error
        });
    }
    Ok(key.as_bytes().try_into().unwrap())
}
fn parse_sp_component(component: &str) -> Result<SpComponent> {
    SpComponent::try_from(component)
        .map_err(|_| ::anyhow::__private::must_use({
            let error = ::anyhow::__private::format_err(
                format_args!("invalid component name: {0}", component),
            );
            error
        }))
}
struct IgnitionLinkEventsTarget(Option<u8>);
#[automatically_derived]
impl ::core::fmt::Debug for IgnitionLinkEventsTarget {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        ::core::fmt::Formatter::debug_tuple_field1_finish(
            f,
            "IgnitionLinkEventsTarget",
            &&self.0,
        )
    }
}
#[automatically_derived]
impl ::core::clone::Clone for IgnitionLinkEventsTarget {
    #[inline]
    fn clone(&self) -> IgnitionLinkEventsTarget {
        let _: ::core::clone::AssertParamIsClone<Option<u8>>;
        *self
    }
}
#[automatically_derived]
impl ::core::marker::Copy for IgnitionLinkEventsTarget {}
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
struct IgnitionLinkEventsTransceiverSelect(Option<TransceiverSelect>);
#[automatically_derived]
impl ::core::fmt::Debug for IgnitionLinkEventsTransceiverSelect {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        ::core::fmt::Formatter::debug_tuple_field1_finish(
            f,
            "IgnitionLinkEventsTransceiverSelect",
            &&self.0,
        )
    }
}
#[automatically_derived]
impl ::core::clone::Clone for IgnitionLinkEventsTransceiverSelect {
    #[inline]
    fn clone(&self) -> IgnitionLinkEventsTransceiverSelect {
        let _: ::core::clone::AssertParamIsClone<Option<TransceiverSelect>>;
        *self
    }
}
#[automatically_derived]
impl ::core::marker::Copy for IgnitionLinkEventsTransceiverSelect {}
impl IgnitionLinkEventsTransceiverSelect {
    fn parse(s: &str) -> Result<Self> {
        match s {
            "all" | "ALL" => Ok(Self(None)),
            "controller" => Ok(Self(Some(TransceiverSelect::Controller))),
            "target-link0" => Ok(Self(Some(TransceiverSelect::TargetLink0))),
            "target-link1" => Ok(Self(Some(TransceiverSelect::TargetLink1))),
            _ => {
                return ::anyhow::__private::Err({
                    let error = ::anyhow::__private::format_err(
                        format_args!(
                            "transceiver selection must be one of \'all\', \'controller\', \'target-link0\', \'target-link1\'",
                        ),
                    );
                    error
                });
            }
        }
    }
}
fn power_state_from_str(s: &str) -> Result<PowerState> {
    match s {
        "a0" | "A0" => Ok(PowerState::A0),
        "a1" | "A1" => Ok(PowerState::A1),
        "a2" | "A2" => Ok(PowerState::A2),
        _ => {
            Err(
                ::anyhow::__private::must_use({
                    let error = ::anyhow::__private::format_err(
                        format_args!("Invalid power state: {0}", s),
                    );
                    error
                }),
            )
        }
    }
}
fn ignition_command_from_str(s: &str) -> Result<IgnitionCommand> {
    match s {
        "power-on" => Ok(IgnitionCommand::PowerOn),
        "power-off" => Ok(IgnitionCommand::PowerOff),
        "power-reset" => Ok(IgnitionCommand::PowerReset),
        _ => {
            Err(
                ::anyhow::__private::must_use({
                    let error = ::anyhow::__private::format_err(
                        format_args!("Invalid ignition command: {0}", s),
                    );
                    error
                }),
            )
        }
    }
}
fn build_logger(level: Level, path: Option<&Path>) -> Result<(Logger, AsyncGuard)> {
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
        let file = File::create(path)
            .with_context(|| {
                {
                    let res = ::alloc::fmt::format(
                        format_args!("failed to create logfile {0}", path.display()),
                    );
                    res
                }
            })?;
        make_drain(level, slog_term::PlainDecorator::new(file))
    } else {
        make_drain(level, slog_term::TermDecorator::new().build())
    };
    Ok((
        Logger::root(
            drain,
            ::slog::OwnedKV((::slog::SingleKV::from(("component", "faux-mgs")), ())),
        ),
        guard,
    ))
}
fn build_requested_interfaces(patterns: Vec<String>) -> Result<Vec<String>> {
    let mut sys_ifaces = Vec::new();
    let ifaddrs = nix::ifaddrs::getifaddrs().context("getifaddrs() failed")?;
    for ifaddr in ifaddrs {
        sys_ifaces.push(ifaddr.interface_name);
    }
    let mut requested_ifaces = Vec::new();
    for pattern in patterns {
        let pattern = glob::Pattern::new(&pattern)
            .with_context(|| {
                {
                    let res = ::alloc::fmt::format(
                        format_args!("failed to build glob pattern for {0}", pattern),
                    );
                    res
                }
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
                return ::anyhow::__private::Err({
                    let error = ::anyhow::__private::format_err(
                        format_args!(
                            "`--interface {0}` did not match any interfaces not already covered by previous `--interface` arguments",
                            pattern,
                        ),
                    );
                    error
                });
            } else {
                return ::anyhow::__private::Err({
                    let error = ::anyhow::__private::format_err(
                        format_args!(
                            "`--interface {0}` did not match any interfaces",
                            pattern,
                        ),
                    );
                    error
                });
            }
        }
    }
    Ok(requested_ifaces)
}
fn main() -> Result<()> {
    let body = async {
        let args = Args::parse();
        let (log, log_guard) = build_logger(args.log_level, args.logfile.as_deref())?;
        let per_attempt_timeout = Duration::from_millis(args.per_attempt_timeout_millis);
        let listen_port = args
            .listen_port
            .unwrap_or_else(|| args.command.default_listen_port());
        let host_phase2_provider = Arc::new(
            InMemoryHostPhase2Provider::with_capacity(usize::MAX),
        );
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
            if ::slog::Level::Info.as_usize()
                <= ::slog::__slog_static_max_level().as_usize()
            {
                ::slog::Logger::log(
                    &log,
                    &{
                        #[allow(dead_code)]
                        static RS: ::slog::RecordStatic<'static> = {
                            static LOC: ::slog::RecordLocation = ::slog::RecordLocation {
                                file: "faux-mgs/src/main.rs",
                                line: 646u32,
                                column: 9u32,
                                function: "",
                                module: "faux_mgs",
                            };
                            ::slog::RecordStatic {
                                location: &LOC,
                                level: ::slog::Level::Info,
                                tag: "",
                            }
                        };
                        ::slog::Record::new(
                            &RS,
                            &format_args!(
                                "creating SP handle on interface {0}",
                                interface,
                            ),
                            ::slog::BorrowedKV(&()),
                        )
                    },
                )
            }
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
        match args.command.clone() {
            Command::UsartAttach {
                raw,
                stdin_buffer_time_millis,
                imap,
                omap,
                uart_logfile,
            } => {
                if !args.json.is_none() {
                    {
                        ::core::panicking::panic_fmt(
                            format_args!("--json not supported for serial console"),
                        );
                    }
                }
                match (&num_sps, &1) {
                    (left_val, right_val) => {
                        if !(*left_val == *right_val) {
                            let kind = ::core::panicking::AssertKind::Eq;
                            ::core::panicking::assert_failed(
                                kind,
                                &*left_val,
                                &*right_val,
                                ::core::option::Option::Some(
                                    format_args!(
                                        "cannot specify multiple interfaces for usart-attach",
                                    ),
                                ),
                            );
                        }
                    }
                };
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
                mem::drop(log_guard);
                std::process::exit(0);
            }
            Command::ServeHostPhase2 { directory } => {
                populate_phase2_images(&host_phase2_provider, &directory, &log).await?;
                if ::slog::Level::Info.as_usize()
                    <= ::slog::__slog_static_max_level().as_usize()
                {
                    ::slog::Logger::log(
                        &log,
                        &{
                            #[allow(dead_code)]
                            static RS: ::slog::RecordStatic<'static> = {
                                static LOC: ::slog::RecordLocation = ::slog::RecordLocation {
                                    file: "faux-mgs/src/main.rs",
                                    line: 719u32,
                                    column: 13u32,
                                    function: "",
                                    module: "faux_mgs",
                                };
                                ::slog::RecordStatic {
                                    location: &LOC,
                                    level: ::slog::Level::Info,
                                    tag: "",
                                }
                            };
                            ::slog::Record::new(
                                &RS,
                                &format_args!(
                                    "serving host phase 2 images (ctrl-c to stop)",
                                ),
                                ::slog::BorrowedKV(&()),
                            )
                        },
                    )
                }
                loop {
                    tokio::time::sleep(Duration::from_secs(1024)).await;
                }
            }
            Command::Update { allow_multiple_update, .. } => {
                if num_sps > 1 && !allow_multiple_update {
                    return ::anyhow::__private::Err({
                        let error = ::anyhow::__private::format_err(
                            format_args!(
                                "Did you mean to attempt to update multiple SPs? If so, add `--allow-multiple-updates`.",
                            ),
                        );
                        error
                    });
                }
            }
            _ => {}
        }
        let maxwidth = sps.iter().map(|sp| sp.interface().len()).max().unwrap_or(0);
        let mut all_results = sps
            .into_iter()
            .map(|sp| {
                let interface = sp.interface().to_string();
                run_command(sp, args.command.clone(), args.json.is_some(), log.clone())
                    .map(|result| (interface, result))
            })
            .collect::<FuturesOrdered<_>>();
        let mut by_interface = BTreeMap::new();
        while let Some((interface, result)) = all_results.next().await {
            let prefix = if args.json.is_none() && num_sps > 1 {
                {
                    let res = ::alloc::fmt::format(
                        format_args!("{0:1$} ", interface, maxwidth),
                    );
                    res
                }
            } else {
                String::new()
            };
            match result {
                Ok(Output::Json(value)) => {
                    by_interface.insert(interface, Ok(value));
                }
                Ok(Output::Lines(lines)) => {
                    for line in lines {
                        {
                            ::std::io::_print(format_args!("{0}{1}\n", prefix, line));
                        };
                    }
                }
                Err(err) => {
                    if args.json.is_some() {
                        by_interface
                            .insert(
                                interface,
                                Err({
                                    let res = ::alloc::fmt::format(format_args!("{0:#}", err));
                                    res
                                }),
                            );
                    } else {
                        {
                            ::std::io::_print(
                                format_args!("{0}Error: {1:#}\n", prefix, err),
                            );
                        };
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
            None => {}
        }
        Ok(())
    };
    #[allow(clippy::expect_used, clippy::diverging_sub_expression)]
    {
        return tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed building the Runtime")
            .block_on(body);
    }
}
fn ssh_list_keys() -> Result<Vec<ssh_key::PublicKey>> {
    let sock = std::env::var("SSH_AUTH_SOCK")?;
    let sock_path = PathBuf::new().join(sock);
    let mut client = ssh_agent_client_rs::Client::connect(&sock_path)
        .with_context(|| "failed to connect to SSH agent on {sock_path:?}")?;
    client.list_identities().context("failed to list identities")
}
async fn run_command(
    sp: SingleSp,
    command: Command,
    json: bool,
    log: Logger,
) -> Result<Output> {
    match command {
        Command::UsartAttach { .. } | Command::ServeHostPhase2 { .. } => {
            ::core::panicking::panic("internal error: entered unreachable code")
        }
        Command::Discover => {
            const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);
            let mut addr_watch = sp.sp_addr_watch().clone();
            loop {
                let current = *addr_watch.borrow();
                match current {
                    Some((addr, port)) => {
                        if ::slog::Level::Info.as_usize()
                            <= ::slog::__slog_static_max_level().as_usize()
                        {
                            ::slog::Logger::log(
                                &log,
                                &{
                                    #[allow(dead_code)]
                                    static RS: ::slog::RecordStatic<'static> = {
                                        static LOC: ::slog::RecordLocation = ::slog::RecordLocation {
                                            file: "faux-mgs/src/main.rs",
                                            line: 826u32,
                                            column: 25u32,
                                            function: "",
                                            module: "faux_mgs",
                                        };
                                        ::slog::RecordStatic {
                                            location: &LOC,
                                            level: ::slog::Level::Info,
                                            tag: "",
                                        }
                                    };
                                    ::slog::Record::new(
                                        &RS,
                                        &format_args!("SP discovered"),
                                        ::slog::BorrowedKV(
                                            &(
                                                ::slog::SingleKV::from((
                                                    "port",
                                                    format_args!("{0:?}", port),
                                                )),
                                                (
                                                    ::slog::SingleKV::from(("addr", format_args!("{0}", addr))),
                                                    (::slog::SingleKV::from(("interface", sp.interface())), ()),
                                                ),
                                            ),
                                        ),
                                    )
                                },
                            )
                        }
                        if json {
                            break Ok(
                                Output::Json(
                                    ::serde_json::Value::Object({
                                        let mut object = ::serde_json::Map::new();
                                        let _ = object
                                            .insert(
                                                ("addr").into(),
                                                ::serde_json::to_value(&addr).unwrap(),
                                            );
                                        let _ = object
                                            .insert(
                                                ("port").into(),
                                                ::serde_json::to_value(&port).unwrap(),
                                            );
                                        object
                                    }),
                                ),
                            );
                        } else {
                            break Ok(
                                Output::Lines(
                                    <[_]>::into_vec(
                                        #[rustc_box]
                                        ::alloc::boxed::Box::new([
                                            {
                                                let res = ::alloc::fmt::format(
                                                    format_args!("addr={0}, port={1:?}", addr, port),
                                                );
                                                res
                                            },
                                        ]),
                                    ),
                                ),
                            );
                        }
                    }
                    None => {
                        match tokio::time::timeout(
                                DISCOVERY_TIMEOUT,
                                addr_watch.changed(),
                            )
                            .await
                        {
                            Ok(recv_result) => recv_result.unwrap(),
                            Err(_) => {
                                return ::anyhow::__private::Err({
                                    let error = ::anyhow::__private::format_err(
                                        format_args!(
                                            "discovery failed (waited {0:?})",
                                            DISCOVERY_TIMEOUT,
                                        ),
                                    );
                                    error
                                });
                            }
                        }
                    }
                }
            }
        }
        Command::State => {
            let state = sp.state().await?;
            if ::slog::Level::Info.as_usize()
                <= ::slog::__slog_static_max_level().as_usize()
            {
                ::slog::Logger::log(
                    &log,
                    &{
                        #[allow(dead_code)]
                        static RS: ::slog::RecordStatic<'static> = {
                            static LOC: ::slog::RecordLocation = ::slog::RecordLocation {
                                file: "faux-mgs/src/main.rs",
                                line: 859u32,
                                column: 13u32,
                                function: "",
                                module: "faux_mgs",
                            };
                            ::slog::RecordStatic {
                                location: &LOC,
                                level: ::slog::Level::Info,
                                tag: "",
                            }
                        };
                        ::slog::Record::new(
                            &RS,
                            &format_args!("{0:?}", state),
                            ::slog::BorrowedKV(&()),
                        )
                    },
                )
            }
            if json {
                return Ok(Output::Json(serde_json::to_value(state).unwrap()));
            }
            let mut lines = Vec::new();
            let zero_padded_to_str = |bytes: [u8; 32]| {
                let stop = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                String::from_utf8_lossy(&bytes[..stop]).to_string()
            };
            match state {
                VersionedSpState::V1(state) => {
                    lines
                        .push({
                            let res = ::alloc::fmt::format(
                                format_args!(
                                    "hubris archive: {0}",
                                    hex::encode(state.hubris_archive_id),
                                ),
                            );
                            res
                        });
                    lines
                        .push({
                            let res = ::alloc::fmt::format(
                                format_args!(
                                    "serial number: {0}",
                                    zero_padded_to_str(state.serial_number),
                                ),
                            );
                            res
                        });
                    lines
                        .push({
                            let res = ::alloc::fmt::format(
                                format_args!("model: {0}", zero_padded_to_str(state.model)),
                            );
                            res
                        });
                    lines
                        .push({
                            let res = ::alloc::fmt::format(
                                format_args!("revision: {0}", state.revision),
                            );
                            res
                        });
                    lines
                        .push({
                            let res = ::alloc::fmt::format(
                                format_args!(
                                    "base MAC address: {0}",
                                    state
                                        .base_mac_address
                                        .iter()
                                        .map(|b| {
                                            let res = ::alloc::fmt::format(format_args!("{0:02x}", b));
                                            res
                                        })
                                        .collect::<Vec<_>>()
                                        .join(":"),
                                ),
                            );
                            res
                        });
                    lines
                        .push({
                            let res = ::alloc::fmt::format(
                                format_args!("hubris version: {0:?}", state.version),
                            );
                            res
                        });
                    lines
                        .push({
                            let res = ::alloc::fmt::format(
                                format_args!("power state: {0:?}", state.power_state),
                            );
                            res
                        });
                    match state.rot {
                        Ok(rot) => {
                            lines
                                .push({
                                    let res = ::alloc::fmt::format(
                                        format_args!("rot: Ok({0})", rot.display()),
                                    );
                                    res
                                })
                        }
                        Err(err) => {
                            lines
                                .push({
                                    let res = ::alloc::fmt::format(
                                        format_args!("rot: Err({0})", err),
                                    );
                                    res
                                })
                        }
                    }
                    Ok(Output::Lines(lines))
                }
                VersionedSpState::V2(state) => {
                    lines
                        .push({
                            let res = ::alloc::fmt::format(
                                format_args!(
                                    "hubris archive: {0}",
                                    hex::encode(state.hubris_archive_id),
                                ),
                            );
                            res
                        });
                    lines
                        .push({
                            let res = ::alloc::fmt::format(
                                format_args!(
                                    "serial number: {0}",
                                    zero_padded_to_str(state.serial_number),
                                ),
                            );
                            res
                        });
                    lines
                        .push({
                            let res = ::alloc::fmt::format(
                                format_args!("model: {0}", zero_padded_to_str(state.model)),
                            );
                            res
                        });
                    lines
                        .push({
                            let res = ::alloc::fmt::format(
                                format_args!("revision: {0}", state.revision),
                            );
                            res
                        });
                    lines
                        .push({
                            let res = ::alloc::fmt::format(
                                format_args!(
                                    "base MAC address: {0}",
                                    state
                                        .base_mac_address
                                        .iter()
                                        .map(|b| {
                                            let res = ::alloc::fmt::format(format_args!("{0:02x}", b));
                                            res
                                        })
                                        .collect::<Vec<_>>()
                                        .join(":"),
                                ),
                            );
                            res
                        });
                    lines
                        .push({
                            let res = ::alloc::fmt::format(
                                format_args!("power state: {0:?}", state.power_state),
                            );
                            res
                        });
                    match state.rot {
                        Ok(rot) => {
                            lines
                                .push({
                                    let res = ::alloc::fmt::format(
                                        format_args!("rot: Ok({0})", rot),
                                    );
                                    res
                                })
                        }
                        Err(err) => {
                            lines
                                .push({
                                    let res = ::alloc::fmt::format(
                                        format_args!("rot: Err({0})", err),
                                    );
                                    res
                                })
                        }
                    }
                    Ok(Output::Lines(lines))
                }
                VersionedSpState::V3(state) => {
                    lines
                        .push({
                            let res = ::alloc::fmt::format(
                                format_args!(
                                    "hubris archive: {0}",
                                    hex::encode(state.hubris_archive_id),
                                ),
                            );
                            res
                        });
                    lines
                        .push({
                            let res = ::alloc::fmt::format(
                                format_args!(
                                    "serial number: {0}",
                                    zero_padded_to_str(state.serial_number),
                                ),
                            );
                            res
                        });
                    lines
                        .push({
                            let res = ::alloc::fmt::format(
                                format_args!("model: {0}", zero_padded_to_str(state.model)),
                            );
                            res
                        });
                    lines
                        .push({
                            let res = ::alloc::fmt::format(
                                format_args!("revision: {0}", state.revision),
                            );
                            res
                        });
                    lines
                        .push({
                            let res = ::alloc::fmt::format(
                                format_args!(
                                    "base MAC address: {0}",
                                    state
                                        .base_mac_address
                                        .iter()
                                        .map(|b| {
                                            let res = ::alloc::fmt::format(format_args!("{0:02x}", b));
                                            res
                                        })
                                        .collect::<Vec<_>>()
                                        .join(":"),
                                ),
                            );
                            res
                        });
                    lines
                        .push({
                            let res = ::alloc::fmt::format(
                                format_args!("power state: {0:?}", state.power_state),
                            );
                            res
                        });
                    Ok(Output::Lines(lines))
                }
            }
        }
        Command::RotBootInfo { version } => {
            let rot_state = sp.rot_state(version).await?;
            if ::slog::Level::Info.as_usize()
                <= ::slog::__slog_static_max_level().as_usize()
            {
                ::slog::Logger::log(
                    &log,
                    &{
                        #[allow(dead_code)]
                        static RS: ::slog::RecordStatic<'static> = {
                            static LOC: ::slog::RecordLocation = ::slog::RecordLocation {
                                file: "faux-mgs/src/main.rs",
                                line: 967u32,
                                column: 13u32,
                                function: "",
                                module: "faux_mgs",
                            };
                            ::slog::RecordStatic {
                                location: &LOC,
                                level: ::slog::Level::Info,
                                tag: "",
                            }
                        };
                        ::slog::Record::new(
                            &RS,
                            &format_args!("{0:x?}", rot_state),
                            ::slog::BorrowedKV(&()),
                        )
                    },
                )
            }
            if json {
                Ok(Output::Json(serde_json::to_value(rot_state).unwrap()))
            } else {
                let mut lines = Vec::new();
                lines
                    .push({
                        let res = ::alloc::fmt::format(
                            format_args!("{0}", rot_state.display()),
                        );
                        res
                    });
                Ok(Output::Lines(lines))
            }
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
                    lines
                        .push({
                            let res = ::alloc::fmt::format(
                                format_args!("target {0}: {1:?}", target, state),
                            );
                            res
                        });
                }
                Ok(Output::Lines(lines))
            }
        }
        Command::IgnitionCommand { target, command } => {
            sp.ignition_command(target, command).await?;
            if ::slog::Level::Info.as_usize()
                <= ::slog::__slog_static_max_level().as_usize()
            {
                ::slog::Logger::log(
                    &log,
                    &{
                        #[allow(dead_code)]
                        static RS: ::slog::RecordStatic<'static> = {
                            static LOC: ::slog::RecordLocation = ::slog::RecordLocation {
                                file: "faux-mgs/src/main.rs",
                                line: 999u32,
                                column: 13u32,
                                function: "",
                                module: "faux_mgs",
                            };
                            ::slog::RecordStatic {
                                location: &LOC,
                                level: ::slog::Level::Info,
                                tag: "",
                            }
                        };
                        ::slog::Record::new(
                            &RS,
                            &format_args!(
                                "ignition command {0:?} send to target {1}",
                                command,
                                target,
                            ),
                            ::slog::BorrowedKV(&()),
                        )
                    },
                )
            }
            if json {
                Ok(
                    Output::Json(
                        ::serde_json::Value::Object({
                            let mut object = ::serde_json::Map::new();
                            let _ = object
                                .insert(
                                    ("ack").into(),
                                    ::serde_json::to_value(&command).unwrap(),
                                );
                            object
                        }),
                    ),
                )
            } else {
                Ok(
                    Output::Lines(
                        <[_]>::into_vec(
                            #[rustc_box]
                            ::alloc::boxed::Box::new([
                                {
                                    let res = ::alloc::fmt::format(
                                        format_args!("successfully sent {0:?}", command),
                                    );
                                    res
                                },
                            ]),
                        ),
                    ),
                )
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
                    lines
                        .push({
                            let res = ::alloc::fmt::format(
                                format_args!("target {0}: {1:?}", target, events),
                            );
                            res
                        });
                }
                Ok(Output::Lines(lines))
            }
        }
        Command::ClearIgnitionLinkEvents { target, transceiver_select } => {
            sp.clear_ignition_link_events(target.0, transceiver_select.0).await?;
            if ::slog::Level::Info.as_usize()
                <= ::slog::__slog_static_max_level().as_usize()
            {
                ::slog::Logger::log(
                    &log,
                    &{
                        #[allow(dead_code)]
                        static RS: ::slog::RecordStatic<'static> = {
                            static LOC: ::slog::RecordLocation = ::slog::RecordLocation {
                                file: "faux-mgs/src/main.rs",
                                line: 1032u32,
                                column: 13u32,
                                function: "",
                                module: "faux_mgs",
                            };
                            ::slog::RecordStatic {
                                location: &LOC,
                                level: ::slog::Level::Info,
                                tag: "",
                            }
                        };
                        ::slog::Record::new(
                            &RS,
                            &format_args!("ignition link events cleared"),
                            ::slog::BorrowedKV(&()),
                        )
                    },
                )
            }
            if json {
                Ok(
                    Output::Json(
                        ::serde_json::Value::Object({
                            let mut object = ::serde_json::Map::new();
                            let _ = object
                                .insert(
                                    ("ack").into(),
                                    ::serde_json::to_value(&"cleared").unwrap(),
                                );
                            object
                        }),
                    ),
                )
            } else {
                Ok(
                    Output::Lines(
                        <[_]>::into_vec(
                            #[rustc_box]
                            ::alloc::boxed::Box::new([
                                "ignition link events cleared".to_string(),
                            ]),
                        ),
                    ),
                )
            }
        }
        Command::ComponentActiveSlot { component, set, persist } => {
            if let Some(slot) = set {
                sp.set_component_active_slot(component, slot, persist).await?;
                if json {
                    Ok(
                        Output::Json(
                            ::serde_json::Value::Object({
                                let mut object = ::serde_json::Map::new();
                                let _ = object
                                    .insert(
                                        ("ack").into(),
                                        ::serde_json::to_value(&"set").unwrap(),
                                    );
                                let _ = object
                                    .insert(
                                        ("slot").into(),
                                        ::serde_json::to_value(&slot).unwrap(),
                                    );
                                object
                            }),
                        ),
                    )
                } else {
                    Ok(
                        Output::Lines(
                            <[_]>::into_vec(
                                #[rustc_box]
                                ::alloc::boxed::Box::new([
                                    {
                                        let res = ::alloc::fmt::format(
                                            format_args!(
                                                "set active slot for {0:?} to {1}",
                                                component,
                                                slot,
                                            ),
                                        );
                                        res
                                    },
                                ]),
                            ),
                        ),
                    )
                }
            } else {
                let slot = sp.component_active_slot(component).await?;
                if ::slog::Level::Info.as_usize()
                    <= ::slog::__slog_static_max_level().as_usize()
                {
                    ::slog::Logger::log(
                        &log,
                        &{
                            #[allow(dead_code)]
                            static RS: ::slog::RecordStatic<'static> = {
                                static LOC: ::slog::RecordLocation = ::slog::RecordLocation {
                                    file: "faux-mgs/src/main.rs",
                                    line: 1053u32,
                                    column: 17u32,
                                    function: "",
                                    module: "faux_mgs",
                                };
                                ::slog::RecordStatic {
                                    location: &LOC,
                                    level: ::slog::Level::Info,
                                    tag: "",
                                }
                            };
                            ::slog::Record::new(
                                &RS,
                                &format_args!(
                                    "active slot for {0:?}: {1}",
                                    component,
                                    slot,
                                ),
                                ::slog::BorrowedKV(&()),
                            )
                        },
                    )
                }
                if json {
                    Ok(
                        Output::Json(
                            ::serde_json::Value::Object({
                                let mut object = ::serde_json::Map::new();
                                let _ = object
                                    .insert(
                                        ("slot").into(),
                                        ::serde_json::to_value(&slot).unwrap(),
                                    );
                                object
                            }),
                        ),
                    )
                } else {
                    Ok(
                        Output::Lines(
                            <[_]>::into_vec(
                                #[rustc_box]
                                ::alloc::boxed::Box::new([
                                    {
                                        let res = ::alloc::fmt::format(format_args!("{0}", slot));
                                        res
                                    },
                                ]),
                            ),
                        ),
                    )
                }
            }
        }
        Command::StartupOptions { options } => {
            if let Some(options) = options {
                let options = StartupOptions::from_bits(options)
                    .with_context(|| {
                        {
                            let res = ::alloc::fmt::format(
                                format_args!(
                                    "invalid startup options bits: {0:#x}",
                                    options,
                                ),
                            );
                            res
                        }
                    })?;
                sp.set_startup_options(options).await?;
                if json {
                    Ok(
                        Output::Json(
                            ::serde_json::Value::Object({
                                let mut object = ::serde_json::Map::new();
                                let _ = object
                                    .insert(
                                        ("ack").into(),
                                        ::serde_json::to_value(&"set").unwrap(),
                                    );
                                let _ = object
                                    .insert(
                                        ("options").into(),
                                        ::serde_json::to_value(&options).unwrap(),
                                    );
                                object
                            }),
                        ),
                    )
                } else {
                    Ok(
                        Output::Lines(
                            <[_]>::into_vec(
                                #[rustc_box]
                                ::alloc::boxed::Box::new([
                                    {
                                        let res = ::alloc::fmt::format(
                                            format_args!(
                                                "successfully set startup options to {0:?}",
                                                options,
                                            ),
                                        );
                                        res
                                    },
                                ]),
                            ),
                        ),
                    )
                }
            } else {
                let options = sp.get_startup_options().await?;
                if json {
                    Ok(
                        Output::Json(
                            ::serde_json::Value::Object({
                                let mut object = ::serde_json::Map::new();
                                let _ = object
                                    .insert(
                                        ("options").into(),
                                        ::serde_json::to_value(&options).unwrap(),
                                    );
                                object
                            }),
                        ),
                    )
                } else {
                    Ok(
                        Output::Lines(
                            <[_]>::into_vec(
                                #[rustc_box]
                                ::alloc::boxed::Box::new([
                                    {
                                        let res = ::alloc::fmt::format(
                                            format_args!("startup options: {0:?}", options),
                                        );
                                        res
                                    },
                                ]),
                            ),
                        ),
                    )
                }
            }
        }
        Command::Inventory => {
            let inventory = sp.inventory().await?;
            if json {
                return Ok(Output::Json(serde_json::to_value(inventory).unwrap()));
            }
            let mut lines = Vec::new();
            lines
                .push({
                    let res = ::alloc::fmt::format(
                        format_args!(
                            "{0:<16} {1:<12} {2:<16} {3:<}",
                            "COMPONENT",
                            "STATUS",
                            "DEVICE",
                            "DESCRIPTION (CAPABILITIES)",
                        ),
                    );
                    res
                });
            for d in inventory.devices {
                lines
                    .push({
                        let res = ::alloc::fmt::format(
                            format_args!(
                                "{0:<16} {1:<12} {2:<16} {3} ({4:?})",
                                d.component.as_str().unwrap_or("???"),
                                {
                                    let res = ::alloc::fmt::format(
                                        format_args!("{0:?}", d.presence),
                                    );
                                    res
                                },
                                d.device,
                                d.description,
                                d.capabilities,
                            ),
                        );
                        res
                    });
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
                lines
                    .push({
                        let res = ::alloc::fmt::format(format_args!("{0:?}", entry));
                        res
                    });
            }
            Ok(Output::Lines(lines))
        }
        Command::ComponentClearStatus { component } => {
            sp.component_clear_status(component).await?;
            if ::slog::Level::Info.as_usize()
                <= ::slog::__slog_static_max_level().as_usize()
            {
                ::slog::Logger::log(
                    &log,
                    &{
                        #[allow(dead_code)]
                        static RS: ::slog::RecordStatic<'static> = {
                            static LOC: ::slog::RecordLocation = ::slog::RecordLocation {
                                file: "faux-mgs/src/main.rs",
                                line: 1127u32,
                                column: 13u32,
                                function: "",
                                module: "faux_mgs",
                            };
                            ::slog::RecordStatic {
                                location: &LOC,
                                level: ::slog::Level::Info,
                                tag: "",
                            }
                        };
                        ::slog::Record::new(
                            &RS,
                            &format_args!("status cleared for component {0}", component),
                            ::slog::BorrowedKV(&()),
                        )
                    },
                )
            }
            if json {
                Ok(
                    Output::Json(
                        ::serde_json::Value::Object({
                            let mut object = ::serde_json::Map::new();
                            let _ = object
                                .insert(
                                    ("ack").into(),
                                    ::serde_json::to_value(&"cleared").unwrap(),
                                );
                            object
                        }),
                    ),
                )
            } else {
                Ok(
                    Output::Lines(
                        <[_]>::into_vec(
                            #[rustc_box]
                            ::alloc::boxed::Box::new(["status cleared".to_string()]),
                        ),
                    ),
                )
            }
        }
        Command::UsartDetach => {
            sp.serial_console_detach().await?;
            if ::slog::Level::Info.as_usize()
                <= ::slog::__slog_static_max_level().as_usize()
            {
                ::slog::Logger::log(
                    &log,
                    &{
                        #[allow(dead_code)]
                        static RS: ::slog::RecordStatic<'static> = {
                            static LOC: ::slog::RecordLocation = ::slog::RecordLocation {
                                file: "faux-mgs/src/main.rs",
                                line: 1136u32,
                                column: 13u32,
                                function: "",
                                module: "faux_mgs",
                            };
                            ::slog::RecordStatic {
                                location: &LOC,
                                level: ::slog::Level::Info,
                                tag: "",
                            }
                        };
                        ::slog::Record::new(
                            &RS,
                            &format_args!("SP serial console detached"),
                            ::slog::BorrowedKV(&()),
                        )
                    },
                )
            }
            if json {
                Ok(
                    Output::Json(
                        ::serde_json::Value::Object({
                            let mut object = ::serde_json::Map::new();
                            let _ = object
                                .insert(
                                    ("ack").into(),
                                    ::serde_json::to_value(&"detached").unwrap(),
                                );
                            object
                        }),
                    ),
                )
            } else {
                Ok(
                    Output::Lines(
                        <[_]>::into_vec(
                            #[rustc_box]
                            ::alloc::boxed::Box::new([
                                "SP serial console detached".to_string(),
                            ]),
                        ),
                    ),
                )
            }
        }
        Command::Update { component, slot, image, .. } => {
            let data = fs::read(&image)
                .with_context(|| {
                    {
                        let res = ::alloc::fmt::format(
                            format_args!("failed to read {0}", image.display()),
                        );
                        res
                    }
                })?;
            update(&log, &sp, component, slot, data)
                .await
                .with_context(|| {
                    {
                        let res = ::alloc::fmt::format(
                            format_args!(
                                "updating {0} slot {1} to {2} failed",
                                component,
                                slot,
                                image.display(),
                            ),
                        );
                        res
                    }
                })?;
            if json {
                Ok(
                    Output::Json(
                        ::serde_json::Value::Object({
                            let mut object = ::serde_json::Map::new();
                            let _ = object
                                .insert(
                                    ("ack").into(),
                                    ::serde_json::to_value(&"updated").unwrap(),
                                );
                            object
                        }),
                    ),
                )
            } else {
                Ok(
                    Output::Lines(
                        <[_]>::into_vec(
                            #[rustc_box]
                            ::alloc::boxed::Box::new(["update complete".to_string()]),
                        ),
                    ),
                )
            }
        }
        Command::UpdateStatus { component } => {
            let status = sp
                .update_status(component)
                .await
                .with_context(|| {
                    {
                        let res = ::alloc::fmt::format(
                            format_args!(
                                "failed to get update status to component {0}",
                                component,
                            ),
                        );
                        res
                    }
                })?;
            if json {
                return Ok(Output::Json(serde_json::to_value(status).unwrap()));
            }
            let status = match status {
                UpdateStatus::Preparing(sub_status) => {
                    let id = Uuid::from(sub_status.id);
                    if let Some(progress) = sub_status.progress {
                        {
                            let res = ::alloc::fmt::format(
                                format_args!(
                                    "update {2} preparing (progress: {0}/{1})",
                                    progress.current,
                                    progress.total,
                                    id,
                                ),
                            );
                            res
                        }
                    } else {
                        {
                            let res = ::alloc::fmt::format(
                                format_args!(
                                    "update {0} preparing (no progress available)",
                                    id,
                                ),
                            );
                            res
                        }
                    }
                }
                UpdateStatus::SpUpdateAuxFlashChckScan { id, found_match, .. } => {
                    let id = Uuid::from(id);
                    {
                        let res = ::alloc::fmt::format(
                            format_args!(
                                "update {0} aux flash scan complete (found_match={1}",
                                id,
                                found_match,
                            ),
                        );
                        res
                    }
                }
                UpdateStatus::InProgress(sub_status) => {
                    let id = Uuid::from(sub_status.id);
                    {
                        let res = ::alloc::fmt::format(
                            format_args!(
                                "update {2} in progress ({0} of {1} received)",
                                sub_status.bytes_received,
                                sub_status.total_size,
                                id,
                            ),
                        );
                        res
                    }
                }
                UpdateStatus::Complete(id) => {
                    let id = Uuid::from(id);
                    {
                        let res = ::alloc::fmt::format(
                            format_args!("update {0} complete", id),
                        );
                        res
                    }
                }
                UpdateStatus::Aborted(id) => {
                    let id = Uuid::from(id);
                    {
                        let res = ::alloc::fmt::format(
                            format_args!("update {0} aborted", id),
                        );
                        res
                    }
                }
                UpdateStatus::Failed { id, code } => {
                    let id = Uuid::from(id);
                    {
                        let res = ::alloc::fmt::format(
                            format_args!("update {0} failed (code={1})", id, code),
                        );
                        res
                    }
                }
                UpdateStatus::RotError { id, error } => {
                    let id = Uuid::from(id);
                    {
                        let res = ::alloc::fmt::format(
                            format_args!(
                                "update {0} failed (rot error={1:?})",
                                id,
                                error,
                            ),
                        );
                        res
                    }
                }
                UpdateStatus::None => "no update status available".to_string(),
            };
            if ::slog::Level::Info.as_usize()
                <= ::slog::__slog_static_max_level().as_usize()
            {
                ::slog::Logger::log(
                    &log,
                    &{
                        #[allow(dead_code)]
                        static RS: ::slog::RecordStatic<'static> = {
                            static LOC: ::slog::RecordLocation = ::slog::RecordLocation {
                                file: "faux-mgs/src/main.rs",
                                line: 1220u32,
                                column: 13u32,
                                function: "",
                                module: "faux_mgs",
                            };
                            ::slog::RecordStatic {
                                location: &LOC,
                                level: ::slog::Level::Info,
                                tag: "",
                            }
                        };
                        ::slog::Record::new(
                            &RS,
                            &format_args!("{0}", status),
                            ::slog::BorrowedKV(&()),
                        )
                    },
                )
            }
            Ok(
                Output::Lines(
                    <[_]>::into_vec(#[rustc_box] ::alloc::boxed::Box::new([status])),
                ),
            )
        }
        Command::UpdateAbort { component, update_id } => {
            sp.update_abort(component, update_id)
                .await
                .with_context(|| {
                    {
                        let res = ::alloc::fmt::format(
                            format_args!("aborting update to {0} failed", component),
                        );
                        res
                    }
                })?;
            if json {
                Ok(
                    Output::Json(
                        ::serde_json::Value::Object({
                            let mut object = ::serde_json::Map::new();
                            let _ = object
                                .insert(
                                    ("ack").into(),
                                    ::serde_json::to_value(&"aborted").unwrap(),
                                );
                            object
                        }),
                    ),
                )
            } else {
                Ok(
                    Output::Lines(
                        <[_]>::into_vec(
                            #[rustc_box]
                            ::alloc::boxed::Box::new([
                                {
                                    let res = ::alloc::fmt::format(
                                        format_args!("update {0} aborted", update_id),
                                    );
                                    res
                                },
                            ]),
                        ),
                    ),
                )
            }
        }
        Command::PowerState { new_power_state } => {
            if let Some(state) = new_power_state {
                sp.set_power_state(state)
                    .await
                    .with_context(|| {
                        {
                            let res = ::alloc::fmt::format(
                                format_args!("failed to set power state to {0:?}", state),
                            );
                            res
                        }
                    })?;
                if ::slog::Level::Info.as_usize()
                    <= ::slog::__slog_static_max_level().as_usize()
                {
                    ::slog::Logger::log(
                        &log,
                        &{
                            #[allow(dead_code)]
                            static RS: ::slog::RecordStatic<'static> = {
                                static LOC: ::slog::RecordLocation = ::slog::RecordLocation {
                                    file: "faux-mgs/src/main.rs",
                                    line: 1238u32,
                                    column: 17u32,
                                    function: "",
                                    module: "faux_mgs",
                                };
                                ::slog::RecordStatic {
                                    location: &LOC,
                                    level: ::slog::Level::Info,
                                    tag: "",
                                }
                            };
                            ::slog::Record::new(
                                &RS,
                                &format_args!(
                                    "successfully set SP power state to {0:?}",
                                    state,
                                ),
                                ::slog::BorrowedKV(&()),
                            )
                        },
                    )
                }
                if json {
                    Ok(
                        Output::Json(
                            ::serde_json::Value::Object({
                                let mut object = ::serde_json::Map::new();
                                let _ = object
                                    .insert(
                                        ("ack").into(),
                                        ::serde_json::to_value(&"set").unwrap(),
                                    );
                                let _ = object
                                    .insert(
                                        ("state").into(),
                                        ::serde_json::to_value(&state).unwrap(),
                                    );
                                object
                            }),
                        ),
                    )
                } else {
                    Ok(
                        Output::Lines(
                            <[_]>::into_vec(
                                #[rustc_box]
                                ::alloc::boxed::Box::new([
                                    {
                                        let res = ::alloc::fmt::format(
                                            format_args!(
                                                "successfully set SP power state to {0:?}",
                                                state,
                                            ),
                                        );
                                        res
                                    },
                                ]),
                            ),
                        ),
                    )
                }
            } else {
                let state = sp.power_state().await.context("failed to get power state")?;
                if ::slog::Level::Info.as_usize()
                    <= ::slog::__slog_static_max_level().as_usize()
                {
                    ::slog::Logger::log(
                        &log,
                        &{
                            #[allow(dead_code)]
                            static RS: ::slog::RecordStatic<'static> = {
                                static LOC: ::slog::RecordLocation = ::slog::RecordLocation {
                                    file: "faux-mgs/src/main.rs",
                                    line: 1251u32,
                                    column: 17u32,
                                    function: "",
                                    module: "faux_mgs",
                                };
                                ::slog::RecordStatic {
                                    location: &LOC,
                                    level: ::slog::Level::Info,
                                    tag: "",
                                }
                            };
                            ::slog::Record::new(
                                &RS,
                                &format_args!("SP power state = {0:?}", state),
                                ::slog::BorrowedKV(&()),
                            )
                        },
                    )
                }
                if json {
                    Ok(
                        Output::Json(
                            ::serde_json::Value::Object({
                                let mut object = ::serde_json::Map::new();
                                let _ = object
                                    .insert(
                                        ("state").into(),
                                        ::serde_json::to_value(&state).unwrap(),
                                    );
                                object
                            }),
                        ),
                    )
                } else {
                    Ok(
                        Output::Lines(
                            <[_]>::into_vec(
                                #[rustc_box]
                                ::alloc::boxed::Box::new([
                                    {
                                        let res = ::alloc::fmt::format(
                                            format_args!("{0:?}", state),
                                        );
                                        res
                                    },
                                ]),
                            ),
                        ),
                    )
                }
            }
        }
        Command::Reset { disable_watchdog } => {
            sp.reset_component_prepare(SpComponent::SP_ITSELF).await?;
            if ::slog::Level::Info.as_usize()
                <= ::slog::__slog_static_max_level().as_usize()
            {
                ::slog::Logger::log(
                    &log,
                    &{
                        #[allow(dead_code)]
                        static RS: ::slog::RecordStatic<'static> = {
                            static LOC: ::slog::RecordLocation = ::slog::RecordLocation {
                                file: "faux-mgs/src/main.rs",
                                line: 1261u32,
                                column: 13u32,
                                function: "",
                                module: "faux_mgs",
                            };
                            ::slog::RecordStatic {
                                location: &LOC,
                                level: ::slog::Level::Info,
                                tag: "",
                            }
                        };
                        ::slog::Record::new(
                            &RS,
                            &format_args!("SP is prepared to reset"),
                            ::slog::BorrowedKV(&()),
                        )
                    },
                )
            }
            sp.reset_component_trigger(SpComponent::SP_ITSELF, disable_watchdog).await?;
            if ::slog::Level::Info.as_usize()
                <= ::slog::__slog_static_max_level().as_usize()
            {
                ::slog::Logger::log(
                    &log,
                    &{
                        #[allow(dead_code)]
                        static RS: ::slog::RecordStatic<'static> = {
                            static LOC: ::slog::RecordLocation = ::slog::RecordLocation {
                                file: "faux-mgs/src/main.rs",
                                line: 1267u32,
                                column: 13u32,
                                function: "",
                                module: "faux_mgs",
                            };
                            ::slog::RecordStatic {
                                location: &LOC,
                                level: ::slog::Level::Info,
                                tag: "",
                            }
                        };
                        ::slog::Record::new(
                            &RS,
                            &format_args!("SP reset complete"),
                            ::slog::BorrowedKV(&()),
                        )
                    },
                )
            }
            if json {
                Ok(
                    Output::Json(
                        ::serde_json::Value::Object({
                            let mut object = ::serde_json::Map::new();
                            let _ = object
                                .insert(
                                    ("ack").into(),
                                    ::serde_json::to_value(&"reset").unwrap(),
                                );
                            object
                        }),
                    ),
                )
            } else {
                Ok(
                    Output::Lines(
                        <[_]>::into_vec(
                            #[rustc_box]
                            ::alloc::boxed::Box::new(["reset complete".to_string()]),
                        ),
                    ),
                )
            }
        }
        Command::ResetComponent { component, disable_watchdog } => {
            sp.reset_component_prepare(component).await?;
            if ::slog::Level::Info.as_usize()
                <= ::slog::__slog_static_max_level().as_usize()
            {
                ::slog::Logger::log(
                    &log,
                    &{
                        #[allow(dead_code)]
                        static RS: ::slog::RecordStatic<'static> = {
                            static LOC: ::slog::RecordLocation = ::slog::RecordLocation {
                                file: "faux-mgs/src/main.rs",
                                line: 1277u32,
                                column: 13u32,
                                function: "",
                                module: "faux_mgs",
                            };
                            ::slog::RecordStatic {
                                location: &LOC,
                                level: ::slog::Level::Info,
                                tag: "",
                            }
                        };
                        ::slog::Record::new(
                            &RS,
                            &format_args!(
                                "SP is prepared to reset component {0}",
                                component,
                            ),
                            ::slog::BorrowedKV(&()),
                        )
                    },
                )
            }
            sp.reset_component_trigger(component, disable_watchdog).await?;
            if ::slog::Level::Info.as_usize()
                <= ::slog::__slog_static_max_level().as_usize()
            {
                ::slog::Logger::log(
                    &log,
                    &{
                        #[allow(dead_code)]
                        static RS: ::slog::RecordStatic<'static> = {
                            static LOC: ::slog::RecordLocation = ::slog::RecordLocation {
                                file: "faux-mgs/src/main.rs",
                                line: 1279u32,
                                column: 13u32,
                                function: "",
                                module: "faux_mgs",
                            };
                            ::slog::RecordStatic {
                                location: &LOC,
                                level: ::slog::Level::Info,
                                tag: "",
                            }
                        };
                        ::slog::Record::new(
                            &RS,
                            &format_args!("SP reset component {0} complete", component),
                            ::slog::BorrowedKV(&()),
                        )
                    },
                )
            }
            if json {
                Ok(
                    Output::Json(
                        ::serde_json::Value::Object({
                            let mut object = ::serde_json::Map::new();
                            let _ = object
                                .insert(
                                    ("ack").into(),
                                    ::serde_json::to_value(&"reset").unwrap(),
                                );
                            object
                        }),
                    ),
                )
            } else {
                Ok(
                    Output::Lines(
                        <[_]>::into_vec(
                            #[rustc_box]
                            ::alloc::boxed::Box::new(["reset complete".to_string()]),
                        ),
                    ),
                )
            }
        }
        Command::SendHostNmi => {
            sp.send_host_nmi().await?;
            if json {
                Ok(
                    Output::Json(
                        ::serde_json::Value::Object({
                            let mut object = ::serde_json::Map::new();
                            let _ = object
                                .insert(
                                    ("ack").into(),
                                    ::serde_json::to_value(&"nmi").unwrap(),
                                );
                            object
                        }),
                    ),
                )
            } else {
                Ok(
                    Output::Lines(
                        <[_]>::into_vec(
                            #[rustc_box]
                            ::alloc::boxed::Box::new(["done".to_string()]),
                        ),
                    ),
                )
            }
        }
        Command::SetIpccKeyValue { key, value_path } => {
            let value = fs::read(&value_path)
                .with_context(|| {
                    {
                        let res = ::alloc::fmt::format(
                            format_args!("failed to read {0}", value_path.display()),
                        );
                        res
                    }
                })?;
            sp.set_ipcc_key_lookup_value(key, value).await?;
            if json {
                Ok(
                    Output::Json(
                        ::serde_json::Value::Object({
                            let mut object = ::serde_json::Map::new();
                            let _ = object
                                .insert(
                                    ("ack").into(),
                                    ::serde_json::to_value(&"ipcc").unwrap(),
                                );
                            object
                        }),
                    ),
                )
            } else {
                Ok(
                    Output::Lines(
                        <[_]>::into_vec(
                            #[rustc_box]
                            ::alloc::boxed::Box::new(["done".to_string()]),
                        ),
                    ),
                )
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
                Ok(
                    Output::Json(
                        ::serde_json::Value::Object({
                            let mut object = ::serde_json::Map::new();
                            let _ = object
                                .insert(
                                    ("value").into(),
                                    ::serde_json::to_value(&out).unwrap(),
                                );
                            object
                        }),
                    ),
                )
            } else {
                Ok(
                    Output::Lines(
                        <[_]>::into_vec(#[rustc_box] ::alloc::boxed::Box::new([out])),
                    ),
                )
            }
        }
        Command::SystemLed { cmd } => {
            sp.component_action(
                    SpComponent::SYSTEM_LED,
                    ComponentAction::Led(
                        match cmd {
                            LedCommand::On => LedComponentAction::TurnOn,
                            LedCommand::Off => LedComponentAction::TurnOff,
                            LedCommand::Blink => LedComponentAction::Blink,
                        },
                    ),
                )
                .await?;
            if json {
                Ok(
                    Output::Json(
                        ::serde_json::Value::Object({
                            let mut object = ::serde_json::Map::new();
                            let _ = object
                                .insert(
                                    ("ack").into(),
                                    ::serde_json::to_value(&"led").unwrap(),
                                );
                            object
                        }),
                    ),
                )
            } else {
                Ok(
                    Output::Lines(
                        <[_]>::into_vec(
                            #[rustc_box]
                            ::alloc::boxed::Box::new(["done".to_string()]),
                        ),
                    ),
                )
            }
        }
        Command::Monorail { cmd } => {
            match cmd {
                MonorailCommand::Lock => {
                    sp.component_action(
                            SpComponent::MONORAIL,
                            ComponentAction::Monorail(MonorailComponentAction::Lock),
                        )
                        .await?
                }
                MonorailCommand::Unlock { time, key, list } => {
                    if list {
                        for k in ssh_list_keys()? {
                            {
                                ::std::io::_print(format_args!("{0}\n", k.to_openssh()?));
                            };
                        }
                    } else {
                        let time_sec = time.unwrap().as_secs_f32() as u32;
                        monorail_unlock(&log, &sp, time_sec, key).await?;
                    }
                }
            }
            if json {
                Ok(
                    Output::Json(
                        ::serde_json::Value::Object({
                            let mut object = ::serde_json::Map::new();
                            let _ = object
                                .insert(
                                    ("ack").into(),
                                    ::serde_json::to_value(&"monorail").unwrap(),
                                );
                            object
                        }),
                    ),
                )
            } else {
                Ok(
                    Output::Lines(
                        <[_]>::into_vec(
                            #[rustc_box]
                            ::alloc::boxed::Box::new(["done".to_string()]),
                        ),
                    ),
                )
            }
        }
        Command::ReadComponentCaboose { component, slot, key } => {
            let slot = match (component, slot.as_deref()) {
                (SpComponent::SP_ITSELF, Some("active" | "0") | None) => 0,
                (SpComponent::SP_ITSELF, Some("inactive" | "1")) => 1,
                (SpComponent::SP_ITSELF, v) => {
                    return ::anyhow::__private::Err(
                        ::anyhow::Error::msg({
                            let res = ::alloc::fmt::format(
                                format_args!(
                                    "invalid slot \'{0}\' for SP; must be \'active\' or \'inactive\'",
                                    v.unwrap(),
                                ),
                            );
                            res
                        }),
                    );
                }
                (SpComponent::ROT, Some("A" | "a" | "0")) => 0,
                (SpComponent::ROT, Some("B" | "b" | "1")) => 1,
                (SpComponent::ROT, None) => {
                    return ::anyhow::__private::Err({
                        let error = ::anyhow::__private::format_err(
                            format_args!("must provide slot (\'A\' or \'B\') for RoT"),
                        );
                        error
                    });
                }
                (SpComponent::ROT, v) => {
                    return ::anyhow::__private::Err(
                        ::anyhow::Error::msg({
                            let res = ::alloc::fmt::format(
                                format_args!(
                                    "invalid slot \'{0}\' for ROT, must be \'A\' or \'B\'",
                                    v.unwrap(),
                                ),
                            );
                            res
                        }),
                    );
                }
                (SpComponent::STAGE0, Some("A" | "a" | "0")) => 0,
                (SpComponent::STAGE0, Some("B" | "b" | "1")) => 1,
                (SpComponent::STAGE0, None) => {
                    return ::anyhow::__private::Err({
                        let error = ::anyhow::__private::format_err(
                            format_args!("must provide slot (\'A\' or \'B\') for Stage0"),
                        );
                        error
                    });
                }
                (SpComponent::STAGE0, v) => {
                    return ::anyhow::__private::Err(
                        ::anyhow::Error::msg({
                            let res = ::alloc::fmt::format(
                                format_args!(
                                    "invalid slot \'{0}\' for Stage0, must be \'A\' or \'B\'",
                                    v.unwrap(),
                                ),
                            );
                            res
                        }),
                    );
                }
                (c, _) => {
                    return ::anyhow::__private::Err({
                        let error = ::anyhow::__private::format_err(
                            format_args!("invalid component {0} for caboose", c),
                        );
                        error
                    });
                }
            };
            let value = sp.read_component_caboose(component, slot, key).await?;
            let out = if value.is_ascii() {
                String::from_utf8(value).unwrap()
            } else {
                hex::encode(value)
            };
            if json {
                Ok(
                    Output::Json(
                        ::serde_json::Value::Object({
                            let mut object = ::serde_json::Map::new();
                            let _ = object
                                .insert(
                                    ("value").into(),
                                    ::serde_json::to_value(&out).unwrap(),
                                );
                            object
                        }),
                    ),
                )
            } else {
                Ok(
                    Output::Lines(
                        <[_]>::into_vec(#[rustc_box] ::alloc::boxed::Box::new([out])),
                    ),
                )
            }
        }
        Command::ReadSensorValue { id } => {
            let out = sp.read_sensor_value(id).await?;
            Ok(
                if json {
                    Output::Json(
                        match out.value {
                            Ok(v) => {
                                ::serde_json::Value::Object({
                                    let mut object = ::serde_json::Map::new();
                                    let _ = object
                                        .insert(
                                            ("value").into(),
                                            ::serde_json::to_value(
                                                    &{
                                                        let res = ::alloc::fmt::format(format_args!("{0}", v));
                                                        res
                                                    },
                                                )
                                                .unwrap(),
                                        );
                                    let _ = object
                                        .insert(
                                            ("timestamp").into(),
                                            ::serde_json::to_value(&out.timestamp).unwrap(),
                                        );
                                    object
                                })
                            }
                            Err(e) => {
                                ::serde_json::Value::Object({
                                    let mut object = ::serde_json::Map::new();
                                    let _ = object
                                        .insert(
                                            ("error").into(),
                                            ::serde_json::to_value(
                                                    &{
                                                        let res = ::alloc::fmt::format(format_args!("{0:?}", e));
                                                        res
                                                    },
                                                )
                                                .unwrap(),
                                        );
                                    let _ = object
                                        .insert(
                                            ("timestamp").into(),
                                            ::serde_json::to_value(&out.timestamp).unwrap(),
                                        );
                                    object
                                })
                            }
                        },
                    )
                } else {
                    Output::Lines(
                        match out.value {
                            Ok(v) => {
                                <[_]>::into_vec(
                                    #[rustc_box]
                                    ::alloc::boxed::Box::new([
                                        {
                                            let res = ::alloc::fmt::format(
                                                format_args!("value:     {0}", v),
                                            );
                                            res
                                        },
                                        {
                                            let res = ::alloc::fmt::format(
                                                format_args!("timestamp: {0}", out.timestamp),
                                            );
                                            res
                                        },
                                    ]),
                                )
                            }
                            Err(e) => {
                                <[_]>::into_vec(
                                    #[rustc_box]
                                    ::alloc::boxed::Box::new([
                                        {
                                            let res = ::alloc::fmt::format(
                                                format_args!("error:     {0:?}", e),
                                            );
                                            res
                                        },
                                        {
                                            let res = ::alloc::fmt::format(
                                                format_args!("timestamp: {0}", out.timestamp),
                                            );
                                            res
                                        },
                                    ]),
                                )
                            }
                        },
                    )
                },
            )
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
                Ok(
                    Output::Json(
                        ::serde_json::Value::Object({
                            let mut object = ::serde_json::Map::new();
                            let _ = object
                                .insert(
                                    ("vpd_lock_status").into(),
                                    ::serde_json::to_value(&data).unwrap(),
                                );
                            object
                        }),
                    ),
                )
            } else {
                let mut out = ::alloc::vec::Vec::new();
                for b in data {
                    out.push({
                        let res = ::alloc::fmt::format(format_args!("{0:x?}", b));
                        res
                    });
                }
                Ok(Output::Lines(out))
            }
        }
    }
}
async fn monorail_unlock(
    log: &Logger,
    sp: &SingleSp,
    time_sec: u32,
    pub_key: Option<String>,
) -> Result<()> {
    let r = sp
        .component_action_with_response(
            SpComponent::MONORAIL,
            ComponentAction::Monorail(MonorailComponentAction::RequestChallenge),
        )
        .await?;
    let ComponentActionResponse::Monorail(
        MonorailComponentActionResponse::RequestChallenge(challenge),
    ) = r else {
        return ::anyhow::__private::Err({
            let error = ::anyhow::__private::format_err(
                format_args!("unexpected response: {0:?}", r),
            );
            error
        });
    };
    if ::slog::Level::Info.as_usize() <= ::slog::__slog_static_max_level().as_usize() {
        ::slog::Logger::log(
            &log,
            &{
                #[allow(dead_code)]
                static RS: ::slog::RecordStatic<'static> = {
                    static LOC: ::slog::RecordLocation = ::slog::RecordLocation {
                        file: "faux-mgs/src/main.rs",
                        line: 1487u32,
                        column: 5u32,
                        function: "",
                        module: "faux_mgs",
                    };
                    ::slog::RecordStatic {
                        location: &LOC,
                        level: ::slog::Level::Info,
                        tag: "",
                    }
                };
                ::slog::Record::new(
                    &RS,
                    &format_args!("received challenge {0:?}", challenge),
                    ::slog::BorrowedKV(&()),
                )
            },
        )
    }
    let response = match challenge {
        UnlockChallenge::Trivial { timestamp } => {
            UnlockResponse::Trivial {
                timestamp,
            }
        }
        UnlockChallenge::EcdsaSha2Nistp256(data) => {
            let Some(pub_key) = pub_key else {
                return ::anyhow::__private::Err({
                    let error = ::anyhow::__private::format_err(
                        format_args!("need --key for ECDSA challenge"),
                    );
                    error
                });
            };
            let pub_key = if pub_key.ends_with(".pub") {
                ssh_key::PublicKey::read_openssh_file(Path::new(&pub_key))
                    .with_context(|| {
                        {
                            let res = ::alloc::fmt::format(
                                format_args!("could not read key from {0:?}", pub_key),
                            );
                            res
                        }
                    })?
            } else {
                let keys = ssh_list_keys()?;
                let mut found = None;
                for k in keys.iter() {
                    if k.to_openssh()?.contains(&pub_key) {
                        if found.is_some() {
                            return ::anyhow::__private::Err({
                                let error = ::anyhow::__private::format_err(
                                    format_args!("multiple keys contain \'{0}\'", pub_key),
                                );
                                error
                            });
                        }
                        found = Some(k);
                    }
                }
                let Some(found) = found else {
                    return ::anyhow::__private::Err({
                        let error = ::anyhow::__private::format_err(
                            format_args!(
                                "could not match \'{0}\'; use `faux-mgs monorail unlock --list` to print keys",
                                pub_key,
                            ),
                        );
                        error
                    });
                };
                found.clone()
            };
            let mut data = data.as_bytes().to_vec();
            let signer_nonce: [u8; 8] = rand::random();
            data.extend(signer_nonce);
            let signed = ssh_keygen_sign(pub_key, &data)?;
            if ::slog::Level::Debug.as_usize()
                <= ::slog::__slog_static_max_level().as_usize()
            {
                ::slog::Logger::log(
                    &log,
                    &{
                        #[allow(dead_code)]
                        static RS: ::slog::RecordStatic<'static> = {
                            static LOC: ::slog::RecordLocation = ::slog::RecordLocation {
                                file: "faux-mgs/src/main.rs",
                                line: 1527u32,
                                column: 13u32,
                                function: "",
                                module: "faux_mgs",
                            };
                            ::slog::RecordStatic {
                                location: &LOC,
                                level: ::slog::Level::Debug,
                                tag: "",
                            }
                        };
                        ::slog::Record::new(
                            &RS,
                            &format_args!("got signature {0:?}", signed),
                            ::slog::BorrowedKV(&()),
                        )
                    },
                )
            }
            let key_bytes = signed.public_key().ecdsa().unwrap().as_sec1_bytes();
            match (&key_bytes.len(), &65) {
                (left_val, right_val) => {
                    if !(*left_val == *right_val) {
                        let kind = ::core::panicking::AssertKind::Eq;
                        ::core::panicking::assert_failed(
                            kind,
                            &*left_val,
                            &*right_val,
                            ::core::option::Option::Some(
                                format_args!("invalid key length"),
                            ),
                        );
                    }
                }
            };
            let mut key = [0u8; 65];
            key.copy_from_slice(key_bytes);
            let mut r = std::io::Cursor::new(signed.signature_bytes());
            use std::io::Read;
            let mut signature = [0u8; 64];
            for i in 0..2 {
                let mut size = [0u8; 4];
                r.read_exact(&mut size)?;
                match u32::from_be_bytes(size) {
                    32 => {}
                    33 => r.read_exact(&mut [0u8])?,
                    _ => {
                        return ::anyhow::__private::Err({
                            let error = ::anyhow::__private::format_err(
                                format_args!("invalid length {0}", i),
                            );
                            error
                        });
                    }
                }
                r.read_exact(&mut signature[i * 32..][..32])?;
            }
            UnlockResponse::EcdsaSha2Nistp256 {
                key,
                signer_nonce,
                signature,
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
fn ssh_keygen_sign(pub_key: ssh_key::PublicKey, data: &[u8]) -> Result<ssh_key::SshSig> {
    use ssh_key::{Algorithm, EcdsaCurve, HashAlg, SshSig};
    let sock = std::env::var("SSH_AUTH_SOCK")
        .context("could not read SSH_AUTH_SOCK environment variable")?;
    let sock_path = PathBuf::new().join(sock);
    let mut client = ssh_agent_client_rs::Client::connect(&sock_path)
        .with_context(|| "failed to connect to SSH agent on {sock_path:?}")?;
    const NAMESPACE: &str = "monorail-unlock";
    const HASH: HashAlg = HashAlg::Sha256;
    let blob = SshSig::signed_data(NAMESPACE, HASH, data)?;
    let sig = client.sign(&pub_key, &blob)?;
    let sig = SshSig::new(pub_key.into(), NAMESPACE, HASH, sig)?;
    match sig.algorithm() {
        Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 } => {}
        h => {
            return ::anyhow::__private::Err({
                let error = ::anyhow::__private::format_err(
                    format_args!("invalid signature algorithm {0:?}", h),
                );
                error
            });
        }
    }
    match sig.hash_alg() {
        HashAlg::Sha256 => {}
        h => {
            return ::anyhow::__private::Err({
                let error = ::anyhow::__private::format_err(
                    format_args!("invalid hash algorithm {0:?}", h),
                );
                error
            });
        }
    }
    Ok(sig)
}
fn handle_cxpa(
    name: &str,
    data: [u8; ROT_PAGE_SIZE],
    out: Option<PathBuf>,
    json: bool,
) -> Result<Output> {
    Ok(
        if let Some(f) = &out {
            std::fs::write(f, data)
                .context({
                    let res = ::alloc::fmt::format(
                        format_args!(
                            "failed to write {0} to {1:?}",
                            name.to_uppercase(),
                            f,
                        ),
                    );
                    res
                })?;
            if json {
                Output::Json(
                    ::serde_json::Value::Object({
                        let mut object = ::serde_json::Map::new();
                        let _ = object
                            .insert(("ok").into(), ::serde_json::Value::Bool(true));
                        object
                    }),
                )
            } else {
                Output::Lines(
                    <[_]>::into_vec(
                        #[rustc_box]
                        ::alloc::boxed::Box::new(["ok".to_string()]),
                    ),
                )
            }
        } else if json {
            Output::Json(
                ::serde_json::Value::Object({
                    let mut object = ::serde_json::Map::new();
                    let _ = object
                        .insert(
                            (name).into(),
                            ::serde_json::to_value(&data.to_vec()).unwrap(),
                        );
                    object
                }),
            )
        } else {
            Output::Lines(
                <[_]>::into_vec(
                    #[rustc_box]
                    ::alloc::boxed::Box::new([
                        {
                            let res = ::alloc::fmt::format(format_args!("{0:x?}", data));
                            res
                        },
                    ]),
                ),
            )
        },
    )
}
async fn update(
    log: &Logger,
    sp: &SingleSp,
    component: SpComponent,
    slot: u16,
    data: Vec<u8>,
) -> Result<()> {
    let update_id = Uuid::new_v4();
    if ::slog::Level::Info.as_usize() <= ::slog::__slog_static_max_level().as_usize() {
        ::slog::Logger::log(
            &log,
            &{
                #[allow(dead_code)]
                static RS: ::slog::RecordStatic<'static> = {
                    static LOC: ::slog::RecordLocation = ::slog::RecordLocation {
                        file: "faux-mgs/src/main.rs",
                        line: 1635u32,
                        column: 5u32,
                        function: "",
                        module: "faux_mgs",
                    };
                    ::slog::RecordStatic {
                        location: &LOC,
                        level: ::slog::Level::Info,
                        tag: "",
                    }
                };
                ::slog::Record::new(
                    &RS,
                    &format_args!("generated update ID"),
                    ::slog::BorrowedKV(
                        &(
                            ::slog::SingleKV::from((
                                "id",
                                format_args!("{0}", update_id),
                            )),
                            (),
                        ),
                    ),
                )
            },
        )
    }
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
                return ::anyhow::__private::Err({
                    let error = ::anyhow::__private::format_err(
                        format_args!("no update status returned by SP (did it reset?)"),
                    );
                    error
                });
            }
            UpdateStatus::Preparing(sub_status) => {
                if sub_status.id != sp_update_id {
                    return ::anyhow::__private::Err(
                        ::anyhow::Error::msg({
                            let res = ::alloc::fmt::format(
                                format_args!(
                                    "different update preparing ({0:?})",
                                    sub_status.id,
                                ),
                            );
                            res
                        }),
                    );
                }
                if let Some(progress) = sub_status.progress {
                    if ::slog::Level::Info.as_usize()
                        <= ::slog::__slog_static_max_level().as_usize()
                    {
                        ::slog::Logger::log(
                            &log,
                            &{
                                #[allow(dead_code)]
                                static RS: ::slog::RecordStatic<'static> = {
                                    static LOC: ::slog::RecordLocation = ::slog::RecordLocation {
                                        file: "faux-mgs/src/main.rs",
                                        line: 1655u32,
                                        column: 21u32,
                                        function: "",
                                        module: "faux_mgs",
                                    };
                                    ::slog::RecordStatic {
                                        location: &LOC,
                                        level: ::slog::Level::Info,
                                        tag: "",
                                    }
                                };
                                ::slog::Record::new(
                                    &RS,
                                    &format_args!(
                                        "update preparing: {0}/{1}",
                                        progress.current,
                                        progress.total,
                                    ),
                                    ::slog::BorrowedKV(&()),
                                )
                            },
                        )
                    }
                } else {
                    if ::slog::Level::Info.as_usize()
                        <= ::slog::__slog_static_max_level().as_usize()
                    {
                        ::slog::Logger::log(
                            &log,
                            &{
                                #[allow(dead_code)]
                                static RS: ::slog::RecordStatic<'static> = {
                                    static LOC: ::slog::RecordLocation = ::slog::RecordLocation {
                                        file: "faux-mgs/src/main.rs",
                                        line: 1662u32,
                                        column: 21u32,
                                        function: "",
                                        module: "faux_mgs",
                                    };
                                    ::slog::RecordStatic {
                                        location: &LOC,
                                        level: ::slog::Level::Info,
                                        tag: "",
                                    }
                                };
                                ::slog::Record::new(
                                    &RS,
                                    &format_args!("update preparing (no progress available)"),
                                    ::slog::BorrowedKV(&()),
                                )
                            },
                        )
                    }
                }
            }
            UpdateStatus::SpUpdateAuxFlashChckScan { id, found_match, total_size } => {
                if id != sp_update_id {
                    return ::anyhow::__private::Err(
                        ::anyhow::Error::msg({
                            let res = ::alloc::fmt::format(
                                format_args!("different update in progress ({0:?})", id),
                            );
                            res
                        }),
                    );
                }
                if ::slog::Level::Info.as_usize()
                    <= ::slog::__slog_static_max_level().as_usize()
                {
                    ::slog::Logger::log(
                        &log,
                        &{
                            #[allow(dead_code)]
                            static RS: ::slog::RecordStatic<'static> = {
                                static LOC: ::slog::RecordLocation = ::slog::RecordLocation {
                                    file: "faux-mgs/src/main.rs",
                                    line: 1673u32,
                                    column: 17u32,
                                    function: "",
                                    module: "faux_mgs",
                                };
                                ::slog::RecordStatic {
                                    location: &LOC,
                                    level: ::slog::Level::Info,
                                    tag: "",
                                }
                            };
                            ::slog::Record::new(
                                &RS,
                                &format_args!("aux flash scan complete"),
                                ::slog::BorrowedKV(
                                    &(
                                        ::slog::SingleKV::from(("total_size", total_size)),
                                        (::slog::SingleKV::from(("found_match", found_match)), ()),
                                    ),
                                ),
                            )
                        },
                    )
                }
            }
            UpdateStatus::InProgress(sub_status) => {
                if sub_status.id != sp_update_id {
                    return ::anyhow::__private::Err(
                        ::anyhow::Error::msg({
                            let res = ::alloc::fmt::format(
                                format_args!(
                                    "different update in progress ({0:?})",
                                    sub_status.id,
                                ),
                            );
                            res
                        }),
                    );
                }
                if ::slog::Level::Info.as_usize()
                    <= ::slog::__slog_static_max_level().as_usize()
                {
                    ::slog::Logger::log(
                        &log,
                        &{
                            #[allow(dead_code)]
                            static RS: ::slog::RecordStatic<'static> = {
                                static LOC: ::slog::RecordLocation = ::slog::RecordLocation {
                                    file: "faux-mgs/src/main.rs",
                                    line: 1683u32,
                                    column: 17u32,
                                    function: "",
                                    module: "faux_mgs",
                                };
                                ::slog::RecordStatic {
                                    location: &LOC,
                                    level: ::slog::Level::Info,
                                    tag: "",
                                }
                            };
                            ::slog::Record::new(
                                &RS,
                                &format_args!("update in progress"),
                                ::slog::BorrowedKV(
                                    &(
                                        ::slog::SingleKV::from((
                                            "total_size",
                                            sub_status.total_size,
                                        )),
                                        (
                                            ::slog::SingleKV::from((
                                                "bytes_received",
                                                sub_status.bytes_received,
                                            )),
                                            (),
                                        ),
                                    ),
                                ),
                            )
                        },
                    )
                }
            }
            UpdateStatus::Complete(id) => {
                if id != sp_update_id {
                    return ::anyhow::__private::Err({
                        let error = ::anyhow::__private::format_err(
                            format_args!("different update complete ({0:?})", id),
                        );
                        error
                    });
                }
                return Ok(());
            }
            UpdateStatus::Aborted(id) => {
                if id != sp_update_id {
                    return ::anyhow::__private::Err({
                        let error = ::anyhow::__private::format_err(
                            format_args!("different update aborted ({0:?})", id),
                        );
                        error
                    });
                }
                return ::anyhow::__private::Err({
                    let error = ::anyhow::__private::format_err(
                        format_args!("update aborted"),
                    );
                    error
                });
            }
            UpdateStatus::Failed { id, code } => {
                if id != sp_update_id {
                    return ::anyhow::__private::Err({
                        let error = ::anyhow::__private::format_err(
                            format_args!(
                                "different update failed ({0:?}, code {1})",
                                id,
                                code,
                            ),
                        );
                        error
                    });
                }
                return ::anyhow::__private::Err({
                    let error = ::anyhow::__private::format_err(
                        format_args!("update failed (code {0})", code),
                    );
                    error
                });
            }
            UpdateStatus::RotError { id, error } => {
                if id != sp_update_id {
                    return ::anyhow::__private::Err({
                        let error = ::anyhow::__private::format_err(
                            format_args!(
                                "different update failed ({0:?}, error {1:?})",
                                id,
                                error,
                            ),
                        );
                        error
                    });
                }
                return ::anyhow::__private::Err({
                    let error = ::anyhow::__private::format_err(
                        format_args!("update failed (error {0:?})", error),
                    );
                    error
                });
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
    let dir_iter = fs::read_dir(path)
        .with_context(|| {
            {
                let res = ::alloc::fmt::format(
                    format_args!(
                        "failed to open directory for reading: {0}",
                        path.display(),
                    ),
                );
                res
            }
        })?;
    for entry in dir_iter {
        let entry = entry
            .with_context(|| {
                {
                    let res = ::alloc::fmt::format(
                        format_args!(
                            "failed to read directory entry in {0}",
                            path.display(),
                        ),
                    );
                    res
                }
            })?;
        let entry_path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| {
                {
                    let res = ::alloc::fmt::format(
                        format_args!(
                            "failed to read file type of {0}",
                            entry_path.display(),
                        ),
                    );
                    res
                }
            })?;
        if file_type.is_symlink() {
            let meta = fs::metadata(&entry_path)
                .with_context(|| {
                    {
                        let res = ::alloc::fmt::format(
                            format_args!(
                                "failed to metadata of {0}",
                                entry_path.display(),
                            ),
                        );
                        res
                    }
                })?;
            if !meta.file_type().is_file() {
                continue;
            }
        } else if !file_type.is_file() {
            continue;
        }
        let data = fs::read(&entry_path)
            .with_context(|| {
                {
                    let res = ::alloc::fmt::format(
                        format_args!("failed to read {0}", entry_path.display()),
                    );
                    res
                }
            })?;
        match cache.insert(data).await {
            Ok(hash) => {
                if ::slog::Level::Info.as_usize()
                    <= ::slog::__slog_static_max_level().as_usize()
                {
                    ::slog::Logger::log(
                        &log,
                        &{
                            #[allow(dead_code)]
                            static RS: ::slog::RecordStatic<'static> = {
                                static LOC: ::slog::RecordLocation = ::slog::RecordLocation {
                                    file: "faux-mgs/src/main.rs",
                                    line: 1754u32,
                                    column: 17u32,
                                    function: "",
                                    module: "faux_mgs",
                                };
                                ::slog::RecordStatic {
                                    location: &LOC,
                                    level: ::slog::Level::Info,
                                    tag: "",
                                }
                            };
                            ::slog::Record::new(
                                &RS,
                                &format_args!("added phase2 image to server cache"),
                                ::slog::BorrowedKV(
                                    &(
                                        ::slog::SingleKV::from(("path", entry_path.display())),
                                        (::slog::SingleKV::from(("hash", hex::encode(hash))), ()),
                                    ),
                                ),
                            )
                        },
                    )
                }
            }
            Err(err) => {
                if ::slog::Level::Warning.as_usize()
                    <= ::slog::__slog_static_max_level().as_usize()
                {
                    ::slog::Logger::log(
                        &log,
                        &{
                            #[allow(dead_code)]
                            static RS: ::slog::RecordStatic<'static> = {
                                static LOC: ::slog::RecordLocation = ::slog::RecordLocation {
                                    file: "faux-mgs/src/main.rs",
                                    line: 1761u32,
                                    column: 17u32,
                                    function: "",
                                    module: "faux_mgs",
                                };
                                ::slog::RecordStatic {
                                    location: &LOC,
                                    level: ::slog::Level::Warning,
                                    tag: "",
                                }
                            };
                            ::slog::Record::new(
                                &RS,
                                &format_args!("skipping file (not a phase2 image?)"),
                                ::slog::BorrowedKV(
                                    &(
                                        err,
                                        (::slog::SingleKV::from(("path", entry_path.display())), ()),
                                    ),
                                ),
                            )
                        },
                    )
                }
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
    #[serde(tag = "kind")]
    enum ComponentDetails {
        PortStatus(Result<PortStatus, PortStatusError>),
        Measurement(Measurement),
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl _serde::Serialize for ComponentDetails {
            fn serialize<__S>(
                &self,
                __serializer: __S,
            ) -> _serde::__private::Result<__S::Ok, __S::Error>
            where
                __S: _serde::Serializer,
            {
                match *self {
                    ComponentDetails::PortStatus(ref __field0) => {
                        _serde::__private::ser::serialize_tagged_newtype(
                            __serializer,
                            "ComponentDetails",
                            "PortStatus",
                            "kind",
                            "PortStatus",
                            __field0,
                        )
                    }
                    ComponentDetails::Measurement(ref __field0) => {
                        _serde::__private::ser::serialize_tagged_newtype(
                            __serializer,
                            "ComponentDetails",
                            "Measurement",
                            "kind",
                            "Measurement",
                            __field0,
                        )
                    }
                }
            }
        }
    };
    struct Measurement {
        pub name: String,
        pub kind: MeasurementKind,
        pub value: Result<f32, MeasurementError>,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl _serde::Serialize for Measurement {
            fn serialize<__S>(
                &self,
                __serializer: __S,
            ) -> _serde::__private::Result<__S::Ok, __S::Error>
            where
                __S: _serde::Serializer,
            {
                let mut __serde_state = _serde::Serializer::serialize_struct(
                    __serializer,
                    "Measurement",
                    false as usize + 1 + 1 + 1,
                )?;
                _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "name",
                    &self.name,
                )?;
                _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "kind",
                    &self.kind,
                )?;
                _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "value",
                    &self.value,
                )?;
                _serde::ser::SerializeStruct::end(__serde_state)
            }
        }
    };
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
    ::serde_json::Value::Object({
        let mut object = ::serde_json::Map::new();
        let _ = object
            .insert(("entries").into(), ::serde_json::to_value(&entries).unwrap());
        object
    })
}
