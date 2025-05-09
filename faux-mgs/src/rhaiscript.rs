// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use slog::crit;
use slog::error;
use slog::trace;

use crate::{anyhow, debug, info, warn};
use crate::{
    fs, json, run_command, Context, Logger, Output, PathBuf, Result, RhaiArgs,
    RotBootInfo, SingleSp,
};
use clap::Parser;

use async_recursion::async_recursion;
use rhai::packages::Package;
use rhai::{
    Array, Dynamic, Engine, EvalAltResult, ImmutableString, Map,
    NativeCallContext, Scope,
};
use rhai_chrono::ChronoPackage;
use rhai_env::EnvironmentPackage;
use rhai_fs::FilesystemPackage;

mod hubris;

/// Use a Rhai interpreter per SingleSp that can maintain a connection.
#[async_recursion]
pub async fn interpreter(
    sp: &SingleSp,
    log: Logger,
    script: PathBuf,
    script_args: Vec<String>,
) -> Result<Output> {
    // Channel: Script -> Master
    let (tx_script, rx_master) = std::sync::mpsc::sync_channel::<String>(1);
    // Channel: Master -> Script
    let (tx_master, rx_script) = std::sync::mpsc::sync_channel::<String>(1);

    let interface = sp.interface().to_string().to_owned();
    let reset_watchdog_timeout_ms = sp.reset_watchdog_timeout_ms() as i64;

    let thread_log = log.clone();
    let handle = std::thread::spawn(move || {
        let log = thread_log;
        // Create Engine
        let mut engine = Engine::new();

        // Setup file system access for scripts
        let package = FilesystemPackage::new();
        package.register_into_engine(&mut engine);

        // Standard date formats
        let package = ChronoPackage::new();
        package.register_into_engine(&mut engine);

        // Setup env access for scripts
        let package = EnvironmentPackage::new();
        package.register_into_engine(&mut engine);

        // Don't limit resources for now.
        engine.set_max_expr_depths(0, 0);

        // Access RawHubrisArchives and their Cabooses
        engine.build_type::<hubris::ArchiveInspector>();
        engine.build_type::<hubris::CabooseInspector>();
        engine.register_fn("system", system);

        // Compile the script
        let program = match fs::read_to_string(&script) {
            Ok(content) => content,
            Err(e) => {
                return Err(anyhow!(
                    "failed to read {}: {}",
                    script.display(),
                    e
                ));
            }
        };

        // Construct argv for the script and canonicalize the script path.
        let pb = fs::canonicalize(&script)
            .context("Cannot canonicalize {&script}")?;
        let script_dir = pb
            .parent()
            .context("Cannot get parent dir of {&script}")?
            .display()
            .to_string();
        let argv0 = pb.display().to_string();

        engine
            // faux_mgs thread consumes and produces JSON
            .register_fn("faux_mgs", move |v: Array| -> Dynamic {
                match tx_script.send(serde_json::to_string(&v).unwrap()) {
                    Ok(()) => match rx_script.recv() {
                        Ok(v) => {
                            // println!("RECEIVED Ok: \"{:?}\"", v);
                            serde_json::from_str::<Dynamic>(&v).unwrap()
                        }
                        Err(e) => {
                            // println!("RECEIVED Ok(Err): \"{:?}\"", v);
                            let err = format!("{{\"error\": \"{:?}\"}}", e)
                                .to_string();
                            serde_json::from_str::<Dynamic>(&err).unwrap()
                        }
                    },
                    Err(e) => {
                        // println!("RECEIVED Err: \"{:?}\"", v);
                        let err =
                            format!("{{\"error\": \"{:?}\"}}", e).to_string();
                        serde_json::from_str::<Dynamic>(&err).unwrap()
                    }
                }
            })
            // Offer proper JSON to Dynamic::Map conversion
            .register_fn("json_to_map", move |v: Dynamic| -> Dynamic {
                match v.clone().into_string() {
                    Ok(s) => match serde_json::from_str::<Dynamic>(&s) {
                        Ok(v) => v,
                        Err(e) => {
                            let err = json!(e.to_string()).to_string();
                            serde_json::from_str::<Dynamic>(&err).unwrap()
                        }
                    },
                    Err(e) => {
                        let err =
                            format!("{{\"error\": \"{:?}\"}}", e).to_string();
                        serde_json::from_str::<Dynamic>(&err).unwrap()
                    }
                }
            });

        // A script can log via debug at any level:
        //   debug("INFO|log message at INFO level");
        //   debug("CRIT|log message at CRIT level");
        // etc.
        let rhai_log = log.clone();
        engine.on_debug(move |x, src, pos| {
            let src = if src.is_some() {
                format!("{}@", src.unwrap())
            } else {
                "".to_string()
            };
            let x: Vec<&str> = x.trim_matches('"').splitn(2, '|').collect();
            let (level, msg) = if x.len() == 1 {
                ("info".to_string(), x[0].to_string())
            } else {
                let level = x[0].to_string().to_lowercase();
                let msg = x[1].to_string();
                match level.as_str() {
                    "trace" => ("trace".to_string(), msg),
                    "debug" => ("debug".to_string(), msg),
                    "info" => ("info".to_string(), msg),
                    "warn" => ("warn".to_string(), msg),
                    "error" => ("error".to_string(), msg),
                    "crit" => ("crit".to_string(), msg),
                    _ => ("debug".to_string(), format!("{}|{}", level, msg)),
                }
            };
            let src = if src.is_empty() {
                format!("{}@", src)
            } else {
                "".to_string()
            };
            let msg = format!("{}pos={:?} {}", src, pos, msg);
            match level.as_str() {
                "crit" => crit!(rhai_log, "{msg}"),
                "debug" => debug!(rhai_log, "{msg}"),
                "error" => error!(rhai_log, "{msg}"),
                "info" => info!(rhai_log, "{msg}"),
                "trace" => trace!(rhai_log, "{msg}"),
                "warn" => warn!(rhai_log, "{msg}"),
                _ => unreachable!(),
            }
        });

        // Print registered functions if you're interested.
        // engine.gen_fn_signatures(false).into_iter().for_each(|func| println!("{func}"));

        match engine.compile(program) {
            Ok(ast) => {
                // These variables are visible in the script main()
                let mut scope = Scope::new();
                let mut argv = vec![];
                argv.push(argv0);
                argv.extend(script_args);
                scope.push_dynamic("argv", argv.clone().into());
                scope.push_dynamic(
                    "rbi_default",
                    RotBootInfo::HIGHEST_KNOWN_VERSION.to_string().into(),
                );
                scope.push_dynamic("script_dir", script_dir.into());
                scope.push_dynamic("interface", interface.into());
                scope.push_dynamic(
                    "reset_watchdog_timeout_ms",
                    reset_watchdog_timeout_ms.into(),
                );
                match engine.call_fn::<i64>(&mut scope, &ast, "main", ()) {
                    Ok(exit_value) => {
                        Ok(Output::Json(json!({"exit": exit_value})))
                    }
                    Err(err) => Err(anyhow!("{err}")),
                }
            }
            Err(e) => Err(anyhow!(format!(
                "failed to parse {}: {:?}",
                &script.display(),
                e
            ))),
        }
    });

    while let Ok(command_args) = rx_master.recv() {
        // Service the script's calls to "faux_mgs".
        // The script can only send arrays of string and i64 values.
        let response = if let Ok(serde_json::Value::Array(script_args)) =
            serde_json::from_str(&command_args)
        {
            // TODO: Check for non-string non-i64 values in the
            // script_args and return an error instead of executing the faux-mgs
            // command.
            let faux_mgs_args: Vec<String> = script_args
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(|s| s.to_string())
                        .or_else(|| v.as_i64().map(|i| i.to_string()))
                        .unwrap()
                })
                .collect();
            debug!(log, "vec string: {:?}", faux_mgs_args);
            let mut ra = vec![];
            // The clap crate is expecting ARGV[0] as the program name, insert a dummy.
            ra.push("faux-mgs".to_string());
            ra.append(&mut faux_mgs_args.clone());

            let args = RhaiArgs::parse_from(&ra);
            match run_command(sp, args.command.clone(), true, log.clone()).await
            {
                Ok(Output::Json(json)) => {
                    // Turn all results into a map for easy digestion
                    // println!("RESULT: Ok: {:?}", &json);
                    let obj = match json {
                        serde_json::Value::Object(map) => map,
                        _ => json!({ "Ok": json })
                            .as_object()
                            .unwrap()
                            .to_owned(),
                    };
                    match serde_json::to_string(&obj) {
                        Ok(s) => s,
                        // More verbose code, but don't need to worry about quoting.
                        Err(e) => serde_json::to_string(json!({
                                "Err": serde_json::Value::String(format!("{:?}", e))
                            }).as_object().unwrap()).unwrap(),
                    }
                }
                Ok(Output::Lines(_)) => {
                    // The --json=pretty option is hard-coded
                    unreachable!();
                }
                Err(e) => {
                    // println!("RESULT: Err: {:?}", &e);
                    format!("{{\"error\": \"failed\", \"message\": \"{}\"}}", e)
                }
            }
        } else {
            "{{\"error\": \"cannot serialize faux_mgs args to json\"}}"
                .to_string()
        };
        if tx_master.send(response).is_err() {
            break;
        }
    }

    match handle.join() {
        Ok(result) => result,
        Err(err) => Err(anyhow!("{:?}", err)),
    }
}

//
// This function was generated with the following prompt to
// gemini.google.com:
//
// Write a Rust function, `system`, that can be registered with the Rhai
// scripting engine. The function should take an array of strings (`Array`)
// as input, representing a command and its arguments, execute the command
// using `std::process::Command`, and return a Rhai `Map` containing the
// command's exit code, standard output, and standard error.
//
// The function should handle the following:
//
// * Convert the input `Array` to a `Vec<String>`.
// * Handle errors if the input `Array` is empty or if any element cannot
//   be converted to a `String`.
// * Use `std::process::Command` with fully qualified names (e.g.,
//   `std::process::Command::new`).
// * Capture the command's standard output and standard error using
//   `std::process::Stdio::piped()`.
// * Convert the captured output to Rhai `ImmutableString` values using
//   `String::from_utf8_lossy`.
// * Return a Rhai `Map` with the keys "exit_code", "stdout", and "stderr".
// * Handle errors during command execution and output capture.
// * Use `EvalAltResult::ErrorInFunctionCall` for function call errors and
//   `EvalAltResult::ErrorRuntime` for runtime errors.
// * Ensure that error messages passed to `EvalAltResult::ErrorRuntime`
//   are converted to `Dynamic` using `.into()`.
// * Place the underlying error in the third position of the
//   `EvalAltResult::ErrorInFunctionCall` variant.
// * Use `context.position()` to get the error position.
// * Do not use the `mut` keyword on the `child` variable when calling
//   `command.spawn()`.
//
// Provide a complete Rust code example that includes the `system` function
// and a `main` function that registers it with a Rhai engine and runs a
// sample Rhai script.

/// Allow Rhai scripts to run a command and capture the stdout, stderr, and
/// exit code.
fn system(
    context: NativeCallContext,
    argv: Array,
) -> Result<Map, Box<EvalAltResult>> {
    let mut string_argv: Vec<String> = Vec::new();
    for arg in argv.iter() {
        match arg.clone().into_string() {
            Ok(s) => string_argv.push(s),
            Err(_) => {
                return Err(Box::new(EvalAltResult::ErrorRuntime(
                    "Arguments must be strings.".into(),
                    context.position(),
                )));
            }
        }
    }

    if string_argv.is_empty() {
        return Err(Box::new(EvalAltResult::ErrorInFunctionCall(
            "system".to_string(),
            "Expected at least one argument.".to_string(),
            Box::new(EvalAltResult::ErrorRuntime(
                "".into(),
                context.position(),
            )),
            context.position(),
        )));
    }

    let command_name = &string_argv[0];
    let args = &string_argv[1..];

    let mut command = std::process::Command::new(command_name);
    command.args(args);

    command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let output = match command.spawn() {
        Ok(child) => child.wait_with_output(),
        Err(e) => {
            return Err(Box::new(EvalAltResult::ErrorRuntime(
                format!("Failed to spawn command: {}", e).into(),
                context.position(),
            )));
        }
    };

    let output = match output {
        Ok(output) => output,
        Err(e) => {
            return Err(Box::new(EvalAltResult::ErrorRuntime(
                format!("Failed to get command output: {}", e).into(),
                context.position(),
            )));
        }
    };

    let exit_code = output.status.code().unwrap_or(-1) as i64;
    let stdout = ImmutableString::from(
        String::from_utf8_lossy(&output.stdout).to_string(),
    );
    let stderr = ImmutableString::from(
        String::from_utf8_lossy(&output.stderr).to_string(),
    );

    let mut result = Map::new();
    result.insert("exit_code".into(), exit_code.into());
    result.insert("stdout".into(), stdout.into());
    result.insert("stderr".into(), stderr.into());

    Ok(result)
}
