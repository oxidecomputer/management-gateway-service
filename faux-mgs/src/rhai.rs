// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use gateway_sp_comms::SingleSp;
use slog::{crit, debug, error, info, trace, warn, Logger};

use gateway_messages::{SpComponent, RotBootInfo};
use rhai::packages::{MoreStringPackage, Package};
use rhai::{Dynamic, Engine, EvalAltResult, NativeCallContext, Scope};
use rhai_chrono::ChronoPackage;
use rhai_env::EnvironmentPackage;
use rhai_fs::FilesystemPackage;
use std::sync::Arc;

fn read_cmpa(
    context: NativeCallContext,
    sp: Arc<SingleSp>,
    rt: tokio::runtime::Handle,
) -> Result<Dynamic, Box<EvalAltResult>> {
    rt.block_on(async {
        match sp.read_rot_cmpa().await {
            Ok(v) => Ok(serde_json::from_value::<Dynamic>(v.into()).map_err(
                |e| {
                    Box::new(EvalAltResult::ErrorRuntime(
                        format!("{}", e).into(),
                        context.call_position(),
                    ))
                },
            )?),
            Err(e) => Err(Box::new(EvalAltResult::ErrorRuntime(
                format!("{}", e).into(),
                context.call_position(),
            ))),
        }
    })
}

fn read_cfpa(
    context: NativeCallContext,
    sp: Arc<SingleSp>,
    rt: tokio::runtime::Handle,
) -> Result<Dynamic, Box<EvalAltResult>> {
    rt.block_on(async {
        match sp.read_rot_active_cfpa().await {
            Ok(v) => Ok(serde_json::from_value::<Dynamic>(v.into()).map_err(
                |e| {
                    Box::new(EvalAltResult::ErrorRuntime(
                        format!("{}", e).into(),
                        context.call_position(),
                    ))
                },
            )?),
            Err(e) => Err(Box::new(EvalAltResult::ErrorRuntime(
                format!("{}", e).into(),
                context.call_position(),
            ))),
        }
    })
}

fn start_host_flash_hash(
    context: NativeCallContext,
    sp: Arc<SingleSp>,
    rt: tokio::runtime::Handle,
    slot: u16,
) -> Result<Dynamic, Box<EvalAltResult>> {
    rt.block_on(async {
        match sp.start_host_flash_hash(slot).await {
            Ok(v) => Ok(serde_json::from_value::<Dynamic>(v.into()).map_err(
                |e| {
                    Box::new(EvalAltResult::ErrorRuntime(
                        format!("{}", e).into(),
                        context.call_position(),
                    ))
                },
            )?),
            Err(e) => Err(Box::new(EvalAltResult::ErrorRuntime(
                format!("{}", e).into(),
                context.call_position(),
            ))),
        }
    })
}

fn get_host_flash_hash(
    context: NativeCallContext,
    sp: Arc<SingleSp>,
    rt: tokio::runtime::Handle,
    slot: u16,
) -> Result<Dynamic, Box<EvalAltResult>> {
    rt.block_on(async {
        match sp.get_host_flash_hash(slot).await {
            Ok(v) => Ok(serde_json::from_value::<Dynamic>(v.into()).map_err(
                |e| {
                    Box::new(EvalAltResult::ErrorRuntime(
                        format!("{}", e).into(),
                        context.call_position(),
                    ))
                },
            )?),
            Err(e) => Err(Box::new(EvalAltResult::ErrorRuntime(
                format!("{}", e).into(),
                context.call_position(),
            ))),
        }
    })
}

fn reset_component(
    context: NativeCallContext,
    sp: Arc<SingleSp>,
    rt: tokio::runtime::Handle,
    component: &str,
) -> Result<Dynamic, Box<EvalAltResult>> {
    let component = SpComponent::try_from(component).map_err(|e| {
        Box::new(EvalAltResult::ErrorRuntime(
            format!("{:?}", e).into(),
            context.call_position(),
        ))
    })?;
    rt.block_on(async {
        sp.reset_component_prepare(component).await.map_err(|e| {
            Box::new(EvalAltResult::ErrorRuntime(
                format!("{}", e).into(),
                context.call_position(),
            ))
        })?;

        sp.reset_component_trigger(component, false).await.map_err(|e| {
            Box::new(EvalAltResult::ErrorRuntime(
                format!("{}", e).into(),
                context.call_position(),
            ))
        })?;
        Ok(().into())
    })
}

/// Use a Rhai interpreter per SingleSp that can maintain a connection.
pub async fn interpreter(
    sp: Arc<SingleSp>,
    log: Logger,
    script: PathBuf,
    script_args: Vec<String>,
) -> Result<()> {
    let thread_log = log.clone();
    let rot_info_rt = tokio::runtime::Handle::current();
    let cfpa_rt = tokio::runtime::Handle::current();
    let cmpa_rt = tokio::runtime::Handle::current();
    let start_host_flash_hash_rt = tokio::runtime::Handle::current();
    let get_host_flash_hash_rt = tokio::runtime::Handle::current();
    let reset_component_rt = tokio::runtime::Handle::current();
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

        // Additional string functions
        let package = MoreStringPackage::new();
        package.register_into_engine(&mut engine);

        // Setup env access for scripts
        let package = EnvironmentPackage::new();
        package.register_into_engine(&mut engine);

        // Don't limit resources for now.
        engine.set_max_expr_depths(0, 0);

        // Compile the script
        let program = match std::fs::read_to_string(&script) {
            Ok(content) => content,
            Err(e) => {
                return Err(anyhow!(
                    "failed to read {}: {}",
                    script.display(),
                    e
                ));
            }
        };

        let script_file_name: String =
            script.file_name().unwrap().to_string_lossy().into();

        // Construct argv for the script and canonicalize the script path.
        let pb = std::fs::canonicalize(&script)
            .context("Cannot canonicalize {&script}")?;
        let script_dir = pb
            .parent()
            .context("Cannot get parent dir of {&script}")?
            .display()
            .to_string();
        let argv0 = pb.display().to_string();

        let rot_info_sp = sp.clone();
        engine.register_fn("rot_boot_info", move |context: NativeCallContext| -> Result<Dynamic, Box<EvalAltResult>> {
            rot_info_rt
                .block_on(async {
                    match rot_info_sp.rot_state(3).await {
                        Ok(v) => {
                            let j = serde_json::to_value(v).map_err(|e| Box::new(EvalAltResult::ErrorRuntime(format!("{}", e).into(), context.call_position())))?;
                            Ok(serde_json::from_value::<Dynamic>(j).map_err(|e| Box::new(EvalAltResult::ErrorRuntime(format!("{}", e).into(), context.call_position())))?)
                        }
                        Err(e) => Err(Box::new(EvalAltResult::ErrorRuntime(format!("{}", e).into(), context.call_position())))
                    }
                })
        });

        let cmpa_sp = sp.clone();
        engine.register_fn(
            "read_cmpa",
            move |context: NativeCallContext| -> Result<Dynamic, Box<EvalAltResult>> {
                read_cmpa(context, cmpa_sp.clone(), cmpa_rt.clone())
            },
        );

        let cfpa_sp = sp.clone();
        engine.register_fn(
            "read_cfpa",
            move |context: NativeCallContext| -> Result<Dynamic, Box<EvalAltResult>> {
                read_cfpa(context, cfpa_sp.clone(), cfpa_rt.clone())
            },
        );

        let start_host_flash_hash_sp = sp.clone();
        engine.register_fn(
            "start_host_flash_hash",
            move |context: NativeCallContext,
                  slot: i64|
                  -> Result<Dynamic, Box<EvalAltResult>> {
                start_host_flash_hash(
                    context,
                    start_host_flash_hash_sp.clone(),
                    start_host_flash_hash_rt.clone(),
                    slot as u16,
                )
            },
        );

        let get_host_flash_hash_sp = sp.clone();
        engine.register_fn(
            "get_host_flash_hash",
            move |context: NativeCallContext,
                  slot: i64|
                  -> Result<Dynamic, Box<EvalAltResult>> {
                get_host_flash_hash(
                    context,
                    get_host_flash_hash_sp.clone(),
                    get_host_flash_hash_rt.clone(),
                    slot as u16,
                )
            },
        );

        let reset_component_sp = sp.clone();
        engine.register_fn(
            "reset_component",
            move |context: NativeCallContext,
                  component: &str|
                  -> Result<Dynamic, Box<EvalAltResult>> {
                reset_component(
                    context,
                    reset_component_sp.clone(),
                    reset_component_rt.clone(),
                    component,
                )
            },
        );

        let rhai_log = log.clone();
        engine.on_debug(move |x, src, pos| {
            let src: String = if let Some(src) = src {
                std::path::Path::new(src)
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into()
            } else {
                script_file_name.clone().into()
            };
            let location = format!("{src}@{pos:?}");
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
            let msg = format!("{location} {msg}");
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

        match engine.compile(program) {
            Ok(ast) => {
                // These variables are visible in the script main()
                let mut scope = Scope::new();
                let mut argv = vec![];
                argv.push(argv0);
                argv.extend(script_args);
                scope.push_dynamic("script_dir", script_dir.into());
                scope.push_dynamic("argv", argv.clone().into());
                scope.push_dynamic(
                    "rbi_default",
                    RotBootInfo::HIGHEST_KNOWN_VERSION.to_string().into(),
                );
                match engine.call_fn::<i64>(&mut scope, &ast, "main", ()) {
                    Ok(_) => Ok(()),
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

    match handle.join() {
        Ok(result) => result,
        Err(err) => Err(anyhow!("{:?}", err)),
    }
}
