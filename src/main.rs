use cascade::{
    center::{self, Center},
    comms::ApplicationCommand,
    config::{Config, SocketConfig},
    daemon::{daemonize, SocketProvider},
    manager::{self, TargetCommand},
    policy,
};
use clap::{crate_authors, crate_version};
use std::{
    io,
    net::SocketAddr,
    process::ExitCode,
    sync::{Arc, Mutex},
};
use tokio::sync::mpsc;

const MAX_SYSTEMD_FD_SOCKETS: usize = 32;

fn main() -> ExitCode {
    // Initialize the logger in fallback mode.
    let logger = cascade::log::Logger::launch();

    // Set up the command-line interface.
    let cmd = clap::Command::new("cascade")
        .version(crate_version!())
        .author(crate_authors!())
        .next_line_help(true)
        .arg(
            clap::Arg::new("check_config")
                .long("check-config")
                .action(clap::ArgAction::SetTrue)
                .help("Check the configuration and exit"),
        );
    let cmd = Config::setup_cli(cmd);

    // Process command-line arguments.
    let matches = cmd.get_matches();

    // Construct the configuration.
    let mut config = match Config::init(&matches) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("Cascade couldn't be configured: {error}");
            return ExitCode::FAILURE;
        }
    };

    if matches.get_flag("check_config") {
        // Try reading the configuration file.
        match config.init_from_file() {
            Ok(()) => return ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("Cascade couldn't be configured: {error}");
                return ExitCode::FAILURE;
            }
        }
    }

    // Load the global state file or build one from scratch.
    let mut state = center::State::new(config);
    if let Err(err) = state.init_from_file() {
        if err.kind() != io::ErrorKind::NotFound {
            log::error!("Could not load the state file: {err}");
            return ExitCode::FAILURE;
        }

        log::info!("State file not found; starting from scratch");

        // Load the configuration file from scratch.
        if let Err(err) = state.config.init_from_file() {
            log::error!("Cascade couldn't be configured: {err}");
            return ExitCode::FAILURE;
        }

        // Load all policies.
        if let Err(err) = policy::reload_all(&mut state.policies, &state.config) {
            log::error!("Cascade couldn't load all policies: {err}");
            return ExitCode::FAILURE;
        }

        // TODO: Fail if any zone state files exist.
    } else {
        log::info!("Successfully loaded the global state file");

        let zone_state_dir = &state.config.zone_state_dir;
        let policies = &mut state.policies;
        for zone in &state.zones {
            let name = &zone.0.name;
            let path = zone_state_dir.join(format!("{name}.db"));
            let spec = match cascade::zone::state::Spec::load(&path) {
                Ok(spec) => {
                    log::debug!("Loaded state of zone '{name}' (from {path})");
                    spec
                }
                Err(err) => {
                    log::error!("Failed to load zone state '{name}' from '{path}': {err}");
                    return ExitCode::FAILURE;
                }
            };
            let mut state = zone.0.state.lock().unwrap();
            spec.parse_into(&zone.0, &mut state, policies);
        }
    }

    // Load the TSIG store file.
    //
    // TODO: Track which TSIG keys are in use by zones.
    match state.tsig_store.init_from_file(&state.config) {
        Ok(()) => log::debug!("Loaded the TSIG store"),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            log::debug!("No TSIG store found; will create one");
        }
        Err(err) => {
            log::error!("Failed to load the TSIG store: {err}");
            return ExitCode::FAILURE;
        }
    }

    logger.apply(
        logger
            .prepare(&state.config.daemon.logging)
            .unwrap()
            .unwrap(),
    );

    let mut socket_provider = SocketProvider::new();

    if state.config.daemon.accept_systemd_sockets {
        socket_provider.init_from_env(Some(MAX_SYSTEMD_FD_SOCKETS));
    }

    fn pre_bind_server_sockets<'a, T: Iterator<Item = &'a SocketConfig>>(
        socket_provider: &mut SocketProvider,
        socket_configs: T,
    ) -> Result<(), (&'static str, SocketAddr, std::io::Error)> {
        for socket_config in socket_configs {
            match socket_config {
                SocketConfig::UDP { addr } => socket_provider.pre_bind_udp(*addr)?,
                SocketConfig::TCP { addr } => socket_provider.pre_bind_tcp(*addr)?,
                SocketConfig::TCPUDP { addr } => {
                    socket_provider.pre_bind_udp(*addr)?;
                    socket_provider.pre_bind_tcp(*addr)?;
                }
            }
        }
        Ok(())
    }

    let http_tcp_sock_addrs: Vec<_> = state
        .config
        .http
        .servers
        .iter()
        .map(|&addr| SocketConfig::TCP { addr }).collect();

    let socket_configs = state
        .config
        .loader
        .review
        .servers
        .iter()
        .chain(state.config.signer.review.servers.iter())
        .chain(state.config.server.servers.iter())
        .chain(http_tcp_sock_addrs.iter());

    if let Err((socket_type, addr, err)) =
        pre_bind_server_sockets(&mut socket_provider, socket_configs)
    {
        log::error!("Failed to pre-bind to {socket_type} {addr} before daemonizing: {err}");
        return ExitCode::FAILURE;
    }

    if let Err(err) = daemonize(&state.config.daemon) {
        log::error!("Failed to daemonize: {err}");
        return ExitCode::FAILURE;
    }

    // Prepare Cascade.
    let (app_cmd_tx, mut app_cmd_rx) = mpsc::unbounded_channel();
    let (update_tx, update_rx) = mpsc::unbounded_channel();
    let center = Arc::new(Center {
        state: Mutex::new(state),
        logger,
        unsigned_zones: Default::default(),
        signed_zones: Default::default(),
        published_zones: Default::default(),
        old_tsig_key_store: Default::default(),
        app_cmd_tx,
        update_tx,
    });

    // Set up an async runtime.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("Couldn't start Tokio: {error}");
            return ExitCode::FAILURE;
        }
    };

    // Enter the runtime.
    runtime.block_on(async {
        // Spawn Cascade's units.
        let mut center_tx = None;
        let mut unit_txs = Default::default();
        if let Err(err) = manager::spawn(
            &center,
            update_rx,
            &mut center_tx,
            &mut unit_txs,
            socket_provider,
        )
        .await
        {
            log::error!("Failed to spawn units: {err}");
            return ExitCode::FAILURE;
        }

        let result = loop {
            tokio::select! {
                // Watch for CTRL-C (SIGINT).
                res = tokio::signal::ctrl_c() => {
                    if let Err(error) = res {
                        log::error!(
                            "Listening for CTRL-C (SIGINT) failed: {error}"
                        );
                        break ExitCode::FAILURE;
                    }
                    break ExitCode::SUCCESS;
                }

                _ = manager::forward_app_cmds(&mut app_cmd_rx, &unit_txs) => {}
            }
        };

        // Shut down Cascade.
        center_tx
            .as_ref()
            .unwrap()
            .send(TargetCommand::Terminate)
            .unwrap();
        center_tx.as_ref().unwrap().closed().await;
        for (_name, tx) in unit_txs {
            tx.send(ApplicationCommand::Terminate).unwrap();
            tx.closed().await;
        }

        // Persist the current state.
        cascade::state::save_now(&center);
        cascade::tsig::save_now(&center);
        let zones = {
            let state = center.state.lock().unwrap();
            state.zones.iter().map(|z| z.0.clone()).collect::<Vec<_>>()
        };
        for zone in zones {
            // TODO: Maybe 'save_state_now()' should take '&Config'?
            cascade::zone::save_state_now(&center, &zone);
        }

        result
    })
}
