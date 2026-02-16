use cascaded::{
    center::{self, Center},
    config::{Config, SocketConfig},
    daemon::{PreBindError, SocketProvider, daemonize},
    loader::Loader,
    manager::Manager,
    policy,
    units::{
        key_manager::KeyManager,
        zone_server::{Source, ZoneServer},
        zone_signer::ZoneSigner,
    },
};
use clap::{crate_authors, crate_description, crate_version};
use std::{collections::HashMap, fs::create_dir_all};
use std::{
    io,
    process::ExitCode,
    sync::{Arc, Mutex},
};
use tracing::{debug, error, info, warn};
use tracing_subscriber::FmtSubscriber;

const MAX_SYSTEMD_FD_SOCKETS: usize = 32;

fn main() -> ExitCode {
    // Make a temporary subscriber to catch logging events happening before we
    // set up the proper logger.
    let log_guard = tracing::subscriber::set_default(FmtSubscriber::new());

    // Set up the command-line interface.
    let cmd = clap::Command::new("cascade")
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .next_line_help(true);
    let cmd = Config::setup_cli(cmd);

    // Process command-line arguments.
    let matches = cmd.get_matches();

    // Construct the configuration.
    let config = match Config::init(&matches) {
        Ok(config) => config,
        Err(error) => {
            error!("Cascade couldn't be configured: {error}");
            return ExitCode::FAILURE;
        }
    };

    if matches.get_flag("check_config") {
        // The configuration was loaded successfully; stop now.
        return ExitCode::SUCCESS;
    }

    // Drop the temporary logger just before we start making the proper logger
    drop(log_guard);

    // Initialize the actual logger
    let logger = match cascaded::log::Logger::launch(&config.daemon.logging) {
        Ok(logger) => logger,
        Err(e) => {
            error!("Failed to initialize logging: {e:?}");
            return ExitCode::FAILURE;
        }
    };

    info!("Cascade version {}", env!("CARGO_PKG_VERSION"));

    // Confirm the right version of 'dnst' is available.
    if !check_dnst_version(&config) {
        // Error is already logged in the function
        return ExitCode::FAILURE;
    }

    // Load the global state file or build one from scratch.
    let mut state = center::State::default();
    if let Err(err) = state.init_from_file(&config) {
        if err.kind() != io::ErrorKind::NotFound {
            error!("Could not load the state file: {err}");
            return ExitCode::FAILURE;
        }

        info!("State file not found; starting from scratch");

        // Create required subdirectories (and their parents) if they don't
        // exist. This is only needed for directories to which we write files
        // without using util::write_file() as that function creates the
        // directory (and parent directories) if missing. However, do it for
        // all state directories now so that we don't discover only later that
        // we can't create the directory.
        // TODO: Once we implement live config reloading, this should move
        // somewhere else to also create the directories as specified in a the
        // reloaded config.
        for dir in [
            &*config.keys_dir,
            config.kmip_credentials_store_path.parent().unwrap(),
            &*config.kmip_server_state_dir,
            &*config.policy_dir,
            &*config.zone_state_dir,
        ] {
            if let Err(e) = create_dir_all(dir) {
                error!("Unable to create directory '{dir}': {e}",);
                return ExitCode::FAILURE;
            };
        }

        // Load all policies.
        match policy::reload_all(&mut state.policies, &config, |_, _| {}) {
            Err(err) => {
                error!("Cascade couldn't load all policies: {err}");
                return ExitCode::FAILURE;
            }
            Ok(updates) => {
                for (name, _old) in updates {
                    let pol = state
                        .policies
                        .get(&name)
                        .expect("we just reloaded these policies");

                    for zone_name in &pol.zones {
                        let zone = state
                            .zones
                            .get(zone_name)
                            .expect("zones and policies are consistent");

                        let mut state = zone.0.state.lock().expect("lock isn't poisoned");
                        state.policy = Some(pol.latest.clone());
                    }
                }
            }
        }

        // TODO: Fail if any zone state files exist.
    } else {
        info!("Successfully loaded the global state file");

        let zone_state_dir = &config.zone_state_dir;
        let policies = &mut state.policies;
        for zone in &state.zones {
            let name = &zone.0.name;
            let path = zone_state_dir.join(format!("{name}.db"));
            let spec = match cascaded::zone::state::Spec::load(&path) {
                Ok(spec) => {
                    debug!("Loaded state of zone '{name}' (from {path})");
                    spec
                }
                Err(err) => {
                    error!("Failed to load zone state '{name}' from '{path}': {err}");
                    return ExitCode::FAILURE;
                }
            };
            let mut state = zone.0.state.lock().unwrap();
            spec.parse_into(&zone.0, &mut state, policies);
        }
    }

    if config.loader.review.servers.is_empty() {
        warn!(
            "No review server configured for [loader.review], therefore no unsigned zone transfer available for review."
        );
    }

    if config.signer.review.servers.is_empty() {
        warn!(
            "No review server configured for [signer.review], therefore no signed zone transfer available for review."
        );
    }

    // Load the TSIG store file.
    //
    // TODO: Track which TSIG keys are in use by zones.
    match state.tsig_store.init_from_file(&config) {
        Ok(()) => debug!("Loaded the TSIG store"),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            debug!("No TSIG store found; will create one");
        }
        Err(err) => {
            error!("Failed to load the TSIG store: {err}");
            return ExitCode::FAILURE;
        }
    }

    // Bind to listen addresses before daemonizing.
    let Ok(socket_provider) = bind_to_listen_sockets_as_needed(&config) else {
        return ExitCode::FAILURE;
    };

    if let Err(err) = daemonize(&config.daemon) {
        error!("Failed to daemonize: {err}");
        return ExitCode::FAILURE;
    }

    // Prepare Cascade.
    let center = Arc::new(Center {
        state: Mutex::new(state),
        config,
        logger,
        loader: Loader::new(),
        key_manager: KeyManager::new(),
        unsigned_review_server: ZoneServer::new(Source::Unsigned),
        signed_review_server: ZoneServer::new(Source::Signed),
        publication_server: ZoneServer::new(Source::Published),
        signer: ZoneSigner::new(),
        unsigned_zones: Default::default(),
        signable_zones: Default::default(),
        signed_zones: Default::default(),
        published_zones: Default::default(),
        old_tsig_key_store: Default::default(),
        resign_busy: Mutex::new(HashMap::new()),
    });

    // Set up the rayon threadpool
    rayon::ThreadPoolBuilder::new()
        .thread_name(|_| "cascade-signer".into())
        .build_global()
        .expect("This should only be set once");

    // Set up an async runtime.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .thread_name("cascade-worker")
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            error!("Couldn't start Tokio: {error}");
            return ExitCode::FAILURE;
        }
    };

    // Enter the runtime.
    let result = runtime.block_on(async {
        // Spawn Cascade's units.
        let manager = match Manager::spawn(center.clone(), socket_provider) {
            Ok(manager) => manager,
            Err(err) => {
                error!("Failed to spawn units: {err}");
                return ExitCode::FAILURE;
            }
        };

        let res = match tokio::signal::ctrl_c().await {
            Ok(_) => ExitCode::SUCCESS,
            Err(error) => {
                error!("Listening for CTRL-C (SIGINT) failed: {error}");
                ExitCode::FAILURE
            }
        };

        // All of Cascade's units have AbortOnDrop's in Manager, so all
        // background tasks will be stopped when Manager is dropped.
        drop(manager);

        res
    });

    // Persist the current state.
    cascaded::state::save_now(&center);
    cascaded::tsig::save_now(&center);
    let zones = {
        let state = center.state.lock().unwrap();
        state.zones.iter().map(|z| z.0.clone()).collect::<Vec<_>>()
    };
    for zone in zones {
        // TODO: Maybe 'save_state_now()' should take '&Config'?
        cascaded::zone::save_state_now(&center, &zone);
    }

    result
}

/// Bind to all listen addresses that are referred to our by the Cascade
/// configuration.
///
/// Sockets provided to us by systemd will be skipped as they are already
/// bound.
fn bind_to_listen_sockets_as_needed(config: &Config) -> Result<SocketProvider, ()> {
    let mut socket_provider = SocketProvider::new();
    socket_provider.init_from_env(Some(MAX_SYSTEMD_FD_SOCKETS));

    // Convert the TCP only listen addresses used by the HTTP server into
    // the same form used by all other units that listen, as the other units
    // use a type that also supports UDP which the HTTP server doesn't need.
    let remote_control_servers: Vec<_> = config
        .remote_control
        .servers
        .iter()
        .map(|&addr| SocketConfig::TCP { addr })
        .collect();

    // Make an iterator over all of the SocketConfig instances we know about.
    let socket_configs = config
        .loader
        .review
        .servers
        .iter()
        .chain(config.loader.notify_listeners.iter())
        .chain(config.signer.review.servers.iter())
        .chain(config.server.servers.iter())
        .chain(remote_control_servers.iter());

    // Bind to each of the specified sockets if needed.
    if let Err(err) = pre_bind_server_sockets_as_needed(&mut socket_provider, socket_configs) {
        error!("{err}");
        return Err(());
    }

    Ok(socket_provider)
}

/// Bind to the specified sockets if needed.
///
/// Sockets provided to us by systemd will be skipped as they are already
/// bound.
fn pre_bind_server_sockets_as_needed<'a, T: Iterator<Item = &'a SocketConfig>>(
    socket_provider: &mut SocketProvider,
    socket_configs: T,
) -> Result<(), PreBindError> {
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

/// Check that the configured dnst binary is executable, prints the correct
/// version, and has the keyset subcommand.
fn check_dnst_version(config: &Config) -> bool {
    let path = &*config.dnst_binary_path;

    debug!("Checking dnst binary version ('{path}')",);
    let dnst_version = match std::process::Command::new(path).arg("--version").output() {
        Err(e) => {
            error!("Unable to verify version of dnst binary (configured as '{path}'): {e}",);
            return false;
        }
        Ok(o) => String::from_utf8_lossy(&o.stderr).into_owned(),
    };

    debug!("Checking dnst keyset subcommand capability");
    // Check if the keyset subcommand exists
    match std::process::Command::new(path)
        .args(["keyset", "--help"])
        .output()
    {
        Err(e) => {
            error!(
                "Unable to verify keyset capability of dnst binary (configured as '{path}'): {e}",
            );
            return false;
        }
        Ok(s) => {
            if !s.status.success() {
                error!(
                    "Unsupported dnst binary (configured as '{path}'): keyset subcommand not supported",
                );
                return false;
            }
        }
    }

    // dnst --version prints: 'dnst 0.1.0-alpha'; but could be include more information in the
    // future. This will make sure to only read the first two segments.
    let mut version_parts = dnst_version.split([' ', '\n']);
    let (Some(name), Some(version)) = (version_parts.next(), version_parts.next()) else {
        error!("Incorrect dnst binary configured: '{path} --version' output was improper",);
        return false;
    };

    // split off any suffix (like '-alpha' or '-rc1') from version string
    let version = match version.split_once('-') {
        None => version,
        Some((v, _)) => v,
    };

    // The version string can be wrong in many ways, but we don't really
    // care in which way it is wrong. Therefore, using this function and only
    // printing one error message at the call-site below.
    fn unpack_version_string(version: &str) -> Result<(u32, u32, u32), ()> {
        let (Ok(major), Ok(minor), Ok(patch)) = ({
            let mut v = version.split('.');
            let (Some(major), Some(minor), Some(patch)) = (v.next(), v.next(), v.next()) else {
                return Err(());
            };
            (
                major.parse::<u32>(),
                minor.parse::<u32>(),
                patch.parse::<u32>(),
            )
        }) else {
            return Err(());
        };
        Ok((major, minor, patch))
    }

    debug!("Checking dnst version string '{version}'");
    let Ok((major, minor, patch)) = unpack_version_string(version) else {
        error!("Incorrect dnst binary configured: '{path} --version' version string was improper",);
        return false;
    };

    // Change this string and the match pattern to whatever version we require in the future
    let required_version = ">0.1.0";
    let res = match (major, minor, patch) {
        // major = 0; minor >= 1; patch = *
        (0, 1.., ..) => true,
        _ => false,
    };

    if res {
        info!("Using dnst binary '{path}' with name '{name}' and version '{version}'",);
    } else {
        error!(
            "Configured dnst binary '{path}' version ({version}) is unsupported. Expected {required_version}",
        );
    }

    res
}
