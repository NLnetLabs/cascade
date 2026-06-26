use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::hash_map::Entry;
use std::future::IntoFuture;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Duration;
use std::time::SystemTime;

use axum::Json;
use axum::Router;
use axum::extract::Path;
use axum::extract::Request;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::routing::post;
use bytes::Bytes;
use domain::base::Name;
use domain::base::Serial;
use domain::dnssec::sign::keys::keyset::KeyType;
use domain::utils::base64;
use domain_kmip::ConnectionSettings;
use domain_kmip::dep::kmip::client::pool::ConnectionManager;
use serde::Deserialize;
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};

use crate::api;
use crate::api::KeyInfo;
use crate::api::keyset::*;
use crate::api::*;
use crate::center;
use crate::center::Center;
use crate::center::get_zone;
use crate::loader;
use crate::manager::Terminated;
use crate::metrics::MetricsCollection;
use crate::policy::AutoConfig;
use crate::policy::SignerDenialPolicy;
use crate::policy::SignerSerialPolicy;
use crate::server::LoadedReviewServer;
use crate::server::SignedReviewServer;
use crate::tsig::{self, RemoveError};
use crate::units::key_manager::KmipClientCredentials;
use crate::units::key_manager::KmipClientCredentialsFile;
use crate::units::key_manager::KmipServerCredentialsFileMode;
use crate::units::key_manager::mk_dnst_keyset_cfg_file_path;
use crate::units::key_manager::mk_dnst_keyset_state_file_path;
use crate::units::zone_signer::KeySetState;
use crate::zone::machine::ZoneStateMachine;
use crate::zone::{HistoricalEvent, HistoricalEventType, ZoneByName};

pub const HTTP_UNIT_NAME: &str = "HS";

// NOTE: To send data back from a unit, send them an app command with
// a transmitter they can use to send the reply

pub struct HttpServer {
    pub center: Arc<Center>,
    pub metrics: Arc<MetricsCollection>,
    pub http_metrics: HttpMetrics,
}

#[derive(Default)]
pub struct HttpMetrics {
    // http_api_last_connection: Counter,
}

impl HttpServer {
    /// Launch the HTTP server.
    pub fn launch(
        center: Arc<Center>,
        http_sockets: Vec<TcpListener>,
        /* mut */ metrics: MetricsCollection,
    ) -> Result<Arc<Self>, Terminated> {
        // TODO: register metrics here

        let http_metrics = HttpMetrics::default();

        // This would require some work in tracking the last API access. I did
        // not find a way to call something on every route in axum. Maybe we
        // need a wrapper function that sets the last_connection timestamp.
        // // - last time a CLI connection was made
        // metrics.register(
        //     "http_api_last_connection",
        //     "The last unix epoch time an API HTTP connection was made (excl. /metrics and /)",
        //     http_metrics.http_api_last_connection.clone()
        // );

        let this = Arc::new(Self {
            center,
            metrics: Arc::new(metrics),
            http_metrics,
        });

        let app = Router::new()
            .route("/health", get(Self::health))
            .route("/info", get(Self::info))
            .route("/metrics", get(Self::metrics))
            .route("/status", get(Self::status))
            .route("/status/keys", get(Self::status_keys))
            .route("/debug/change-logging", post(Self::change_logging))
            .route("/tsig/", get(Self::tsig_key_list))
            .route("/tsig/add", post(Self::tsig_key_add))
            .route("/tsig/{name}/remove", post(Self::tsig_key_remove))
            .route("/zone/", get(Self::zones_list))
            .route("/zone/add", post(Self::zone_add))
            // TODO: .route("/zone/{name}/", get(Self::zone_get))
            .route("/zone/{name}/remove", post(Self::zone_remove))
            .route("/zone/{name}/reset", post(Self::zone_reset))
            .route("/zone/{name}/status", get(Self::zone_status))
            .route("/zone/{name}/history", get(Self::zone_history))
            .route("/zone/{name}/reload", post(Self::zone_reload))
            .route(
                "/zone/{name}/unsigned/{serial}/approve",
                post(Self::approve_unsigned),
            )
            .route(
                "/zone/{name}/unsigned/{serial}/reject",
                post(Self::reject_unsigned),
            )
            .route(
                "/zone/{name}/unsigned/override",
                post(Self::override_unsigned),
            )
            .route(
                "/zone/{name}/signed/{serial}/approve",
                post(Self::approve_signed),
            )
            .route(
                "/zone/{name}/signed/{serial}/reject",
                post(Self::reject_signed),
            )
            .route("/zone/{name}/signed/override", post(Self::override_signed))
            .route(
                "/zone/{zone}/maintenance/enable",
                post(Self::enable_maintenance_mode),
            )
            .route(
                "/zone/{zone}/maintenance/disable",
                post(Self::disable_maintenance_mode),
            )
            .route("/policy/", get(Self::policy_list))
            .route("/policy/reload", post(Self::policy_reload))
            .route("/policy/{name}", get(Self::policy_show))
            .route("/kmip", get(Self::kmip_server_list))
            .route("/kmip", post(Self::kmip_server_add))
            .route("/kmip/{server_id}", get(Self::hsm_server_get))
            .route("/key/{zone}/roll", post(Self::key_roll))
            .route("/key/{zone}/remove", post(Self::key_remove))
            .route("/key/{zone}/get", post(Self::key_get))
            .with_state(this.clone())
            .fallback(Self::warn_route_not_found);

        // Serve at the configured endpoints.
        tokio::spawn(async move {
            let mut set = JoinSet::new();
            for sock in http_sockets {
                set.spawn(axum::serve(sock, app.clone()).into_future());
            }

            // Wait for each future in the order they complete.
            while let Some(res) = set.join_next().await {
                if let Err(err) = res {
                    error!("HTTP serving failed: {err}");
                    return Err(Terminated);
                }
            }

            Ok(())
        });

        Ok(this)
    }

    /// Log a warning if the HTTP request does not match any route handler
    /// registered with Axum.
    ///
    /// As Cascade is not supposed to be exposed directly to the internet one
    /// would not expect lots of malicious requests to end up being logged by
    /// this handler. Instead if something is logged by this handler it likely
    /// indicates a problem in the Cascade daemon or in the Cascade CLI client
    /// and is thus worthy of being logged at warning level.
    async fn warn_route_not_found(request: Request) -> StatusCode {
        warn!("No route for {} {}", request.method(), request.uri());
        StatusCode::NOT_FOUND
    }

    /// If this endpoint responds, the daemon is considered healthy.
    async fn health() -> Json<api::Health> {
        Json(Health { healthy: true })
    }

    /// Get server info
    async fn info() -> Json<api::Info> {
        Json(Info {
            version: env!("CASCADE_BUILD_VERSION").into(),
        })
    }

    async fn metrics(State(state): State<Arc<HttpServer>>) -> impl IntoResponse {
        match state.metrics.assemble(state.center.clone()) {
            Ok(b) => Ok((
                StatusCode::OK,
                [(
                    "content-type",
                    "application/openmetrics-text; version=1.0.0; charset=utf-8",
                )],
                b,
            )),
            Err(_) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to encode metrics as text",
            )),
        }
    }

    async fn status(State(state): State<Arc<HttpServer>>) -> Json<ServerStatusResult> {
        let mut halted_zones = vec![];

        let center = &state.center;

        // Determine which pipelines are halted.
        for ZoneByName(zone) in center.state.lock().unwrap().zones.iter() {
            if let Some(err) = zone.read().machine.display_halted_reason() {
                halted_zones.push((zone.name.clone(), err.clone()))
            }
        }

        // Fetch the signing queue.
        let signing_queue = center.signer.on_queue_report(center);

        let f = |x: &Vec<cascade_cfg::SocketConfig>| x.iter().map(|s| s.addr()).collect::<Vec<_>>();
        let loaded_review_addrs = f(&center.config.loader.review.servers);
        let signed_review_addrs = f(&center.config.signer.review.servers);
        let server_addrs = f(&center.config.server.servers);

        Json(ServerStatusResult {
            halted_zones,
            signing_queue,
            loaded_review_addrs,
            signed_review_addrs,
            server_addrs,
        })
    }

    /// Change how Cascade logs information.
    async fn change_logging(
        State(state): State<Arc<HttpServer>>,
        Json(command): Json<ChangeLogging>,
    ) -> Json<ChangeLoggingResult> {
        let center = &state.center;
        {
            // Lock the global state.
            let mut state = center.state.lock().unwrap();

            // Apply the provided changes to the runtime logging config.
            if let Some(level) = command.level {
                let level = match level {
                    LogLevel::Trace => crate::config::LogLevel::Trace,
                    LogLevel::Debug => crate::config::LogLevel::Debug,
                    LogLevel::Info => crate::config::LogLevel::Info,
                    LogLevel::Warning => crate::config::LogLevel::Warning,
                    LogLevel::Error => crate::config::LogLevel::Error,
                    LogLevel::Critical => crate::config::LogLevel::Critical,
                };
                state.rt_config.log_level = Some(level);
            }
            if let Some(trace_targets) = command.trace_targets {
                let trace_targets = trace_targets
                    .into_iter()
                    .map(|TraceTarget(s)| s.into_boxed_str())
                    .collect();
                state.rt_config.log_trace_targets = Some(trace_targets);
            }

            // Update the logger.
            center.logger.apply(&state.rt_config);
        }

        Json(())
    }

    async fn zone_add(
        State(state): State<Arc<HttpServer>>,
        Json(zone_register): Json<ZoneAdd>,
    ) -> Json<Result<ZoneAddResult, ZoneAddError>> {
        let res = center::add_zone(
            &state.center,
            zone_register.name.clone(),
            zone_register.policy.into(),
            zone_register.source,
            zone_register.key_imports,
        )
        .await;

        match res {
            Ok(_) => Json(Ok(ZoneAddResult {
                name: zone_register.name,
                status: "Submitted".to_string(),
            })),
            Err(err) => Json(Err(err.into())),
        }
    }

    async fn zone_remove(
        State(state): State<Arc<HttpServer>>,
        Path(name): Path<Name<Bytes>>,
    ) -> Json<Result<ZoneRemoveResult, ZoneRemoveError>> {
        // TODO: Use the result.
        Json(
            center::remove_zone(&state.center, name.clone())
                .map(|_| ZoneRemoveResult { name })
                .map_err(|e| e.into()),
        )
    }

    async fn zone_reset(
        State(state): State<Arc<HttpServer>>,
        Path(name): Path<Name<Bytes>>,
    ) -> Json<ZoneResetResult> {
        // Poor man's try block
        let do_zone_reset = || {
            let zone = center::get_zone(&state.center, &name).ok_or(ZoneResetError::NoSuchZone)?;

            match zone.write_handle(&state.center).get().try_reset() {
                Ok(_) => Ok(ZoneResetOutput {
                    zone: zone.name.clone(),
                }),
                Err(_) => Err(ZoneResetError::NotHalted),
            }
        };

        Json(do_zone_reset())
    }

    async fn zones_list(State(http_state): State<Arc<HttpServer>>) -> Json<ZonesListResult> {
        let state = http_state.center.state.lock().unwrap();
        let zones = state
            .zones
            .iter()
            .map(|z| z.0.name.clone())
            .collect::<Vec<_>>();
        Json(ZonesListResult { zones })
    }

    async fn zone_status(
        State(state): State<Arc<HttpServer>>,
        Path(name): Path<Name<Bytes>>,
    ) -> Json<Result<ZoneStatus, ZoneStatusError>> {
        Json(Self::get_zone_status(state, name).await)
    }

    async fn get_zone_status(
        state: Arc<HttpServer>,
        name: Name<Bytes>,
    ) -> Result<ZoneStatus, ZoneStatusError> {
        let state_path;
        let policy;
        let source;
        let unsigned_review_addr;
        let signed_review_addr;
        let publish_addr;
        let unsigned_review_status;
        let signed_review_status;
        let zone;
        let halted_reason;
        let progress;
        let signing_report;
        let unsigned_serial;
        let signed_serial;
        let published_serial;
        let last_published;
        let error;
        let maintenance_mode;
        {
            let locked_state = state.center.state.lock().unwrap();
            let keys_dir = &state.center.config.keys_dir;
            state_path = mk_dnst_keyset_state_file_path(keys_dir, &name);
            zone = locked_state
                .zones
                .get(&name)
                .ok_or(ZoneStatusError::ZoneDoesNotExist)?
                .0
                .clone();

            let zone_state = zone.read();
            halted_reason = zone_state.halted_reason();

            policy = zone_state
                .policy
                .as_ref()
                .map_or("<none>".into(), |p| p.name.to_string());
            // TODO: Needs some info from the zone loader?
            source = match zone_state.loader.source.clone() {
                loader::Source::None => api::ZoneSource::None,
                loader::Source::Zonefile { path } => api::ZoneSource::Zonefile { path },
                loader::Source::Server { addr, tsig_key } => {
                    let tsig_key = tsig_key.map(|k| k.name().clone());
                    api::ZoneSource::Server { addr, tsig_key }
                }
            };
            unsigned_review_addr = state
                .center
                .config
                .loader
                .review
                .servers
                .iter()
                .map(|s| s.addr())
                .collect();
            signed_review_addr = state
                .center
                .config
                .signer
                .review
                .servers
                .iter()
                .map(|s| s.addr())
                .collect();
            publish_addr = state
                .center
                .config
                .server
                .servers
                .iter()
                .map(|s| s.addr())
                .collect();

            unsigned_review_status = zone_state
                .find_last_event(HistoricalEventType::UnsignedZoneReview, None)
                .map(|item| {
                    let HistoricalEvent::UnsignedZoneReview { status } = item.event else {
                        unreachable!()
                    };
                    TimestampedZoneReviewStatus {
                        status,
                        when: item.when,
                    }
                });

            signed_review_status = zone_state
                .find_last_event(HistoricalEventType::SignedZoneReview, None)
                .map(|item| {
                    let HistoricalEvent::SignedZoneReview { status } = item.event else {
                        unreachable!()
                    };
                    TimestampedZoneReviewStatus {
                        status,
                        when: item.when,
                    }
                });

            unsigned_serial = zone_state
                .storage
                .loaded_review_soa
                .as_ref()
                .map(|r| Serial::from(u32::from(r.rdata.serial)));
            signed_serial = zone_state
                .storage
                .signed_review_soa
                .as_ref()
                .map(|r| Serial::from(u32::from(r.rdata.serial)));
            published_serial = zone_state
                .storage
                .published_soa
                .as_ref()
                .map(|r| Serial::from(u32::from(r.rdata.serial)));

            progress = match zone_state.machine {
                ZoneStateMachine::Waiting(..) => {
                    if zone_state.storage.is_restoring() {
                        Progress::Restoring
                    } else {
                        Progress::Waiting
                    }
                }
                ZoneStateMachine::Loading(..) => Progress::Loading,
                ZoneStateMachine::LoadedReview(..) => Progress::LoadedReview,
                ZoneStateMachine::HaltLoaded(..) => Progress::HaltLoaded,
                ZoneStateMachine::Signing(..) => Progress::Signing,
                ZoneStateMachine::SigningFailed(..) => Progress::SigningFailed,
                ZoneStateMachine::SignedReview(..) => Progress::SignedReview,
                ZoneStateMachine::HaltSigned(..) => Progress::HaltSigned,
                ZoneStateMachine::Poisoned => unreachable!(),
            };

            // Query signing status
            signing_report = if progress >= Progress::SignedReview {
                zone_state
                    .signer
                    .active_signing_status
                    .as_ref()
                    .and_then(|s| s.read().unwrap().mk_signing_report())
            } else {
                None
            };

            last_published = zone_state
                .last_published
                .as_ref()
                .map(|p| LastPublishedZone {
                    loaded_serial: p.loaded_serial,
                    signed_serial: p.signed_serial,
                    num_records: p.num_records,
                    timestamp: p.timestamp,
                });

            let mut found_error = None;
            for item in zone_state.history.iter().rev() {
                // TODO: When we have instance IDs we should only look through
                // history items related to that ID.
                match &item.event {
                    HistoricalEvent::StartedLoad | HistoricalEvent::StartedResign => {
                        break;
                    }
                    HistoricalEvent::LoadingFailed { reason } => {
                        found_error = Some(reason.clone());
                        break;
                    }
                    HistoricalEvent::SigningFailed { trigger: _, reason } => {
                        found_error = Some(format!("signing failed: {reason}"));
                        break;
                    }
                    HistoricalEvent::UnsignedZoneReview {
                        status: ZoneReviewStatus::Rejected,
                    } => {
                        found_error = Some("loaded zone was rejected".into());
                        break;
                    }
                    HistoricalEvent::SignedZoneReview {
                        status: ZoneReviewStatus::Rejected,
                    } => {
                        found_error = Some("signed zone was rejected".into());
                        break;
                    }
                    HistoricalEvent::UnsignedHookFailed { err } => {
                        found_error = Some(format!("could not execute loaded review hook: {err}"));
                        break;
                    }
                    HistoricalEvent::SignedHookFailed { err } => {
                        found_error = Some(format!("could not execute signed review hook: {err}"));
                        break;
                    }
                    _ => {}
                }
            }
            error = found_error;

            maintenance_mode = zone_state.maintenance_mode;
        }

        // Query key status
        let key_status = {
            let center = &state.center;
            let res = center.key_manager.on_status(center, &zone).await;

            let (Ok(output) | Err(output)) = res;

            // Strip out lines that would be correct for a dnst user
            // but confusing for a cascade user, and rewrite advice to
            // invoke dnst to be equivalent advice to invoke cascade.
            let mut sanitized_output = String::new();
            for line in output.lines() {
                if line.contains("Next time to run the 'cron' subcommand") {
                    continue;
                }

                if line.contains("dnst keyset -c") {
                    // The config file path after -c should NOT contain a
                    // space as it is based on a zone name, and zone names
                    // cannot contain spaces. Find the config file path so
                    // that we can strip it out (as users of the cascade
                    // CLI should not need to know or care what internal
                    // dnst config files are being used).
                    let mut parts = line.split(' ');
                    if parts.any(|part| part == "-c")
                        && let Some(dnst_config_path) = parts.next()
                    {
                        let sanitized_line = line.replace(
                            &format!("dnst keyset -c {dnst_config_path}"),
                            &format!("cascade keyset {name}"),
                        );
                        sanitized_output.push_str(&sanitized_line);
                        sanitized_output.push('\n');
                        continue;
                    }
                }

                sanitized_output.push_str(line);
                sanitized_output.push('\n');
            }
            sanitized_output
        };

        // Query zone keys
        let mut keys = vec![];
        match std::fs::read_to_string(&state_path) {
            Ok(json) => {
                let keyset_state: KeySetState = serde_json::from_str(&json).unwrap();
                for (pubref, key) in keyset_state.keyset.keys() {
                    let (key_type, signer) = match key.keytype() {
                        KeyType::Ksk(s) => (api::KeyType::Ksk, s.signer()),
                        KeyType::Zsk(s) => (api::KeyType::Zsk, s.signer()),
                        KeyType::Csk(s1, s2) => (api::KeyType::Csk, s1.signer() || s2.signer()),
                        KeyType::Include(_) => continue,
                    };
                    keys.push(KeyInfo {
                        pubref: pubref.clone(),
                        key_type,
                        key_tag: key.key_tag(),
                        signer,
                    });
                }
            }
            Err(err) => {
                error!(
                    "Unable to read `dnst keyset` state file '{state_path}' while querying status of zone {name} for the API: {err}"
                );
            }
        }

        // TODO: Report separate information for ongoing and completed loads.
        let receipt_report = {
            let state = zone.read();
            let active = state.loader.active_load_metrics.as_ref();
            let last = state.loader.last_load_metrics.as_ref();
            active
                .map(|metrics| ZoneLoaderReport {
                    started_at: metrics.start.1,
                    finished_at: None,
                    byte_count: metrics.num_loaded_bytes.load(Relaxed),
                    total_byte_count: Some(metrics.num_total_bytes.load(Relaxed)),
                    record_count: metrics.num_loaded_records.load(Relaxed),
                })
                .or_else(|| {
                    last.map(|metrics| ZoneLoaderReport {
                        started_at: metrics.start,
                        finished_at: Some(metrics.end),
                        byte_count: metrics.num_loaded_bytes,
                        total_byte_count: None,
                        record_count: metrics.num_loaded_records,
                    })
                })
        };

        Ok(ZoneStatus {
            name,
            source,
            policy,
            progress,
            maintenance_mode,
            last_published,
            keys,
            key_status,
            receipt_report,
            unsigned_serial,
            unsigned_review_status,
            unsigned_review_addr,
            signed_serial,
            signed_review_status,
            signed_review_addr,
            signing_report,
            published_serial,
            publish_addr,
            halted_reason,
            error,
        })
    }

    async fn zone_history(
        State(state): State<Arc<HttpServer>>,
        Path(name): Path<Name<Bytes>>,
    ) -> Json<Result<ZoneHistory, ZoneHistoryError>> {
        let zone = match get_zone(&state.center, &name) {
            Some(zone) => zone,
            None => return Json(Err(ZoneHistoryError::ZoneDoesNotExist)),
        };
        Json(Ok(ZoneHistory {
            history: zone
                .read()
                .history
                .iter()
                .map(|i| i.clone().into())
                .collect(),
        }))
    }

    async fn zone_reload(
        State(api_state): State<Arc<HttpServer>>,
        Path(name): Path<Name<Bytes>>,
    ) -> Json<Result<ZoneReloadResult, ZoneReloadError>> {
        Json(Self::do_zone_reload(api_state, name))
    }

    fn do_zone_reload(
        api_state: Arc<HttpServer>,
        zone_name: Name<Bytes>,
    ) -> Result<ZoneReloadResult, ZoneReloadError> {
        let center = &api_state.center;
        let zone =
            crate::center::get_zone(center, &zone_name).ok_or(ZoneReloadError::ZoneDoesNotExist)?;
        center.loader.on_reload_zone(center, &zone)?;
        Ok(ZoneReloadResult { name: zone_name })
    }

    /// Approve an unsigned version of a zone.
    async fn approve_unsigned(
        State(state): State<Arc<HttpServer>>,
        Path((zone_name, zone_serial)): Path<(Name<Bytes>, Serial)>,
    ) -> Json<ZoneReviewResult> {
        let center = &state.center;
        let Some(zone) = get_zone(center, &zone_name) else {
            debug!(
                "[{HTTP_UNIT_NAME}] Got a review approval for unsigned {zone_name}/{zone_serial}, but the zone does not exist"
            );
            return Json(Err(ZoneReviewError::NoSuchZone));
        };
        let result = LoadedReviewServer::process_review(
            center,
            &zone,
            zone_serial,
            ZoneReviewDecision::Approve,
        );

        Json(result)
    }

    /// Reject an unsigned version of a zone.
    async fn reject_unsigned(
        State(state): State<Arc<HttpServer>>,
        Path((zone_name, zone_serial)): Path<(Name<Bytes>, Serial)>,
    ) -> Json<ZoneReviewResult> {
        let center = &state.center;
        let Some(zone) = get_zone(center, &zone_name) else {
            debug!(
                "[{HTTP_UNIT_NAME}] Got a review rejection for unsigned {zone_name}/{zone_serial}, but the zone does not exist"
            );
            return Json(Err(ZoneReviewError::NoSuchZone));
        };
        let result = LoadedReviewServer::process_review(
            center,
            &zone,
            zone_serial,
            ZoneReviewDecision::Reject,
        );

        Json(result)
    }

    async fn override_unsigned(
        State(state): State<Arc<HttpServer>>,
        Path(name): Path<Name<Bytes>>,
    ) -> Json<ZoneOverrideResult> {
        // Poor man's try block
        let do_override = || {
            let zone =
                center::get_zone(&state.center, &name).ok_or(ZoneOverrideError::NoSuchZone)?;

            match zone
                .write_handle(&state.center)
                .get()
                .try_override_loaded_reject()
            {
                Ok(_) => Ok(ZoneOverrideOutput {
                    review_stage: ZoneReviewStage::Unsigned,
                    zone: zone.name.clone(),
                }),
                Err(_) => Err(ZoneOverrideError::NotRejected),
            }
        };

        Json(do_override())
    }

    /// Approve a signed version of a zone.
    async fn approve_signed(
        State(state): State<Arc<HttpServer>>,
        Path((zone_name, zone_serial)): Path<(Name<Bytes>, Serial)>,
    ) -> Json<ZoneReviewResult> {
        let center = &state.center;
        let Some(zone) = get_zone(center, &zone_name) else {
            debug!(
                "[{HTTP_UNIT_NAME}] Got a review approval for signed {zone_name}/{zone_serial}, but the zone does not exist"
            );
            return Json(Err(ZoneReviewError::NoSuchZone));
        };
        let result = SignedReviewServer::process_review(
            center,
            &zone,
            zone_serial,
            ZoneReviewDecision::Approve,
        );

        Json(result)
    }

    /// Reject a signed version of a zone.
    async fn reject_signed(
        State(state): State<Arc<HttpServer>>,
        Path((zone_name, zone_serial)): Path<(Name<Bytes>, Serial)>,
    ) -> Json<ZoneReviewResult> {
        let center = &state.center;
        let Some(zone) = get_zone(center, &zone_name) else {
            debug!(
                "[{HTTP_UNIT_NAME}] Got a review rejection for signed {zone_name}/{zone_serial}, but the zone does not exist"
            );
            return Json(Err(ZoneReviewError::NoSuchZone));
        };
        let result = SignedReviewServer::process_review(
            center,
            &zone,
            zone_serial,
            ZoneReviewDecision::Reject,
        );

        Json(result)
    }

    async fn override_signed(
        State(state): State<Arc<HttpServer>>,
        Path(name): Path<Name<Bytes>>,
    ) -> Json<ZoneOverrideResult> {
        // Poor man's try block
        let do_override = || {
            let zone =
                center::get_zone(&state.center, &name).ok_or(ZoneOverrideError::NoSuchZone)?;

            match zone
                .write_handle(&state.center)
                .get()
                .try_override_signed_reject()
            {
                Ok(_) => Ok(ZoneOverrideOutput {
                    review_stage: ZoneReviewStage::Signed,
                    zone: zone.name.clone(),
                }),
                Err(_) => Err(ZoneOverrideError::NotRejected),
            }
        };

        Json(do_override())
    }

    async fn enable_maintenance_mode(
        State(state): State<Arc<HttpServer>>,
        Path(name): Path<Name<Bytes>>,
    ) -> Json<ZoneMaintenanceModeResult> {
        Json(Self::set_maintenance_mode(state, name, true))
    }

    async fn disable_maintenance_mode(
        State(state): State<Arc<HttpServer>>,
        Path(name): Path<Name<Bytes>>,
    ) -> Json<ZoneMaintenanceModeResult> {
        Json(Self::set_maintenance_mode(state, name, false))
    }

    fn set_maintenance_mode(
        state: Arc<HttpServer>,
        name: Name<Bytes>,
        enable: bool,
    ) -> ZoneMaintenanceModeResult {
        let zone =
            center::get_zone(&state.center, &name).ok_or(ZoneMaintenanceModeError::NoSuchZone)?;

        let mut zone_state = zone.write(&state.center);

        if zone_state.maintenance_mode == enable {
            return Err(ZoneMaintenanceModeError::AlreadyInThatState);
        }

        zone_state.maintenance_mode = enable;
        Ok(ZoneMaintenanceModeOutput { zone: name.clone() })
    }

    async fn policy_list(State(state): State<Arc<HttpServer>>) -> Json<PolicyListResult> {
        let state = state.center.state.lock().unwrap();

        let mut policies: Vec<String> = state
            .policies
            .keys()
            .map(|s| String::from(s.as_ref()))
            .collect();

        // We don't _have_ to sort, but seems useful for consistent output
        policies.sort();

        Json(PolicyListResult { policies })
    }

    async fn policy_reload(
        State(state): State<Arc<HttpServer>>,
    ) -> Json<Result<PolicyChanges, PolicyReloadError>> {
        let center = &state.center;
        let mut state = state.center.state.lock().unwrap();
        let state = &mut *state;

        let mut changes = state
            .policies
            .keys()
            .map(|p| (p.clone(), PolicyChange::Unchanged))
            .collect::<foldhash::HashMap<_, _>>();
        let mut changed = false;
        let mut updates = Vec::new();
        let res = crate::policy::reload_all(
            &mut state.policies,
            &center.config,
            &state.tsig_store,
            |name, change| {
                changed = true;

                changes.insert(
                    name.clone(),
                    match change {
                        crate::policy::PolicyChange::Removed { .. } => PolicyChange::Removed,
                        crate::policy::PolicyChange::Updated { .. } => PolicyChange::Updated,
                        crate::policy::PolicyChange::Added { .. } => PolicyChange::Added,
                    },
                );

                updates.push((name.clone(), change));
            },
        );

        if let Err(err) = res {
            return Json(Err(err));
        }

        if changed {
            state.mark_dirty(center);
        }

        for (name, change) in updates {
            let (old, new) = match change {
                crate::policy::PolicyChange::Removed { .. } => continue,
                crate::policy::PolicyChange::Updated { old, new } => (Some(old), new),
                crate::policy::PolicyChange::Added(new) => (None, new),
            };

            let pol = state
                .policies
                .get(&name)
                .expect("we just reloaded these policies");

            for zone_name in &pol.zones {
                let ZoneByName(zone) = state
                    .zones
                    .get(zone_name)
                    .expect("zones and policies are consistent");

                zone.write(center).policy = Some(pol.latest.clone());

                center
                    .key_manager
                    .on_zone_policy_changed(center, zone, old.clone(), new.clone());
            }
        }

        // We should have an on_zone_policy_changed per zone. For now, just
        // call it once.
        center.signer.on_zone_policy_changed();

        let mut changes: Vec<(String, _)> =
            changes.into_iter().map(|(p, c)| (p.into(), c)).collect();
        changes.sort_unstable_by(|l, r| l.0.cmp(&r.0));

        Json(Ok(PolicyChanges { changes }))
    }

    async fn policy_show(
        State(state): State<Arc<HttpServer>>,
        Path(name): Path<Box<str>>,
    ) -> Json<Result<PolicyInfo, PolicyInfoError>> {
        let state = state.center.state.lock().unwrap();
        let Some(p) = state.policies.get(&name) else {
            return Json(Err(PolicyInfoError::PolicyDoesNotExist));
        };

        let zones = p.zones.iter().cloned().collect();

        let crate::policy::PolicyVersion {
            name,
            loader,
            key_manager,
            signer,
            server,
        } = &*p.latest;

        let loader = {
            let crate::policy::LoaderPolicy { review } = loader;

            LoaderPolicyInfo {
                review: ReviewPolicyInfo {
                    mode: match review.mode.clone() {
                        crate::policy::ReviewMode::Off => ReviewPolicyMode::Off,
                        crate::policy::ReviewMode::Manual => ReviewPolicyMode::Manual,
                        crate::policy::ReviewMode::Script { hook } => {
                            ReviewPolicyMode::Script { hook }
                        }
                    },
                    on_reject: match review.on_reject {
                        crate::policy::OnReject::Discard => ReviewPolicyOnReject::Discard,
                        crate::policy::OnReject::Halt => ReviewPolicyOnReject::Halt,
                    },
                },
            }
        };

        let signer = {
            let &crate::policy::SignerPolicy {
                serial_policy,
                sig_inception_offset,
                sig_validity_time,
                sig_remain_time,
                signature_refresh_interval,
                key_roll_time,
                ref denial,
                ref review,
            } = signer;

            SignerPolicyInfo {
                serial_policy: match serial_policy {
                    SignerSerialPolicy::Keep => SignerSerialPolicyInfo::Keep,
                    SignerSerialPolicy::Counter => SignerSerialPolicyInfo::Counter,
                    SignerSerialPolicy::UnixTime => SignerSerialPolicyInfo::UnixTime,
                    SignerSerialPolicy::DateCounter => SignerSerialPolicyInfo::DateCounter,
                },
                sig_inception_offset,
                sig_validity_offset: sig_validity_time,
                sig_remain_time,
                signature_refresh_interval,
                key_roll_time,
                denial: match denial {
                    SignerDenialPolicy::NSec => SignerDenialPolicyInfo::NSec,
                    &SignerDenialPolicy::NSec3 { opt_out } => {
                        SignerDenialPolicyInfo::NSec3 { opt_out }
                    }
                },
                review: ReviewPolicyInfo {
                    mode: match review.mode.clone() {
                        crate::policy::ReviewMode::Off => ReviewPolicyMode::Off,
                        crate::policy::ReviewMode::Manual => ReviewPolicyMode::Manual,
                        crate::policy::ReviewMode::Script { hook } => {
                            ReviewPolicyMode::Script { hook }
                        }
                    },
                    on_reject: match review.on_reject {
                        crate::policy::OnReject::Discard => ReviewPolicyOnReject::Discard,
                        crate::policy::OnReject::Halt => ReviewPolicyOnReject::Halt,
                    },
                },
            }
        };

        let key_manager = {
            let &crate::policy::KeyManagerPolicy {
                ref hsm_server_id,
                use_csk,
                ref algorithm,
                ksk_validity,
                zsk_validity,
                csk_validity,
                ref auto_ksk,
                ref auto_zsk,
                ref auto_csk,
                ref auto_algorithm,
                dnskey_inception_offset,
                dnskey_signature_lifetime,
                dnskey_remain_time,
                cds_inception_offset,
                cds_signature_lifetime,
                cds_remain_time,
                ref ds_algorithm,
                default_ttl,
                auto_remove,
                auto_remove_delay,
                ref publication_nameservers,
            } = key_manager;

            fn map_auto(
                &AutoConfig {
                    start,
                    report,
                    expire,
                    done,
                }: &AutoConfig,
            ) -> AutoConfigPolicyInfo {
                AutoConfigPolicyInfo {
                    start,
                    report,
                    expire,
                    done,
                }
            }

            KeyManagerPolicyInfo {
                hsm_server_id: hsm_server_id.clone(),
                algorithm: algorithm.to_string(),
                use_csk,
                ksk_validity,
                zsk_validity,
                csk_validity,
                auto_ksk: map_auto(auto_ksk),
                auto_zsk: map_auto(auto_zsk),
                auto_csk: map_auto(auto_csk),
                auto_algorithm: map_auto(auto_algorithm),
                dnskey_inception_offset,
                dnskey_signature_lifetime,
                dnskey_remain_time,
                cds_inception_offset,
                cds_signature_lifetime,
                cds_remain_time,
                ds_algorithm: ds_algorithm.to_string(),
                default_ttl: default_ttl.as_secs(),
                auto_remove,
                auto_remove_delay,
                publication_nameservers: publication_nameservers
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
            }
        };

        let server = {
            let crate::policy::ServerPolicy { outbound } = server;
            ServerPolicyInfo {
                outbound: OutboundPolicyInfo {
                    provide_xfr_to: outbound
                        .provide_xfr_to
                        .iter()
                        .map(|v| NameserverCommsPolicyInfo { addr: v.addr })
                        .collect(),
                    send_notify_to: outbound
                        .send_notify_to
                        .iter()
                        .map(|v| NameserverCommsPolicyInfo { addr: v.addr })
                        .collect(),
                },
            }
        };

        Json(Ok(PolicyInfo {
            name: name.clone(),
            zones,
            loader,
            key_manager,
            signer,
            server,
        }))
    }

    async fn key_roll(
        State(state): State<Arc<HttpServer>>,
        Path(zone): Path<Name<Bytes>>,
        Json(KeyRoll { variant, cmd }): Json<KeyRoll>,
    ) -> Json<Result<(), String>> {
        let center = &state.center;
        let Some(zone) = center::get_zone(center, &zone) else {
            return Json(Err(format!("Zone '{zone}' does not exist")));
        };
        let res = center
            .key_manager
            .on_roll_key(center, &zone, variant, cmd)
            .await;

        Json(res)
    }

    async fn key_remove(
        State(state): State<Arc<HttpServer>>,
        Path(zone): Path<Name<Bytes>>,
        Json(KeyRemove {
            key,
            force,
            continue_flag,
        }): Json<KeyRemove>,
    ) -> Json<Result<(), String>> {
        let center = &state.center;
        let Some(zone) = center::get_zone(center, &zone) else {
            return Json(Err(format!("Zone '{zone}' does not exist")));
        };
        let res = center
            .key_manager
            .on_remove_key(center, &zone, key, force, continue_flag)
            .await;

        Json(res)
    }

    async fn key_get(
        State(state): State<Arc<HttpServer>>,
        Path(zone): Path<Name<Bytes>>,
        Json(KeyGet { key_type }): Json<KeyGet>,
    ) -> Json<Result<String, String>> {
        let center = &state.center;
        let Some(zone) = center::get_zone(center, &zone) else {
            return Json(Err(format!("Zone '{zone}' does not exist")));
        };
        let res = center
            .key_manager
            .on_get_key(center, &zone, key_type.to_string())
            .await;

        Json(res)
    }

    async fn status_keys(State(state): State<Arc<HttpServer>>) -> Json<KeyStatusResult> {
        #[derive(Deserialize)]
        struct KeySetConfig {
            ksk_validity: Option<Duration>,
            zsk_validity: Option<Duration>,
            csk_validity: Option<Duration>,
            autoremove: bool,
        }

        let keys_dir = &state.center.config.keys_dir;

        let state = state.center.state.lock().unwrap();

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("System time is expected to be after UNIX_EPOCH");

        let mut zones = Vec::new();
        let mut expirations = Vec::new();

        for zone in state.zones.iter() {
            let mut zone_keys = Vec::new();

            let cfg_path = mk_dnst_keyset_cfg_file_path(keys_dir, &zone.0.name);
            let cfg_str = match std::fs::read_to_string(&cfg_path) {
                Ok(cfg_str) => cfg_str,
                Err(e) => {
                    warn!("Could not read `{cfg_path}`: {e}");
                    continue;
                }
            };
            let ksc = match serde_json::from_str::<KeySetConfig>(&cfg_str) {
                Ok(ksc) => ksc,
                Err(e) => {
                    warn!("Could not parse `{cfg_path}`: {e}");
                    continue;
                }
            };

            let state_path = mk_dnst_keyset_state_file_path(keys_dir, &zone.0.name);
            let state_str = match std::fs::read_to_string(&state_path) {
                Ok(state_str) => state_str,
                Err(e) => {
                    error!("Could not read `{state_path}`: {e}");
                    continue;
                }
            };
            let keyset_state = match serde_json::from_str::<KeySetState>(&state_str) {
                Ok(keyset_state) => keyset_state,
                Err(e) => {
                    warn!("Could not parse `{state_path}`: {e}");
                    continue;
                }
            };

            let keyset_keys = keyset_state.keyset.keys();
            for (pubref, key) in keyset_keys {
                let (keystate, validity) = match key.keytype() {
                    KeyType::Ksk(keystate) => (keystate, Some(ksc.ksk_validity)),
                    KeyType::Zsk(keystate) => (keystate, Some(ksc.zsk_validity)),
                    KeyType::Csk(ksk_keystate, _) => (ksk_keystate, Some(ksc.csk_validity)),
                    KeyType::Include(keystate) => (keystate, None),
                };
                let msg = if keystate.stale() {
                    if ksc.autoremove {
                        "stale (will be removed automatically)".into()
                    } else {
                        "state (must be removed manually)".into()
                    }
                } else if let Some(opt_validity) = validity {
                    if let Some(validity) = opt_validity {
                        match key.timestamps().published() {
                            None => "not yet published".into(),
                            Some(timestamp) if timestamp.elapsed() > validity => {
                                expirations.push(KeyExpiration {
                                    zone: zone.0.name.to_string(),
                                    key: pubref.clone(),
                                    time_left: None,
                                });
                                "expired".into()
                            }
                            Some(timestamp) => {
                                let timestamp_duration: Duration = timestamp.clone().into();
                                expirations.push(KeyExpiration {
                                    zone: zone.0.name.to_string(),
                                    key: pubref.clone(),
                                    time_left: Some(now - timestamp_duration),
                                });
                                format!("expires at {}", timestamp + validity)
                            }
                        }
                    } else {
                        "does not expire".into()
                    }
                } else {
                    "does not expire (imported key)".into()
                };

                zone_keys.push(KeyMsg {
                    name: pubref.clone(),
                    msg,
                })
            }

            zones.push(KeysPerZone {
                zone: zone.0.name.to_string(),
                keys: zone_keys,
            });
        }

        // Sort by time until expiration
        expirations.sort_by_key(|e| e.time_left);

        // Sort the zones alphabetically for a predictable order
        zones.sort_by(|a, b| a.zone.cmp(&b.zone));

        Json(KeyStatusResult { expirations, zones })
    }

    async fn tsig_key_add(
        State(state): State<Arc<HttpServer>>,
        Json(tsig_add): Json<TsigAdd>,
    ) -> Json<Result<TsigAddResult, TsigAddError>> {
        let Ok(secret) = base64::decode::<Vec<u8>>(&tsig_add.secret) else {
            return Json(Err(TsigAddError::InvalidBase64Secret));
        };

        let alg = match tsig_add.alg {
            TsigAlgorithm::HmacSha1 => domain::tsig::Algorithm::Sha1,
            TsigAlgorithm::HmacSha256 => domain::tsig::Algorithm::Sha256,
            TsigAlgorithm::HmacSha384 => domain::tsig::Algorithm::Sha384,
            TsigAlgorithm::HmacSha512 => domain::tsig::Algorithm::Sha512,
        };

        match center::add_tsig_key(&state.center, tsig_add.name, alg, &secret).await {
            Ok(TsigAddResult) => Json(Ok(TsigAddResult)),
            Err(err) => Json(Err(err)),
        }
    }

    async fn tsig_key_remove(
        State(http_server_state): State<Arc<HttpServer>>,
        Path(tsig_key_name): Path<TsigKeyName>,
    ) -> Json<Result<TsigRemoveResult, TsigRemoveError>> {
        let res = tsig::remove_key(&http_server_state.center, &tsig_key_name)
            .map(|_| TsigRemoveResult)
            .map_err(|e| match e {
                RemoveError::NotFound => TsigRemoveError::NotFound,
                RemoveError::InUse(usage_references) => TsigRemoveError::InUse(
                    usage_references
                        .into_iter()
                        .map(|usage| match usage {
                            tsig::UsageReference::ZoneSource(zone) => {
                                TsigKeyUsageReference::ZoneSource(zone.0.name.clone())
                            }
                            tsig::UsageReference::ZoneOther(zone) => {
                                TsigKeyUsageReference::ZoneOther(zone.0.name.clone())
                            }
                            tsig::UsageReference::Policy(policy) => {
                                TsigKeyUsageReference::Policy(policy.name.clone())
                            }
                        })
                        .collect::<Vec<_>>(),
                ),
            });
        Json(res)
    }

    async fn tsig_key_list(State(http_state): State<Arc<HttpServer>>) -> Json<TsigListResult> {
        let mut tsig_key_info = HashMap::new();

        let state = http_state.center.state.lock().unwrap();

        // Get the set of TSIG keys and related zones from the TSIG key store.
        for (tsig_key_name, key) in state.tsig_store.map.iter() {
            let zone_names = key.zones.iter().map(|item| item.0.name.clone()).collect();
            tsig_key_info.insert(
                tsig_key_name.clone(),
                TsigKeyInfo {
                    zone_names,
                    policy_names: HashSet::new(),
                },
            );
        }

        // Note: We don't loop over all of the zones checking for TSIG keys
        // referenced in the upstream source configuration because those
        // relationships should be captured in the set of zones associated
        // with TSIG keys in the TSIG key store that we accessed in the loop
        // above.

        // Find the set of policies that reference TSIG keys as these
        // relationships are not tracked by the TSIG key store. Ignore
        // policies that are in the process of being deleted.
        let current_policies = state.policies.iter().filter(|(_, p)| !p.mid_deletion);

        // For each policy, collect any TSIG key names from the various policy
        // fields that may refer to TSIG keys, then update the TSIG key info
        // result set we are building to note the relationship between the
        // TSIG key and the policies that refer to it.
        for (policy_name, policy) in current_policies {
            let mut tsig_key_names = policy
                .latest
                .key_manager
                .publication_nameservers
                .iter()
                .chain(policy.latest.server.outbound.provide_xfr_to.iter())
                .chain(policy.latest.server.outbound.send_notify_to.iter())
                .filter_map(|acl| acl.tsig_key_name.as_ref())
                .peekable();

            // If we found at least one reference to a TSIG key in this policy
            // update the map of TSIG key info results to pass back to the
            // caller.
            if tsig_key_names.peek().is_some() {
                // For each found TSIG key:
                for tsig_key_name in tsig_key_names {
                    match tsig_key_info.entry(tsig_key_name.clone()) {
                        Entry::Occupied(mut e) => {
                            // Info about this TSIG key already exists in the
                            // results, update the result info to note the
                            // relationship to this policy.
                            e.get_mut().policy_names.insert(policy_name.to_string());
                        }
                        Entry::Vacant(e) => {
                            // Info about this TSIG key does not yet exist in
                            // the results, update the result info to note the
                            // relationship to this policy.
                            e.insert(TsigKeyInfo {
                                zone_names: HashSet::new(),
                                policy_names: [policy_name.to_string()].into(),
                            });
                        }
                    }
                }
            }
        }

        Json(TsigListResult { tsig_key_info })
    }
}

//------------ HttpServer Handler for /kmip ----------------------------------

/// Non-sensitive KMIP server settings to be persisted.
///
/// Sensitive details such as certificates and credentials should be stored
/// separately.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct KmipServerState {
    pub server_id: String,
    pub ip_host_or_fqdn: String,
    pub port: u16,
    pub insecure: bool,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub write_timeout: Duration,
    pub max_response_bytes: u32,
    pub key_label_prefix: Option<String>,
    pub key_label_max_bytes: u8,
    pub has_credentials: bool,
}

impl From<HsmServerAdd> for KmipServerState {
    fn from(srv: HsmServerAdd) -> Self {
        KmipServerState {
            server_id: srv.server_id,
            ip_host_or_fqdn: srv.ip_host_or_fqdn,
            port: srv.port,
            insecure: srv.insecure,
            connect_timeout: srv.connect_timeout,
            read_timeout: srv.read_timeout,
            write_timeout: srv.write_timeout,
            max_response_bytes: srv.max_response_bytes,
            key_label_prefix: srv.key_label_prefix,
            key_label_max_bytes: srv.key_label_max_bytes,
            has_credentials: srv.username.is_some(),
        }
    }
}

impl From<KmipServerState> for api::KmipServerState {
    fn from(value: KmipServerState) -> Self {
        let KmipServerState {
            server_id,
            ip_host_or_fqdn,
            port,
            insecure,
            connect_timeout,
            read_timeout,
            write_timeout,
            max_response_bytes,
            key_label_prefix,
            key_label_max_bytes,
            has_credentials,
        } = value;

        Self {
            server_id,
            ip_host_or_fqdn,
            port,
            insecure,
            connect_timeout,
            read_timeout,
            write_timeout,
            max_response_bytes,
            key_label_prefix,
            key_label_max_bytes,
            has_credentials,
        }
    }
}

impl HttpServer {
    async fn kmip_server_add(
        State(state): State<Arc<HttpServer>>,
        Json(req): Json<HsmServerAdd>,
    ) -> Json<Result<HsmServerAddResult, HsmServerAddError>> {
        // TODO: Write the given certificates to disk.
        // TODO: Create a single common way to store secrets.
        let server_id = req.server_id.clone();
        let config = &state.center.config;
        let kmip_server_state_file = config.kmip_server_state_dir.join(server_id.clone());
        let kmip_credentials_store_path = config.kmip_credentials_store_path.clone();

        // Test the connection before using the HSM.
        let conn_settings = {
            let HsmServerAdd {
                ip_host_or_fqdn,
                port,
                username,
                password,
                insecure,
                connect_timeout,
                read_timeout,
                write_timeout,
                max_response_bytes,
                ..
            } = req.clone();

            ConnectionSettings {
                host: ip_host_or_fqdn,
                port,
                username,
                password,
                insecure,
                client_cert: None, // TODO
                server_cert: None, // TODO
                ca_cert: None,     // TODO
                connect_timeout: Some(connect_timeout),
                read_timeout: Some(read_timeout),
                write_timeout: Some(write_timeout),
                max_response_bytes: Some(max_response_bytes),
            }
        };

        let pool = match ConnectionManager::create_connection_pool(
            server_id.clone(),
            Arc::new(conn_settings.clone()),
            10,
            Some(Duration::from_secs(60)),
            Some(Duration::from_secs(60)),
        ) {
            Ok(pool) => pool,
            Err(err) => {
                return Json(Err(HsmServerAddError::UnableToConnect {
                    server_id,
                    host: conn_settings.host,
                    port: conn_settings.port,
                    err: format!("Error creating connection pool: {err}"),
                }));
            }
        };

        // Test the connectivity (but not the HSM capabilities).
        let conn = match pool.get() {
            Ok(conn) => conn,
            Err(err) => {
                return Json(Err(HsmServerAddError::UnableToConnect {
                    server_id,
                    host: conn_settings.host,
                    port: conn_settings.port,
                    err: format!("Error retrieving connection from pool: {err}"),
                }));
            }
        };

        let query_res = match conn.query() {
            Ok(query_res) => query_res,
            Err(err) => {
                return Json(Err(HsmServerAddError::UnableToQuery {
                    server_id,
                    host: conn_settings.host,
                    port: conn_settings.port,
                    err: err.to_string(),
                }));
            }
        };

        let vendor_id = query_res
            .vendor_identification
            .unwrap_or("Anonymous HSM vendor".to_string());

        // Copy the username and password as we consume the req object below.
        let username = req.username.clone();
        let password = req.password.clone();

        // Add any credentials to the credentials store.
        if let Some(username) = username {
            let creds = KmipClientCredentials { username, password };
            let mut creds_file = match KmipClientCredentialsFile::new(
                kmip_credentials_store_path.as_std_path(),
                KmipServerCredentialsFileMode::CreateReadWrite,
            ) {
                Ok(creds_file) => creds_file,
                Err(err) => {
                    return Json(Err(
                        HsmServerAddError::CredentialsFileCouldNotBeOpenedForWriting {
                            err: err.to_string(),
                        },
                    ));
                }
            };
            let _ = creds_file.insert(server_id, creds);
            if let Err(err) = creds_file.save() {
                return Json(Err(HsmServerAddError::CredentialsFileCouldNotBeSaved {
                    err: err.to_string(),
                }));
            }
        }

        // Extract just the settings that do not need to be
        // stored separately.
        let kmip_state = KmipServerState::from(req);

        info!("Writing to KMIP server file '{kmip_server_state_file}");
        let f = match std::fs::File::create_new(kmip_server_state_file.clone()) {
            Ok(f) => f,
            Err(err) => {
                return Json(Err(
                    HsmServerAddError::KmipServerStateFileCouldNotBeCreated {
                        path: kmip_server_state_file.into_string(),
                        err: err.to_string(),
                    },
                ));
            }
        };
        if let Err(err) = serde_json::to_writer_pretty(&f, &kmip_state) {
            return Json(Err(HsmServerAddError::KmipServerStateFileCouldNotBeSaved {
                path: kmip_server_state_file.into_string(),
                err: err.to_string(),
            }));
        }

        Json(Ok(HsmServerAddResult { vendor_id }))
    }

    async fn kmip_server_list(State(state): State<Arc<HttpServer>>) -> Json<HsmServerListResult> {
        let kmip_server_state_dir = &*state.center.config.kmip_server_state_dir;

        let mut servers = Vec::<String>::new();

        if let Ok(entries) = std::fs::read_dir(kmip_server_state_dir) {
            for entry in entries {
                let Ok(entry) = entry else { continue };

                if let Ok(f) = std::fs::File::open(entry.path())
                    && let Ok(server) = serde_json::from_reader::<_, KmipServerState>(f)
                {
                    servers.push(server.server_id);
                }
            }
        }

        // We don't _have_ to sort, but seems useful for consistent output
        servers.sort();

        Json(HsmServerListResult { servers })
    }

    async fn hsm_server_get(
        State(state): State<Arc<HttpServer>>,
        Path(name): Path<Box<str>>,
    ) -> Json<Result<HsmServerGetResult, ()>> {
        let kmip_server_state_dir = &*state.center.config.kmip_server_state_dir;

        let p = kmip_server_state_dir.join(&*name);
        if let Ok(f) = std::fs::File::open(p)
            && let Ok(server) = serde_json::from_reader::<_, KmipServerState>(f)
        {
            return Json(Ok(HsmServerGetResult {
                server: server.into(),
            }));
        }

        Json(Err(()))
    }
}
