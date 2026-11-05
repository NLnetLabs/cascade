//! Integration tests.

#![allow(clippy::disallowed_macros)]

use std::{
    net::{Ipv4Addr, SocketAddr},
    process::ExitCode,
    sync::Arc,
};

use camino::Utf8Path;
use cascade_api as api;
use clap::{ArgAction, arg, builder::BoolishValueParser, value_parser};
use domain::base::{Rtype, iana::OptRcode};
use tracing_subscriber::EnvFilter;

mod infra;
use infra::{Test, TestPatterns, ports};

fn all_tests() -> Vec<Test> {
    vec![add_zone_query(), remove_zone()]
}

fn add_zone_query() -> Test {
    Test::new("add-zone-query", |container| async move {
        let cascade = Arc::new(infra::Cascade::start(&container).await);

        tracing::info!("Add a zone served by the NSD primary");
        let zone_name: api::ZoneName = "example.test".parse().unwrap();
        cascade
            .add_zone(api::ZoneAdd {
                name: zone_name.clone(),
                source: api::ZoneSource::Server {
                    addr: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), ports::PRIMARY.0),
                    tsig_key: None,
                },
                policy: "default".into(),
                key_imports: vec![],
            })
            .await
            .unwrap();

        tracing::info!("Check zone status");
        let _ = infra::poll(
            || cascade.clone(),
            async |c| c.zone_status("example.test").await,
            |status| status.as_ref().is_ok_and(|s| s.last_published.is_some()),
        )
        .await;

        tracing::info!("Query the zone");
        let res = container
            .dns_query(ports::PUBLICATION, "example.test", Rtype::SOA, None)
            .await;
        assert!(res.as_ref().is_ok_and(|r| r.no_error()), "{res:?}");

        tracing::info!("The new zone should now be available via the resolver");
        let _ = infra::poll(
            || container.clone(),
            async |c| {
                c.dns_query(ports::RESOLVER, "example.test", Rtype::SOA, None)
                    .await
            },
            |res| res.as_ref().is_ok_and(|r| r.no_error()),
        )
        .await;
    })
}

fn remove_zone() -> Test {
    Test::new("remove-zone", |container| async move {
        let cascade = Arc::new(infra::Cascade::start(&container).await);

        tracing::info!("Add a zone");
        let zone_name: api::ZoneName = "example.test".parse().unwrap();
        cascade
            .add_zone(api::ZoneAdd {
                name: zone_name.clone(),
                source: api::ZoneSource::Zonefile {
                    path: Utf8Path::new("/test/primary/example.test.zone").into(),
                },
                policy: "default".into(),
                key_imports: vec![],
            })
            .await
            .unwrap();

        tracing::info!("Cascade should list the zone");
        infra::poll(
            || cascade.clone(),
            async |c| c.zone_names().await,
            |names| names.contains(&zone_name),
        )
        .await;

        tracing::info!("Check zone status");
        let _ = infra::poll(
            || cascade.clone(),
            async |c| c.zone_status("example.test").await,
            |status| status.as_ref().is_ok_and(|s| s.last_published.is_some()),
        )
        .await;

        tracing::info!("Querying the zone should succeed");
        let res = container
            .dns_query(ports::PUBLICATION, "example.test", Rtype::SOA, None)
            .await;
        assert!(res.as_ref().is_ok_and(|r| r.no_error()), "{res:?}");

        tracing::info!("Remove the zone");
        cascade.remove_zone("example.test").await.unwrap();

        tracing::info!("Cascade should no longer list the zone");
        infra::poll(
            || cascade.clone(),
            async |c| c.zone_names().await,
            |names| !names.contains(&zone_name),
        )
        .await;

        tracing::info!("Querying the zone should now fail");
        let res = container
            .dns_query(ports::PUBLICATION, "example.test", Rtype::SOA, None)
            .await;
        assert!(
            res.as_ref()
                .is_ok_and(|r| r.opt_rcode() == OptRcode::REFUSED),
            "{res:?}"
        );

        tracing::info!("Check that Cascade is still running");
        assert!(cascade.health().await.unwrap().healthy);
    })
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        // Filter out unnecessary noise.
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(tracing::Level::WARN.into())
                .from_env_lossy()
                .add_directive("h2=error".parse().unwrap())
                .add_directive("tonic=error".parse().unwrap())
                .add_directive("hyper_util=error".parse().unwrap())
                .add_directive("bollard=error".parse().unwrap()),
        )
        .init();

    let matches = clap::command!()
        .arg(arg!([patterns] "Patterns for matching tests to run").action(ArgAction::Append))
        .arg(
            arg!(-B --"bless" [BOOL] "When a data mismatch occurs, update the test's expectation")
                .value_parser(BoolishValueParser::new())
                .num_args(0..=1)
                .require_equals(true)
                .default_missing_value("true"),
        )
        .arg(
            arg!(-L --"leave-containers-on-failure" [BOOL] "Leave Docker containers on failure")
                .value_parser(BoolishValueParser::new())
                .num_args(0..=1)
                .require_equals(true)
                .default_missing_value("true"),
        )
        .arg(
            arg!(--"max-dump-size" <SIZE> "The maximum size of tarball dumps")
                .required(false)
                .value_parser(value_parser!(usize)),
        )
        .get_matches();

    let _ = infra::CURRENT_CONFIG.set(infra::TestConfig {
        bless: matches.get_one("bless").copied(),
        leave_containers_on_failure: matches.get_one("leave-containers-on-failure").copied(),
        max_dump_size: matches.get_one("max-dump-size").copied(),
    });

    let patterns = TestPatterns {
        raw: matches
            .get_many::<String>("patterns")
            .into_iter()
            .flatten()
            .cloned()
            .collect(),
    };

    infra::runtime::block_on(async {
        let docker = Arc::new(bollard::Docker::connect_with_defaults().unwrap());

        let image = Arc::new(infra::ImageBuilder::new(docker).build().await);

        let mut test_jobs = tokio::task::JoinSet::new();
        for test in all_tests() {
            test.run(&patterns, &mut test_jobs, &image);
        }
        let mut success = 0;
        let mut failure = 0;
        while let Some(res) = test_jobs.join_next().await {
            let res = res.unwrap();
            let name = Test::job_name(&res.name, &res.job_value);
            if res.result.is_ok() {
                println!("... test {name} passed");
                success += 1;
            } else {
                eprintln!("... test {name} failed!");
                failure += 1;
            }
        }
        match (success, failure) {
            (0, 0) => {
                eprintln!("No tests matched the given patterns");
                ExitCode::FAILURE
            }
            (num, 0) => {
                println!("{num} tests passed");
                ExitCode::SUCCESS
            }
            (s, f) => {
                eprintln!("{s} tests passed, {f} tests failed");
                ExitCode::FAILURE
            }
        }
    })
}
