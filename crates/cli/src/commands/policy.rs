use std::fmt::Display;

use cascade_api::{
    KeyManagerPolicyInfo, LoaderPolicyInfo, ReviewPolicyMode, ServerPolicyInfo, SignerPolicyInfo,
};

use crate::{
    ansi,
    api::{
        NameserverCommsPolicyInfo, PolicyChange, PolicyChanges, PolicyInfo, PolicyInfoError,
        PolicyListResult, PolicyReloadError, ReviewPolicyInfo, SignerDenialPolicyInfo,
        SignerSerialPolicyInfo,
    },
    client::CascadeApiClient,
    println,
};

#[derive(Clone, Debug, clap::Args)]
pub struct Policy {
    #[command(subcommand)]
    command: PolicyCommand,
}

#[derive(Clone, Debug, clap::Subcommand)]
pub enum PolicyCommand {
    /// List registered policies
    #[command(name = "list")]
    List,

    /// Show the settings contained in a policy
    #[command(name = "show")]
    Show { name: String },

    /// Reload all the policies from the files
    #[command(name = "reload")]
    Reload,
}

impl Policy {
    pub async fn execute(self, client: CascadeApiClient) -> Result<(), String> {
        match self.command {
            PolicyCommand::List => {
                let res: PolicyListResult = client.get_json("policy/").await?;

                for policy in res.policies {
                    println!("{policy}");
                }
            }
            PolicyCommand::Show { name } => {
                let res: Result<PolicyInfo, PolicyInfoError> =
                    client.get_json(&format!("policy/{name}")).await?;

                let p = match res {
                    Ok(p) => p,
                    Err(e) => {
                        return Err(format!("{e:?}"));
                    }
                };

                print_policy(&p);
            }
            PolicyCommand::Reload => {
                let res: Result<PolicyChanges, PolicyReloadError> =
                    client.post_json("policy/reload").await?;

                let res = match res {
                    Ok(res) => res,
                    Err(err) => {
                        return Err(err.to_string());
                    }
                };

                println!("Policies reloaded:");

                let max_width = res.changes.iter().map(|(s, _)| s.len()).max().unwrap_or(0);

                for p in res.changes {
                    let name = p.0;

                    let change = match p.1 {
                        PolicyChange::Added => "added",
                        PolicyChange::Removed => "removed",
                        PolicyChange::Updated => "updated",
                        PolicyChange::Unchanged => "unchanged",
                    };

                    let color = match p.1 {
                        PolicyChange::Added => ansi::GREEN,
                        PolicyChange::Removed => ansi::RED,
                        PolicyChange::Updated => ansi::BLUE,
                        PolicyChange::Unchanged => ansi::GRAY,
                    };

                    println!(
                        "{color} - {name:<width$} {change}{reset}",
                        width = max_width,
                        reset = ansi::RESET
                    );
                }
            }
        }
        Ok(())
    }
}

fn print_policy(p: &PolicyInfo) {
    let PolicyInfo {
        name,
        zones,
        loader,
        key_manager,
        signer,
        server,
    } = p;

    let none = "<none>".to_string();

    let zones: Vec<_> = zones.iter().map(|z| format!("{}", z)).collect();

    let zones = if !zones.is_empty() {
        zones.join(", ")
    } else {
        none.clone()
    };

    println!("{name}:");
    println!("  zones: {zones}");
    print_loader_policy(loader);
    print_key_manager_policy(key_manager);
    print_signer_policy(signer);
    print_server_policy(server);
}

fn or_none(x: &Option<impl Display>) -> String {
    x.as_ref()
        .map(ToString::to_string)
        .unwrap_or("<none>".into())
}

fn print_loader_policy(LoaderPolicyInfo { review }: &LoaderPolicyInfo) {
    println!("  loader:");
    print_review(review);
}

fn print_key_manager_policy(
    KeyManagerPolicyInfo {
        hsm_server_id,
        use_csk,
        algorithm,
        ksk_validity,
        zsk_validity,
        csk_validity,
        auto_ksk,
        auto_zsk,
        auto_csk,
        auto_algorithm,
        dnskey_inception_offset,
        dnskey_signature_lifetime,
        dnskey_remain_time,
        cds_inception_offset,
        cds_signature_lifetime,
        cds_remain_time,
        ds_algorithm,
        default_ttl,
        auto_remove,
        auto_remove_delay,
        publication_nameservers,
    }: &KeyManagerPolicyInfo,
) {
    // TODO: we should probably condense this information a lot or hide unnecessary details. For example, only
    // show CSK info when `use_csk` is `true`.
    println!("  key manager:");
    println!("    hsm server: {}", or_none(hsm_server_id));
    println!("    use csk: {use_csk}");
    println!("    ds algorithm: {ds_algorithm}");
    println!("    auto-remove: {auto_remove}");
    println!("    auto-remove delay: {}s", auto_remove_delay.as_secs());
    println!("    algorithm: {algorithm}");
    println!("      auto-start: {}", auto_algorithm.start);
    println!("      auto-report: {}", auto_algorithm.report);
    println!("      auto-expire: {}", auto_algorithm.expire);
    println!("      auto-done: {}", auto_algorithm.done);
    println!("    ksk:");
    println!("      validity: {}", or_none(ksk_validity));
    println!("      auto-start: {}", auto_ksk.start);
    println!("      auto-report: {}", auto_ksk.report);
    println!("      auto-expire: {}", auto_ksk.expire);
    println!("      auto-done: {}", auto_ksk.done);
    println!("    zsk:");
    println!("      validity: {}", or_none(zsk_validity));
    println!("      auto-start: {}", auto_zsk.start);
    println!("      auto-report: {}", auto_zsk.report);
    println!("      auto-expire: {}", auto_zsk.expire);
    println!("      auto-done: {}", auto_zsk.done);
    println!("    csk:");
    println!("      validity: {}", or_none(csk_validity));
    println!("      auto-start: {}", auto_csk.start);
    println!("      auto-report: {}", auto_csk.report);
    println!("      auto-expire: {}", auto_csk.expire);
    println!("      auto-done: {}", auto_csk.done);
    println!("    records:");
    println!("      TTL: {default_ttl}s");
    println!("      DNSKEY:");
    println!("        signature inception offset: {dnskey_inception_offset}s");
    println!("        signature lifetime: {dnskey_signature_lifetime}s");
    println!("        signature remain time: {dnskey_remain_time}s");
    println!("      CDS:");
    println!("        signature inception offset: {cds_inception_offset}s");
    println!("        signature lifetime: {cds_signature_lifetime}s");
    println!("        signature remain time: {cds_remain_time}s");

    if publication_nameservers.is_empty() {
        println!("    publication nameservers: <none>");
    } else {
        println!("    publication nameservers:");

        for ns in publication_nameservers {
            println!("     - {ns}")
        }
    }
}

fn print_signer_policy(
    SignerPolicyInfo {
        review,
        serial_policy,
        sig_inception_offset,
        sig_validity_offset,
        sig_remain_time,
        signature_refresh_interval,
        key_roll_time,
        denial,
    }: &SignerPolicyInfo,
) {
    let serial_policy = match serial_policy {
        SignerSerialPolicyInfo::Keep => "keep",
        SignerSerialPolicyInfo::Counter => "counter",
        SignerSerialPolicyInfo::UnixTime => "unix time",
        SignerSerialPolicyInfo::DateCounter => "date counter",
    };

    let denial = match &denial {
        SignerDenialPolicyInfo::NSec => "NSEC",
        SignerDenialPolicyInfo::NSec3 { opt_out } => match opt_out {
            true => "NSEC3 (opt-out: disabled)",
            false => "NSEC3 (opt-out: enabled)",
        },
    };

    println!("  signer:");
    println!("    serial policy: {serial_policy}");
    println!("    signature inception offset: {sig_inception_offset}s");
    println!("    signature validity offset: {sig_validity_offset}s");
    println!("    signature remain time: {sig_remain_time}");
    println!("    signature refresh interval: {signature_refresh_interval}");
    println!("    key roll time: {key_roll_time}");
    println!("    denial: {denial}");
    print_review(review);
}

fn print_server_policy(
    ServerPolicyInfo {
        outbound:
            cascade_api::OutboundPolicyInfo {
                provide_xfr_to,
                send_notify_to,
            },
    }: &ServerPolicyInfo,
) {
    println!("  server:");
    println!("    outbound:");
    print_nameserver_comms_policy("provide XFR to", provide_xfr_to);
    print_nameserver_comms_policy("send NOTIFY to", send_notify_to);
}

fn print_review(ReviewPolicyInfo { mode, on_reject }: &ReviewPolicyInfo) {
    println!("    review:");
    match mode {
        ReviewPolicyMode::Off => println!("      mode: off"),
        ReviewPolicyMode::Manual => println!("      mode: manual"),
        ReviewPolicyMode::Script { hook } => {
            println!("      mode: script");
            println!("      hook: {hook}")
        }
    }
    let on_reject = match on_reject {
        cascade_api::ReviewPolicyOnReject::Discard => "discard",
        cascade_api::ReviewPolicyOnReject::Halt => "halt",
    };
    println!("      on reject: {on_reject}")
}

fn print_nameserver_comms_policy(name: &str, n: &[NameserverCommsPolicyInfo]) {
    if n.is_empty() {
        println!("      {name}: <none>");
        return;
    }
    println!("      {name}:");
    for item in n {
        println!("        {item}");
    }
}
