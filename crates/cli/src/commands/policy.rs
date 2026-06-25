use std::fmt::Display;

use cascade_api::{
    AutoConfigPolicyInfo, KeyManagerPolicyInfo, LoaderPolicyInfo, ReviewPolicyMode,
    ServerPolicyInfo, SignerPolicyInfo,
};

use crate::{
    ansi,
    api::{
        NameserverCommsPolicyInfo, PolicyChange, PolicyChanges, PolicyInfo, PolicyInfoError,
        PolicyListResult, PolicyReloadError, ReviewPolicyInfo, SignerDenialPolicyInfo,
        SignerSerialPolicyInfo,
    },
    client::CascadeApiClient,
    eprintln, println,
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

                if res.policies.is_empty() {
                    eprintln!("No policies to show");
                }

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
    println!("    HSM server: {}", or_none(hsm_server_id));
    println!("    DS algorithm: {ds_algorithm}");
    if *auto_remove {
        println!(
            "    auto-remove: true (delay {}s)",
            auto_remove_delay.as_secs()
        );
    } else {
        println!("    auto-remove: false",);
    }
    println!("    algorithm: {algorithm}");
    print_auto_flags(auto_algorithm);
    if *use_csk {
        println!("    CSK:");
        println!("      validity: {}s", or_none(csk_validity));
        print_auto_flags(auto_csk);
    } else {
        println!("    KSK:");
        println!("      validity: {}s", or_none(ksk_validity));
        print_auto_flags(auto_ksk);
        println!("    ZSK:");
        println!("      validity: {}s", or_none(zsk_validity));
        print_auto_flags(auto_zsk);
    }
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

fn print_auto_flags(auto: &AutoConfigPolicyInfo) {
    print!("      auto flags:");
    if !auto.start && !auto.report && !auto.expire && !auto.done {
        println!(" <none>");
        return;
    }
    if auto.start {
        print!(" start");
    }
    if auto.report {
        print!(" report");
    }
    if auto.expire {
        print!(" expire");
    }
    if auto.done {
        print!(" done");
    }
    println!();
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
    println!("    signature remain time: {sig_remain_time}s");
    println!("    signature refresh interval: {signature_refresh_interval}s");
    println!("    key roll time: {key_roll_time}s");
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
    print!("    review:");
    match mode {
        ReviewPolicyMode::Off => {
            println!(" off");
            return;
        }
        ReviewPolicyMode::Manual => {
            println!("");
            println!("      mode: manual");
        }
        ReviewPolicyMode::Script { hook } => {
            println!("");
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
