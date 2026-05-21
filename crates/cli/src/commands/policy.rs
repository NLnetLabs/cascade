use std::fmt::Display;
use std::fmt::Write;

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

                print_policy(&p).unwrap();
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

pub fn print_policy(p: &PolicyInfo) -> Result<String, std::fmt::Error> {
    let mut res = String::new();
    let out = &mut res;
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

    writeln!(out, "{name}:")?;
    writeln!(out, "  zones: {zones}")?;
    print_loader_policy(out, loader)?;
    print_key_manager_policy(out, key_manager)?;
    print_signer_policy(out, signer)?;
    print_server_policy(out, server)?;

    Ok(res)
}

fn or_none(x: &Option<impl Display>) -> String {
    x.as_ref()
        .map(ToString::to_string)
        .unwrap_or("<none>".into())
}

fn print_loader_policy(
    out: &mut String,
    LoaderPolicyInfo { review }: &LoaderPolicyInfo,
) -> Result<(), std::fmt::Error> {
    writeln!(out, "  loader:")?;
    print_review(out, review)?;
    Ok(())
}

fn print_key_manager_policy(
    out: &mut String,
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
) -> Result<(), std::fmt::Error> {
    // TODO: we should probably condense this information a lot or hide unnecessary details. For example, only
    // show CSK info when `use_csk` is `true`.
    writeln!(out, "  key manager:")?;
    writeln!(out, "    HSM server: {}", or_none(hsm_server_id))?;
    writeln!(out, "    DS algorithm: {ds_algorithm}")?;
    if *auto_remove {
        writeln!(
            out,
            "    auto-remove: true (delay {}s)?",
            auto_remove_delay.as_secs()
        )?;
    } else {
        writeln!(out, "    auto-remove: false",)?;
    }
    writeln!(out, "    algorithm: {algorithm}")?;
    print_auto_flags(out, auto_algorithm)?;
    if *use_csk {
        writeln!(out, "    CSK:")?;
        writeln!(out, "      validity: {}s", or_none(csk_validity))?;
        print_auto_flags(out, auto_csk)?;
    } else {
        writeln!(out, "    KSK:")?;
        writeln!(out, "      validity: {}s", or_none(ksk_validity))?;
        print_auto_flags(out, auto_ksk)?;
        writeln!(out, "    ZSK:")?;
        writeln!(out, "      validity: {}s", or_none(zsk_validity))?;
        print_auto_flags(out, auto_zsk)?;
    }
    writeln!(out, "    records:")?;
    writeln!(out, "      TTL: {default_ttl}s")?;
    writeln!(out, "      DNSKEY:")?;
    writeln!(
        out,
        "        signature inception offset: {dnskey_inception_offset}s"
    )?;
    writeln!(
        out,
        "        signature lifetime: {dnskey_signature_lifetime}s"
    )?;
    writeln!(out, "        signature remain time: {dnskey_remain_time}s")?;
    writeln!(out, "      CDS:")?;
    writeln!(
        out,
        "        signature inception offset: {cds_inception_offset}s"
    )?;
    writeln!(out, "        signature lifetime: {cds_signature_lifetime}s")?;
    writeln!(out, "        signature remain time: {cds_remain_time}s")?;

    if publication_nameservers.is_empty() {
        writeln!(out, "    publication nameservers: <none>")?;
    } else {
        writeln!(out, "    publication nameservers:")?;

        for ns in publication_nameservers {
            writeln!(out, "     - {ns}")?
        }
    }

    Ok(())
}

fn print_auto_flags(out: &mut String, auto: &AutoConfigPolicyInfo) -> Result<(), std::fmt::Error> {
    write!(out, "      auto flags:")?;
    if !auto.start && !auto.report && !auto.expire && !auto.done {
        writeln!(out, " <none>")?;
        return Ok(());
    }
    if auto.start {
        write!(out, " start")?;
    }
    if auto.report {
        write!(out, " report")?;
    }
    if auto.expire {
        write!(out, " expire")?;
    }
    if auto.done {
        write!(out, " done")?;
    }
    writeln!(out)?;
    Ok(())
}

fn print_signer_policy(
    out: &mut String,
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
) -> Result<(), std::fmt::Error> {
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

    writeln!(out, "  signer:")?;
    writeln!(out, "    serial policy: {serial_policy}")?;
    writeln!(
        out,
        "    signature inception offset: {sig_inception_offset}s"
    )?;
    writeln!(out, "    signature validity offset: {sig_validity_offset}s")?;
    writeln!(out, "    signature remain time: {sig_remain_time}s")?;
    writeln!(
        out,
        "    signature refresh interval: {signature_refresh_interval}s"
    )?;
    writeln!(out, "    key roll time: {key_roll_time}s")?;
    writeln!(out, "    denial: {denial}")?;
    print_review(out, review)?;
    Ok(())
}

fn print_server_policy(
    out: &mut String,
    ServerPolicyInfo {
        outbound:
            cascade_api::OutboundPolicyInfo {
                provide_xfr_to,
                send_notify_to,
            },
    }: &ServerPolicyInfo,
) -> Result<(), std::fmt::Error> {
    writeln!(out, "  server:")?;
    writeln!(out, "    outbound:")?;
    print_nameserver_comms_policy(out, "provide XFR to", provide_xfr_to)?;
    print_nameserver_comms_policy(out, "send NOTIFY to", send_notify_to)?;
    Ok(())
}

fn print_review(
    out: &mut String,
    ReviewPolicyInfo { mode, on_reject }: &ReviewPolicyInfo,
) -> Result<(), std::fmt::Error> {
    write!(out, "    review:")?;
    match mode {
        ReviewPolicyMode::Off => {
            writeln!(out, " off")?;
            return Ok(());
        }
        ReviewPolicyMode::Manual => {
            writeln!(out)?;
            writeln!(out, "      mode: manual")?;
        }
        ReviewPolicyMode::Script { hook } => {
            writeln!(out)?;
            writeln!(out, "      mode: script")?;
            writeln!(out, "      hook: {hook}")?
        }
    }
    let on_reject = match on_reject {
        cascade_api::ReviewPolicyOnReject::Discard => "discard",
        cascade_api::ReviewPolicyOnReject::Halt => "halt",
    };
    writeln!(out, "      on reject: {on_reject}")?;
    Ok(())
}

fn print_nameserver_comms_policy(
    out: &mut String,
    name: &str,
    n: &[NameserverCommsPolicyInfo],
) -> Result<(), std::fmt::Error> {
    if n.is_empty() {
        writeln!(out, "      {name}: <none>")?;
        return Ok(());
    }
    writeln!(out, "      {name}:")?;
    for item in n {
        writeln!(out, "        {item}")?;
    }
    Ok(())
}
