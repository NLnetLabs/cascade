use futures::TryFutureExt;

use crate::{
    api::{
        NameserverCommsPolicyInfo, PolicyChange, PolicyChanges, PolicyInfo, PolicyInfoError,
        PolicyListResult, PolicyReloadError, ReviewPolicyInfo, SignerDenialPolicyInfo,
        SignerSerialPolicyInfo,
    },
    cli::client::{format_http_error, CascadeApiClient},
    common::ansi,
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
                let res: PolicyListResult = client
                    .get("policy/")
                    .send()
                    .and_then(|r| r.json())
                    .await
                    .map_err(format_http_error)?;

                for policy in res.policies {
                    println!("{policy}");
                }
            }
            PolicyCommand::Show { name } => {
                let res: Result<PolicyInfo, PolicyInfoError> = client
                    .get(&format!("policy/{name}"))
                    .send()
                    .and_then(|r| r.json())
                    .await
                    .map_err(format_http_error)?;

                let p = match res {
                    Ok(p) => p,
                    Err(e) => {
                        return Err(format!("{e:?}"));
                    }
                };

                print_policy(&p);
            }
            PolicyCommand::Reload => {
                let res: Result<PolicyChanges, PolicyReloadError> = client
                    .post("policy/reload")
                    .send()
                    .and_then(|r| r.json())
                    .await
                    .map_err(format_http_error)?;

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
    let none = "<none>".to_string();
    let name = &p.name;

    let zones: Vec<_> = p.zones.iter().map(|z| format!("{}", z)).collect();

    let zones = if !zones.is_empty() {
        zones.join(", ")
    } else {
        none.clone()
    };

    let serial_policy = match p.signer.serial_policy {
        SignerSerialPolicyInfo::Keep => "keep",
        SignerSerialPolicyInfo::Counter => "counter",
        SignerSerialPolicyInfo::UnixTime => "unix time",
        SignerSerialPolicyInfo::DateCounter => "date counter",
    };

    let inc = p.signer.sig_inception_offset.as_secs();
    let val = p.signer.sig_validity_offset.as_secs();

    let denial = match &p.signer.denial {
        SignerDenialPolicyInfo::NSec => "NSEC",
        SignerDenialPolicyInfo::NSec3 { opt_out } => match opt_out {
            true => "NSEC3 (opt-out: disabled)",
            false => "NSEC3 (opt-out: enabled)",
        },
    };

    let hsm_server_id = p.key_manager.hsm_server_id.as_ref().unwrap_or(&none);

    fn print_review(r: &ReviewPolicyInfo) {
        println!("    review:");
        println!("      required: {}", r.required);
        println!(
            "      cmd_hook: {}",
            r.cmd_hook.as_ref().cloned().unwrap_or("<none>".into())
        );
    }

    fn print_nameserver_comms_policy(n: &[NameserverCommsPolicyInfo]) {
        for item in n {
            println!("        {item}");
        }
    }

    println!("{name}:");
    println!("  zones: {zones}");
    println!("  loader:");
    print_review(&p.loader.review);
    println!("  key manager:");
    println!("    hsm server: {hsm_server_id}");
    println!("  signer:");
    println!("    serial policy: {serial_policy}");
    println!("    signature inception offset: {inc} seconds",);
    println!("    signature validity offset: {val} seconds",);
    println!("    denial: {denial}");
    print_review(&p.signer.review);
    println!("  server:");
    println!("    outbound:");
    println!("      accept XFR requests from:");
    print_nameserver_comms_policy(&p.server.outbound.accept_xfr_requests_from);
    println!("      send NOTIFY to:");
    print_nameserver_comms_policy(&p.server.outbound.send_notify_to);
}
