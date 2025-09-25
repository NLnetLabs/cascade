use futures::TryFutureExt;

use crate::{
    api::{
        PolicyChange, PolicyChanges, PolicyInfo, PolicyInfoError, PolicyListResult,
        PolicyReloadError, ReviewPolicyInfo, SignerDenialPolicyInfo, SignerSerialPolicyInfo,
    },
    cli::client::CascadeApiClient,
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

#[allow(unused)]
pub mod ansi {
    pub const BLACK: &str = "\x1b[0;30m";
    pub const RED: &str = "\x1b[0;31m";
    pub const GREEN: &str = "\x1b[0;32m";
    pub const YELLOW: &str = "\x1b[0;33m";
    pub const BLUE: &str = "\x1b[0;34m";
    pub const PURPLE: &str = "\x1b[0;35m";
    pub const CYAN: &str = "\x1b[0;36m";
    pub const WHITE: &str = "\x1b[0;37m";
    pub const GRAY: &str = "\x1b[38;5;248m";
    pub const RESET: &str = "\x1b[0m";
    pub const ITALIC: &str = "\x1b[3m";
}

impl Policy {
    pub async fn execute(self, client: CascadeApiClient) -> Result<(), String> {
        match self.command {
            PolicyCommand::List => {
                let res: PolicyListResult = client
                    .get("policy/list")
                    .send()
                    .and_then(|r| r.json())
                    .await
                    .map_err(|e| format!("HTTP request failed: {e}"))?;

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
                    .map_err(|e| format!("HTTP request failed: {e}"))?;

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
                    .map_err(|e| format!("HTTP request failed: {e}"))?;

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
    println!("  server: <unimplemented>");
}
