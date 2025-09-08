use futures::TryFutureExt;
use log::error;

use crate::{
    api::{
        Nsec3OptOutPolicyInfo, PolicyInfo, PolicyInfoError, PolicyListResult, PolicyReloadResult,
        ReviewPolicyInfo, SignerDenialPolicyInfo, SignerSerialPolicyInfo,
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

impl Policy {
    pub async fn execute(self, client: CascadeApiClient) -> Result<(), ()> {
        match self.command {
            PolicyCommand::List => {
                let res: PolicyListResult = client
                    .get("policy/list")
                    .send()
                    .and_then(|r| r.json())
                    .await
                    .map_err(|e| {
                        error!("HTTP request failed: {e}");
                    })?;

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
                    .map_err(|e| {
                        error!("HTTP request failed: {e}");
                    })?;

                let p = match res {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("{e:?}");
                        return Err(());
                    }
                };

                print_policy(&p);
            }
            PolicyCommand::Reload => {
                let _res: PolicyReloadResult = client
                    .post("policy/reload")
                    .send()
                    .and_then(|r| r.json())
                    .await
                    .map_err(|e| {
                        error!("HTTP request failed: {e}");
                    })?;

                println!("Policies reloaded");
            }
        }
        Ok(())
    }
}

fn print_policy(p: &PolicyInfo) {
    let name = &p.name;

    let zones: Vec<_> = p.zones.iter().map(|z| format!("{}", z)).collect();

    let zones = if !zones.is_empty() {
        zones.join(", ")
    } else {
        "<none>".into()
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
            Nsec3OptOutPolicyInfo::Disabled => "NSEC3 (opt-out: disabled)",
            Nsec3OptOutPolicyInfo::Enabled => "NSEC3 (opt-out: enabled)",
            Nsec3OptOutPolicyInfo::FlagOnly => "NSEC3 (opt-out: flag-only)",
        },
    };

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
    println!("  key manager: <unimplemented>");
    println!("  signer:");
    println!("    serial policy: {serial_policy}");
    println!("    signature inception offset: {inc} seconds",);
    println!("    signature validity offset: {val} seconds",);
    println!("    denial: {denial}");
    print_review(&p.signer.review);
    println!("  server: <unimplemented>");
}
