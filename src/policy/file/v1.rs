//! Version 1 of the policy file.

use std::time::Duration;

use crate::policy::{
    AutoConfig, DsAlgorithm, KeyManagerPolicy, KeyParameters, KeyValidity, LoaderPolicy,
    NameserverCommsPolicy, OutboundPolicy, PolicyVersion, ReviewPolicy, ServerPolicy,
    SignerDenialPolicy, SignerPolicy, SignerSerialPolicy,
};
use crate::policy::{RejectionPolicy, ReviewMode};

pub use cascade_policy_file::v1::*;

//------------------------------------------------------------------------------
//
// NOTE: Use destructuring patterns instead of field access, as the former are
// exhaustive and cause compilation errors when new fields are added. This helps
// us keep this module synchronized with external changes.

pub fn parse(
    Spec {
        loader,
        key_manager,
        signer,
        server,
    }: Spec,
    name: &str,
) -> PolicyVersion {
    PolicyVersion {
        name: name.into(),
        loader: loader.into(),
        key_manager: key_manager.into(),
        signer: signer.into(),
        server: server.into(),
    }
}

impl From<LoaderSpec> for LoaderPolicy {
    fn from(LoaderSpec { review }: LoaderSpec) -> Self {
        Self {
            review: review.map(Into::into).unwrap_or_default(),
        }
    }
}

impl From<KeyManagerSpec> for KeyManagerPolicy {
    fn from(
        KeyManagerSpec {
            ksk:
                KskManagementSpec {
                    validity: ksk_validity,
                    rollover: auto_ksk,
                },
            zsk:
                ZskManagementSpec {
                    validity: zsk_validity,
                    rollover: auto_zsk,
                },
            csk:
                CskManagementSpec {
                    validity: csk_validity,
                    rollover: auto_csk,
                },
            algorithm: algorithm_rollover,
            ds_algorithm,
            auto_remove,
            auto_remove_delay,
            records:
                KeyManagerRecordsSpec {
                    ttl: default_ttl,
                    dnskey:
                        RecordSigningSpec {
                            signature_inception_offset: dnskey_inception_offset,
                            signature_lifetime: dnskey_signature_lifetime,
                            signature_remain_time: dnskey_remain_time,
                        },
                    cds:
                        RecordSigningSpec {
                            signature_inception_offset: cds_inception_offset,
                            signature_lifetime: cds_signature_lifetime,
                            signature_remain_time: cds_remain_time,
                        },
                },
            generation:
                KeyManagerGenerationSpec {
                    hsm_server_id,
                    use_csk,
                    algorithm: keygen_algorithm,
                },
            publication_nameservers,
        }: KeyManagerSpec,
    ) -> Self {
        Self {
            hsm_server_id,
            use_csk,
            algorithm: keygen_algorithm.into(),
            ksk_validity: ksk_validity.into(),
            zsk_validity: zsk_validity.into(),
            csk_validity: csk_validity.into(),
            auto_ksk: auto_ksk.into(),
            auto_zsk: auto_zsk.into(),
            auto_csk: auto_csk.into(),
            auto_algorithm: algorithm_rollover.into(),
            dnskey_inception_offset: dnskey_inception_offset.as_secs(),
            dnskey_signature_lifetime: dnskey_signature_lifetime.as_secs(),
            dnskey_remain_time: dnskey_remain_time.as_secs(),
            cds_inception_offset: cds_inception_offset.as_secs(),
            cds_signature_lifetime: cds_signature_lifetime.as_secs(),
            cds_remain_time: cds_remain_time.as_secs(),
            ds_algorithm: ds_algorithm.into(),
            default_ttl: default_ttl.as_ttl(),
            auto_remove,
            auto_remove_delay: Duration::from_secs(auto_remove_delay.as_secs().into()),
            publication_nameservers: publication_nameservers
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }
}

impl From<KeyGenerationParametersSpec> for KeyParameters {
    fn from(value: KeyGenerationParametersSpec) -> Self {
        match value {
            KeyGenerationParametersSpec::RsaSha256(bits) => Self::RsaSha256(bits.into()),
            KeyGenerationParametersSpec::RsaSha512(bits) => Self::RsaSha512(bits.into()),
            KeyGenerationParametersSpec::EcdsaP256Sha256 => Self::EcdsaP256Sha256,
            KeyGenerationParametersSpec::EcdsaP384Sha384 => Self::EcdsaP384Sha384,
            KeyGenerationParametersSpec::Ed25519 => Self::Ed25519,
            KeyGenerationParametersSpec::Ed448 => Self::Ed448,
        }
    }
}

impl From<RolloverSpec> for AutoConfig {
    fn from(
        RolloverSpec {
            auto_start,
            auto_report,
            auto_expire,
            auto_done,
        }: RolloverSpec,
    ) -> Self {
        Self {
            start: auto_start,
            report: auto_report,
            expire: auto_expire,
            done: auto_done,
        }
    }
}

impl From<KeyValiditySpec> for KeyValidity {
    fn from(value: KeyValiditySpec) -> Self {
        match value {
            KeyValiditySpec::Finite(span) => Self::Finite(span.as_secs()),
            KeyValiditySpec::Forever => Self::Forever,
        }
    }
}

impl From<DsAlgorithmSpec> for DsAlgorithm {
    fn from(value: DsAlgorithmSpec) -> Self {
        match value {
            DsAlgorithmSpec::Sha256 => Self::Sha256,
            DsAlgorithmSpec::Sha384 => Self::Sha384,
        }
    }
}

impl From<SignerSpec> for SignerPolicy {
    fn from(
        SignerSpec {
            serial_policy,
            signature_inception_offset,
            signature_lifetime,
            signature_remain_time,
            signature_refresh_interval,
            key_roll_time,
            denial,
            review,
        }: SignerSpec,
    ) -> Self {
        Self {
            serial_policy: serial_policy.into(),
            sig_inception_offset: signature_inception_offset.as_secs(),
            sig_validity_time: signature_lifetime.as_secs(),
            sig_remain_time: signature_remain_time.as_secs(),
            signature_refresh_interval: signature_refresh_interval.as_secs(),
            key_roll_time: key_roll_time.as_secs(),
            denial: denial.into(),
            review: review.into(),
        }
    }
}

impl From<SignerSerialPolicySpec> for SignerSerialPolicy {
    fn from(value: SignerSerialPolicySpec) -> Self {
        match value {
            SignerSerialPolicySpec::Keep => Self::Keep,
            SignerSerialPolicySpec::Counter => Self::Counter,
            SignerSerialPolicySpec::UnixTime => Self::UnixTime,
            SignerSerialPolicySpec::DateCounter => Self::DateCounter,
        }
    }
}

impl From<SignerDenialSpec> for SignerDenialPolicy {
    fn from(value: SignerDenialSpec) -> Self {
        match value {
            SignerDenialSpec::NSec => Self::NSec,
            SignerDenialSpec::NSec3 { opt_out } => Self::NSec3 { opt_out },
        }
    }
}

impl From<ReviewSpec> for ReviewPolicy {
    fn from(value: ReviewSpec) -> Self {
        match value {
            ReviewSpec::Off => Self {
                mode: ReviewMode::Off,
                on_reject: RejectionPolicy::Discard,
            },
            ReviewSpec::Manual { on_reject } => Self {
                mode: ReviewMode::Manual,
                on_reject: on_reject.into(),
            },
            ReviewSpec::Script { hook, on_reject } => Self {
                mode: ReviewMode::Script { hook },
                on_reject: on_reject.into(),
            },
        }
    }
}

impl From<RejectionSpec> for RejectionPolicy {
    fn from(value: RejectionSpec) -> Self {
        match value {
            RejectionSpec::Discard => Self::Discard,
            RejectionSpec::Halt => Self::Halt,
        }
    }
}

impl From<ServerSpec> for ServerPolicy {
    fn from(ServerSpec { outbound }: ServerSpec) -> Self {
        Self {
            outbound: outbound.into(),
        }
    }
}

impl From<OutboundSpec> for OutboundPolicy {
    fn from(
        OutboundSpec {
            provide_xfr_to,
            send_notify_to,
            max_diffs,
            max_diffs_size,
        }: OutboundSpec,
    ) -> Self {
        Self {
            provide_xfr_to: provide_xfr_to.into_iter().map(Into::into).collect(),
            send_notify_to: send_notify_to.into_iter().map(Into::into).collect(),
            max_diffs,
            max_diffs_size,
        }
    }
}

impl From<NameserverCommsSpec> for NameserverCommsPolicy {
    fn from(value: NameserverCommsSpec) -> Self {
        let (NameserverCommsSpec::Simple(SimpleNameserverCommsSpec {
            addr,
            tsig_key_name,
        })
        | NameserverCommsSpec::Complex(ComplexNameserverCommsSpec {
            addr,
            tsig_key_name,
        })) = value;

        Self {
            addr,
            tsig_key_name,
        }
    }
}
