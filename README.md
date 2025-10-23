# Cascade

[![CI](https://github.com/NLnetLabs/cascade/workflows/ci/badge.svg)](https://github.com/NLnetLabs/cascade/actions?query=workflow%3Aci)
[![Packaging](https://github.com/NLnetLabs/cascade/actions/workflows/pkg.yml/badge.svg)](https://nlnetlabs.nl/packages/)
[![Documentation Status](https://app.readthedocs.org/projects/cascade-signer/badge/?version=latest)](https://cascade.docs.nlnetlabs.nl/)
[![Mastodon Follow](https://img.shields.io/mastodon/follow/114692612288811644?domain=social.nlnetlabs.nl&style=social)](https://social.nlnetlabs.nl/@nlnetlabs)

Cascade is a flexible DNSSEC signing pipeline. 

An [alpha release](https://github.com/NLnetLabs/cascade/releases) is
available now, we encourage you to test it. Read our [comprehensive
documentation](https://cascade.docs.nlnetlabs.nl/) to get started.

Based on your feedback, we will continue work to offer a production grade
release of Cascade in the first half of 2026. Please do *not* use the current
codebase in production.

If you have questions, suggestions or feature requests, don't hesitate to
create an [issue on GitGub](https://github.com/NLnetLabs/cascade/issues),
send us [an email](mailto:cascade@nlnetlabs.nl) or mention us on
[Mastodon](https://social.nlnetlabs.nl/@nlnetlabs/)! You can also find us in
the [NLnet Labs DNS](https://chat.dns-oarc.net/community/channels/ldns)
channel on the [DNS OARC Mattermost
server](https://www.dns-oarc.net/oarc/services/chat).

## Feature Set

Cascade offers a pipeline where zones are loaded, signed and published in
several stages, letting you review and approve with automation at each step:

![cascade-pipeline](https://github.com/user-attachments/assets/8427c617-bb73-44a4-a47e-90e9699157e0)

### Flexible Signing

Cascade does *not* require a Hardware Security Module (HSM) to operate. It is
able to use OpenSSL and ring software cryptography to generate keys in
on-disk files. For operators wishing to use an HSM, Cascade can connect to
KMIP and PKCS#11 compatible
[HSMs](https://cascade.docs.nlnetlabs.nl/en/latest/hsms.html).

### Bespoke Zone Verification

Using [Review
Hooks](https://cascade.docs.nlnetlabs.nl/en/latest/review-hooks.html),
Cascade supports optional verification of your zone data at two critical
stages: verification of the unsigned zone, and verification of the signed
zone. These review hooks can be used to perform any validation you require to
ensure your zone is correct at all stages, using any (third-party) tools
desired.

### Controllability

Cascade gives you tight control over [key
management](https://cascade.docs.nlnetlabs.nl/en/latest/key-management.html),
automation of key rolls and the DNSSEC signing process.

### Robustness

Cascade is written in the Rust programming language making it significantly
less likely to crash or suffer from memory safety issues, and at the same
time making it easier to leverage the higher core count of modern computers
via Rust's "fearless concurrency" when needed.

## Installation

Getting started with Cascade is really easy by installing a binary package
for either Debian and Ubuntu or for Red Hat Enterprise Linux (RHEL) and
compatible systems such as Rocky Linux.

Alternatively, you can build from the source code using Cargo, Rust’s build
system and package manager.

