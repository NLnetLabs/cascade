# Cascade

[![CI](https://github.com/NLnetLabs/cascade/workflows/ci/badge.svg)](https://github.com/NLnetLabs/cascade/actions?query=workflow%3Aci)
[![Packaging](https://github.com/NLnetLabs/cascade/actions/workflows/pkg.yml/badge.svg)](https://nlnetlabs.nl/packages/)
[![Documentation Status](https://app.readthedocs.org/projects/cascade-signer/badge/?version=latest)](https://cascade.docs.nlnetlabs.nl/)
[![Mastodon Follow](https://img.shields.io/mastodon/follow/114692612288811644?domain=social.nlnetlabs.nl&style=social)](https://social.nlnetlabs.nl/@nlnetlabs)

**Cascade will offer a flexible DNSSEC signing pipeline.** 

**A proof of concept (PoC) is scheduled to be available before October 2025,
followed by a production grade release in Q4 2025. Do NOT use the 
current codebase in production.**

For more information, visit the [Cascade landing page](https://blog.nlnetlabs.nl/cascade/).

If you have questions, suggestions or feature requests, don't hesitate to
[reach out](mailto:cascade@nlnetlabs.nl)!

## Pipeline Design

![cascade-pipeline 001](https://github.com/user-attachments/assets/0d9c599c-5362-4ee6-96bc-dc54de9c8c0f)

## HSM Support

Signing keys can either be BIND format key files or signing keys stored in a
KMIP compatible HSM, or PKCS#11 compatible HSM (via
[`kmip2pkcs11`](https://github.com/NLnetLabs/kmip2pkcs11)).

KMIP support is currently limited to that needed to communicate with
`kmip2pkcs11`.
