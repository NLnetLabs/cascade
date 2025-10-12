An Intro to DNSSEC
==================

DNS Security Extensions (DNSSEC) protects against attacks on the DNS
infrastructure by digitally signing data to help ensure its validity. In
order to ensure a secure lookup, signing must happen at every level in the
DNS lookup process.

Though DNSSEC is often perceived as a complicated topic, Cascade tries to
make the experience as understandable and robust as possible. In this section
we explain the basic concepts that you will encounter in the DNSSEC signing
process.

The Value of DNSSEC
-------------------

DNSSEC mitigates attacks that compromise the integrity and authenticity of
DNS data. These can be categorised into roughly four types:

1. DNS Spoofing: the act of sending a forged DNS response to a user or
   resolver. 
2. Cache Poisoning: an attacker injects fake DNS data into a DNS resolver's
   cache. When other users request the same record, the resolver serves the
   malicious, cached information. DNSSEC's validation process prevents this
   by ensuring the cached data is cryptographically signed by the
   authoritative source. 
3. Man-in-the-Middle Attacks: DNSSEC helps prevent attackers from
   intercepting and altering DNS queries and responses, ensuring data
   integrity during transit. 
4. Authenticated Denial of Existence: attackers can try to exploit
   vulnerabilities to forge an "unauthenticated" response to a non-existent
   record (NXDOMAIN). DNSSEC uses NSEC records to provide a cryptographically
   signed proof that a record does not exist, making the zone resistant to
   this type of attack. 

DNSSEC does not encrypt DNS data, but rather uses digital signatures to
ensure the response is authentic and has not been tampered with. By verifying
DNS responses, DNSSEC prevents malicious actors from for example redirecting
users to fake or malicious websites. 

How DNSSEC Works 
----------------

DNSSEC adds an extra layer of information to DNS responses, allowing
resolvers to verify that each answer is authentic. This is done by adding a 
digital signature to each Resource Record (RR) in a zone. 

The keys that are used for DNSSEC asymmetric, such as RSA and ECDSA (Elliptic
Curve Digital Signature Algorithm). The private part is used for signing and
must be kept secret all all times. The the public part of the key is
published in DNS as a DNSKEY record, which is used for verification.

Each DNSSEC-enabled zone, including the root ``(.)``, a Top-Level Domain
(TLD) such as ``.com``, or a Second-Level Domain (SLD) such as
``example.com`` has its public key stored in DNSKEY records. The
corresponding private key is used to generate so-called Resource Record
Signature (RRSIG) records, which are cryptographic signatures over the data
in your zone. 

Rather than signing each RR individually, the DNSKEY is used to sign a
Resource Record Set (RRSET), which is a collection of individual DNS records
that share the same name and type. For example, all the A (IPv4) or AAAA
(IPv6) records for a specific domain are grouped into a single RRSET. RRSETs
are the fundamental records for DNSSEC signing, as the entire set is signed
digitally to ensure its integrity. 

Chain of Trust
""""""""""""""

DNSSEC relies on a chain of trust by creating a hierarchical system where
each DNS zone is cryptographically validated by the zone above it, starting
from the root zone, which acts as a trusted starting point. Without a chain
of trust, a DNSSEC-validating resolver wouldn't know where to begin trusting
DNS data.

The chain of trust works though the interaction of two key DNSSEC record
types: DNSKEY records and Delegation Signer (DS) records. The DNSSEC Trust
Anchor is the top of this chain, representing a public Key Signing Key (KSK)
that is implicitly trusted by a DNSSEC-validating resolver. 

A parent zone doesn't directly sign the data in a child zone. To establish a
secure delegation, the parent zone signs a a hash of the child zone's KSK. 
This is called a DS record.

To do this, the operator of a child zone (such as example.com) generates a
KSK and then calculates a hash over it. This digest is then given to the
parent zone (in this case .com). The parent zone publishes this digest as a
DS record within its own zone file and signs it with its own Key Signing Key.
This DS record effectively acts as a secure pointer to the child zone's KSK.
This process is repeated all the way down the hierarchy. 

Validation
""""""""""

The chain of trust must remain unbroken at all times. If, for example, a DS
record points to an incorrect DNSKEY, or if a signature is invalid or
missing, resolvers will not be able to verify the data. This results in a
"bogus" status, telling you that the DNS record does not pass DNSSEC
authentication checks. 

The other possible DNSSEC validation states are "secure" (valid) or
"insecure" (unsigned or DNSSEC not implemented). 