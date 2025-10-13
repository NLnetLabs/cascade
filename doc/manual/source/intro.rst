An Intro to DNSSEC
==================

DNS Security Extensions (DNSSEC) protect end users against forged or modified DNS responses, both deliberate and accidental, by digitally signing DNS record data to allow its authenticity to be verified. 

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
3. On-Path Attacks: DNSSEC helps prevent attackers from
   intercepting and altering DNS queries and responses, ensuring data
   integrity during transit. 
4. Authenticated Denial of Existence: attackers can try to exploit
   vulnerabilities to forge an "unauthenticated" response to a non-existent
   record (NXDOMAIN). DNSSEC uses NSEC records to provide a cryptographically
   signed proof that a record does not exist, making the zone resistant to
   this type of attack. 

DNSSEC uses digital signatures to ensure the response is authentic and has
not been tampered with. By verifying DNS responses, DNSSEC prevents malicious
actors from for example redirecting users to fake or malicious websites. 

How DNSSEC Works 
----------------

DNSSEC adds an extra layer of information to DNS responses, allowing
resolvers to verify that each answer is authentic. This is done by adding a
digital signature to resource records grouped by type (RRsets) in a zone.
These digital signatures are stored in DNS nameservers alongside common
record types like A, AAAA, MX, CNAME, etc.

The keys that are used for DNSSEC are asymmetric, such as RSA and ECDSA
(Elliptic Curve Digital Signature Algorithm). The private part is used for
signing and must be kept secret all all times.

DNSSEC adds these record types:

- RRSIG, which contains a cryptographic signature over an :term:`Resource Record Set (RRset)`
- DNSKEY, which contains a public signing key
- DS, which stores a hashed representation of a DNSKEY record
- NSEC and NSEC3, which offer proof that a DNS record *doesn't*
  exist
- CDNSKEY and CDS, allowing a child zone to request updates to DS record(s)
  in the parent zone

Each DNSSEC-enabled zone, including the root ``(.)``, a Top-Level Domain
(TLD) such as ``(.com)``, or a Second-Level Domain (SLD) such as
``(.example.com)`` has its public key stored in DNSKEY records. The
corresponding private key is used to generate so-called Resource Record
Signature (RRSIG) records, which are cryptographic signatures over the data
in your zone. 

Resource Record Sets
""""""""""""""""""""

Rather than signing each resource record individually, the DNSKEY is used to
sign a :term:`Resource Record Set (RRset)`, which is a collection of
individual DNS records that share the same name and type. For example, all
the A (IPv4) records for a specific domain are grouped into a
single RRset. RRsets are the fundamental records for DNSSEC signing, as the
entire set is signed digitally to ensure its integrity. 

Zone Signing Keys
"""""""""""""""""

Each zone in DNSSEC has a :term:`Zone signing key (ZSK)` set. The private
portion of this key set key digitally signs each RRset in the zone. The the
public portion of the set is used to verify the signature. You create digital
signatures for each RRset using the private ZSK and stores them on your
nameserver as RRSIG records. 

We now almost have all the puzzle pieces in place for a :term:`Validating 
resolver` to verify the signatures. The remaining part you need to make
available is the public part of the ZSK by adding it to your nameserver in a
DNSKEY record. 

Now, the resolver can use the RRset, RRSIG, and public ZSK to validate if the
response is authentic.

Key Signing Keys
""""""""""""""""

In addition to a zone signing key, DNSSEC name servers also have a :term:`Key
signing key (KSK)`. The KSK only signs the :term:`apex <Apex (Zone)>` DNSKEY
RRset in a zone. The KSK signs the public ZSK, creating an RRSIG for the
DNSKEY.

The public part of the KSK in published in another DNSKEY record. Both the
public KSK and public ZSK are signed by the private KSK. Validating resolvers
can use the public KSK to validate the public ZSK.

Building a Chain of Trust
"""""""""""""""""""""""""

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
:term:`"bogus" <Bogus (DNSSEC State)>` status, telling you that the DNS
record does not pass DNSSEC authentication checks. 

The other possible DNSSEC validation states are :term:`"secure" <Secure
(DNSSEC State)>`, :term:`"insecure" <Insecure (DNSSEC State)>` and
:term:`"indeterminate" <Indeterminate (DNSSEC State)>`. 