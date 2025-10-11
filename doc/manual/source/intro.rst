An Intro to DNSSEC
==================

DNS Security Extensions (DNSSEC) is often perceived as a complicated topic,
but Cascade tries to make the experience as understandable and robust as
possible. In this section we explain the basic concepts that you will
encounter in the DNSSEC signing process.

The Value of DNSSEC
-------------------

DNSSEC protects against attacks on the DNS infrastructure by digitally
signing data to help ensure its validity. In order to ensure a secure lookup,
the signing must happen at every level in the DNS lookup process.

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

So... 

