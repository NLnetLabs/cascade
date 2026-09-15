FIXME Some us are worried that the list of assumptions will become cluttered if we also include how the user is expected to meet the assumption. Ie. no tutorials interspersed with security analysis.

TODO while discussing:
    - Does KMIP have a timeout? Define reasonable response time in this document with a reference, preferably to a spec.
    - keyset queries for DS records at the parent. In theory it could do DNSSEC validation to guard against tampering. It queries for SOA records, which could also be DNSSEC validated if the zone already is connected to the parent.
    - discussion about port defaults on the server: systemd bind to 53, the default config binds to 4542
  - NSEC3 collisions
  - DNSSEC validation for dnst-keyset queries
  - Zone server resilience to DoS attacks
  - Review hook timeouts

##############
 Threat Model
##############

Cascade is a DNS Security Extensions (:doc:`DNSSEC <intro>`) signing solution
that is meant to be integrated into a :term:`zone` publication pipeline. It is
meant to run as a "hidden signer", a dedicated server with restricted access
that takes local zone files or zones received over the network from an
upstream :term:`primary nameserver`, signs those zones and makes the results
available to downstream, Internet facing :term:`secondary nameservers
<secondary nameserver>`.

The Domain Name System (DNS) is a globally distributed hierarchical lookup
system which serves data associated to a domain name. DNS Security Extensions
(DNSSEC) protect end users against forged or modified DNS responses, both
deliberate and accidental, by digitally signing DNS record data to allow its
authenticity to be verified.

The zone data Cascade retrieves from the primary nameserver, as well as any
potential Hardware Security Modules (HSM) are trusted. Trust can be
established by cryptographic signatures through Transaction Signature (TSIG)
keys, network segmentation, etc.

.. image:: img/cascade-data-flow.png

[itemized list of data flows]

FIXME There are N kinds of data:

- **Zone data** is the data received. Trust is established by verifying TSIG
  records. 

We have created a threat model for Cascade [#f1]_, where we outline the
assumptions of the system that Cascade runs on, and the guarantees
Cascade provides given that those assumptions are met. The model concludes
with a description of threats posed by adversaries with different
capabilities.

*********************************
 Goals, Assumptions & Guarantees
*********************************

Cascade should:

- retrieve zone data from an upstream nameserver in a reasonable time,
- parse zone data correctly and in a reasonable time,
- FIXME something related to (freshness of) signatures 

General assumptions:

- The user uses authentic copies of cascade(d), dnst.
- An adversary does not have local user access to the host machine Cascade
  runs on.
- An adversary does not have access to key material (KSK/ZSK/CSK/TSIG).

- Key material is protected from unauthorized access, including command-line
  history and backup processes. 
  
- The host machine Cascade runs on has enough resources (compute, memory,
  disk, network) for Cascade to function, including during the execution of
  user-supplied review hooks.

Assumptions on input zone data:

- Input zone contents as received by Cascade are assumed to be what the
  operators wants signed
- Input zone contents are well-formed and suitable for DNSSEC signing (e.g.
  free of NSEC3 collisions)

Assumptions 

AVAILABILITY
- if there's an attacker, we have a DoS risk

CONFIDENTIALITY
- if there's an attacker, the zone contents are known

INTEGRITY
- 
- Input zone contents are TSIG protected, or the adversary does not ha


## HSM
- Cascade, if configured to use an HSM, relies on a correctly functioning KMIP server. Correctly functioning includes a reasonable response time and sufficient signing capacity for the signing workload. See FIXME for the threat model of the cascade-hsm-bridge which can provide this functionality in combination with a vendor pckcs#11 library.

## remote-control server
- An adversary does not have access to the remote-control server endpoint. By default, it listens on localhost only. When exposing the server to the network, compensating measures outside of Cascade are required.

## Review server
- An adversary does not have access to the review server endpoint. By default, it listens on localhost only. When exposing the server to the network, compensating measures outside of Cascade are required.

## Review hook execution
- User-supplied review hooks terminate in a reasonable time.
- User-supplied review hooks code are not under control of the attacker.

## Publication server
- An adversary does not have access to the publication server endpoint. By default, it listens on localhost only. When exposing the server to the network, compensating measures outside of Cascade are required.

Cascade guarantees the following:

- TSIG signed inputs are validated to detect tampering and rejected if invalid.
- Cacade's output is a correct 'signed zone' (See Section 10 in RFC 9499) TODO: get wording from def.
- Cascade's per-zone pipelines are independent while load is under signing capacity
- Cascade does not crash
- Pubishes refreshed signatures early enough for propagation into caches.

*******************************
 What an adversary can achieve
*******************************

With the aforementioned assumptions and guarantees in mind, the following are
examples of things an adversary with various capabilities can achieve.

An adversary that can tamper with zone contents in the upstream registry could:
    
   - tamper with input zones prior to them being signed by Cascade (added by Jannis) and included in the published zone

An adversary with network access on-path between Cascade and up-/downstream
nameservers or HSM could:

   - block access to the dns zone, degrade throughput of transfer, and cause a
     Denial of Service on Cascade

***********************************
 Example violations of assumptions
***********************************

The following are examples of the implications associated with violating some
of the aforementioned assumptions.

An adversary with access to [list of servers] remote-server, review-server,
publication-server could:
 
    - cause a Denial of Service

An adversary with access to TSIG key material and access to the upstream nameserver and Cascade could:

-  inject or overwrite zone content passed to Cascade

An adversary who compromises the host system could:

-  stop, modify, and manipulate Cascade,
-  modify the Cascade configuration and policies,
-  add, modify or remove signing material,
-  bypass Cascade and provide all sorts of invalid or altered zone contents
   
.. rubric:: Footnotes

.. [#f1]

   Based on the `threat model for restic
   <https://github.com/restic/restic/blob/master/doc/design.rst#threat-model>`_.
