---
title: "ML-KEM Post-Quantum Key Agreement for TLS 1.3"
abbrev: connolly-tls-mlkem-key-agreement
category: info

docname: draft-connolly-tls-mlkem-key-agreement-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
keyword:
 - mlkem
 - tls
 - post-quantum

area: "Security"
workgroup: "Transport Layer Security"
venue:
  group: "Transport Layer Security"
  type: "Working Group"
  mail: "tls@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/tls/"
  github: "dconnolly/draft-tls-mlkem-key-agreement"

author:
 -
    fullname: Deirdre Connolly
    organization: SandboxAQ
    email: durumcrustulum@gmail.com

normative:
  RFC9180:
  FIPS203: DOI.10.6028/NIST.FIPS.203

informative:
  CDM23:
    title: "Keeping Up with the KEMs: Stronger Security Notions for KEMs and automated analysis of KEM-based protocols"
    target: https://eprint.iacr.org/2023/1933.pdf
    date: 2023
    author:
      -
        ins: C. Cremers
        name: Cas Cremers
        org: CISPA Helmholtz Center for Information Security
      -
        ins: A. Dax
        name: Alexander Dax
        org: CISPA Helmholtz Center for Information Security
      -
        ins: N. Medinger
        name: Niklas Medinger
        org: CISPA Helmholtz Center for Information Security

  hybrid: I-D.ietf-tls-hybrid-design
  tlsiana: I-D.ietf-tls-rfc8447bis

--- abstract

This memo defines ML-KEM as a standalone `NamedGroup` for use in TLS 1.3
to achieve post-quantum key agreement.


--- middle

# Introduction

## Motivation

FIPS 203 standard (ML-KEM) is a new FIPS / CNSA 2.0 standard for
post-quantum key agreement via lattice-based key establishment mechanism
(KEM). Having a fully post-quantum (not hybrid) FIPS-compliant key
agreement option for TLS 1.3 is necessary for eventual movement beyond
hybrids and for users that need to be fully post-quantum sooner than later.

# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Construction

We align with {{hybrid}} except that instead of joining ECDH options
with a KEM, we just have the KEM as a `NamedGroup`.

# Security Considerations

TLS 1.3's key schedule commits to the the ML-KEM encapsulation key and
the encapsulated shared secret ciphertext, providing resilience against
re-encapsulation attacks against KEMs used for key agreement.

ML-KEM is MAL-BIND-K-PK-secure but only LEAK-BIND-K-CT and
LEAK-BIND-K,PK-CT-secure, but because of the inclusion of the ML-KEM
ciphertext in the TLS 1.3 key schedule there is no concern of malicious
tampering (MAL) adversaries, not just honestly-generated but leaked key
pairs (LEAK adversaries). The same is true of other KEMs with weaker
binding properties, even if they were to have more constraints for
secure use in contexts outside of TLS 1.3 handshake key agreement.These
computational binding properties for KEMs were formalized in {{CDM23}}.

# IANA Considerations

This document requests/registers two new entries to the TLS Named Group
(or Supported Group) registry, according to the procedures in {{Section
6 of tlsiana}}.

 Value:
 : 0x0768 (please)

 Description:
 : MLKEM768

 DTLS-OK:
 : Y

 Recommended:
 : N

 Reference:
 : This document

 Comment:
 : FIPS 203 version of ML-KEM-768


 Value:
 : 0x1024 (please)

 Description:
 : MLKEM1024

 DTLS-OK:
 : Y

 Recommended:
 : N

 Reference:
 : This document

 Comment:
 : FIPS 203 version of ML-KEM-1024


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
