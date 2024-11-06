---
title: "ML-KEM Post-Quantum Key Agreement for TLS 1.3"
abbrev: connolly-tls-mlkem-key-agreement
category: info

docname: draft-connolly-tls-mlkem-key-agreement-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - kems
 - tls

area: "Security"
workgroup: "Transport Layer Security"
venue:
  group: "Transport Layer Security"
  type: "Working Group"
  mail: "tls@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/tls/"
  github: "dconnolly/draft-connolly-tls-mlkem-key-agreement"

author:
 -
    fullname: Deirdre Connolly
    organization: SandboxAQ
    email: durumcrustulum@gmail.com

normative:
  RFC9180:
  FIPS203: DOI.10.6028/NIST.FIPS.203

informative:
  AVIRAM:
    target: https://mailarchive.ietf.org/arch/msg/tls/F4SVeL2xbGPaPB2GW_GkBbD_a5M/
    title: "[TLS] Combining Secrets in Hybrid Key Exchange in TLS 1.3"
    date: 2021-09-01
    author:
      -
        ins: Nimrod Aviram
      -
        ins: Benjamin Dowling
      -
        ins: Ilan Komargodski
      -
        ins: Kenny Paterson
      -
        ins: Eyal Ronen
      -
        ins: Eylon Yogev
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

  DOWLING: DOI.10.1007/s00145-021-09384-1
  FO: DOI.10.1007/s00145-011-9114-1
  HHK: DOI.10.1007/978-3-319-70500-2_12
  HPKE: RFC9180
  hybrid: I-D.ietf-tls-hybrid-design
  LUCKY13:
    target: https://ieeexplore.ieee.org/iel7/6547086/6547088/06547131.pdf
    title: "Lucky Thirteen: Breaking the TLS and DTLS record protocols"
    author:
    -
      ins: N. J. Al Fardan
    -
      ins: K. G. Paterson
  RACCOON:
    target: https://raccoon-attack.com/
    title: "Raccoon Attack: Finding and Exploiting Most-Significant-Bit-Oracles in TLS-DH(E)"
    author:
    -
      ins: R. Merget
    -
      ins: M. Brinkmann
    -
      ins: N. Aviram
    -
      ins: J. Somorovsky
    -
      ins: J. Mittmann
    -
      ins: J. Schwenk
    date: 2020-09
  tlsiana: I-D.ietf-tls-rfc8447bis

--- abstract

This memo defines ML-KEM-512, ML-KEM-768, and ML-KEM-1024 as a standalone
`NamedGroup`s for use in TLS 1.3 to achieve post-quantum key agreement.

--- middle

# Introduction

## Motivation

FIPS 203 standard (ML-KEM) is a new FIPS standard for post-quantum
key agreement via lattice-based key establishment mechanism
(KEM). Having a fully post-quantum (not hybrid) key agreement
option for TLS 1.3 is necessary for migrating beyond hybrids and
for users that need to be fully post-quantum.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Key encapsulation mechanisms {#kems}

This document models key agreement as key encapsulation mechanisms
(KEMs), which consist of three algorithms:

- `KeyGen() -> (pk, sk)`: A probabilistic key generation algorithm,
  which generates a public encapsulation key `pk` and a secret
  decapsulation key `sk`.
- `Encaps(pk) -> (ct, shared_secret)`: A probabilistic encapsulation
  algorithm, which takes as input a public encapsulation key `pk` and
  outputs a ciphertext `ct` and shared secret `shared_secret`.
- `Decaps(sk, ct) -> shared_secret`: A decapsulation algorithm, which takes as
  input a secret decapsulation key `sk` and ciphertext `ct` and outputs
  a shared secret `shared_secret`.


ML-KEM-512, ML-KEM-768 and ML-KEM-1024 conform to this API:

- ML-KEM-512 has encapsulation keys of size 800 bytes, expanded decapsulation
  keys of 1632 bytes, decapsulation key seeds of size 64 bytes, ciphertext
  size of 768 bytes, and shared secrets of size 32 bytes

- ML-KEM-768 has encapsulation keys of size 1184 bytes, expanded
  decapsulation keys of 2400 bytes, decapsulation key seeds of size 64 bytes,
  ciphertext size of 1088 bytes, and shared secrets of size 32 bytes

- ML-KEM-1024 has encapsulation keys of size 1568 bytes, expanded
  decapsulation keys of 3168 bytes, decapsulation key seeds of size 64 bytes,
  ciphertext size of 1568 bytes, and shared secrets of size 32 bytes

# Construction {#construction}

We define the KEMs as `NamedGroup`s, sent in the `supported_groups`
extension.

## Negotiation {#negotiation}

Each method is its own solely post-quantum key agreement method, which
are assigned their own identifiers, registered by IANA in the TLS
Supported Groups registry:

~~~
    enum {

         ...,

          /* ML-KEM Key Agreement Methods */
          mlkem512(0x0200),
          mlkem768(0x0201),
          mlkem1024(0x0202)

         ...,

    } NamedGroup;
~~~


## Transmitting encapsulation keys and ciphertexts {#construction-transmitting}

The encapsulation key and ciphertext values are directly encoded with
fixed lengths as in {{FIPS203}}; the representation and length of
elements MUST be fixed once the algorithm is fixed.

In TLS 1.3 a KEM encapsulation key or KEM ciphertext is
represented as a `KeyShareEntry`:

~~~
    struct {
        NamedGroup group;
        opaque key_exchange<1..2^16-1>;
    } KeyShareEntry;
~~~

These are transmitted in the `extension_data` fields of
`KeyShareClientHello` and `KeyShareServerHello` extensions:

~~~
    struct {
        KeyShareEntry client_shares<0..2^16-1>;
    } KeyShareClientHello;

    struct {
        KeyShareEntry server_share;
    } KeyShareServerHello;
~~~

The client's shares are listed in descending order of client preference;
the server selects one algorithm and sends its corresponding share.

For the client's share, the `key_exchange` value contains the `pk`
output of the corresponding KEM `NamedGroup`'s `KeyGen` algorithm.

For the server's share, the `key_exchange` value contains the `ct`
output of the corresponding KEM `NamedGroup`'s `Encaps` algorithm.

For all parameter sets, the server MUST perform the encapsulation key check
described in Section 7.2 of {{FIPS203}} on the client's encapsulation key,
and abort with an `illegal_parameter` alert if it fails.

For all parameter sets, the client MUST check if the ciphertext length
matches the selected parameter set, and abort with an `illegal_parameter`
alert if it fails.

If ML-KEM decapsulation fails for any other reason, the connection MUST be
aborted with an `internal_error` alert.

## Shared secret calculation {#construction-shared-secret}

The shared secret output from the ML-KEM `Encaps` and `Decaps`
algorithms over the appropriate keypair and ciphertext results in the
same shared secret `shared_secret`, which is inserted into the TLS 1.3
key schedule in place of the (EC)DHE shared secret, as shown in
{{fig-key-schedule}}.

~~~~
                                    0
                                    |
                                    v
                      PSK ->  HKDF-Extract = Early Secret
                                    |
                                    +-----> Derive-Secret(...)
                                    +-----> Derive-Secret(...)
                                    +-----> Derive-Secret(...)
                                    |
                                    v
                              Derive-Secret(., "derived", "")
                                    |
                                    v
             shared_secret -> HKDF-Extract = Handshake Secret
             ^^^^^^^^^^^^^          |
                                    +-----> Derive-Secret(...)
                                    +-----> Derive-Secret(...)
                                    |
                                    v
                              Derive-Secret(., "derived", "")
                                    |
                                    v
                         0 -> HKDF-Extract = Master Secret
                                    |
                                    +-----> Derive-Secret(...)
                                    +-----> Derive-Secret(...)
                                    +-----> Derive-Secret(...)
                                    +-----> Derive-Secret(...)
~~~~
{: #fig-key-schedule title="Key schedule for key agreement"}

# Discussion {#discussion}

## Larger encapsulation keys and/or ciphertexts

The `KeyShareEntry` struct limits public keys and ciphertexts to 2^16-1
bytes; this is the (2^16-1)-byte limit on the `key_exchange` field in the
`KeyShareEntry` struct. All defined parameter sets for ML-KEM have
encapsulation keys and ciphertexts that fall within the TLS constraints.

## Failures

Some post-quantum key exchange algorithms, including ML-KEM, have non-zero
probability of failure, meaning two honest parties may derive different
shared secrets.  This would cause a handshake failure. ML-KEM has a
cryptographically small failure rate less than 2^-138; implementers should
be aware of the potential of handshake failure. Clients can retry if a
failure is encountered.

# Security Considerations {#security-considerations}

## Fixed lengths

For each `NameGroup`, the lengths are fixed (that is, constant) for
encapsulation keys, the ciphertexts, and the shared secrets.

Variable-length secrets are, generally speaking, dangerous.  In particular,
when using key material of variable length and processing it using hash
functions, a timing side channel may arise.  In broad terms, when the secret
is longer, the hash function may need to process more blocks internally.  In
some unfortunate circumstances, this has led to timing attacks, e.g. the
Lucky Thirteen {{LUCKY13}} and Raccoon {{RACCOON}} attacks.

{{AVIRAM}} identified a risk of using variable-length secrets when the hash
function used in the key derivation function is no longer
collision-resistant.

## IND-CCA

The main security property for KEMs is indistinguishability under adaptive
chosen ciphertext attack (IND-CCA2), which means that shared secret values
should be indistinguishable from random strings even given the ability to
have other arbitrary ciphertexts decapsulated.  IND-CCA2 corresponds to
security against an active attacker, and the public key / secret key pair can
be treated as a long-term key or reused.  A common design pattern for
obtaining security under key reuse is to apply the Fujisaki-Okamoto (FO)
transform {{FO}} or a variant thereof {{HHK}}.

Key exchange in TLS 1.3 is phrased in terms of Diffie-Hellman key exchange in
a group.  DH key exchange can be modeled as a KEM, with `KeyGen`
corresponding to selecting an exponent `x` as the secret key and computing
the public key `g^x`; encapsulation corresponding to selecting an exponent
`y`, computing the ciphertext `g^y` and the shared secret `g^(xy)`, and
decapsulation as computing the shared secret `g^(xy)`. See {{HPKE}} for more
details of such Diffie-Hellman-based key encapsulation
mechanisms. Diffie-Hellman key exchange, when viewed as a KEM, does not
formally satisfy IND-CCA2 security, but is still safe to use for ephemeral
key exchange in TLS 1.3, see e.g. {{DOWLING}}.

TLS 1.3 does not require that ephemeral public keys be used only in a single
key exchange session; some implementations may reuse them, at the cost of
limited forward secrecy.  As a result, any KEM used in the manner described
in this document MUST explicitly be designed to be secure in the event that
the public key is reused.  Finite-field and elliptic-curve Diffie-Hellman key
exchange methods used in TLS 1.3 satisfy this criteria.  For generic KEMs,
this means satisfying IND-CCA2 security or having a transform like the
Fujisaki-Okamoto transform {{FO}} {{HHK}} applied.  While it is recommended
that implementations avoid reuse of KEM public keys, implementations that do
reuse KEM public keys MUST ensure that the number of reuses of a KEM public
key abides by any bounds in the specification of the KEM or subsequent
security analyses.  Implementations MUST NOT reuse randomness in the
generation of KEM ciphertexts.

## Binding properties

TLS 1.3's key schedule commits to the the ML-KEM encapsulation key and the
ciphertext as the `key_exchange` field as part of the `key_share` extension
are populated with those values are included as part of the handshake
messages, providing resilience against re-encapsulation attacks against KEMs
used for key agreement.

Because of the inclusion of the ML-KEM ciphertext in the TLS 1.3 key
schedule, there is no concern of malicious tampering (MAL) adversaries, nor
of just honestly-generated but leaked key pairs (LEAK adversaries). The same
is true of KEMs with weaker binding properties, even if they were to have
more constraints for secure use in contexts outside of TLS 1.3 handshake key
agreement. These computational binding properties for KEMs were formalized in
{{CDM23}}.

# IANA Considerations

This document requests/registers three new entries to the TLS Named Group
(or Supported Group) registry, according to the procedures in {{Section
6 of tlsiana}}.


 Value:
 : 0x0200

 Description:
 : MLKEM512

 DTLS-OK:
 : Y

 Recommended:
 : N

 Reference:
 : This document

 Comment:
 : FIPS 203 version of ML-KEM-512



 Value:
 : 0x0201

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
 : 0x0202

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

Thanks to Douglas Stebila for consultation on the
draft-ietf-tls-hybrid-design design.
