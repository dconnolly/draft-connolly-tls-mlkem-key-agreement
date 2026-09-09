---
title: "ML-KEM Post-Quantum Key Agreement for TLS 1.3"
abbrev: ietf-tls-mlkem
category: info

docname: draft-ietf-tls-mlkem-latest
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
  github: "tlswg/draft-ietf-tls-mlkem"

author:
 -
    fullname: Deirdre Connolly
    organization: SandboxAQ
    email: durumcrustulum@gmail.com

normative:
  FIPS203: DOI.10.6028/NIST.FIPS.203
  RFC9846:

informative:
  BJ24:
    target: https://bblanche.gitlabpages.inria.fr/publications/BlanchetJacommeCSF24.pdf
    title: "Post-Quantum Sound CryptoVerif and Verification of Hybrid TLS and SSH Key-Exchanges"
    date: 2024
    seriesinfo: "Proceedings of CSF 2024"
    author:
    -
      ins: B. Blanchet
      name: Bruno Blanchet
    -
      ins: C. Jacomme
      name: Charlie Jacomme
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
  CHSW22:
    target: https://doi.org/10.1007/978-3-031-17143-7_4
    title: "A Tale of Two Models: Formal Verification of KEMTLS via Tamarin"
    date: 2022
    seriesinfo: "Proceedings of ESORICS 2022"
    author:
    -
      ins: S. Celi
    -
      ins: J. Hoyland
    -
      ins: D. Stebila
    -
      ins: T. Wiggers
  CPWB25:
    target: https://doi.org/10.3390/e27121242
    title: "On the Security and Efficiency of TLS 1.3 Handshake with Hybrid Key Exchange from CPA-Secure KEMs"
    date: 2025
    seriesinfo: "Entropy 27(12):1242"
    author:
    -
      ins: J. Chen
      name: Jinrong Chen
    -
      ins: W. Peng
      name: Wei Peng
    -
      ins: Y. Wang
      name: Yi Wang
    -
      ins: Y. Bian
      name: Yutong Bian
  CZCJWH25:
    target: https://eprint.iacr.org/2025/1748.pdf
    date: 2025
    title: "Post-Quantum {TLS} 1.3 Handshake from {CPA}-Secure {KEMs} with Tighter Reductions"
  DOWLING:
    target: https://doi.org/10.1007/s00145-021-09384-1
    title: "A Cryptographic Analysis of the TLS 1.3 Handshake Protocol"
    date: 2020
    seriesinfo: "Journal of Cryptology 2021"
  DUALECTLS:
    title: "On the Practical Exploitability of Dual EC in TLS Implementations"
    target: https://www.usenix.org/system/files/conference/usenixsecurity14/sec14-paper-checkoway.pdf
    date: 2014
  GHS25:
    target: https://eprint.iacr.org/2025/343.pdf
    title: "On The Multi-target Security of Post-Quantum Key Encapsulation Mechanisms"
    date: 2025
    seriesinfo: "Cryptology ePrint Archive, Report 2025/343"
    author:
    -
      name: Lewis Glabush
    -
      name: Kathrin Hovelmanns
    -
      name: Douglas Stebila
  HV22:
    target: https://link.springer.com/chapter/10.1007/978-3-031-07082-2_22
    title: "On IND-qCCA Security in the ROM and Its Applications - CPA Security Is Sufficient for TLS 1.3"
    seriesinfo: Proceedings of Eurocrypt 2022
    author:
    -
      name: Loïs Huguenin-Dumittan
    -
      name: Serge Vaudenay
  KOBEISSI26:
    target: "https://eprint.iacr.org/2026/1147.pdf"
    title: "FATT Chance: On the Robustness of Standalone and Hybrid ML-KEM Key Exchange in TLS 1.3"
  KEMTLS: DOI.10.1145/3372297.3423350
  NIST-SP-800-227: DOI.10.6028/NIST.SP.800-227
  RFC8937:
  RFC9794:
  RFC9847:
  RFC9954:
  RFC10024:
  ZJZ24:
    target: https://doi.org/10.1007/978-981-96-0891-1_14
    title: "CPA-Secure KEMs are also Sufficient for Post-quantum TLS 1.3"
    seriesinfo: Proceedings of Asiacrypt 2024
    author:
    -
      ins: B. Zhou
    -
      ins: H.Jiang
    -
      ins: Y. Zhao

--- abstract

This memo defines ML-KEM-512, ML-KEM-768, and ML-KEM-1024 as `NamedGroup`s
and registers IANA values in the TLS Supported Groups registry for use in TLS
1.3 to achieve post-quantum (PQ) key establishment.

--- middle

# Introduction

ML-KEM {{FIPS203}} is a FIPS standard for post-quantum {{RFC9794}} key
establishment via a lattice-based key encapsulation mechanism (KEM). This
document defines key establishment options for TLS 1.3 via the existing
`supported_groups` ({{Section 4.3.7 of RFC9846}}) and `key_share` ({{Section
4.3.8 of RFC9846}}) extensions.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Key encapsulation mechanisms {#kems}

This document models key establishment as key encapsulation mechanisms
(KEMs), which consist of three algorithms:

- `KeyGen() -> (pk, sk)`: A probabilistic key generation algorithm,
  which generates a public encapsulation key `pk` and a secret
  decapsulation key `sk`.
- `Encaps(pk) -> (ct, shared_secret)`: A probabilistic encapsulation
  algorithm, which takes as input a public encapsulation key `pk` and
  outputs a ciphertext `ct` and shared secret `shared_secret`.
- `Decaps(sk, ct) -> shared_secret`: A decapsulation algorithm, which takes
  as input a secret decapsulation key `sk` and ciphertext `ct` and outputs a
  shared secret `shared_secret`.


ML-KEM-512, ML-KEM-768, and ML-KEM-1024 conform to this interface (Table 3 of {{FIPS203}}):

- ML-KEM-512 has encapsulation keys of size 800 bytes, expanded decapsulation
  keys of 1632 bytes, decapsulation key seeds of size 64 bytes, ciphertext
  size of 768 bytes, and shared secrets of size 32 bytes.

- ML-KEM-768 has encapsulation keys of size 1184 bytes, expanded
  decapsulation keys of 2400 bytes, decapsulation key seeds of size 64 bytes,
  ciphertext size of 1088 bytes, and shared secrets of size 32 bytes.

- ML-KEM-1024 has encapsulation keys of size 1568 bytes, expanded
  decapsulation keys of 3168 bytes, decapsulation key seeds of size 64 bytes,
  ciphertext size of 1568 bytes, and shared secrets of size 32 bytes.

# Construction {#construction}

The KEMs are defined as `NamedGroup`s, sent in the `supported_groups`
extension ({{Section 4.3.7 of RFC9846}}).

## Negotiation {#negotiation}

Each parameter set of ML-KEM is assigned an identifier, registered by IANA in
the TLS Supported Groups registry:

~~~
    enum {

         ...,

          /* ML-KEM Key Establishment Methods */
          mlkem512(0x0200),
          mlkem768(0x0201),
          mlkem1024(0x0202)

         ...,

    } NamedGroup;
~~~

## Transmitting encapsulation keys and ciphertexts {#construction-transmitting}

The public encapsulation key and ciphertext values are each
directly encoded with fixed lengths as in {{FIPS203}}.

In TLS 1.3 a KEM public encapsulation key `pk` or ciphertext `ct` is
represented as a `KeyShareEntry` as specified in {{Section 4.3.8 of
RFC9846}}. These are transmitted in the `extension_data` fields of
`KeyShareClientHello` and `KeyShareServerHello` extensions.

For the client's share, the `key_exchange` value contains the `pk`
output of the corresponding ML-KEM parameter set's `KeyGen` algorithm.

For the server's share, the `key_exchange` value contains the `ct`
output of the corresponding ML-KEM parameter set's `Encaps` algorithm.

For all parameter sets, the server MUST perform the encapsulation key check
described in Section 7.2 of {{FIPS203}} on the client's encapsulation key,
and abort with an `illegal_parameter` alert if it fails.

For all parameter sets, the client MUST perform the decapsulation input check
described in Section 7.3 of {{FIPS203}} on the ciphertext, and abort with
an `illegal_parameter` alert if it fails.

If ML-KEM encapsulation or decapsulation fails for any other reason,
the connection MUST be aborted with an `internal_error` alert.

Implementations MUST NOT reuse randomness in the generation of ML-KEM
ciphertexts— it follows that ML-KEM ciphertexts also MUST NOT be reused.

During encapsulation, ML-KEM draws the encapsulation randomness from a random
bit generator; the peer holding the decapsulation key `sk` recovers this
randomness exactly. Any information that this randomness provides about other
outputs of the generator is therefore available to that peer.

## Shared secret calculation {#construction-shared-secret}

The fixed-length shared secret output from the ML-KEM `Encaps` and `Decaps`
algorithms over the appropriate keypair and ciphertext results in the same
shared secret `shared_secret` as its peer, which is inserted into the TLS 1.3
key schedule in place of the (EC)DHE shared secret, as shown in {{Section 7.1
of RFC9846}}.

# Security Considerations {#security-considerations}

This document defines standalone ML-KEM key establishment for TLS 1.3.  Use
of KEMs for key agreement in TLS 1.3 has been analyzed in multiple settings
and security models {{DOWLING}} {{KEMTLS}} {{HV22}} {{CHSW22}} {{CZCJWH25}}
{{ZJZ24}}; ML-KEM's IND-CCA security (Indistinguishability under
Chosen-Ciphertext Attack) exceeds the requirements for ephemeral key
establishment {{GHS25}} {{RFC9846}}. Multiple formal analyses, including
pen-and-paper computational proofs and machine-checked symbolic analysis
using ProVerif {{KOBEISSI26}}, demonstrate that replacing Diffie-Hellman with
an IND-CCA-secure KEM preserves the security properties of the TLS
handshake. Formal analysis has also shown that hybrid key establishment
(e.g., {{RFC9954}}, {{RFC10024}}) provides compositional security: the
exchange remains secure as long as at least one of the component algorithms
is unbroken {{BJ24}} {{CPWB25}}.

TLS 1.3's key schedule commits to the ML-KEM encapsulation key and the
ciphertext as the `key_exchange` field of the `key_share` extension is
populated with those values, which are included as part of the handshake
messages. This provides resilience against re-encapsulation attacks against
KEMs used for key establishment {{CDM23}}.

{{NIST-SP-800-227}} includes guidelines and requirements for implementations
on using KEMs securely. Implementers are encouraged to use implementations
resistant to side-channel attacks, especially those that can be applied by
remote attackers.

Implementers must evaluate their specific security, performance, and
operational constraints when deciding whether to deploy standalone ML-KEM or
a hybrid construction. The recommended column in the IANA TLS Supported
Groups registry contains the IETF's current guidance on the recommended use
of these algorithms for general purposes.

The disclosure of the output(s) of an insecure random number generator (RNG)
when used in TLS and other protocols can be used in an attack to compromise
the state of the insecure RNG itself as described in [DUALECTLS]. The
encapsulation randomness in ML-KEM is an additional place where raw RNG
output may be disclosed, therefore it is important to follow the RNG guidance
in [FIPS203] and [RFC9846]. Implementers can choose to implement mechanisms
from [RFC8937] for additional protection across sessions.

# IANA Considerations

This document registers three new entries to the [TLS Supported Groups
registry](https://www.iana.org/assignments/tls-parameters#tls-parameters-8),
according to the procedures in {{Section 6 of RFC9847}}.

| Value         | Description | DTLS-OK | Recommended | Reference      | Comment                         |
|---------------|-------------|---------|-------------|----------------|---------------------------------|
| 512 (0x0200)  | MLKEM512    | Y       | N           | This document  | FIPS 203 version of ML-KEM-512  |
| 513 (0x0201)  | MLKEM768    | Y       | N           | This document  | FIPS 203 version of ML-KEM-768  |
| 514 (0x0202)  | MLKEM1024   | Y       | N           | This document  | FIPS 203 version of ML-KEM-1024 |

As defined in {{Section 3 of RFC9847}}, the value N:

{: quote}
> Indicates that the item has not been evaluated by the IETF and that the
> IETF has made no statement about the suitability of the associated mechanism.
> This does not necessarily mean that the mechanism is flawed, only that no
> consensus exists. The IETF might have consensus to leave an item marked as
> "N" on the basis of the item having limited applicability or usage constraints.

--- back

# Acknowledgments
{:numbered="false"}

Thanks to Douglas Stebila for consultation on RFC 9954's design, and to Scott
Fluhrer, Eric Rescorla, John Preuß Mattsson, Martin Thomson, and Rebecca
Guthrie for reviews.
