# VORLATH Shield — KEM binding (X-BIND-K-CT and X-BIND-K-PK)

> **What this page is.** A rigorous, *honest* account of one question on the 2024-2026
> KEM-binding frontier: does a shared secret **K** uniquely name the ciphertext that
> produced it (**X-BIND-K-CT**) and the public key it was produced under
> (**X-BIND-K-PK**), and under which adversary key-access level? It states **exactly what
> bare ML-KEM (FIPS 203) guarantees in 2026** — no more, no less — and then shows that the
> VORLATH Shield handshake **binds `kem_ct` AND `recipient_key_id` (= H(recipient hybrid
> public keys)) into BOTH the KDF transcript and the signed `pre_auth`**, so the key the
> Shield actually *uses* and the tuples it *accepts* are bound to `(ct, pk, suite,
> transcript)` even on inputs where a bare KEM's K is not.
>
> **Claim type, stated up front.** This is a **symbolic / reduction-level PROTOCOL claim**
> about the Shield handshake, under the idealizations already enumerated in
> [`FORMAL_COVERAGE.md`](FORMAL_COVERAGE.md) (HKDF a secure dual-PRF/extractor; H / SHA-384
> collision-resistant or a random oracle in the symbolic models; ML-DSA EUF-CMA; Dolev-Yao
> for Tamarin/Verifpal). It is **NOT** a new primitive theorem, does **NOT** make bare
> ML-KEM MAL-binding as a standalone KEM, and is **NOT** a FIPS claim. No "X-BIND"
> statement here is machine-checked *as such*; it is argued by reduction and is consistent
> with — not identical to — the existing Tamarin sender-authentication and
> downgrade-resistance lemmas. See [§5 Honest scope](#5-honest-scope).

---

## 1. The binding notions, defined

The naming follows Cremers, Dux, Medinger, *"Keeping Up with the KEMs"* (IACR eprint
2023/1933), which introduces a family written **X-BIND-P-Q**:

- **X** is the adversary's **key-access level** (the prefix).
- **P-Q** reads "**P binds Q**": the property holds if, across two
  encapsulation/decapsulation instances, agreement on the value(s) **P** forces agreement
  on the value(s) **Q**.
- **P, Q** range over **K** (shared secret), **CT** (ciphertext), **PK** (encapsulation /
  public key).

The BIND family generalizes earlier "robustness / collision-freeness" notions and is
**orthogonal to IND-CCA** — a KEM can be IND-CCA secure and still fail a binding notion.

### 1.1 Key-access levels (the X prefix)

| Level | Adversary's power over key material | Order |
|---|---|---|
| **HON** (honest) | Only oracle / Decaps access; cannot see or choose key material. Must win using honestly generated keys it does not control. | weakest |
| **LEAK** | Is *given* the honestly generated key pairs (secret keys leaked) — but the keys were still produced by an honest `KeyGen`. | middle |
| **MAL** (malicious) | May craft **arbitrary, malformed** key pairs itself (not necessarily `KeyGen` outputs) and controls all key material. | strongest |

Strength order **HON < LEAK < MAL**: passing **MAL** implies **LEAK** implies **HON**.

### 1.2 The two notions VORLATH targets

- **X-BIND-K-CT (key binds ciphertext).** If two decapsulation instances yield the **same
  K**, they must have used the **same ciphertext `ct`**. Failure = a *shared-K,
  distinct-ct* collision — the core of **re-encapsulation** attacks.
- **X-BIND-K-PK (key binds public key).** If two instances yield the **same K**, they must
  have used the **same encapsulation key `pk`** (equivalently `H(pk)`). Failure = a
  *shared-K, distinct-pk* collision — the same K is reachable under two different public
  keys, so K does not identify the intended peer.

Each is read at all three levels: HON-BIND-K-CT, LEAK-BIND-K-CT, MAL-BIND-K-CT (and
likewise for K-PK). The literature also defines combined notions (e.g. X-BIND-K,CT-PK and
X-BIND-K,PK-CT) and reverse directions; **K-CT and K-PK are the two the VORLATH question
targets**, because they are exactly the notions bare ML-KEM provably fails at the MAL level
and that protocol-level transcript binding is meant to restore.

### 1.3 The re-encapsulation attack class

The notions forbid a **re-encapsulation attack**: an adversary forces two separate sessions
(e.g. Alice-to-attacker and attacker-to-Bob) to arrive at the **same K** under **different
`ct` and/or `pk`**, breaking the implicit assumption that K uniquely names its `(ct, pk)`
context. Cremers et al. report that **Tamarin auto-discovered** that the original
Kyber-paper key exchange required binding notions stronger than what had been proven —
which is why these notions matter at the *protocol* layer, not just for the primitive.

---

## 2. What bare ML-KEM gives, accurately (2026 status)

This section is the load-bearing honesty section. **Do not over- or under-claim.**

### 2.1 The verdict (authoritative, RFC 9935 §9)

With the **expanded decapsulation-key format** (the default `dk` that caches `H(ek)` and
the implicit-rejection secret `z`), bare ML-KEM (FIPS 203) is:

| Notion | HON | LEAK | MAL |
|---|---|---|---|
| **BIND-K-CT** | yes | **yes** | **NO** |
| **BIND-K-PK** | yes | **yes** | **NO** |

So ML-KEM **IS LEAK-BIND-K-CT and LEAK-BIND-K-PK**, but is **NEITHER MAL-BIND-K-CT NOR
MAL-BIND-K-PK**. This is the verdict codified in **RFC 9935 §9** (2025), which cites
Cremers/Dux/Medinger (CDM23) and Schmieg (KEMMY24).

History worth recording so nobody re-derives a wrong claim: CDM23 originally **conjectured**
ML-KEM had MAL-BIND-K-PK. Schmieg, *"Unbindable Kemmy Schmidt"* (IACR eprint 2024/523, Apr
2024), **corrected this**, showing ML-KEM has **neither** MAL notion.

### 2.2 Why the MAL failure exists — it is a key-FORMAT artifact, not a lattice break

The MAL failure is **not** a Module-LWE or IND-CCA weakness. It is an artifact of the
**expanded `dk` format**, which stores a cached copy of `H(ek)` and the implicit-rejection
secret `z`. A MAL adversary who hand-crafts a malformed `dk`:

- **breaks K-CT** by swapping the cached `H(ek)` for the hash of a *different* public key:
  Alice encapsulates to `pk1`; a doctored `dk2'` that carries `H(pk1)` makes Bob
  decapsulate a **different** ciphertext to the **same** K; or
- **breaks K-PK** by setting two keys to share the same `z`, so a deliberately-failing
  (implicitly-rejected) ciphertext yields the **same** pseudorandom K under **two different**
  public keys.

### 2.3 The positive half — do NOT under-claim what FIPS 203 already gives

ML-KEM's **FO transform genuinely hashes the public-key hash `H(ek)` into the shared-secret
derivation** (`K = KDF(m, H(ek))` in encaps, with the FO re-encryption / ciphertext-
consistency check on decaps). **That is precisely why honestly generated keys give
LEAK-BIND-K-CT and LEAK-BIND-K-PK.** Binding collapses **only** when the adversary is
allowed to forge the `dk` so the cached `H(ek)` no longer matches the real `ek`. So:

- **Do NOT claim ML-KEM is "wholly unbound."** It is not — it has real, standardized
  binding for honest and leaked keys.
- **Do NOT claim it has MAL binding.** It does not.

### 2.4 The standards-recognized primitive mitigation, and its residual gap

RFC 9935 §9 records that using the **64-byte `(d, z)` SEED format** for the decapsulation
key (re-deriving the expanded key from the seed at decaps time) **restores MAL-BIND-K-CT**,
because a seed-derived `dk` cannot carry a mismatched cached `H(ek)`. But the seed format
**still does not give MAL-BIND-K-PK** — the shared-`z` K-PK collision survives. So **even
the strongest FIPS-compliant key format leaves MAL-BIND-K-PK to be supplied at the protocol
layer.** This is the precise gap the Shield closes by construction. (Recommendation: adopt
the `(d, z)` seed `dk` format at the implementation layer so the K-CT vector is *also*
closed at the primitive level — defense in depth, not the Shield's only line.)

### 2.5 Existence proof that the protocol/combiner layer can repair binding

**X-Wing** (Barbosa, Connolly, Duarte, Kaiser, Schwabe, Varner, Westerbaan, IACR CiC 1(1)
2024 / `draft-connolly-cfrg-xwing-kem`) is proven **MAL-BIND-K-CT AND MAL-BIND-K-PK** as a
hybrid — *even though its combiner deliberately does NOT hash the ML-KEM ciphertext*. Its
binding is supplied by hashing the **X25519 ephemeral `ct_X` and recipient `pk_X`** into the
SHA3-256 combiner together with ML-KEM's own `H(ek)`-in-K. This is the model case: hashing
`ct` and `pk` at the combiner / protocol layer **repairs the binding the bare KEM lacks** —
exactly the lever VORLATH pulls, only VORLATH does it *more explicitly* by hashing the
ML-KEM `kem_ct` itself into the transcript.

---

## 3. How the Shield achieves protocol-level binding

### 3.1 The construction (ground truth from `vorlath_shield/shield.py`)

The AEAD key is

```
K = HKDF-SHA384( ikm  = lenframe(ss_classical) || lenframe(ss_pq),
                 salt = "VORLATH-Shield-combiner/v2",
                 info = "VORLATH-Shield/2 hybrid-kem combiner" || suite_id || pre_auth )
```

where `lenframe(s) = uint16_be(len(s)) || s`, and

```
pre_auth (the transcript) = suite_id || flags || recipient_key_id || eph_pub || kem_ct || nonce
recipient_key_id          = H(recipient hybrid public keys)        # SHAKE-derived key id
```

The **same `pre_auth` transcript is the AEAD associated data (AAD)**. In **authenticated
mode**, an **ML-DSA signature over `pre_auth || sender_key_id`** (with
`sender_key_id = H(sender signing pubkey)`) is **verified BEFORE decapsulation**
(SIGMA own-identity). Note `suite_id` is bound twice — once in the HKDF label region and
once inside `pre_auth` — and `kem_ct` and `recipient_key_id` both sit inside `pre_auth`,
hence inside both the KDF `info` and the signed message.

### 3.2 Mechanism 1 — transcript-as-FixedInfo binds K to (ct, pk)

Because `kem_ct` and `recipient_key_id = H(pk)` sit **inside the HKDF `info`**, **any**
change to the ML-KEM ciphertext or to the recipient public key changes the FixedInfo and
hence changes **K** (under HKDF-as-PRF / RO). This is a **protocol-enforced X-BIND-K-CT and
X-BIND-K-PK**: two runs that derive the same K must agree on `ct` and on `H(pk)`. That
directly neutralizes the 2024/523 re-encapsulation collisions, whose colliding sessions
differ in `ct` (K-CT) or in the true `pk` (K-PK).

### 3.3 Mechanism 2 — length-framed combine prevents combiner ambiguity

The combine is a **length-framed** concatenation (`uint16_be` length prefix on each secret)
*before* HKDF, so an attacker cannot shift bytes across the `ss_classical || ss_pq` boundary
or pad one secret to forge a colliding combiner pre-image. A different split is a different
framed input, hence a different K. This closes the classic "sloppy combiner" misbinding by
canonical encoding (no concatenation ambiguity).

### 3.4 Mechanism 3 — signed pre_auth adds a MAL-level lock in authenticated mode

In authenticated mode the ML-DSA signature is over `(pre_auth || sender_key_id)` and is
verified **before** any decapsulation runs. Since `pre_auth` already commits to `kem_ct` and
`recipient_key_id`, the signature binds `(ct, pk, suite, sender identity)` under EUF-CMA. A
MAL adversary who forges a doctored `dk` to manufacture a K-CT or K-PK collision **cannot
also produce a valid ML-DSA signature over the matching transcript** without the sender's
signing key — so the doctored tuple is **rejected at verify time, before decapsulation**.
This is the layer that lifts the guarantee from "binding under HKDF/RO" toward a
MAL-resistant, attributable lock.

### 3.5 Reduction sketch

Suppose a PPT adversary **A** makes the Shield accept two runs with the **same derived K**
but **different `(ct, pk)`**. Different `ct` or different `H(pk)` implies a **different
`pre_auth` transcript** (both are transcript fields). Then:

- **(a) UNAUTH mode.** Identical K from different HKDF `info` contradicts HKDF/KDF security.
  Reduce to a **PRF distinguisher / collision-finder on HKDF-SHA384** (treating HKDF as a
  PRF/extractor per [`FORMAL_COVERAGE.md`](FORMAL_COVERAGE.md)).
- **(b) AUTH mode.** **A** must additionally exhibit a valid ML-DSA signature over each
  distinct `pre_auth || sender_key_id`. Two accepted distinct transcripts under one honest
  sender key yield an **EUF-CMA forgery**. Reduce to **ML-DSA unforgeability**.

Either way,

```
Adv_A  <=  Adv_KDF-distinguish(HKDF-SHA384)  +  Adv_EUF-CMA(ML-DSA)  +  Adv_collision(H)
```

matching the assumption set in [`FORMAL_COVERAGE.md`](FORMAL_COVERAGE.md). This is the same
*shape* of argument X-Wing uses (bind `ct`/`pk` into the hash), specialized to the Shield's
transcript and combiner.

---

## 4. Must-reject negative-vector corpus

Each forbidden tuple maps to a binding notion and an **expected rejection layer**. The
common thread: `kem_ct`, `recipient_key_id`, `suite_id`, `flags`, and `nonce` are all
transcript fields, and the transcript is simultaneously the **KDF `info`**, the **AEAD
AAD**, and (in AUTH mode) the **signed message**. So a substitution fails at *whichever
layer the adversary reaches first*.

| # | Vector | Notion | Must reject — why | Rejection layer |
|---|---|---|---|---|
| NV-1 | **Re-encapsulation / K-CT swap:** same derived K claimed for two **different `kem_ct`** (the 2024/523 expanded-`dk` swap: `dk'` carries `H(pk_other)` so a different ciphertext re-encaps to the same ML-KEM `ss`). | X-BIND-K-CT | The Shield derives K with `info` containing the **actual** `kem_ct`; a substituted `ct` yields different `info` => different K => **AEAD tag fails**. In AUTH mode the ML-DSA sig over `pre_auth` (which fixes `kem_ct`) **fails first, before decapsulation**. | AEAD tag (UNAUTH) / signature verify (AUTH) — *before decaps* |
| NV-2 | **K-PK collision:** same K claimed under two **different recipient public keys** (shared-`z` implicit-rejection collision, or any `pk` substitution). | X-BIND-K-PK | `recipient_key_id = H(recipient hybrid pubkeys)` is in the transcript; different `pk` => different `recipient_key_id` => different K **and/or** signature-verify failure. Decaps also checks `priv_key_id == recipient_key_id`. | key-id mismatch / signature verify / AEAD tag |
| NV-3 | **Downgrade / suite confusion:** reuse a valid `(ct, pk, K)` under a different `suite_id` or `flags` (e.g. claim an ML-KEM-768 transcript under ML-KEM-1024, or flip anonymous/auth flags). | X-BIND-K-CT/PK in wrong context | `suite_id` and `flags` are transcript fields bound into K (twice for `suite_id`) and the signature; mismatch changes K / breaks the sig. Maps to the FORMAL_COVERAGE downgrade lemma `recipient_only_accepts_pinned_suite`. | KDF / AEAD tag / signature verify |
| NV-4 | **Combiner-shift / length-confusion:** move bytes across the `ss_classical || ss_pq` boundary (or pad one secret) to forge a colliding combiner pre-image. | combiner misbinding | By construction the combine is **length-framed** (`uint16_be` prefixes), so a different split is a different framed `ikm` => different K. | KDF (no concatenation ambiguity) — AEAD tag downstream |
| NV-5 | **Partitioning-oracle / multi-key AEAD:** one ciphertext+tag crafted to decrypt validly under many candidate keys (AEAD key-multi-collision) to mount a partitioning oracle. | binding under AEAD | The transcript (`ct`, `recipient_key_id`, `suite`, `nonce`) is **both** the AEAD AAD **and** the KDF `info`, so each candidate `(ct, pk, suite)` yields a **distinct** K and **distinct** AAD; a crafted tag cannot validate across keys. | AEAD tag under the transcript-bound key |
| NV-6 | **MAL malformed-`dk`:** a peer presents a malformed/expanded ML-KEM `dk` whose cached `H(ek)` does not match the advertised `ek` (the 2024/523 root cause). | X-BIND-K-CT/PK at MAL | `recipient_key_id` is `H` of the **advertised** hybrid public keys, so a `dk` with swapped internal `H(ek)` cannot make the advertised `recipient_key_id` (and thus the transcript and any signature over it) consistent; the doctored binding never matches what was signed/derived. Implementations SHOULD additionally prefer the `(d, z)` seed `dk` format per RFC 9935 §9. | key-id / transcript mismatch (neutralized) + primitive-layer seed `dk` |
| NV-7 | **Cross-protocol transcript reuse:** replay a transcript/signature from another protocol/session that shares `ct`/`pk` but not the `suite_id`/`recipient_key_id` binding. | cross-context binding | `suite_id` domain-separates and `recipient_key_id` pins the key; non-matching context fails KDF/AEAD/signature. **NB:** pure same-context **replay/freshness is OUT of scope by design** ([`FORMAL_COVERAGE.md`](FORMAL_COVERAGE.md): the Shield is stateless one-pass), so this vector is **cross-context binding, not anti-replay**. | KDF / AEAD / signature verify |

---

## 5. Honest scope

- **Symbolic / reduction-level, not a primitive proof.** The repair argument is a
  protocol-level claim under the [`FORMAL_COVERAGE.md`](FORMAL_COVERAGE.md) idealizations
  (HKDF as PRF/extractor; H collision-resistant or RO; ML-DSA EUF-CMA; Dolev-Yao for the
  symbolic provers). It **does not** retrofit MAL-binding onto the raw ML-KEM primitive and
  is **not** a new primitive theorem.
- **What is restored, precisely.** Binding is restored **for the Shield's session key K and
  for what the Shield accepts** — not for ML-KEM as a standalone KEM. The guarantee is only
  as strong as the idealized HKDF/H and the EUF-CMA assumption.
- **UNAUTH vs AUTH.** In **unauthenticated mode** the binding rests on **HKDF/RO alone** —
  it is *binding but not non-repudiable*. The MAL-level, attributable lock (NV-1/NV-2
  rejection *before decapsulation*) requires **authenticated mode** and ML-DSA EUF-CMA.
- **Not machine-checked as an X-BIND theorem.** No "X-BIND" statement here is mechanized as
  such; it is argued by reduction and is *consistent with* — but not identical to — the
  existing Tamarin `sender_authentication` and `recipient_only_accepts_pinned_suite`
  lemmas. The negative vectors in §4 are intended as a **CI corpus** (see the companion
  spec) to make the must-reject behavior executable, not to substitute for a mechanized
  binding proof.
- **Not a FIPS / certification claim.** "CNSA 2.0" / FIPS 203/204 name the *algorithms*; no
  CAVP/CMVP certificate is asserted (`SECURITY.md`).
- **Defense-in-depth recommendation.** Adopt the RFC 9935 `(d, z)` **seed `dk`** format at
  the implementation layer so the **K-CT** vector is *also* closed at the primitive level,
  independent of the protocol binding. Even then, **MAL-BIND-K-PK remains a protocol-layer
  responsibility** — which is exactly what the Shield's transcript + signed `pre_auth`
  supply.
- **Salt-side "dual-PRF" pk-binding was evaluated and declined (2026-06-21).** Moving
  `recipient_key_id` into the HKDF-Extract *salt* (`_COMBINER_SALT ‖ recipient_key_id`, X-Wing /
  split-PRF style) was assessed by a deliberately skeptical council round and judged **redundant**
  with the `info` / AAD / signed-`pre_auth` binding documented above (§3), and **net-negative** for
  the SP 800-56C extract analysis (a per-recipient salt correlates the salt with the IKM). The
  binding stays where this page documents it — the fixed salt is retained. See
  [`VERIFICATION_GAP_MAP.md`](VERIFICATION_GAP_MAP.md) "Council-recommended hardening".

---

## Sources

1. Cremers, Dux, Medinger, *"Keeping Up with the KEMs: Stronger Security Notions for KEMs
   and Automated Analysis of KEM-based Protocols"*, IACR eprint **2023/1933** — defines the
   X-BIND-P-Q family, HON/LEAK/MAL levels, re-encapsulation attacks, Tamarin case study on
   the Kyber KE. <https://eprint.iacr.org/2023/1933>
2. Schmieg, *"Unbindable Kemmy Schmidt: ML-KEM is neither MAL-BIND-K-CT nor MAL-BIND-K-PK"*,
   IACR eprint **2024/523** (Apr 2024) — shows ML-KEM fails *both* MAL notions via malformed
   expanded `dk` (swapped `H(ek)` / shared `z`), correcting the 2023/1933 conjecture;
   seed-format mitigation. <https://eprint.iacr.org/2024/523>
3. **RFC 9935** (2025), *"Algorithm Identifiers for ML-KEM"*, §9 — authoritative: ML-KEM is
   LEAK-BIND-K-PK and LEAK-BIND-K-CT with expanded `dk`, NOT MAL-BIND-K-CT/-PK; the 64-byte
   seed format additionally provides MAL-BIND-K-CT but still not MAL-BIND-K-PK; cites CDM23
   and KEMMY24. <https://www.rfc-editor.org/rfc/rfc9935.html>
4. Barbosa, Connolly, Duarte, Kaiser, Schwabe, Varner, Westerbaan, *"X-Wing: The Hybrid KEM
   You've Been Looking For"*, IACR CiC 1(1) 2024 / `draft-connolly-cfrg-xwing-kem` — proves
   the hybrid is MAL-BIND-K-CT and MAL-BIND-K-PK by hashing X25519 `ct_X` and `pk_X` (plus
   ML-KEM's `H(ek)`-in-K) into a SHA3-256 combiner, despite NOT hashing the ML-KEM
   ciphertext. <https://cic.iacr.org/p/1/1/21> ;
   <https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-09.html>
5. Connolly, *"How to Hold KEMs"* (durumcrustulum.com, Feb 2024) — accessible taxonomy of
   the binding notions and ML-KEM's HON/LEAK/MAL status.
   <https://durumcrustulum.com/2024/02/24/how-to-hold-kems/>
6. **FIPS 203** (NIST, Aug 2024), *Module-Lattice-Based Key-Encapsulation Mechanism
   Standard* — the FO transform hashing `H(ek)` into the shared-secret derivation and the
   implicit-rejection / ciphertext-consistency check underpinning LEAK-level binding.
   <https://csrc.nist.gov/pubs/fips/203/final>
7. Schmieg follow-up, *"Unbindable Kemmy Schmidt"* (keymaterial.net, Sep 2024) —
   step-by-step K-CT and K-PK re-encapsulation constructions on malformed expanded `dk`.
   <https://keymaterial.net/2024/09/14/unbindable-kemmy-schmidt/>
8. NIST CSRC presentation, *"Misbinding KEMs"* (2025) — confirms the binding-notion frontier
   is active standards-track work feeding SP 800-227.
   <https://csrc.nist.gov/presentations/2025/misbinding-kems>
9. VORLATH internal: [`FORMAL_COVERAGE.md`](FORMAL_COVERAGE.md) — the assumed idealizations
   (HKDF dual-PRF/extractor, ML-DSA EUF-CMA, downgrade-resistance and sender-authentication
   lemmas, stateless one-pass => replay out of scope) that scope this protocol-level claim.

## Source-access caveat (honesty)

`eprint.iacr.org` and `cic.iacr.org` returned HTTP 403 to the fetcher, so the exact interior
definitions of 2023/1933, 2024/523, and the X-Wing paper were **reconstructed from their
abstracts plus RFC 9935 §9** (which directly states the ML-KEM binding status), the
keymaterial.net author writeup, and the durumcrustulum taxonomy. The **load-bearing facts**
(ML-KEM is LEAK-BIND-K-CT/-PK but neither MAL-BIND-K-CT nor MAL-BIND-K-PK with expanded
`dk`; seed format adds MAL-BIND-K-CT but not MAL-BIND-K-PK; X-Wing achieves both MAL notions
without hashing the ML-KEM ciphertext) are **corroborated by the official RFC 9935 text** and
stated with high confidence. On notion-name orientation: the literature is consistent that X
is the key-access prefix (HON/LEAK/MAL) and P-Q is "P binds Q"; this page states K-CT/K-PK as
"equal-K forces equal-CT/PK" (the re-encapsulation framing) — reviewers should confirm the
exact P-vs-Q ordering against the 2023/1933 PDF when reachable. No theorems or citations are
fabricated; where a paper interior could not be fetched it is said so rather than invented.