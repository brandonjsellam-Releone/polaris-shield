# VORLATH Shield — computational security argument for the hybrid combiner

> **What this is.** The Verifpal and Tamarin models in [`formal/`](formal/) prove the *protocol
> logic* (Dolev-Yao, symbolic). This note adds the layer a cryptographer asks for next: a
> **computational** argument that the hybrid **combiner** is a sound IND-CCA KEM combiner — by
> showing the Shield's construction is an *instantiation of published, proven-secure constructions*,
> not a novel scheme. It is an **argument by reduction to established results**, with precise
> assumptions and honest scope — **and** the combiner's key-indistinguishability core is now also
> **machine-checked in CryptoVerif** (see the *Mechanized (CryptoVerif)* section below). It is **not**
> a new theorem or a peer-reviewed proof, and the mechanized proof covers the combiner core only —
> not ML-KEM IND-CCA itself, nor the full end-to-end protocol (see §5).

## 1. The construction under analysis

For recipient hybrid key pair `(sk_c, pk_c)` (X25519/X448) and `(dk, ek)` (ML-KEM-768/1024), a
sender draws an ephemeral DH key and an ML-KEM encapsulation, yielding two shared secrets:

- `ss_c`  — the classical ECDH secret (RFC 7748), and
- `ss_pq` — the ML-KEM shared secret (FIPS 203).

The session/AEAD key is derived by a **length-framed concatenation KEM combiner fed through HKDF**
(`shield.py:_derive_key`, [`FORMAT.md` §2.6](FORMAT.md)):

```
K = HKDF(salt = "VORLATH-Shield-combiner/v2",
         IKM  = u16(len ss_c) ‖ ss_c ‖ u16(len ss_pq) ‖ ss_pq,
         info = label ‖ suite_id ‖ pre_auth,
         L    = 32)                                 # AES-256 key
```

where `pre_auth = suite_id ‖ flags ‖ recipient_key_id ‖ eph_pub ‖ kem_ct ‖ nonce` is the full
handshake transcript. The payload is then sealed with AES-256-GCM under `K`, with the envelope
header as associated data.

This is exactly the shape of a **KEM combiner**: two component KEMs (a DH-based KEM and ML-KEM)
whose secrets are combined by a KDF into one key.

## 2. The established results this instantiates

1. **Giacon–Heuer–Poettering, "KEM Combiners" (PKC 2018) [GHP18].** A combiner that concatenates
   component KEM secrets (and the ciphertexts, for robustness) and applies a KDF modeled as a PRF
   yields an **IND-CCA** KEM provided **at least one** component KEM is IND-CCA and the KDF/core
   function is a secure PRF. The combiner input encoding must be **injective** (unambiguous
   parsing) — which the Shield guarantees with `u16` length prefixes. *Binding location, stated
   precisely:* GHP18 folds the component ciphertexts into the combiner **CORE / IKM** (its robustness
   mechanism). The Shield does **not** put `kem_ct` in the IKM; it binds `kem_ct` (and the rest of the
   transcript) through the HKDF **`info`** and the AEAD **AAD** — the X-Wing / HPKE-style
   context-binding location. For a PRF-modeled KDF this is sound: binding the ciphertext in `info`
   domain-separates the derived key by ciphertext exactly as folding it into the IKM would, so the
   IND-CCA argument carries over (the IKM still satisfies the injectivity GHP18 requires of the
   secret encoding). See §3.
2. **X-Wing (Barbosa, Bos, Cremers, Cong, Hülsing, Kwiatkowski, Stebila et al.), [eprint 2024/039].**
   The hybrid KEM combining **X25519 + ML-KEM-768** via a hash-based combiner. X-Wing gives a
   **reduction (combiner hash modeled as a PRF / in the (Q)ROM)**: it is post-quantum IND-CCA if
   ML-KEM-768 is IND-CCA and the combiner hash is a PRF, and classically IND-CCA under strong
   Diffie-Hellman for X25519 — *"closely
   following the proof idea for KEM combiners of [GHP18], extended to KEMs with a small decryption
   error."* This is the closest standardized analogue to the Shield's apex idea.
3. **Dual-PRF combiners.** Choosing the combiner `W(k1, k2)` to be a **dual PRF** (secure when keyed
   by *either* input) preserves IND-CCA; a hash function instantiates `W` securely in the
   (quantum-accessible) random-oracle model. HKDF-Extract (HMAC) is the standard dual-PRF / extractor
   used for this purpose, and is the two-step extract-then-expand KDF of **NIST SP 800-56C**.

## 3. The argument

Read the Shield combiner as `K = HKDF(...)` over the injective encoding of `(ss_c, ss_pq)` with the
transcript as `info`. Then:

- **Hybrid IND-CCA (one-leg-break resistance).** Treating HKDF as a secure dual-PRF/extractor and
  ML-KEM as IND-CCA (its standardized assumption), the GHP18/X-Wing reduction applies: the derived
  key `K` is indistinguishable from random as long as **at least one** of `ss_c`, `ss_pq` is
  unknown to the adversary. Concretely:
  - if a CRQC breaks the classical leg (adversary learns `ss_c`), `K` stays pseudorandom because
    `ss_pq` is protected by ML-KEM IND-CCA — this is the **harvest-now-decrypt-later** guarantee;
  - if ML-KEM were broken (adversary learns `ss_pq`), `K` stays pseudorandom because `ss_c` is
    protected by strong DH on X25519/X448.
  This is the computational counterpart of the symbolic `hybrid_secrecy` lemma
  ([`formal/shield.spthy`](formal/shield.spthy)) and the two single-leg Verifpal models.
- **Injective encoding.** The `u16` length-framing makes `ss_c ‖ ss_pq` unambiguous, meeting the
  GHP18 requirement that prevents combiner-input collisions across different secret pairs.
- **Context/transcript binding and downgrade resistance.** Binding `suite_id ‖ flags ‖
  recipient_key_id ‖ eph_pub ‖ kem_ct ‖ nonce` into the HKDF `info` (and, identically, the AEAD AAD)
  domain-separates each handshake and ties `K` to the negotiated parameters, so a re-bound suite or a
  swapped transcript yields a different, independent key (the computational basis for the
  `recipient_only_accepts_pinned_suite` result). Note this is **where the Shield binds `kem_ct`** — in
  `info`/AAD, *not* in the IKM the way GHP18's robustness variant folds the ciphertext into the CORE.
  For a PRF-modeled KDF that placement is equivalent for the IND-CCA argument, and it is stronger than
  the minimal GHP18 combiner, which need not bind a transcript at all.
- **From KEM to channel.** Given a pseudorandom `K`, AES-256-GCM provides IND-CCA/INT-CTXT
  authenticated encryption (SP 800-38D) over the payload and the header-as-AAD, yielding
  confidentiality + integrity of the message — the standard KEM-DEM composition.

## 4. Assumptions (stated precisely)

The argument holds under, and only under:

| Assumption | Standard | Used for |
|---|---|---|
| ML-KEM IND-CCA (Module-LWE) | FIPS 203 | the post-quantum leg |
| Strong Diffie-Hellman on X25519/X448 | RFC 7748 | the classical leg |
| HKDF is a secure (dual-)PRF / extractor, modeled in the (Q)ROM | RFC 5869 / SP 800-56C | the combiner core |
| AES-256-GCM is IND-CCA + INT-CTXT AEAD | SP 800-38D | the data-encapsulation layer |

These are the same idealized-primitive assumptions the symbolic models make explicit — here used in
a *computational* reduction rather than a symbolic abstraction.

## 5. What is **not** claimed

- This is **not** a new theorem or a peer-reviewed proof. It argues that the Shield combiner *is an
  instance of* [GHP18]/[X-Wing]/dual-PRF combiners and *inherits* their security; the precise
  reduction lives in those papers, not here.
- The combiner's key-indistinguishability core **is** machine-checked computationally, and the
  **hybrid-KEM IND-CCA composition is now mechanized on both legs** (CryptoVerif — see the
  *Mechanized (CryptoVerif)* section: `shield_combiner_indcca.cv` reduces to ML-KEM IND-CCA,
  `shield_combiner_dh.cv` to Gap-DH). What is **not** mechanized is ML-KEM IND-CCA and Gap-DH
  **themselves**, and the full end-to-end protocol (handshake + AEAD channel): those remain the
  standardized assumptions and/or are covered by the symbolic Verifpal + Tamarin + ProVerif models.
- The Shield is **algorithm-agile with an HKDF combiner**, which is *structurally analogous to* but
  **not** the X-Wing construction (X-Wing fixes X25519 + ML-KEM-768 and a specific SHA3-256
  combiner, and is itself a standardization candidate). **For interoperable production traffic,
  prefer a standardized hybrid KEM (X-Wing) or hybrid TLS 1.3 / HPKE** rather than this project
  convention — see [`SECURITY.md`](SECURITY.md).
- Nothing here changes the [`SECURITY.md`](SECURITY.md) caveats: `kyber-py`/`dilithium-py` track
  FIPS 203/204 but are **not FIPS 140-3 validated** and **not side-channel hardened**.

## 6. The next rigor frontier

> **Update (largely addressed 2026-06-20).** This frontier — a machine-checked **computational** proof
> of the combiner **and** the hybrid-KEM IND-CCA **composition** — is now done in CryptoVerif: the
> combiner core (`shield_combiner.cv` / `shield_kemdem.cv`) **and** the composition on **both** legs
> (`shield_combiner_indcca.cv`, bound carrying `Adv_PQ_CCA`; `shield_combiner_dh.cv`, bound carrying
> `Adv_GDH`) — see "## Mechanized (CryptoVerif)" below and `FORMAL_COVERAGE.md` row 9.

What remains on the frontier: the leg assumptions themselves (ML-KEM IND-CCA / Gap-DH — standardized,
not re-derived here), ML-KEM's small decryption-error term (X-Wing's delta_correctness), curve
point-validation / small-subgroup handling, and HKDF-as-ROM; plus constant-time / side-channel analysis
of the reference code (a separate, orthogonal hardening axis). These are tracked as future work; none is
claimed done.

## Mechanized (CryptoVerif)

A **machine-checked computational** proof of the combiner's core claim now exists, in
**CryptoVerif 2.12**. Full details and verbatim output:
[`formal/COMBINER_CRYPTOVERIF.md`](formal/COMBINER_CRYPTOVERIF.md). Models:
[`formal/shield_combiner.cv`](formal/shield_combiner.cv) (required core) and
[`formal/shield_kemdem.cv`](formal/shield_kemdem.cv) (optional KEM-DEM corollary).

**What is mechanically proven.** Modeling HKDF as a **random oracle** `H` on its three logical
inputs `K = H(ss_c, ss_pq, transcript)` — exactly the `(dual-)PRF / (Q)ROM` abstraction §3/§4 already
states, with `ss_c` and `ss_pq` as separate types capturing the injective `u16` length-framing —
CryptoVerif proves that `K` is **indistinguishable from a fresh random key under single-leg
compromise, in both directions**. This is the computational counterpart of the symbolic
`hybrid_secrecy` lemma. Verbatim `RESULT` lines:

```
RESULT Proved secrecy of Kq up to probability 2 * qH / |ss_pq_t| + (2 + 2 * qH) / |ss_c_t|
RESULT Proved secrecy of Kc up to probability 2 * qH / |ss_pq_t| + (2 + 2 * qH) / |ss_c_t|
All queries proved.
```

`Kc` = classical leg leaked (`ss_c` given to the adversary, `ss_pq` protected — the
harvest-now-decrypt-later / CRQC case); `Kq` = post-quantum leg leaked (`ss_pq` given, `ss_c`
protected). The bound `qH / |·|` is the honest intuition: the only way to distinguish `K` is to
**guess the still-secret leg** among the `qH` hash-oracle queries.

The optional corollary ([`formal/shield_kemdem.cv`](formal/shield_kemdem.cv)) chains one KEM-DEM step
— AES-256-GCM (modeled as IND-CPA + INT-CTXT AEAD) keyed by the combiner output — and proves message
confidentiality and ciphertext integrity:

```
RESULT Proved forall c: bitstring; event(accept(c)) ==> event(sent(c)) up to probability ... + qH / |ss_pq_t|
RESULT Proved secrecy of b up to probability 2 * Penc(...) + 2 * Pencctxt(...) + 2 * qH / |ss_pq_t|
All queries proved.
```

**Assumptions of the mechanized proof:** HKDF is a random oracle (the `(Q)ROM` abstraction of §4);
one leg's shared secret is hidden (the withheld secret); and, for the corollary, AES-256-GCM is
IND-CPA + INT-CTXT (SP 800-38D).

**The composition, mechanized on both legs.** Beyond the single-leg combiner result above, two further
CryptoVerif models close the GHP18/X-Wing **composition** step — "each component leg secure => the
combined hybrid KEM is IND-CCA" — by *reducing to* the leg assumption rather than abstracting it:
[`formal/shield_combiner_indcca.cv`](formal/shield_combiner_indcca.cv) equips the ML-KEM leg with a
genuine IND-CCA2 KEM macro + an encapsulation/decapsulation oracle and proves the combined-KEM session
key real-or-random with bound `2*qH/|ss_c_t| + 2*Adv_PQ_CCA` (the `Adv_PQ_CCA` term confirms ML-KEM
IND-CCA is actually invoked); its mirror
[`formal/shield_combiner_dh.cv`](formal/shield_combiner_dh.cv) reduces the same goal to the classical
leg's **Gap-DH** hardness on X25519/X448 via CryptoVerif's GDH macro, bound `4*PDistRerandom + 2*Adv_GDH`.
Together they give one-leg-break resistance reduced, on **each** side, to the surviving leg's standard
assumption. CI asserts both advantage terms are present (a bare `auto` that dropped them would collapse
back to the single-leg abstraction). See `FORMAL_COVERAGE.md` row 9.

**What remains argued, not mechanized:** ML-KEM IND-CCA and Gap-DH **themselves** (FIPS 203 / Module-LWE;
RFC 7748) — the standardized hard problems the composition reduces *to*, cited not re-proven; ML-KEM's
small decryption-error term (X-Wing's delta_correctness); curve point-validation / small-subgroup
handling; and the HKDF→ROM step (modeled, not derived from HMAC/SHA-2/SHA-3). The full channel/protocol
logic (downgrade resistance, sender authentication, replay) is covered by the **symbolic**
Tamarin / Verifpal / ProVerif models. This is a **complete proof of the scoped combiner + composition
claims**, not an end-to-end protocol proof.

## References

- F. Giacon, F. Heuer, B. Poettering. *KEM Combiners.* PKC 2018. <https://eprint.iacr.org/2018/024>
- M. Barbosa et al. *X-Wing: The Hybrid KEM You've Been Looking For.* IACR CiC / eprint 2024/039.
  <https://eprint.iacr.org/2024/039>
- NIST SP 800-56C Rev. 2, *Recommendation for Key-Derivation Methods.*
- H. Krawczyk, P. Eronen. RFC 5869, *HMAC-based Extract-and-Expand KDF (HKDF).*
- FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), NIST SP 800-38D (GCM), RFC 7748 (X25519/X448).
