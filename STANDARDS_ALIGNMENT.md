# VORLATH Shield — hybrid-KEM standards alignment crosswalk

> **What this is.** A conformance **argument** — how the Shield's combiner and key
> derivation map onto the emerging hybrid-KEM *standardization* (IETF CFRG + NIST), with
> each claim tied to a specific section. It is **not** a certification or a validation
> (see [`SECURITY.md`](SECURITY.md): the Shield is a reference implementation, **not**
> FIPS 140-3 validated; "CNSA 2.0" names the algorithm set, never a certificate). The
> CFRG drafts cited are **work in progress** and may change; this page states the alignment
> as of the cited versions and is maintained as those documents evolve.
>
> **Why it exists.** A full AI-council review (2026-06-21; Grok, DeepSeek, Gemini, Mistral,
> watsonx, Perplexity) concluded the Shield is *at* the cryptographic frontier — the apex
> move is **consolidate + align with the standards**, not pursue a novel research property
> (a key-confirmation-under-component-failure proof was named but judged diminishing-returns,
> consistent with the earlier dual-PRF decision in [`VERIFICATION_GAP_MAP.md`](VERIFICATION_GAP_MAP.md)).
> This crosswalk is that alignment.

## The Shield combiner (ground truth, `vorlath_shield/shield.py:_derive_key`)

```
K = HKDF(salt = "VORLATH-Shield-combiner/v2",                       # SP 800-56C two-step (extract-then-expand)
         IKM  = u16(len ss_c)‖ss_c ‖ u16(len ss_pq)‖ss_pq [‖ u16(len ppk)‖ppk],   # length-framed -> injective
         info = label ‖ suite_id ‖ pre_auth ‖ sender_kid,          # transcript as FixedInfo
         L    = 32)
pre_auth = suite_id ‖ flags ‖ recipient_key_id ‖ eph_pub ‖ kem_ct ‖ nonce   # also the AEAD AAD
```

## Crosswalk

| Standard / document (version) | What it specifies for a hybrid KEM | Shield | Evidence |
|---|---|---|---|
| **IETF `draft-irtf-cfrg-hybrid-kems-11`** (CFRG) | **`Concat-then-KDF`**: `ss = KDF(ss_1 ‖ ss_2, info, L)`; HKDF is the canonical KDF; a fixed domain-separation label; **recommends** folding the component public keys + ciphertexts into `info` for MAL-BIND-K-CT/K-PK robustness. | **CONFORM (instantiation)** | The Shield's combiner **is** Concat-then-KDF: length-framed `ss_c ‖ ss_pq` as the HKDF IKM (the `u16` framing is an unambiguous encoding of the concatenation), a fixed `_COMBINER_LABEL` + suite_id for domain separation, and `recipient_key_id` (=H(pk)) + `kem_ct` bound into `info` **and** the AEAD AAD — directly satisfying the draft's pk/ct-binding recommendation. |
| **NIST SP 800-227** (final) §5.3 Hybrid Key-Establishment | Defers hybrid shared-secret derivation to **SP 800-56C Rev.2 §4.1 (Concatenation)**; the KDF MUST be an SP 800-56C-approved KDF (the two-step HKDF extract-then-expand qualifies); `OtherInput`/`info` should bind the transaction (parties, public keys). | **CONFORM** | The Shield uses exactly the SP 800-56C two-step HKDF (HMAC-SHA-256/384) over the concatenated secrets, with the transcript in `OtherInput`/`info`. This is the construction SP 800-227 points to. (Algorithm-set alignment only — **not** a CAVP/CMVP certificate.) |
| **`draft-connolly-cfrg-xwing-kem`** (X-Wing) + *"Starfighters"* generalization (SandboxAQ) | A **fixed, non-agile** KEM: a single `SHA3-256(ss_ML-KEM ‖ ss_X25519 ‖ ct_X25519 ‖ pk_X25519 ‖ label)` — one hash, **no HKDF**, fixed to X25519+ML-KEM-768. Proven MAL-BIND-K-CT **and** K-PK. | **STRUCTURALLY ANALOGOUS, NOT byte-compatible** | The Shield is **algorithm-agile** (suites 0x01–0x03, X25519/X448, ML-KEM-768/1024) with an HKDF combiner — a different, also-standards-aligned point in the design space. It is **not** wire-compatible with X-Wing and does not claim to be. For byte-level interop with X-Wing peers, use X-Wing; see [`SECURITY.md`](SECURITY.md) / [`SECURITY_ARGUMENT.md`](SECURITY_ARGUMENT.md). The Shield's binding for the same notions is argued + tested at the protocol layer in [`BINDING.md`](BINDING.md). |
| **RFC 9958** | Application-/protocol-level (multiple-recipient / KEM usage); does **not** define the internal hybrid-KEM combiner. | **N/A to the combiner** | Out of scope for the combiner crosswalk; noted for completeness. |
| **Cremers–Dux–Medinger X-BIND notions** (eprint 2023/1933) + Schmieg 2024/523 | MAL-BIND-K-CT / K-PK: a shared secret must uniquely name its ciphertext + public key; bare ML-KEM fails the MAL level. | **Restored at the protocol layer** | [`BINDING.md`](BINDING.md) §3 + the NV-1..NV-7 must-reject corpus + the `*_recipient_binding` / `*_binds_the_pq_ciphertext` tests: `kem_ct` + `recipient_key_id` are in the KDF `info`, the AEAD AAD, and (auth mode) the signed `pre_auth`. |
| **Deployment profiles**: `draft-ietf-tls-mlkem`, `draft-ietf-hpke-pq`, `draft-ietf-mls-pq-ciphersuites` | How hybrids appear on the wire in TLS 1.3 / HPKE / MLS. | **Out of scope by design** | The Shield is a **reference library + its own one-pass wire format**, not a TLS/HPKE/MLS integration. For interoperable production traffic, prefer the standardized profiles (already stated in [`SECURITY.md`](SECURITY.md)). |

## Net

The Shield's combiner **is the `Concat-then-KDF` construction that `draft-irtf-cfrg-hybrid-kems-11`
specifies and that NIST SP 800-227 §5.3 → SP 800-56C §4.1 approves**, instantiated with the draft's
*recommended* public-key/ciphertext binding (in `info` + AAD). It diverges from X-Wing **deliberately**
— algorithm-agility over a single fixed hash — and makes no wire-compatibility claim there. So the
design is not idiosyncratic: it sits squarely on the standardized path for hybrid KEMs, with its
non-standard choices (HKDF over single-hash; one-pass PKE over a TLS/HPKE profile) explicitly scoped.

**Honest limits.** This is a *conformance argument* (SP 800-227 is final; the CFRG hybrid-KEMs and X-Wing
drafts are work-in-progress and re-checked as they evolve) — not a NIST validation, an IETF conformance
certificate, or wire-interop with X-Wing/TLS/HPKE.
The Shield remains a reference implementation; for interoperable production traffic use a standardized
hybrid KEM (X-Wing) or a hybrid TLS 1.3 / HPKE / MLS profile.

## Sources

- IETF CFRG, *Hybrid PQ/T Key Encapsulation Mechanisms*, `draft-irtf-cfrg-hybrid-kems-11`.
- NIST SP 800-227 (final), *Recommendations for Key-Encapsulation Mechanisms*, §5.3 → SP 800-56C Rev.2 §4.1.
- Connolly et al., `draft-connolly-cfrg-xwing-kem`; SandboxAQ, *"Starfighters: On the General Applicability of X-Wing."*
- RFC 9958.
- Cremers, Dux, Medinger, eprint 2023/1933; Schmieg, eprint 2024/523 (see [`BINDING.md`](BINDING.md)).
- Deployment: `draft-ietf-tls-mlkem`, `draft-ietf-hpke-pq`, `draft-ietf-mls-pq-ciphersuites`.
