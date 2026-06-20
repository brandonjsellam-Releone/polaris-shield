# POLARIS Shield — formal-coverage matrix (one authoritative table)

This is the single page a reviewer should read to know **exactly what is machine-checked,
what is argued by reduction, and what is explicitly out of scope** — and the mapping from
each prover artifact to a standard security goal. It consolidates the per-tool tables in
[`formal/README.md`](formal/README.md), [`SECURITY_ARGUMENT.md`](SECURITY_ARGUMENT.md) and
[`THREAT_MODEL.md`](THREAT_MODEL.md) so nothing has to be reassembled by hand.

## What this is, and is NOT (read first)

- **POLARIS Shield is a post-quantum *cryptography* reference implementation** that runs on
  ordinary classical machines. It is the runnable form of the BOREALIS / POLARIS "L9 root of
  trust" layer. **It is not a quantum computer and contains no quantum hardware.** The
  "quantum-computing citadel" is a separate, speculative *systems* hypothesis in the dossier;
  the Shield is the one piece of that vision that is real, runnable, and verifiable today.
- **Symbolic proofs (Verifpal bounded; Tamarin and ProVerif unbounded)** establish that the
  *protocol logic* is sound against an unbounded Dolev-Yao attacker, assuming the primitives are ideal.
- **The computational proofs (CryptoVerif)** establish that the *combiner* is a sound hybrid KEM
  combiner with concrete probability bounds, AND mechanize the **composition** "each component leg
  secure => the combined hybrid KEM is IND-CCA" on **both** legs (ML-KEM IND-CCA and Gap-DH).
- **None of the four** proves ML-KEM IND-CCA, ML-DSA EUF-CMA, or Gap-DH themselves; those are the
  standardized assumptions the hybrid is *built on* (and hedges across). See "Assumed".

## Mechanized security goals (each row is checked by a tool that re-runs in CI)

| # | Security goal (standard name) | Where machine-checked | Artifact / lemma | Kind |
|---|---|---|---|---|
| 1 | **Hybrid session-key secrecy** — plaintext stays secret unless **both** legs break (harvest-now-decrypt-later defeated) | Tamarin (unbounded) + Verifpal (bounded) | `hybrid_secrecy`; `shield.vp`+`shield_pq.vp` `confidentiality? plaintext` | all-traces / query |
| 2 | **Secrecy under classical-leg break** (a CRQC breaks X-DH) | Tamarin + Verifpal | `secrecy_under_classical_break`; `shield.vp` | all-traces / query |
| 3 | **Secrecy under PQ-leg break** (a hypothetical ML-KEM break) | Tamarin + Verifpal | `secrecy_under_pq_break`; `shield_pq.vp` | all-traces / query |
| 4 | **Sender authentication** (transcript agreement; deliberately non-injective) | Tamarin + Verifpal | `sender_authentication`; `authentication? ct` | all-traces / query |
| 5 | **Downgrade resistance** (recipient accepts only the suite pinned to its key) | Tamarin | `recipient_only_accepts_pinned_suite` | all-traces |
| 6 | **KCI resistance** (sender authenticity survives compromise of the recipient's hybrid keys) | Tamarin | `kci_resistance` | all-traces |
| 7 | **Combiner key-indistinguishability** — derived key ≈ random under single-leg compromise, **both directions** | CryptoVerif (computational) | `shield_combiner.cv` "RESULT Proved secrecy of Kq/Kc"; KEM-DEM corollary `shield_kemdem.cv` | computational |
| 8 | **Non-vacuity controls** — honest runs exist; each protection provably breaks once its safeguard is removed | Tamarin | `executable`, `sanity_both_legs_broken_leaks`, `sanity_sign_reveal_allows_forgery`, `sanity_classical_break_run_exists`, `sanity_pq_break_run_exists` | exists-trace |
| 9 | **Hybrid-KEM IND-CCA composition** — "each component leg secure => the combined hybrid KEM is IND-CCA", mechanized on **both** legs | CryptoVerif | `shield_combiner_indcca.cv` (bound carries `Adv_PQ_CCA` = the ML-KEM leg) + `shield_combiner_dh.cv` (bound carries `Adv_GDH` = the classical X25519/X448 leg) | computational |

All 11 Tamarin lemmas auto-prove (~11 s, 1.12.0 / Maude 3.4); **ProVerif independently re-proves the
unbounded goals (rows 1-6) as a fourth lineage** (`shield.pv`, all queries hold); both Verifpal models
report *All queries pass*; CryptoVerif reports *All queries proved* for the combiner **and both
composition models**. The **four** jobs (`prove`, `prove-tamarin`, `prove-proverif`, `prove-cryptoverif`)
gate CI in [`.github/workflows/formal.yml`](../.github/workflows/formal.yml); the CryptoVerif gate
additionally asserts the `Adv_PQ_CCA` / `Adv_GDH` advantage terms are actually invoked (not collapsed
to an abstraction).

## Documented non-properties (verified *negative* results, not gaps we hid)

| Property | Status | Evidence |
|---|---|---|
| **Replay / freshness** | OUT of scope **by design** (stateless one-pass open) | `shield_replay.vp`: `authentication? sig` reported attacker-relayable — a *verified* non-result |
| ML-DSA signing constant-time | **leak measured, not fixed** | `CONSTANT_TIME.md`: dudect \|t\|≈575 on the pure-Python leg |

## Assumed (the standardized primitive assumptions — argued, not mechanized)

| Assumption | Standard | Role |
|---|---|---|
| ML-KEM IND-CCA | FIPS 203 (Module-LWE) | the post-quantum leg |
| ML-DSA EUF-CMA | FIPS 204 | sender authenticity |
| strong-DH (X25519/X448) | — | the classical leg |
| HKDF a secure dual-PRF/extractor; AES-256-GCM IND-CCA + INT-CTXT | SP 800-56C / SP 800-38D | combiner + channel |

The hybrid is precisely the **hedge against one of the two KEM assumptions failing** — goals
1–3 quantify that a single-leg break is survivable. The reduction from "each component leg is secure"
to "the combined hybrid KEM is IND-CCA" — the GHP18 / X-Wing argument, sketched in
[`SECURITY_ARGUMENT.md`](SECURITY_ARGUMENT.md) — is now **mechanized on both legs** (row 9): CryptoVerif
reduces the combined-KEM IND-CCA to ML-KEM IND-CCA (`shield_combiner_indcca.cv`) and, in the mirror, to
Gap-DH (`shield_combiner_dh.cv`). What stays *assumed* are the leg assumptions themselves (the rows just
above), ML-KEM's small decryption error / implicit rejection, curve point-validation, and HKDF-as-ROM.

## Explicitly out of scope (and where that is stated)

- Side channels beyond timing (power / EM / cache / fault) — `SECURITY.md`, `CONSTANT_TIME.md`.
- FIPS 140-3 (CAVP/CMVP) validation — `SECURITY.md` ("CNSA 2.0" = algorithm set, never a cert claim).
- Wire-encoding length-framing fidelity — carried by ACVP + the 497-test suite + `interop/` + `FORMAT.md`.
- Anonymous-mode flag-stripping as a distinct Tamarin rule, and injective (anti-replay) agreement —
  carried by the Verifpal models and the implementation/interop tests.

## How to re-derive every row yourself

See [`REPRODUCE.md`](REPRODUCE.md). Every artifact named above is content-addressed in
[`release/RELEASE_MANIFEST.json`](release/RELEASE_MANIFEST.json); the bundle digest is signed at
release, so you can confirm the bytes you re-run are the bytes that were proved.
