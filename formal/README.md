# VORLATH Shield — formal verification

Machine-checked **symbolic** security proofs of the Shield's authenticated hybrid handshake,
under an active **Dolev-Yao** attacker — the exact adversary `THREAT_MODEL.md` names. Every
prose property in the threat-model table is here a query/lemma a checker either **proves** or
**breaks**, across **three independent tool lineages** (Verifpal, bounded; Tamarin and ProVerif, unbounded), and
the proofs run in CI (the dedicated `formal.yml` workflow) whenever the handshake model or its
implementation changes.

> **What this adds.** ACVP + the 497-test suite + hypothesis fuzzing show the *primitives* are
> correct and the *implementation* behaves on sampled inputs. This layer raises the assurance
> *ceiling*: it proves the **protocol design** meets its goals against an unbounded active
> attacker, not just on examples. *Our security goals are not asserted — they are checked by a
> tool that re-runs whenever the handshake model or its implementation changes.*

## Tooling

[Verifpal](https://verifpal.com) v0.52.0 (pinned), an automated symbolic protocol verifier with
an active attacker. It is **sound for finding attacks** (a reported attack is real in the model)
and, where it reports a query verified, no attack exists within its analysis. Install is a single
static binary; the CI `prove` matrix downloads the pinned Linux build and runs `verifpal verify`.

[Tamarin](https://tamarin-prover.com) v1.12.0 (pinned), an automatic/interactive prover that
analyzes protocols over an **unbounded** number of concurrent sessions in the same Dolev-Yao
model — a strictly broader statement than a bounded analysis. The `shield.spthy` model
**auto-proves with no manual guidance**; the CI `prove-tamarin` job installs Maude + the pinned
Tamarin binary and gates on **every lemma verifying**.

[CryptoVerif](https://cryptoverif.inria.fr) v2.12 (pinned), an automatic prover in the
**computational** model (concrete probability bounds, not Dolev-Yao symbolic). It machine-checks the
hybrid-combiner **key-indistinguishability** core — the derived key is indistinguishable from random
under single-leg compromise, in both directions (`shield_combiner.cv`), with an optional KEM-DEM
corollary (`shield_kemdem.cv`). The CI `prove-cryptoverif` job installs it via opam and gates on
`All queries proved`. See [`COMBINER_CRYPTOVERIF.md`](COMBINER_CRYPTOVERIF.md) and
[`../SECURITY_ARGUMENT.md`](../SECURITY_ARGUMENT.md).

```
make prove-all        # all three layers locally (needs verifpal + tamarin + cryptoverif)
verifpal verify tech/formal/shield.vp
tamarin-prover --prove tech/formal/shield.spthy         # all 11 lemmas: verified (~11 s)
cryptoverif -in oracles tech/formal/shield_combiner.cv  # computational: All queries proved
```

## Models

| File | What it establishes | Result |
|---|---|---|
| `shield.vp` | The authenticated hybrid handshake; **CRQC breaks the classical leg** (recipient X-DH key leaks in a later phase). | `confidentiality? plaintext` **PASS**, `authentication? ct` **PASS** — *All 2 queries pass.* |
| `shield_pq.vp` | The same handshake; **the ML-KEM leg breaks** (decapsulation key leaks) while the classical leg holds. | `confidentiality? plaintext` **PASS**, `authentication? ct` **PASS** — *All 2 queries pass.* |
| `shield_replay.vp` | The documented **non-property**: replay is not prevented. (Not a CI gate — verified evidence.) | `authentication? sig` **reported attacker-relayable** — the genuine envelope is replayable by design. |

Together `shield.vp` + `shield_pq.vp` prove **hybrid soundness in both directions**: breaking
*either single leg alone* — classical (a CRQC) or post-quantum (a hypothetical ML-KEM break) — is
insufficient to recover plaintext, because the AEAD key is derived from **both** shared secrets.
That is the machine-checked form of "harvest-now, decrypt-later is defeated."

## Tamarin — the unbounded-session lineage (`shield.spthy`)

An **independent second lineage**: where Verifpal performs a bounded analysis, Tamarin proves the
*same* core goals over an **unbounded** number of concurrent sessions, and adds standalone
downgrade- and KCI-resistance lemmas. The transcript binds `suite_id || flags || recipient_key_id
|| eph_pub || kem_ct || nonce` (mirroring the real `_pre_auth_transcript`), and the recipient pins
a suite to its key. All **11 lemmas verify automatically** (~11 s, Tamarin 1.12.0 / Maude 3.4):

| Lemma | Kind | Establishes |
|---|---|---|
| `hybrid_secrecy` | all-traces | plaintext secret unless **both** legs break (harvest-now, decrypt-later) |
| `secrecy_under_classical_break` / `secrecy_under_pq_break` | all-traces | secrecy survives a single-leg break (a CRQC **or** an ML-KEM break) |
| `sender_authentication` | all-traces | transcript agreement; deliberately **non-injective** (replay out of scope by design) |
| `recipient_only_accepts_pinned_suite` | all-traces | **downgrade resistance**: a recipient accepts only under the suite pinned to its key |
| `kci_resistance` | all-traces | sender authenticity survives compromise of the **recipient's** hybrid keys |
| `executable`, `sanity_both_legs_broken_leaks`, `sanity_sign_reveal_allows_forgery`, `sanity_classical_break_run_exists`, `sanity_pq_break_run_exists` | exists-trace | **non-vacuity controls**: honest runs exist, and the adversary provably *does* break each protection once its safeguard is removed (both-legs leak → key recovered; sign-key leak → forgery; each single-leg run is reachable) |

The two lineages agree: Verifpal (bounded) and Tamarin (unbounded) independently prove hybrid
secrecy under single-leg compromise + sender authenticity; Tamarin additionally proves downgrade
and KCI resistance as standalone lemmas. The same scope caveats (below) apply to both.

## Claim-by-claim traceability

Each query maps to a `THREAT_MODEL.md` property, the `shield.py` code that enforces it, and the
`FORMAT.md` section that specifies the bytes.

| THREAT_MODEL.md property | Verifpal query / result | Enforced in `shield.py` | `FORMAT.md` |
|---|---|---|---|
| Confidentiality vs CRQC (harvest-now, decrypt-later) | `confidentiality? plaintext` PASS after leaking the classical leg (`shield.vp`) | `_derive_key` — HKDF over length-framed `ss_classical \|\| ss_pq` | §2.6 |
| Hybrid soundness (reduces to the stronger KEM) | `confidentiality? plaintext` PASS after leaking the ML-KEM leg (`shield_pq.vp`) | combiner takes **both** secrets | §2.6 |
| Integrity / tamper-evidence | `authentication? ct` PASS (a tampered/forged envelope is rejected) | AES-256-GCM over the full header as AAD | §2.4, §2.6 |
| Downgrade resistance | subsumed by `authentication? ct`: `suite_id` is in the signed `pre_auth`, the AAD **and** the KDF `info`, so a re-bound suite is unreachable | `suite_id` in `pre_auth` + AAD + HKDF `info` | §2.7 |
| Transcript binding (no mix-and-match) | subsumed by `authentication? ct`: the whole transcript is signed and is the AAD | `_pre_auth_transcript` = `suite_id\|\|flags\|\|recipient_key_id\|\|eph_pub\|\|kem_ct\|\|nonce` | §2.6 |
| Sender authenticity, SIGMA-style, no UKS | `authentication? ct` PASS — the signature covers `pre_auth \|\| sender_key_id` (the signer binds its **own** identity), verified before decapsulation | ML-DSA `SIGN`/`SIGNVERIF` under `AUTH_CTX`, checked pre-decaps | §3 |
| No nonce reuse | modeled implicitly: a fresh ephemeral + fresh nonce per session | random 12-byte GCM nonce per message | §2.3 |
| **Replay / freshness (OUT of scope, by design)** | `shield_replay.vp`: `authentication? sig` reported **attacker-relayable** — a verified non-result | stateless one-pass open; no nonce cache | THREAT_MODEL.md residual-risks |

## Scope — read this to avoid over-reading the proof

- **Symbolic, not computational.** This is a Dolev-Yao symbolic model. It proves the *protocol
  logic* is sound assuming the primitives are ideal. It is **not** a computational/cryptographic
  reduction and assigns no concrete security bits.
- **Idealized primitives.** ML-KEM is assumed **IND-CCA** and modeled via `PKE_ENC`/`PKE_DEC`;
  ML-DSA is assumed **EUF-CMA** (`SIGN`/`SIGNVERIF`); HKDF/AEAD/hash are ideal. A break of an
  underlying primitive is outside the model (the hybrid is the hedge *against* one such break,
  which is exactly what `shield.vp`/`shield_pq.vp` quantify).
- **Out of scope:** constant-time / side-channel / timing behaviour, FIPS 140-3 validation,
  and the wire-encoding length-framing fidelity (the codec is covered by ACVP + the 497-test
  suite + the `interop/` corpus + `FORMAT.md`, not here). See `SECURITY.md`.
- **What "reference implementation" still means.** A verified design does **not** make this a
  validated module. The Shield remains a reference implementation; this proof concerns the
  protocol, not the deployment.
- **Unbounded / second-lineage rigor (DELIVERED):** `shield.spthy` is a [Tamarin](https://tamarin-prover.com)
  model that proves the same core goals (plus standalone downgrade + KCI resistance) over
  **unbounded** sessions; all 11 lemmas verify and the `prove-tamarin` CI job gates on it. A
  **third lineage, [ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/) (`shield.pv`), is now
  verified** over unbounded sessions too: all queries give their expected results — the secrecy
  family, downgrade resistance, and both authentication correspondences (scoped to honest senders) —
  and the `prove-proverif` CI job gates on it (pinned image `proverif.Dockerfile`). The Tamarin model is authenticated-mode and
  honestly scopes out — as the comment block in the model states — the anonymous-mode send path /
  flag-stripping as a distinct rule, ephemeral-state reveal / forward secrecy, and injective
  (anti-replay) agreement; those are carried by the Verifpal models and/or the implementation +
  interop tests.

## Honest summary

Two independent tool lineages — Verifpal (bounded) and Tamarin (unbounded) — verify the handshake's
goals clean, and the replay non-result reproduces the documented caveat. The proof is exactly as
strong as a symbolic model under idealized primitives — and no stronger. That scope is stated
above precisely so the result is a credential, not theater.
