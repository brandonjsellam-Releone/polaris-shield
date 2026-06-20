# Constant-time / side-channel measurement — POLARIS Shield

This document **measures** the timing side-channel behaviour of the POLARIS Shield's
cryptographic operations. It does **not** make the Shield constant-time, and it makes
**no** claim that it is. `SECURITY.md` already states that the pure-Python PQ legs are
"not side-channel / constant-time hardened"; this turns that qualitative disclaimer into
the quantitative number a side-channel reviewer asks for first.

> **Bottom line, stated up front.** The reference legs are **not** constant-time and are
> not expected to be. ML-DSA-87 deterministic signing shows a **large, unambiguous**
> data-dependent timing signal (|t| ≈ 575, far above the dudect 4.5 threshold). ML-KEM
> decapsulation (valid vs invalid ciphertext) and `shield.decrypt` (valid vs tampered
> envelope) showed **no dependency detectable at the sample sizes used here** — which is a
> *negative result at finite N*, **not** a proof of constant-time behaviour (see
> [Interpretation](#interpretation)).

The harness lives in [`sidechannel/ct_measure.py`](sidechannel/ct_measure.py).

---

## Methodology (dudect / Welch's two-sample t-test)

The approach is the classic **dudect** test (Reparaz, Balasch & Verbauwhede, *"Dude, is my
code constant time?"*, DATE 2017): rather than counting CPU cycles in a model, it measures
*wall-clock* time over two carefully chosen input classes and asks, statistically, whether
the two timing distributions differ.

For each target operation:

1. **Two input classes.** We pick two inputs that a constant-time implementation would
   process in the same time. Any measurable timing gap between them is leakage.
2. **Interleaved sampling.** Each iteration times **class A then class B** back-to-back, so
   slow environmental drift (CPU frequency scaling, the OS scheduler, garbage collection)
   hits both classes equally instead of biasing one. Timing uses
   `time.perf_counter_ns()` (the highest-resolution monotonic clock Python exposes).
3. **Warmup discard.** The first `warmup` samples (default 200) are run and thrown away to
   pass cold caches and interpreter/allocator warmup.
4. **High-cutoff filter.** For each class we keep the **fastest 90%** of samples (drop the
   slow tail). This is standard dudect practice: rare OS-scheduling outliers inflate the
   variance and can *mask* a real difference of means. We compare the fast bulk.
5. **Welch's t-statistic.** `t = (mean_A − mean_B) / sqrt(var_A/n_A + var_B/n_B)`. Welch
   (not Student) because the two classes need not have equal variance.

**Decision rule (dudect standard):** `|t| > 4.5` ⇒ the timing **demonstrably depends** on
the input class ⇒ the operation is **not constant-time**. `|t| < 4.5` at the sample size
tested ⇒ "no dependency detected at this N" (a negative result, *not* a certificate).

### The three targets and their input classes

| # | Operation | Class A | Class B | Why these classes |
|---|-----------|---------|---------|-------------------|
| 1 | **ML-KEM-1024 decapsulation** (raw `kyber-py`) | valid ciphertext | invalid ciphertext (1 byte flipped) | Exercises the **FO-transform implicit-rejection branch** — a classic KEM timing-oracle target. A leak here is the Kyber decapsulation oracle reviewers worry about most. |
| 2 | **`shield.decrypt`** (full path) | valid envelope | tampered envelope (flipped AEAD tag byte) | The **AEAD reject path**. Times the whole Shield open (ECDH + ML-KEM decaps + AES-256-GCM), i.e. exactly what an application calls. |
| 3 | **ML-DSA-87 sign** (raw `dilithium-py`, **deterministic**) | message `0x00`×32 | message `0xa5`×32 | ML-DSA signs via **rejection sampling**; the number of loop iterations until a valid signature is found is **data-dependent**. Deterministic mode removes per-call randomness and **both classes use the same signing key**, so the only varying input is the message. |

---

## Measured results (this machine)

Captured by running the harness end-to-end:

```
cd tech
python sidechannel/ct_measure.py
```

**Environment:** `win32`, CPython 3.14.5, `time.perf_counter_ns()`,
`kyber-py==1.2.0`, `dilithium-py==1.4.0`, default suite `0x02`
(X448 + ML-KEM-1024 + ML-DSA-87 + HKDF-SHA384 + AES-256-GCM). Full run ≈ 107 s.

| Operation | N / class (after 90% filter) | mean A | mean B | **\|t\|** | Verdict |
|-----------|------------------------------|--------|--------|-----------|---------|
| **ML-KEM-1024 decaps** — valid vs invalid ct | 1200 (1081) | 8124.5 µs | 8116.3 µs | **1.24** | no dependency detected at this N |
| **`shield.decrypt`** — valid vs tampered envelope | 1000 (901) | 8875.4 µs | 8876.3 µs | **0.11** | no dependency detected at this N |
| **ML-DSA-87 sign** — message A vs message B | 300 (271) | 32 427.8 µs | 91 105.7 µs | **575.03** | **timing dependency DETECTED (> 4.5)** |

(`µs` shown as `us` in the harness console; values are means of the filtered fast bulk.)

### Run-to-run stability

`|t|` is itself a random variable, so we re-ran the harness several times:

- **ML-KEM decaps:** `|t|` observed across runs ≈ **0.34, 1.24, 1.59** — all far below 4.5,
  with the sign of the (tiny) mean difference flipping between runs. Consistent with **no
  detectable dependency** at this N.
- **`shield.decrypt`:** `|t|` ≈ **0.1 – 2.3** across runs (e.g. 0.11, 0.85, 1.10, and ~2.25 on
  a busier machine) — same picture; the per-call ML-KEM decapsulation dominates the ~8.9 ms cost
  and the valid/tampered means sit within a few ns of each other. All observed values are well
  below the 4.5 detection threshold, but the run-to-run spread is itself a reminder that a
  finite-N non-detection is not a constant-time certificate.
- **ML-DSA-87 sign:** `|t|` ≈ **575, 711, 781** — always *enormous* and always positive in
  significance. The mean cost flips between ~32 ms and ~136 ms across runs **because the
  shared signing key is regenerated each run**, and the per-message rejection-loop count is a
  function of (message, key); within any single run, message A and message B differ by a
  factor of ~2–3×. This is a textbook data-dependent timing signal.

---

## Interpretation

**What is proven.** ML-DSA-87 signing is **not constant-time** in `dilithium-py`. The
rejection-sampling loop runs a *secret/message-dependent* number of iterations, and that
shows up as a 2–3× wall-clock swing and a t-statistic two orders of magnitude past the
threshold. Anyone who can time signatures observes information correlated with the message
(and, for a fixed message, with the key). This is exactly the disclosed limitation, now
quantified.

**What is *not* proven.** ML-KEM decapsulation and `shield.decrypt` returned `|t| < 4.5` at
N = 1200 / 1000 per class. **This is a negative result, not a proof of constant-time.**
Three reasons it is not a certificate:

1. **Finite N.** A smaller leak may simply require more samples to clear 4.5. Absence of
   evidence at one sample size is not evidence of absence.
2. **One machine, one config.** A different CPU, OS scheduler, memory pressure, or a
   cache/branch-prediction microarchitectural channel (which wall-clock timing does not
   isolate) could expose a dependency this test cannot see.
3. **One input split.** dudect can only detect a dependency along the *specific* two-class
   axis chosen. ML-KEM may well leak along an axis other than valid-vs-corrupted ciphertext
   (e.g. specific malformed structures), which this split does not probe.

So the honest reading of targets 1 and 2 is: *"no timing dependency was detectable with this
test, at this N, on this machine"* — useful as a sanity check and a regression baseline, but
**not** a claim that those operations are constant-time. **Detecting leakage with dudect is
sound; failing to detect it is not.**

---

## Scope and mitigation

- **This measures; it does not fix.** Nothing in `sidechannel/` changes the Shield's
  cryptographic logic. It adds an evaluation harness, nothing more.
- **The reference legs are not expected to be constant-time.** `kyber-py` and `dilithium-py`
  are clean, readable pure-Python implementations that *track* FIPS 203/204; they are written
  for correctness and clarity, not for constant-time execution. Pure Python cannot even make
  meaningful constant-time guarantees (the interpreter, allocator, and GC are all
  data-dependent). A *measured* leak here is the expected outcome, not a surprise.
- **Production requires a constant-time, FIPS-validated module.** Per `SECURITY.md`'s "Path
  to production", real deployment must adopt a validated, side-channel-aware build —
  AWS-LC / BoringSSL, OpenSSL 3.5+, or liboqs in a validated configuration — and commission
  an independent side-channel review. This harness is a triage tool that *motivates* that
  work; it is not a substitute for it.
- **Threat-model alignment.** `THREAT_MODEL.md` already places "side-channel / timing / power
  / fault / co-resident observation" **explicitly out of scope**. These measurements are
  consistent with that posture: any adversary with local/co-resident/physical timing
  observation is out of scope, and the numbers above show *why* that scoping is necessary
  for this reference build.

---

## Reproducing

```bash
cd tech
python sidechannel/ct_measure.py                 # default tuned sample sizes, ~2 min
python sidechannel/ct_measure.py --samples 5000  # longer run, more stable |t|
python sidechannel/ct_measure.py --cutoff-pct 95 # keep more of the tail
```

A non-timing **smoke test** (`test_sidechannel.py`) confirms the harness imports and runs a
tiny measurement; it deliberately asserts **nothing** about timing magnitudes (a
threshold-gated test would be flaky across machines/CI) and is therefore safe in the suite.
