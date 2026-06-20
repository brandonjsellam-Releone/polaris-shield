"""dudect-style leakage detection for VORLATH Shield operations.

WHAT THIS IS
------------
A *measurement* harness. It does NOT make the Shield constant-time and it does NOT
claim the Shield is constant-time. It turns the qualitative disclaimer in
``SECURITY.md`` ("not side-channel / constant-time hardened") into a *quantitative*
number a reviewer can read: for a chosen operation, does its wall-clock time depend
on a secret/input class?

METHODOLOGY (classic dudect; Reparaz, Balasch & Verbauwhede, 2017)
-----------------------------------------------------------------
For each target operation we define TWO input classes that, in a constant-time
implementation, *should* take the same time. We then:

  1. time the operation many times for each class with ``time.perf_counter_ns()``;
  2. INTERLEAVE the two classes per sample (class A, class B, A, B, ...), so any
     slow environmental drift (CPU frequency scaling, scheduler, GC) hits both
     classes equally instead of biasing one;
  3. discard a warmup prefix (cold caches / JIT-like warmup of the interpreter);
  4. apply a high-percentile cutoff filter to each class (drop the slowest tail),
     the standard dudect step that removes OS-scheduling outliers which otherwise
     inflate the variance and *hide* a real signal; and
  5. compute Welch's two-sample t-statistic between the two filtered timing
     distributions (Welch, not Student, because the variances are unequal).

INTERPRETATION (and its honest limits)
--------------------------------------
``|t| > 4.5`` is the standard dudect decision threshold. Above it, the timing
*demonstrably* depends on the input class -> the operation is NOT constant-time.

Below it at a finite N, we report "no dependency detected at this N". This is a
NEGATIVE result, not a proof: absence of evidence at one sample size, on one
machine, is not evidence of constant-time behaviour. Detecting leakage is sound;
failing to detect it is not a certificate.

SCOPE
-----
This measures; it does not fix. Production requires a constant-time, FIPS-validated
module (see ``SECURITY.md`` / ``CONSTANT_TIME.md``). The pure-Python ``kyber-py`` /
``dilithium-py`` reference legs are not expected to be constant-time, and the
measured results confirm that for several operations.
"""
from __future__ import annotations

import os
import statistics
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vorlath_shield import shield  # noqa: E402

# --- dudect parameters ------------------------------------------------------
DUDECT_THRESHOLD = 4.5     # standard |t| cutoff for "timing depends on input class"
DEFAULT_WARMUP = 200       # samples discarded before measurement begins
DEFAULT_CUTOFF_PCT = 90.0  # keep the fastest 90% of each class (drop the slow tail)

# Per-operation sample counts. ML-KEM decaps (~8 ms) and ML-DSA sign (~32 ms) are
# slow pure-Python ops, so N is sized so one full run of all three targets stays
# well under ~2 minutes on a typical machine while the t-statistic still stabilizes.
# Override with --samples / the `samples=` kwarg for a longer, more stable run.
DEFAULT_SAMPLES = {
    "mlkem_decaps_valid_vs_invalid": 1200,
    "shield_decrypt_valid_vs_tampered": 1000,
    # ML-DSA-87 deterministic sign is the slowest op (~40-140 ms/call, and the
    # difference IS the signal). 300/class is plenty for the huge t it produces
    # and keeps the full three-target run under ~2 minutes.
    "mldsa_sign_two_messages": 300,
}


@dataclass(frozen=True)
class LeakageResult:
    """Outcome of measuring one operation across its two input classes."""

    name: str
    description: str
    class_a: str
    class_b: str
    n_per_class: int
    n_used_a: int
    n_used_b: int
    mean_a_ns: float
    mean_b_ns: float
    t: float

    @property
    def detected(self) -> bool:
        return abs(self.t) > DUDECT_THRESHOLD

    def verdict(self) -> str:
        if self.detected:
            return f"timing dependency DETECTED (|t|={abs(self.t):.2f} > {DUDECT_THRESHOLD})"
        return f"no dependency detected at this N (|t|={abs(self.t):.2f})"


def welch_t(a: list[float], b: list[float]) -> float:
    """Welch's two-sample t-statistic for unequal variances.

    t = (mean_a - mean_b) / sqrt(var_a/n_a + var_b/n_b). Returns 0.0 if either
    sample is degenerate (too small or zero variance in both).
    """
    na, nb = len(a), len(b)
    if na < 2 or nb < 2:
        return 0.0
    ma, mb = statistics.fmean(a), statistics.fmean(b)
    va, vb = statistics.variance(a), statistics.variance(b)
    denom = (va / na) + (vb / nb)
    if denom <= 0.0:
        return 0.0
    return (ma - mb) / (denom ** 0.5)


def _high_cutoff(samples: list[float], pct: float) -> list[float]:
    """Drop the slow tail: keep only samples at or below the ``pct`` percentile.

    Standard dudect practice — OS scheduling produces rare very-slow outliers that
    blow up the variance and mask a real difference of means. We keep the fast bulk.
    """
    if len(samples) < 10:
        return samples
    ordered = sorted(samples)
    idx = min(len(ordered) - 1, int(len(ordered) * pct / 100.0))
    threshold = ordered[idx]
    return [s for s in samples if s <= threshold]


def measure_operation(
    name: str,
    description: str,
    class_a_label: str,
    class_b_label: str,
    prep_a: Callable[[], Callable[[], object]],
    prep_b: Callable[[], Callable[[], object]],
    samples: int,
    warmup: int = DEFAULT_WARMUP,
    cutoff_pct: float = DEFAULT_CUTOFF_PCT,
) -> LeakageResult:
    """Time two input classes interleaved and return their Welch t-statistic.

    ``prep_a`` / ``prep_b`` each build and return a zero-argument callable that runs
    the operation once for that class (the fixed inputs are captured in the closure,
    so per-sample timing measures only the operation, not input construction).
    """
    op_a = prep_a()
    op_b = prep_b()

    # Warmup: run both, discard timings (cold caches, allocator warmup).
    for _ in range(warmup):
        op_a()
        op_b()

    times_a: list[float] = []
    times_b: list[float] = []
    for _ in range(samples):
        # Interleave A then B every iteration so environmental drift is shared.
        t0 = time.perf_counter_ns()
        op_a()
        t1 = time.perf_counter_ns()
        op_b()
        t2 = time.perf_counter_ns()
        times_a.append(float(t1 - t0))
        times_b.append(float(t2 - t1))

    fa = _high_cutoff(times_a, cutoff_pct)
    fb = _high_cutoff(times_b, cutoff_pct)
    t = welch_t(fa, fb)
    return LeakageResult(
        name=name,
        description=description,
        class_a=class_a_label,
        class_b=class_b_label,
        n_per_class=samples,
        n_used_a=len(fa),
        n_used_b=len(fb),
        mean_a_ns=statistics.fmean(fa) if fa else 0.0,
        mean_b_ns=statistics.fmean(fb) if fb else 0.0,
        t=t,
    )


# --------------------------------------------------------------------------- #
# Target 1: ML-KEM decapsulation — valid ciphertext vs invalid (modified)
# ciphertext. This exercises the FO-transform implicit-rejection branch, a
# classic KEM timing-oracle target. We drive the raw kyber-py decaps directly so
# the measured time is the PQ leg alone (no ECDH / AEAD noise).
# --------------------------------------------------------------------------- #
def _prep_mlkem_decaps_valid() -> Callable[[], object]:
    suite = shield.SUITES[shield.DEFAULT_SUITE_ID]
    ek, dk = suite.kem.keygen()
    _ss, ct = suite.kem.encaps(ek)
    valid_ct = bytes(ct)
    decaps = suite.kem.decaps
    return lambda: decaps(dk, valid_ct)


def _prep_mlkem_decaps_invalid() -> Callable[[], object]:
    suite = shield.SUITES[shield.DEFAULT_SUITE_ID]
    ek, dk = suite.kem.keygen()
    _ss, ct = suite.kem.encaps(ek)
    bad = bytearray(ct)
    bad[0] ^= 0xFF  # corrupt -> triggers implicit rejection (K = J(z||c))
    invalid_ct = bytes(bad)
    decaps = suite.kem.decaps
    return lambda: decaps(dk, invalid_ct)


# --------------------------------------------------------------------------- #
# Target 2: shield.decrypt of a valid envelope vs a tampered envelope (AEAD
# reject path). The tampered envelope flips a ciphertext byte so the AES-256-GCM
# tag check fails; the valid one decrypts cleanly. Full Shield path (ECDH +
# ML-KEM decaps + AEAD), so this reflects what an application actually calls.
# --------------------------------------------------------------------------- #
def _prep_shield_decrypt_valid() -> Callable[[], object]:
    pub, priv = shield.generate_recipient_keys(shield.DEFAULT_SUITE_ID)
    env = shield.encrypt(b"vorlath shield constant-time probe payload", pub)
    return lambda: shield.decrypt(env, priv)


def _prep_shield_decrypt_tampered() -> Callable[[], object]:
    pub, priv = shield.generate_recipient_keys(shield.DEFAULT_SUITE_ID)
    env = bytearray(shield.encrypt(b"vorlath shield constant-time probe payload", pub))
    env[-1] ^= 0x01  # corrupt the AEAD tag region -> InvalidTag on open
    bad_env = bytes(env)

    def run() -> object:
        try:
            return shield.decrypt(bad_env, priv)
        except Exception:  # noqa: BLE001 - reject path is the measured behaviour
            return None

    return run


# --------------------------------------------------------------------------- #
# Target 3: ML-DSA sign of two fixed, distinct messages (DETERMINISTIC mode).
# ML-DSA uses rejection sampling: the number of loop iterations until a valid
# signature is found is data-dependent. Deterministic signing removes the
# per-call randomness so the ONLY varying input is the message. We also bind
# BOTH classes to the SAME signing key (built once, below) so the measured
# difference is attributable to the message alone, not to two different keys.
# We drive raw dilithium-py so the time is the PQ signer, not the Shield wrapper.
# --------------------------------------------------------------------------- #
_SIGN_MSG_A = b"\x00" * 32
_SIGN_MSG_B = b"\xa5" * 32
# One shared signing key for both classes (lazy, so import stays cheap/fast).
_SHARED_SIGN_SK: bytes | None = None


def _shared_sign_sk() -> bytes:
    global _SHARED_SIGN_SK
    if _SHARED_SIGN_SK is None:
        _pk, sk = shield.SUITES[shield.DEFAULT_SUITE_ID].sig.keygen()
        _SHARED_SIGN_SK = sk
    return _SHARED_SIGN_SK


def _prep_mldsa_sign_msg_a() -> Callable[[], object]:
    sign = shield.SUITES[shield.DEFAULT_SUITE_ID].sig.sign
    sk = _shared_sign_sk()
    return lambda: sign(sk, _SIGN_MSG_A, b"", True)  # deterministic=True, fixed key


def _prep_mldsa_sign_msg_b() -> Callable[[], object]:
    sign = shield.SUITES[shield.DEFAULT_SUITE_ID].sig.sign
    sk = _shared_sign_sk()
    return lambda: sign(sk, _SIGN_MSG_B, b"", True)  # same key, different message


@dataclass(frozen=True)
class Target:
    name: str
    description: str
    class_a: str
    class_b: str
    prep_a: Callable[[], Callable[[], object]]
    prep_b: Callable[[], Callable[[], object]]


TARGETS: list[Target] = [
    Target(
        name="mlkem_decaps_valid_vs_invalid",
        description="ML-KEM-1024 decapsulation: valid ciphertext vs modified ciphertext "
        "(FO-transform implicit-rejection branch)",
        class_a="valid ciphertext",
        class_b="invalid (1-byte-corrupted) ciphertext",
        prep_a=_prep_mlkem_decaps_valid,
        prep_b=_prep_mlkem_decaps_invalid,
    ),
    Target(
        name="shield_decrypt_valid_vs_tampered",
        description="shield.decrypt: valid envelope vs tampered envelope (AES-256-GCM AEAD reject path)",
        class_a="valid envelope",
        class_b="tampered envelope (flipped tag byte)",
        prep_a=_prep_shield_decrypt_valid,
        prep_b=_prep_shield_decrypt_tampered,
    ),
    Target(
        name="mldsa_sign_two_messages",
        description="ML-DSA-87 deterministic sign: two fixed distinct messages "
        "(rejection-sampling loop count is data-dependent)",
        class_a="message A (0x00*32)",
        class_b="message B (0xa5*32)",
        prep_a=_prep_mldsa_sign_msg_a,
        prep_b=_prep_mldsa_sign_msg_b,
    ),
]


def run_all(
    samples: dict[str, int] | int | None = None,
    warmup: int = DEFAULT_WARMUP,
    cutoff_pct: float = DEFAULT_CUTOFF_PCT,
) -> list[LeakageResult]:
    """Measure every target and return the list of LeakageResults."""
    results: list[LeakageResult] = []
    for tgt in TARGETS:
        if isinstance(samples, int):
            n = samples
        elif isinstance(samples, dict):
            n = samples.get(tgt.name, DEFAULT_SAMPLES[tgt.name])
        else:
            n = DEFAULT_SAMPLES[tgt.name]
        results.append(
            measure_operation(
                name=tgt.name,
                description=tgt.description,
                class_a_label=tgt.class_a,
                class_b_label=tgt.class_b,
                prep_a=tgt.prep_a,
                prep_b=tgt.prep_b,
                samples=n,
                warmup=warmup,
                cutoff_pct=cutoff_pct,
            )
        )
    return results


# ruff: noqa: E501
def _print_report(results: list[LeakageResult]) -> None:
    bar = "=" * 78
    print(bar)
    print("VORLATH Shield — dudect-style leakage measurement (Welch's two-sample t-test)")
    print(f"decision threshold: |t| > {DUDECT_THRESHOLD}  (dudect standard)")
    print(f"machine: {sys.platform} / python {sys.version.split()[0]} / perf_counter_ns")
    print(bar)
    for r in results:
        print(f"\n[{r.name}]")
        print(f"  {r.description}")
        print(f"  class A: {r.class_a}")
        print(f"  class B: {r.class_b}")
        print(f"  N (per class)   : {r.n_per_class}  (after high-cutoff filter: A={r.n_used_a}, B={r.n_used_b})")
        print(f"  mean A          : {r.mean_a_ns / 1000:.3f} us")
        print(f"  mean B          : {r.mean_b_ns / 1000:.3f} us")
        print(f"  |t| statistic   : {abs(r.t):.2f}")
        print(f"  VERDICT         : {r.verdict()}")
    print("\n" + bar)
    leaks = [r.name for r in results if r.detected]
    if leaks:
        print(f"timing dependency DETECTED in: {', '.join(leaks)}")
    else:
        print("no timing dependency detected at this N (NOT a proof of constant-time)")
    print("This harness MEASURES; it does not make the Shield constant-time. See CONSTANT_TIME.md.")
    print(bar)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="dudect-style leakage measurement for VORLATH Shield")
    parser.add_argument(
        "--samples",
        type=int,
        default=None,
        help="override samples-per-class for every target (default: per-target tuned values)",
    )
    parser.add_argument("--warmup", type=int, default=DEFAULT_WARMUP, help="warmup samples to discard")
    parser.add_argument(
        "--cutoff-pct",
        type=float,
        default=DEFAULT_CUTOFF_PCT,
        help="keep the fastest CUTOFF_PCT%% of each class (drop slow OS-scheduling tail)",
    )
    args = parser.parse_args(argv)

    t0 = time.perf_counter()
    results = run_all(samples=args.samples, warmup=args.warmup, cutoff_pct=args.cutoff_pct)
    elapsed = time.perf_counter() - t0
    _print_report(results)
    print(f"total run time: {elapsed:.1f} s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
