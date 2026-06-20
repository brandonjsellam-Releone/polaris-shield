"""Smoke test for the side-channel measurement harness.

IMPORTANT: this test deliberately makes NO timing/constant-time assertion and is
NOT threshold-gated. Wall-clock timing is environment-dependent and a |t|-gated
assertion would be flaky in CI. We only confirm the harness imports and runs a
tiny measurement, producing well-formed LeakageResult objects. The real measured
numbers live in CONSTANT_TIME.md, produced by running the harness directly.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sidechannel import ct_measure  # noqa: E402


def test_welch_t_basic():
    # Identical distributions -> ~0; clearly separated -> large |t|. Pure math,
    # no timing involved, so this IS safe to assert.
    same = [10.0] * 50
    assert ct_measure.welch_t(same, [10.0] * 50) == 0.0
    a = [1.0, 1.1, 0.9, 1.0, 1.05, 0.95] * 5
    b = [5.0, 5.1, 4.9, 5.0, 5.05, 4.95] * 5
    assert abs(ct_measure.welch_t(a, b)) > 4.5


def test_high_cutoff_drops_slow_tail():
    # 5% slow outliers, keep the fastest 90%: the slow tail must be dropped.
    samples = [1.0] * 95 + [1000.0] * 5
    kept = ct_measure._high_cutoff(samples, 90.0)
    assert max(kept) <= 1.0  # every 1000.0 outlier removed
    assert len(kept) == 95


def test_harness_runs_tiny_measurement():
    # A handful of samples per class with no warmup: just prove it executes end to
    # end and returns a well-formed result. NO assertion about |t| magnitude.
    results = ct_measure.run_all(samples=3, warmup=0)
    assert len(results) == len(ct_measure.TARGETS)
    for r in results:
        assert isinstance(r, ct_measure.LeakageResult)
        assert r.n_per_class == 3
        assert r.mean_a_ns >= 0.0
        assert r.mean_b_ns >= 0.0
        # verdict() always renders one of the two strings; we don't assert which.
        assert "|t|=" in r.verdict()


def test_targets_have_two_distinct_classes():
    for tgt in ct_measure.TARGETS:
        assert tgt.class_a != tgt.class_b
        assert callable(tgt.prep_a)
        assert callable(tgt.prep_b)
