"""Tests for the opt-in high-assurance (FIPS 205 SLH-DSA) signatures.

Kept in a separate file because SLH-DSA signing is deliberately slow (seconds); these
do not bloat the fast core suite. Uses the faster 128s param where the test only needs
the round-trip logic. Run: cd tech && python -m pytest -q test_highassurance.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pytest

from vorlath_shield import highassurance as ha
from vorlath_shield import shield

FAST = 0x02  # SLH-DSA-SHAKE-128s


def test_slh_dsa_roundtrip():
    pub, priv = ha.generate_high_assurance_keys(FAST)
    msg = b"VORLATH long-lived evidence root"
    sig = ha.high_assurance_sign(priv, msg)
    assert ha.high_assurance_verify(pub, msg, sig)
    assert not ha.high_assurance_verify(pub, b"forged", sig)


def test_slh_dsa_context_separation():
    pub, priv = ha.generate_high_assurance_keys(FAST)
    sig = ha.high_assurance_sign(priv, b"m", ctx=b"ctx-A")
    assert not ha.high_assurance_verify(pub, b"m", sig, ctx=b"ctx-B")


def test_slh_dsa_wrong_key_rejected():
    pub, _ = ha.generate_high_assurance_keys(FAST)
    _, other = ha.generate_high_assurance_keys(FAST)
    sig = ha.high_assurance_sign(other, b"m")
    assert not ha.high_assurance_verify(pub, b"m", sig)


def test_dual_signature_requires_both():
    mpub, mpriv = shield.generate_signing_keys()          # ML-DSA (lattice)
    hpub, hpriv = ha.generate_high_assurance_keys(FAST)   # SLH-DSA (hash-based)
    msg = b"dual-signed release manifest"
    dsig = ha.dual_sign(mpriv, hpriv, msg)
    assert ha.dual_verify(mpub, hpub, msg, dsig)
    # tampering the message breaks it
    assert not ha.dual_verify(mpub, hpub, b"tampered", dsig)
    # a wrong ML-DSA key (one leg) fails the whole dual
    wpub, _ = shield.generate_signing_keys()
    assert not ha.dual_verify(wpub, hpub, msg, dsig)
    # a wrong SLH-DSA key (other leg) fails the whole dual
    whpub, _ = ha.generate_high_assurance_keys(FAST)
    assert not ha.dual_verify(mpub, whpub, msg, dsig)


@pytest.mark.parametrize("pid", [0x01, 0x02])
def test_param_sets_present(pid):
    pub, _ = ha.generate_high_assurance_keys(pid)
    assert "FIPS 205" in ha.ha_param_name(pub)


def test_dual_verify_rejects_malformed_blobs():
    # dual_verify must return False (never crash) on attacker-supplied garbage. Fast: no signing.
    mpub, _ = shield.generate_signing_keys()
    hpub, _ = ha.generate_high_assurance_keys(FAST)
    for bad in [b"", b"PLDU", b"XXXX",
                b"PLDU" + b"\xff\xff\xff\xff" + b"\x00" * 4,            # lying inner length
                b"PLDU" + (0).to_bytes(4, "big") + b"\xff\xff\xff\xff"]:
        assert ha.dual_verify(mpub, hpub, b"m", bad) is False


def test_dual_verify_rejects_single_leg_tamper():
    # Flipping one byte of the (SLH-DSA) leg must fail the whole dual signature.
    mpub, mpriv = shield.generate_signing_keys()
    hpub, hpriv = ha.generate_high_assurance_keys(FAST)
    dsig = bytearray(ha.dual_sign(mpriv, hpriv, b"m"))
    dsig[-1] ^= 0x01
    assert ha.dual_verify(mpub, hpub, b"m", bytes(dsig)) is False
