"""Tests for the at-rest private-key protection (scrypt n=2^17 -> AES-256-GCM).

The CLI's _wrap_private / _maybe_unwrap are the only confidentiality control for
private keys on disk; this pins their round-trip, wrong-passphrase, and tamper behaviour.
Run: cd tech && python -m pytest -q test_keywrap.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pytest

from polaris_shield import __main__ as cli


def test_keywrap_roundtrip():
    bundle = os.urandom(200)
    wrapped = cli._wrap_private(bundle, "correct horse battery staple")
    assert wrapped[:4] == cli._WRAP_MAGIC
    assert wrapped != bundle
    assert cli._maybe_unwrap(wrapped, "correct horse battery staple") == bundle


def test_keywrap_wrong_passphrase_rejected():
    wrapped = cli._wrap_private(os.urandom(200), "right")
    with pytest.raises(Exception):          # AES-256-GCM InvalidTag
        cli._maybe_unwrap(wrapped, "wrong")


def test_keywrap_tamper_rejected():
    wrapped = bytearray(cli._wrap_private(os.urandom(200), "pw"))
    wrapped[-1] ^= 0x01
    with pytest.raises(Exception):          # InvalidTag (_WRAP_MAGIC bound as AAD)
        cli._maybe_unwrap(bytes(wrapped), "pw")


def test_unwrapped_passthrough():
    # _maybe_unwrap returns non-wrapped data unchanged (no magic prefix).
    plain = os.urandom(64)
    assert cli._maybe_unwrap(plain, "ignored") == plain


def test_scrypt_cost_is_apex():
    # The keygen banner must not understate the work factor (was a stale n=2^15 label).
    assert cli._SCRYPT_N == 2 ** 17
