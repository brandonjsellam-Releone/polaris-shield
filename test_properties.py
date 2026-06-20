"""Property-based / fuzz tests for the VORLATH Shield core (hypothesis).

These complement the example-based suite in test_shield.py by fuzzing the Shield's
INVARIANTS over wide, randomly-generated inputs:

  (a) round-trip            encrypt(m) -> decrypt == m for arbitrary m (empty/large/binary)
  (b) stream round-trip     seal_stream/open_stream over arbitrary payloads + chunk sizes
  (c) tamper-rejection      flipping ANY single byte of an envelope makes open RAISE
                            (never a silent wrong plaintext)
  (d) parser robustness     decrypt()/open_stream() on ARBITRARY bytes return or raise
                            ValueError -- never an uncaught TypeError/IndexError/struct.error
  (e) cross-suite / wrong-recipient never decrypt

Speed: suite 0x01 (X25519 + ML-KEM-768) is used wherever a suite is needed, examples are
bounded (max_size on payloads), and deadlines are relaxed so keygen jitter never flakes the
run. Recipient keys are generated ONCE at module import and reused, because keygen dominates
the per-example cost; the cryptographic invariants do not depend on a fresh key per example.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from vorlath_shield import shield

# Suite 0x01 = X25519 + ML-KEM-768 + ML-DSA-65 -- the fastest suite; the invariants under
# test are suite-independent, so we fuzz on the cheap one to keep the run well under 20s.
SUITE = 0x01

# Keygen is the expensive operation, not the AEAD; generate every identity ONCE at import and
# reuse it across examples. The cryptographic invariants do not depend on a fresh key per
# example, and keygen would otherwise dominate the run time.
_PUB, _PRIV = shield.generate_recipient_keys(SUITE)
_PUB_OTHER, _PRIV_OTHER = shield.generate_recipient_keys(SUITE)   # independent recipient B
_PUB2, _PRIV2 = shield.generate_recipient_keys(0x02)              # other-suite recipient
_SIG_PK, _SIG_SK = shield.generate_signing_keys(SUITE)            # the legitimate sender
_WRONG_SIG = shield.generate_signing_keys(SUITE)                  # a different sender

# Shared, fast settings: relaxed deadline (keygen/AEAD timing varies on CI) and a modest
# example budget so the whole module stays fast. function_scoped_fixture check is irrelevant
# here (no fixtures) but we silence the data-generation health check for the large-payload case.
_FAST = settings(
    max_examples=60,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)

# ML-DSA sign+verify costs tens of ms per example; the authenticated-mode properties get a
# smaller budget so the whole module stays comfortably under the ~20s target while still
# fuzzing the sender binding over many random plaintexts.
_SLOW_SIG = settings(
    max_examples=20,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)

# Bounded byte payloads: small_payloads exercises the empty/tiny boundary heavily; payloads
# adds the occasional larger blob (a few KB) without making the suite slow.
small_payloads = st.binary(min_size=0, max_size=256)
payloads = st.binary(min_size=0, max_size=8192)


# ----------------------------------------------------------------- (a) single-shot round-trip
@_FAST
@given(msg=payloads)
def test_roundtrip_arbitrary_message(msg):
    """encrypt then decrypt returns the exact plaintext for arbitrary bytes."""
    env = shield.encrypt(msg, _PUB)
    assert shield.decrypt(env, _PRIV) == msg


@_SLOW_SIG
@given(msg=small_payloads)
def test_roundtrip_authenticated_arbitrary_message(msg):
    """Authenticated round-trip preserves the plaintext and the sender binding holds."""
    env = shield.encrypt_authenticated(msg, _PUB, _SIG_SK, _SIG_PK)
    assert shield.decrypt_authenticated(env, _PRIV, _SIG_PK) == msg
    assert shield.decrypt(env, _PRIV) == msg  # anonymous open still works


# ----------------------------------------------------------------- (b) stream round-trip
@_FAST
@given(msg=payloads, chunk_size=st.integers(min_value=1, max_value=4096))
def test_stream_roundtrip_arbitrary_payload_and_chunk(msg, chunk_size):
    """seal_stream/open_stream is loss-less for arbitrary payloads and any valid chunk size."""
    env = shield.seal_stream(msg, _PUB, chunk_size=chunk_size)
    assert shield.open_stream(env, _PRIV) == msg


# ----------------------------------------------------------------- (c) tamper-rejection
def _flip(buf: bytes, index: int, mask: int) -> bytes:
    b = bytearray(buf)
    b[index] ^= mask
    return bytes(b)


@_FAST
@given(
    msg=small_payloads,
    flip_frac=st.floats(min_value=0.0, max_value=1.0),
    mask=st.integers(min_value=1, max_value=255),
)
def test_single_byte_flip_never_silently_decrypts(msg, flip_frac, mask):
    """Flipping ANY single byte of an envelope makes decrypt RAISE -- never a wrong plaintext.

    The byte index is chosen from a fraction so hypothesis explores the whole envelope:
    magic, version, suite_id, flags, every TLV length/value, the length prefix, and the
    sealed ciphertext+tag. A flip must either be rejected structurally (ValueError) or by the
    AEAD (InvalidTag); it must NEVER yield the original (or any) plaintext.
    """
    env = shield.encrypt(msg, _PUB)
    index = min(len(env) - 1, int(flip_frac * len(env)))
    tampered = _flip(env, index, mask)
    try:
        out = shield.decrypt(tampered, _PRIV)
    except Exception:
        return  # any raise satisfies the invariant
    # Reached only if decrypt returned -- which must be impossible for a real bit-flip.
    raise AssertionError(
        f"single-byte flip at index {index} (mask {mask:#04x}) decrypted silently to {out!r}"
    )


@_FAST
@given(
    msg=small_payloads,
    flip_frac=st.floats(min_value=0.0, max_value=1.0),
    mask=st.integers(min_value=1, max_value=255),
)
def test_stream_single_byte_flip_never_silently_decrypts(msg, flip_frac, mask):
    """Same tamper invariant for the streaming construction."""
    env = shield.seal_stream(msg, _PUB, chunk_size=64)
    index = min(len(env) - 1, int(flip_frac * len(env)))
    tampered = _flip(env, index, mask)
    try:
        out = shield.open_stream(tampered, _PRIV)
    except Exception:
        return
    raise AssertionError(
        f"stream single-byte flip at index {index} (mask {mask:#04x}) opened silently to {out!r}"
    )


# ----------------------------------------------------------------- (d) parser robustness
# The documented contract (see shield.decrypt / open_stream and
# test_malformed_envelopes_raise_valueerror) is: malformed input raises ValueError -- never an
# uncaught TypeError / IndexError / struct.error, and never a hang. Random bytes cannot reach
# the AEAD (the 32-byte recipient key-id would have to match by chance), so on this corpus the
# only acceptable outcomes are a clean return (vanishingly unlikely) or ValueError.
_UNCAUGHT = (TypeError, IndexError, struct.error, KeyError, AttributeError, OverflowError)

# Arbitrary bytes, plus bytes that start with the right magic so the fuzzer gets PAST the magic
# check and exercises the TLV / length-prefix parser deeply.
arbitrary_bytes = st.binary(min_size=0, max_size=512)
plsh_prefixed = st.builds(lambda tail: b"VRSH" + tail, st.binary(min_size=0, max_size=512))
plst_prefixed = st.builds(lambda tail: b"VRST" + tail, st.binary(min_size=0, max_size=512))


@_FAST
@given(blob=st.one_of(arbitrary_bytes, plsh_prefixed))
def test_decrypt_arbitrary_bytes_never_crashes(blob):
    """decrypt() on arbitrary bytes returns or raises ValueError -- no uncaught crash, no hang."""
    try:
        shield.decrypt(blob, _PRIV)
    except ValueError:
        pass
    except _UNCAUGHT as e:  # pragma: no cover - this firing IS the bug we are hunting
        raise AssertionError(f"decrypt leaked an uncaught {type(e).__name__}: {e}") from e


@_FAST
@given(blob=st.one_of(arbitrary_bytes, plst_prefixed))
def test_open_stream_arbitrary_bytes_never_crashes(blob):
    """open_stream() on arbitrary bytes returns or raises ValueError -- no uncaught crash, no hang."""
    try:
        shield.open_stream(blob, _PRIV)
    except ValueError:
        pass
    except _UNCAUGHT as e:  # pragma: no cover - this firing IS the bug we are hunting
        raise AssertionError(f"open_stream leaked an uncaught {type(e).__name__}: {e}") from e


@_FAST
@given(blob=st.one_of(arbitrary_bytes, plsh_prefixed))
def test_decrypt_grafted_real_envelope_never_crashes(blob):
    """A real envelope with arbitrary trailing/middle corruption still parses safely.

    We graft random bytes onto a genuine header so the parser walks real TLV lengths against a
    corrupted body -- the classic place a length/offset bug would surface as IndexError. Only
    the uncaught parser-crash types are forbidden; ValueError and InvalidTag are both fine.
    """
    real = shield.encrypt(b"anchor", _PUB)
    spliced = real[: len(real) // 2] + blob
    try:
        shield.decrypt(spliced, _PRIV)
    except _UNCAUGHT as e:  # pragma: no cover
        raise AssertionError(f"decrypt leaked an uncaught {type(e).__name__}: {e}") from e
    except Exception:
        pass  # ValueError / InvalidTag are acceptable outcomes


@_FAST
@given(
    head_frac=st.floats(min_value=0.0, max_value=1.0),
    tail=st.binary(min_size=0, max_size=256),
)
def test_decrypt_prefix_of_real_envelope_is_clean(head_frac, tail):
    """Any prefix of a real envelope, optionally extended with junk, must not crash uncaught."""
    real = shield.encrypt(b"anchor", _PUB)
    cut = int(head_frac * len(real))
    blob = real[:cut] + tail
    try:
        shield.decrypt(blob, _PRIV)
    except ValueError:
        pass
    except _UNCAUGHT as e:  # pragma: no cover
        raise AssertionError(f"decrypt leaked an uncaught {type(e).__name__}: {e}") from e
    except Exception:
        pass  # InvalidTag etc. are acceptable; only the parser-crash types are forbidden


# ----------------------------------------------------------------- (e) wrong recipient / cross-suite
@_FAST
@given(msg=small_payloads)
def test_wrong_recipient_never_decrypts(msg):
    """An envelope sealed to recipient A is never opened by an independent recipient B."""
    env = shield.encrypt(msg, _PUB)
    try:
        out = shield.decrypt(env, _PRIV_OTHER)
    except Exception:
        return
    raise AssertionError(f"wrong recipient decrypted to {out!r}")


@_FAST
@given(msg=small_payloads)
def test_stream_wrong_recipient_never_decrypts(msg):
    """Same wrong-recipient invariant for the streaming construction."""
    env = shield.seal_stream(msg, _PUB, chunk_size=128)
    try:
        out = shield.open_stream(env, _PRIV_OTHER)
    except Exception:
        return
    raise AssertionError(f"wrong recipient opened stream to {out!r}")


@_FAST
@given(msg=small_payloads)
def test_cross_suite_never_decrypts(msg):
    """A suite-0x02 envelope must never open under a suite-0x01 key (and vice versa)."""
    env2 = shield.encrypt(msg, _PUB2)
    try:
        out = shield.decrypt(env2, _PRIV)  # _PRIV is suite 0x01
    except Exception:
        return
    raise AssertionError(f"cross-suite envelope decrypted to {out!r}")


@_SLOW_SIG
@given(msg=small_payloads)
def test_wrong_expected_sender_never_decrypts(msg):
    """An authenticated envelope must not open when a DIFFERENT sender is required."""
    env = shield.encrypt_authenticated(msg, _PUB, _SIG_SK, _SIG_PK)
    wrong_pk, _ = _WRONG_SIG
    try:
        out = shield.decrypt_authenticated(env, _PRIV, wrong_pk)
    except Exception:
        return
    raise AssertionError(f"wrong expected-sender decrypted to {out!r}")
