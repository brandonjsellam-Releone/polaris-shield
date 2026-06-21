"""Functional + negative tests for the VORLATH Shield v2 core.
Run: cd tech && python -m pytest -q   (KAT conformance lives in tests/test_kats.py)
"""
import os
import struct as _struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pytest

from vorlath_shield import shield

SUITES = [0x01, 0x02, 0x03]   # 0x03 = CNSA-2.0 pure-PQC (no classical leg)


@pytest.mark.parametrize("suite", SUITES)
def test_hybrid_roundtrip(suite):
    pub, priv = shield.generate_recipient_keys(suite)
    msg = os.urandom(4096)
    env = shield.encrypt(msg, pub)
    assert env[:4] == b"VRSH"
    assert env[5] == suite
    assert shield.decrypt(env, priv) == msg


@pytest.mark.parametrize("suite", SUITES)
def test_wrong_recipient_fails(suite):
    pub, _ = shield.generate_recipient_keys(suite)
    _, priv_other = shield.generate_recipient_keys(suite)
    env = shield.encrypt(b"classified", pub)
    with pytest.raises(Exception):
        shield.decrypt(env, priv_other)


@pytest.mark.parametrize("suite", SUITES)
def test_tamper_is_detected(suite):
    pub, priv = shield.generate_recipient_keys(suite)
    env = bytearray(shield.encrypt(b"hello world", pub))
    env[-1] ^= 0x01
    with pytest.raises(ValueError):   # every reject path raises ValueError per the decrypt() contract
        shield.decrypt(bytes(env), priv)


@pytest.mark.parametrize("suite", SUITES)
def test_hybrid_binds_the_pq_ciphertext(suite):
    # Corrupting ANY byte of the ML-KEM ciphertext region must break decryption,
    # proving the post-quantum secret is load-bearing (not decorative).
    pub, priv = shield.generate_recipient_keys(suite)
    base = shield.encrypt(b"secret payload", pub)
    s = shield.SUITES[suite]
    # locate the kem_ct TLV: header = MAGIC(4)+ver/suite/flags(3) then TLVs
    # key_id(16), eph_pub, kem_ct ...
    import struct
    off = 7
    for _ in range(2):  # skip key_id and eph_pub
        (n,) = struct.unpack_from(">H", base, off); off += 2 + n
    (ctn,) = struct.unpack_from(">H", base, off); ct_start = off + 2
    assert ctn == s.kem_ct_len
    for i in (0, ctn // 2, ctn - 1):
        env = bytearray(base); env[ct_start + i] ^= 0xFF
        with pytest.raises(Exception):
            shield.decrypt(bytes(env), priv)


@pytest.mark.parametrize("suite", SUITES)
def test_downgrade_suite_id_is_rejected(suite):
    pub, priv = shield.generate_recipient_keys(suite)
    env = bytearray(shield.encrypt(b"x", pub))
    env[5] ^= 0x03  # flip the bound suite_id
    with pytest.raises(Exception):
        shield.decrypt(bytes(env), priv)


@pytest.mark.parametrize("suite", SUITES)
def test_authenticated_handshake(suite):
    pub, priv = shield.generate_recipient_keys(suite)
    spk, ssk = shield.generate_signing_keys(suite)
    env = shield.encrypt_authenticated(b"orders", pub, ssk, spk)
    assert shield.decrypt_authenticated(env, priv, spk) == b"orders"
    # anonymous decrypt of an authenticated envelope still works (no expectation)
    assert shield.decrypt(env, priv) == b"orders"


@pytest.mark.parametrize("suite", SUITES)
def test_wrong_sender_is_rejected(suite):
    pub, priv = shield.generate_recipient_keys(suite)
    spk, ssk = shield.generate_signing_keys(suite)
    wpk, _ = shield.generate_signing_keys(suite)
    env = shield.encrypt_authenticated(b"orders", pub, ssk, spk)
    with pytest.raises(Exception):
        shield.decrypt_authenticated(env, priv, wpk)


@pytest.mark.parametrize("suite", SUITES)
def test_expected_sender_but_anonymous_is_rejected(suite):
    pub, priv = shield.generate_recipient_keys(suite)
    spk, _ = shield.generate_signing_keys(suite)
    env = shield.encrypt(b"anon", pub)  # no sender identity
    with pytest.raises(Exception):
        shield.decrypt(env, priv, expected_sender_public=spk)


@pytest.mark.parametrize("suite", SUITES)
def test_signatures_with_context(suite):
    pk, sk = shield.generate_signing_keys(suite)
    m = b"VORLATH evidence record"
    sig = shield.sign(sk, m)
    assert shield.verify(pk, m, sig)
    assert not shield.verify(pk, b"forged record", sig)
    # context separation: a signature made under SIG_CTX must not verify under AUTH_CTX
    assert not shield.verify(pk, m, sig, ctx=shield.AUTH_CTX)


@pytest.mark.parametrize("suite", SUITES)
def test_classical_only_is_distinct_and_smaller(suite):
    pub, _ = shield.generate_recipient_keys(suite)
    if getattr(shield.SUITES[suite].ecdh, "is_null", False):
        # pure-PQC suite (0x03): there is no classical leg, so a classical-only seal is
        # undefined and must be refused rather than silently producing an empty-secret key.
        with pytest.raises(ValueError):
            shield.encrypt_classical_only(b"x", pub)
        return
    classical = shield.encrypt_classical_only(b"x", pub)
    hybrid = shield.encrypt(b"x", pub)
    assert classical[:4] == b"X25O" and hybrid[:4] == b"VRSH"
    assert len(hybrid) - len(classical) > 1000  # the ML-KEM ciphertext (1088/1568 B)


def test_ppk_rfc8784_third_leg():
    # An out-of-band pre-shared key (RFC 8784-style) mixes into the combiner as a third leg,
    # flag-bound so it is downgrade-resistant and backward-compatible when absent.
    pub, priv = shield.generate_recipient_keys(0x02)
    ppk = b"\x11" * 32
    env = shield.encrypt(b"belt and suspenders", pub, ppk=ppk)
    assert env[6] & shield.FLAG_PPK                       # presence bound in the header
    assert shield.decrypt(env, priv, ppk=ppk) == b"belt and suspenders"
    with pytest.raises(Exception):                        # wrong PPK -> different key -> AEAD reject
        shield.decrypt(env, priv, ppk=b"\x22" * 32)
    with pytest.raises(ValueError):                       # PPK-bound envelope, no PPK supplied
        shield.decrypt(env, priv)
    # a non-PPK envelope ignores any supplied PPK (back-compat) and still opens
    env2 = shield.encrypt(b"no ppk", pub)
    assert not (env2[6] & shield.FLAG_PPK)
    assert shield.decrypt(env2, priv, ppk=b"\x33" * 32) == b"no ppk"


def test_ppk_combines_with_authentication_and_pure_pqc():
    # PPK is orthogonal: it composes with authenticated mode AND the pure-PQC suite 0x03.
    pub, priv = shield.generate_recipient_keys(0x03)
    spk, ssk = shield.generate_signing_keys(0x03)
    ppk = b"\xAB" * 32
    env = shield.encrypt_authenticated(b"signed+ppk", pub, ssk, spk, ppk=ppk)
    assert (env[6] & shield.FLAG_PPK) and (env[6] & shield.FLAG_AUTHENTICATED)
    assert shield.decrypt_authenticated(env, priv, spk, ppk=ppk) == b"signed+ppk"
    with pytest.raises(Exception):
        shield.decrypt_authenticated(env, priv, spk, ppk=b"\x00" * 32)


def test_pure_pqc_suite_0x03_roundtrip_and_no_classical():
    # suite 0x03 is CNSA-2.0 pure-PQC: round-trip (anonymous + authenticated) works, the
    # suite_id is bound in the header, classical-only is refused, and the public bundle is
    # materially smaller than the hybrid 0x02 bundle (it carries no classical public key).
    pub, priv = shield.generate_recipient_keys(0x03)
    env = shield.encrypt(b"pure-pqc secret", pub)
    assert env[:4] == b"VRSH" and env[5] == 0x03
    assert shield.decrypt(env, priv) == b"pure-pqc secret"
    spk, ssk = shield.generate_signing_keys(0x03)
    aenv = shield.encrypt_authenticated(b"signed", pub, ssk, spk)
    assert shield.decrypt_authenticated(aenv, priv, spk) == b"signed"
    with pytest.raises(ValueError):
        shield.encrypt_classical_only(b"x", pub)
    pub2, _ = shield.generate_recipient_keys(0x02)
    assert len(pub) < len(pub2)   # no 56-byte X448 public in the pure-PQC bundle


def test_key_id_is_stable_and_bound():
    pub, priv = shield.generate_recipient_keys()
    assert shield.kem_key_id(pub) == shield.kem_key_id(pub)
    assert len(shield.kem_key_id(pub)) == 32  # 256-bit fingerprint at the apex tier
    env = shield.encrypt(b"x", pub)
    assert shield.kem_key_id(pub) in env  # recipient key-id is carried in the header


def test_malformed_envelopes_raise_valueerror():
    pub, priv = shield.generate_recipient_keys()
    for bad in [b"", b"VRSH", b"XXXX" + b"\x02" * 40,
                shield.encrypt(b"x", pub)[:20],  # truncated mid-header
                12345, None]:                    # non-bytes: documented ValueError, not TypeError
        with pytest.raises(ValueError):
            shield.decrypt(bad, priv)


def test_malformed_streams_raise_valueerror():
    pub, priv = shield.generate_recipient_keys()
    good = shield.seal_stream(b"x", pub)
    for bad in [b"", b"VRST", b"XXXX" + b"\x02" * 40,
                good[:20], good[:-1],   # truncated header / dropped trailing byte
                12345, None]:           # non-bytes: documented ValueError, not TypeError
        with pytest.raises(ValueError):
            shield.open_stream(bad, priv)


def test_default_suite_is_apex():
    assert shield.DEFAULT_SUITE_ID == 0x02
    pub, _ = shield.generate_recipient_keys()
    assert pub[5] == 0x02  # X448 + ML-KEM-1024 + ML-DSA-87


# ----------------------------------------------------------------- streaming AEAD
@pytest.mark.parametrize("suite", SUITES)
def test_stream_roundtrip_multichunk(suite):
    pub, priv = shield.generate_recipient_keys(suite)
    msg = os.urandom(64 * 1024 * 3 + 1234)   # several chunks + a partial
    env = shield.seal_stream(msg, pub, chunk_size=64 * 1024)
    assert env[:4] == b"VRST"
    assert shield.open_stream(env, priv) == msg


@pytest.mark.parametrize("payload", [b"", b"x", b"small payload"])
def test_stream_roundtrip_small(payload):
    pub, priv = shield.generate_recipient_keys()
    assert shield.open_stream(shield.seal_stream(payload, pub), priv) == payload


def test_stream_truncation_is_rejected():
    # dropping the final chunk must fail (the new last chunk was sealed as non-final)
    pub, priv = shield.generate_recipient_keys()
    msg = os.urandom(4096 * 5)
    env = bytearray(shield.seal_stream(msg, pub, chunk_size=4096))
    import struct
    # walk to the body and drop the last chunk blob
    # header end: find by re-parsing is complex; instead drop a trailing chunk by length
    # easier: re-seal and strip the last (4-byte len + blob)
    env = shield.seal_stream(msg, pub, chunk_size=4096)
    # locate last chunk: scan blobs from the body. Reuse a simple strip of the final framed chunk.
    # Find body start: header has MAGIC(4)+3 + tlv(kid)+tlv(eph)+tlv(ct)+tlv(nonce)+u32
    off = 7
    for _ in range(4):
        (n,) = struct.unpack_from(">H", env, off); off += 2 + n
    off += 4  # chunk_size
    # walk chunks, remember last start
    last_start = off
    while off < len(env):
        (clen,) = struct.unpack_from(">I", env, off); last_start = off; off += 4 + clen
    truncated = env[:last_start]
    with pytest.raises(Exception):
        shield.open_stream(truncated, priv)


def test_stream_tamper_is_rejected():
    pub, priv = shield.generate_recipient_keys()
    env = bytearray(shield.seal_stream(os.urandom(4096 * 4), pub, chunk_size=4096))
    env[-1] ^= 0x01
    with pytest.raises(ValueError):   # tampered stream rejects as ValueError per the open_stream() contract
        shield.open_stream(bytes(env), priv)


def test_stream_wrong_recipient_is_rejected():
    pub, _ = shield.generate_recipient_keys()
    _, other = shield.generate_recipient_keys()
    env = shield.seal_stream(b"classified bulk", pub)
    with pytest.raises(Exception):
        shield.open_stream(env, other)


# ----------------------------------------------------------------- positional / reorder binding
def _stream_parts(env):
    """Split a VRST envelope into (header, [chunk_blobs])."""
    off = 7
    for _ in range(4):  # key_id, eph_pub, kem_ct, base_nonce
        (n,) = _struct.unpack_from(">H", env, off); off += 2 + n
    off += 4  # chunk_size
    head = env[:off]
    blobs = []
    while off < len(env):
        (clen,) = _struct.unpack_from(">I", env, off); off += 4
        blobs.append(env[off:off + clen]); off += clen
    return head, blobs


def _reassemble(head, blobs):
    out = bytearray(head)
    for b in blobs:
        out += _struct.pack(">I", len(b)) + b
    return bytes(out)


def test_stream_reorder_is_rejected():
    # Swapping two interior chunks must fail: the chunk index is bound into the nonce + AAD.
    pub, priv = shield.generate_recipient_keys()
    env = shield.seal_stream(os.urandom(4096 * 4), pub, chunk_size=4096)
    head, blobs = _stream_parts(env)
    blobs[0], blobs[1] = blobs[1], blobs[0]
    with pytest.raises(Exception):
        shield.open_stream(_reassemble(head, blobs), priv)


def test_stream_extension_is_rejected():
    # Appending/duplicating a chunk past the sealed final chunk must fail.
    pub, priv = shield.generate_recipient_keys()
    env = shield.seal_stream(os.urandom(4096 * 4), pub, chunk_size=4096)
    head, blobs = _stream_parts(env)
    blobs.append(blobs[-1])
    with pytest.raises(Exception):
        shield.open_stream(_reassemble(head, blobs), priv)


# ----------------------------------------------------------------- auth-strip / transplant (UKS)
@pytest.mark.parametrize("suite", SUITES)
def test_auth_strip_is_rejected(suite):
    # Clearing the AUTHENTICATED flag on the wire must fail: flags is in the AAD + KDF.
    pub, priv = shield.generate_recipient_keys(suite)
    spk, ssk = shield.generate_signing_keys(suite)
    env = bytearray(shield.encrypt_authenticated(b"orders", pub, ssk, spk))
    assert env[6] == shield.FLAG_AUTHENTICATED
    env[6] = 0
    with pytest.raises(Exception):
        shield.decrypt(bytes(env), priv)


@pytest.mark.parametrize("suite", SUITES)
def test_sender_block_transplant_is_rejected(suite):
    # Splicing a different sender's sender_block into an envelope must fail (it is in the AAD).
    pub, priv = shield.generate_recipient_keys(suite)
    spkA, sskA = shield.generate_signing_keys(suite)
    spkB, sskB = shield.generate_signing_keys(suite)
    envA = shield.encrypt_authenticated(b"orders", pub, sskA, spkA)
    envB = shield.encrypt_authenticated(b"orders", pub, sskB, spkB)

    def sb_span(env):
        off = 7
        for _ in range(4):
            (n,) = _struct.unpack_from(">H", env, off); off += 2 + n
        (n,) = _struct.unpack_from(">H", env, off)
        return off, off + 2 + n

    a0, a1 = sb_span(envA)
    b0, b1 = sb_span(envB)
    spliced = envA[:a0] + envB[b0:b1] + envA[a1:]
    with pytest.raises(Exception):
        shield.decrypt(spliced, priv)


# ----------------------------------------------------------------- suite / construction separation
def test_cross_suite_envelope_is_rejected():
    # An envelope sealed under suite 0x02 must not open with a 0x01 private key (and vice versa).
    pub1, priv1 = shield.generate_recipient_keys(0x01)
    pub2, priv2 = shield.generate_recipient_keys(0x02)
    with pytest.raises(ValueError, match="suite"):
        shield.decrypt(shield.encrypt(b"secret", pub2), priv1)
    with pytest.raises(ValueError, match="suite"):
        shield.open_stream(shield.seal_stream(b"secret", pub2), priv1)


def test_cross_construction_is_rejected():
    # A single-shot (VRSH) envelope must not open as a stream (VRST), and vice versa.
    pub, priv = shield.generate_recipient_keys()
    env = shield.encrypt(b"x", pub)
    st = shield.seal_stream(b"x", pub)
    with pytest.raises(Exception):
        shield.open_stream(env, priv)
    with pytest.raises(Exception):
        shield.decrypt(st, priv)


@pytest.mark.parametrize("suite", SUITES)
def test_authenticated_recipient_binding(suite):
    # An authenticated envelope sealed to recipient A must not open with recipient B's key.
    pubA, privA = shield.generate_recipient_keys(suite)
    pubB, privB = shield.generate_recipient_keys(suite)
    spk, ssk = shield.generate_signing_keys(suite)
    env = shield.encrypt_authenticated(b"orders", pubA, ssk, spk)
    with pytest.raises(Exception):
        shield.decrypt_authenticated(env, privB, spk)


def test_replay_is_accepted_by_design():
    # Documents (does not enforce): a one-shot envelope is replayable; freshness is an
    # application-layer responsibility. See THREAT_MODEL.md residual-risks.
    pub, priv = shield.generate_recipient_keys()
    env = shield.encrypt(b"x", pub)
    assert shield.decrypt(env, priv) == shield.decrypt(env, priv) == b"x"
