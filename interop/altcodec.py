"""altcodec — an INDEPENDENT decoder for the VORLATH Shield ``VRSH`` envelope.

This module is written **only from the wire-format specification** in
``tech/FORMAT.md``. It deliberately does **not** import ``vorlath_shield``'s
envelope, combiner, KDF, or key-bundle code: the whole point is to cross-validate
the spec with a second, separately-coded parsing + combiner + KDF + AEAD-open path
(which shares the same primitive libraries — see below). The cross-check proves
independence at the FORMAT / TLV-parse / combiner / KDF-transcript / AEAD-orchestration
layer over those SHARED primitive libs and the same spec author; it does **not**
cross-validate the ML-KEM / ML-DSA / AES-GCM primitives themselves, and it cannot
catch a spec misreading shared by both implementations.

What it reuses (allowed): the same underlying *primitive* libraries the reference
uses — ``kyber-py`` (ML-KEM decapsulation), ``dilithium-py`` (ML-DSA verify), and
``cryptography`` (X25519/X448 ECDH, HKDF, AES-256-GCM). Re-implementing lattice
math from scratch is out of scope; re-implementing the *format* is the point.

Scope: decode-only of the single-shot ``VRSH`` envelope (anonymous and
authenticated) for both suites 0x01 and 0x02. Streaming (``VRST``) decode is a
bonus and is provided as ``open_stream`` below. Everything is derived from the
sections of FORMAT.md cited inline.

Honest framing: this is a project convention, not a standardized protocol; the
primitive libraries are reference implementations, not FIPS-validated modules.
"""
from __future__ import annotations

import hashlib
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from dilithium_py.ml_dsa import ML_DSA_65, ML_DSA_87
from kyber_py.ml_kem import ML_KEM_768, ML_KEM_1024

# --------------------------------------------------------------------------- #
# Constants — every value is transcribed from FORMAT.md (section cited).
# --------------------------------------------------------------------------- #
_MAGIC = b"VRSH"            # FORMAT.md §2.2 / §9
_STREAM_MAGIC = b"VRST"     # FORMAT.md §4.1 / §9
_KEY_MAGIC = b"VRSK"        # FORMAT.md §5
_VERSION = 0x02             # FORMAT.md §2.2 (VERSION = 2)
_KEY_VERSION = 0x02         # FORMAT.md §5
_NONCE_LEN = 12             # FORMAT.md §2.3 (NONCE = 12)
_KEY_ID_LEN = 32            # FORMAT.md §5.2 (KEY_ID_LEN = 32, SHAKE-256/256-bit)
_FLAG_AUTHENTICATED = 0x01  # FORMAT.md §2.2

# Key-bundle roles — FORMAT.md §5.1
_ROLE_KEM_PUB = 1
_ROLE_KEM_PRIV = 2
_ROLE_SIG_PUB = 3
_ROLE_SIG_PRIV = 4

# Domain-separation labels / salt / context — FORMAT.md §2.6 and §3.
_COMBINER_LABEL = b"VORLATH-Shield/2 hybrid-kem combiner"
_COMBINER_SALT = b"VORLATH-Shield-combiner/v2"
_AUTH_CTX = b"VORLATH-Shield/auth/v2"
_STREAM_NONCE_PREFIX = 7    # FORMAT.md §4.2 (_NONCE_PREFIX = 7)


class _ECDH:
    """Thin X25519/X448 adapter over ``cryptography`` (RFC 7748)."""

    def __init__(self, priv_cls, pub_cls):
        self._priv_cls = priv_cls
        self._pub_cls = pub_cls

    def exchange(self, priv_raw: bytes, peer_pub_raw: bytes) -> bytes:
        priv = self._priv_cls.from_private_bytes(priv_raw)
        return priv.exchange(self._pub_cls.from_public_bytes(peer_pub_raw))


# Suite registry — FORMAT.md §7 (cipher-suite table) and §5.1 (per-suite sizes).
# Each entry: ecdh adapter, ML-KEM module, ML-DSA module, HKDF hash, raw sizes.
class _Suite:
    def __init__(self, suite_id, ecdh, kem, sig, hkdf_hash,
                 ecdh_pub_len, kem_ek_len, kem_dk_len, kem_ct_len):
        self.suite_id = suite_id
        self.ecdh = ecdh
        self.kem = kem
        self.sig = sig
        self.hkdf_hash = hkdf_hash
        self.ecdh_pub_len = ecdh_pub_len
        self.kem_ek_len = kem_ek_len
        self.kem_dk_len = kem_dk_len
        self.kem_ct_len = kem_ct_len


_SUITES = {
    0x01: _Suite(0x01, _ECDH(X25519PrivateKey, X25519PublicKey),
                 ML_KEM_768, ML_DSA_65, hashes.SHA256,
                 ecdh_pub_len=32, kem_ek_len=1184, kem_dk_len=2400, kem_ct_len=1088),
    0x02: _Suite(0x02, _ECDH(X448PrivateKey, X448PublicKey),
                 ML_KEM_1024, ML_DSA_87, hashes.SHA384,
                 ecdh_pub_len=56, kem_ek_len=1568, kem_dk_len=3168, kem_ct_len=1568),
}


class AltCodecError(ValueError):
    """Raised by altcodec on any malformed, tampered, or wrong-key input.

    Subclasses ``ValueError`` so callers (and tests) can catch the same broad
    family the reference raises for structural problems.
    """


def _suite(suite_id: int) -> _Suite:
    s = _SUITES.get(suite_id)
    if s is None:
        raise AltCodecError(f"unknown VORLATH Shield suite_id 0x{suite_id:02x}")
    return s


# --------------------------------------------------------------------------- #
# TLV primitive — FORMAT.md §1. Bounds-checked on both ends, independently.
# --------------------------------------------------------------------------- #
def _read_tlv(buf: bytes, off: int) -> tuple[bytes, int]:
    if off + 2 > len(buf):
        raise AltCodecError("truncated: missing TLV length")
    (n,) = struct.unpack_from(">H", buf, off)
    start = off + 2
    end = start + n
    if end > len(buf):
        raise AltCodecError("truncated: TLV value runs past end")
    return buf[start:end], end


# --------------------------------------------------------------------------- #
# Key-bundle parsing — FORMAT.md §5. Independent of vorlath_shield._parse_key.
# --------------------------------------------------------------------------- #
def _parse_key(bundle: bytes, expect_role: int) -> tuple[int, bytes, list[bytes]]:
    if len(bundle) < 7 or bundle[:4] != _KEY_MAGIC:
        raise AltCodecError("not a VORLATH Shield key bundle")
    if bundle[4] != _KEY_VERSION:
        raise AltCodecError(f"unsupported key version {bundle[4]}")
    suite_id, role = bundle[5], bundle[6]
    if role != expect_role:
        raise AltCodecError(f"wrong key role: expected {expect_role}, got {role}")
    key_id, off = _read_tlv(bundle, 7)
    parts: list[bytes] = []
    while off < len(bundle):
        part, off = _read_tlv(bundle, off)
        parts.append(part)
    return suite_id, key_id, parts


def _sig_key_id(public_bundle: bytes) -> bytes:
    """SHAKE-256 fingerprint of a signing public bundle — FORMAT.md §5.2.

    ``signing public: _shake16(b"VRSK-sig-pub", bytes([suite_id]), pk)``.
    Recomputed independently here so the altcodec can pin ``expected_sender``.
    """
    suite_id, _kid, parts = _parse_key(public_bundle, _ROLE_SIG_PUB)
    (pk,) = parts
    h = hashlib.shake_256()
    h.update(b"VRSK-sig-pub")
    h.update(bytes([suite_id]))
    h.update(pk)
    return h.digest(_KEY_ID_LEN)


# --------------------------------------------------------------------------- #
# Combiner + KDF — FORMAT.md §2.6(b) / §8.1 (SP 800-56C-shaped).
# --------------------------------------------------------------------------- #
def _pre_auth_transcript(suite_id: int, flags: int, recipient_key_id: bytes,
                         eph_pub: bytes, kem_ct: bytes, nonce: bytes) -> bytes:
    # FORMAT.md §2.6: flat concatenation of raw values (no TLV framing).
    return bytes([suite_id, flags]) + recipient_key_id + eph_pub + kem_ct + nonce


def _derive_key(suite: _Suite, ss_classical: bytes, ss_pq: bytes,
                pre_auth: bytes, sender_kid: bytes = b"") -> bytes:
    # FORMAT.md §2.6(b): length-framed IKM, label||suite_id||pre_auth[||sender_kid] as FixedInfo.
    # In authenticated mode the verified sender key-id is bound into the FixedInfo (channel
    # binding), so the AEAD key witnesses the sender identity, not only the ML-DSA signature.
    ikm = (struct.pack(">H", len(ss_classical)) + ss_classical
           + struct.pack(">H", len(ss_pq)) + ss_pq)
    info = _COMBINER_LABEL + bytes([suite.suite_id]) + pre_auth + sender_kid
    return HKDF(algorithm=suite.hkdf_hash(), length=32,
                salt=_COMBINER_SALT, info=info).derive(ikm)


# --------------------------------------------------------------------------- #
# Single-shot VRSH decode — FORMAT.md §2 and §3.
# --------------------------------------------------------------------------- #
def open_envelope(envelope: bytes, recipient_private_bundle: bytes,
                  expected_sender_public: bytes | None = None) -> bytes:
    """Independently decode + decrypt a ``VRSH`` envelope, or raise on tamper.

    Mirrors the contract of ``vorlath_shield.decrypt`` but is built only from
    FORMAT.md. If ``expected_sender_public`` is supplied, the envelope MUST be
    authenticated by exactly that sender (FORMAT.md §3, step 4).
    """
    if not isinstance(envelope, (bytes, bytearray)):
        raise AltCodecError("envelope must be bytes")
    envelope = bytes(envelope)

    # --- fixed prefix (FORMAT.md §2.2) ---
    if len(envelope) < 7 or envelope[:4] != _MAGIC:
        raise AltCodecError("not a VORLATH Shield envelope")
    if envelope[4] != _VERSION:
        raise AltCodecError(f"unsupported Shield envelope version {envelope[4]}")
    suite_id, flags = envelope[5], envelope[6]
    s = _suite(suite_id)

    # --- ordered header TLVs (FORMAT.md §2.3) ---
    off = 7
    recipient_key_id, off = _read_tlv(envelope, off)
    eph_pub, off = _read_tlv(envelope, off)
    kem_ct, off = _read_tlv(envelope, off)
    nonce, off = _read_tlv(envelope, off)
    sender_block, off = _read_tlv(envelope, off)
    header = envelope[:off]   # AAD is the entire header (FORMAT.md §2.6(a))

    # --- ciphertext framing (FORMAT.md §2.4) ---
    if off + 4 > len(envelope):
        raise AltCodecError("truncated envelope: missing ciphertext length")
    (clen,) = struct.unpack_from(">I", envelope, off)
    off += 4
    if off + clen != len(envelope):
        raise AltCodecError("envelope length mismatch (truncated or trailing bytes)")
    sealed = envelope[off:off + clen]

    # --- recipient key cross-checks (FORMAT.md §2.7 / §5.2) ---
    sid, priv_key_id, priv_parts = _parse_key(recipient_private_bundle, _ROLE_KEM_PRIV)
    if sid != suite_id:
        raise AltCodecError("recipient key suite does not match envelope suite")
    if priv_key_id != recipient_key_id:
        raise AltCodecError("wrong recipient key (key-id mismatch)")
    x_priv, kem_dk = priv_parts

    # --- transcript (FORMAT.md §2.6) ---
    pre_auth = _pre_auth_transcript(suite_id, flags, recipient_key_id,
                                    eph_pub, kem_ct, nonce)

    # --- authenticated sender block (FORMAT.md §3), verified BEFORE decapsulation ---
    kdf_sender_kid = b""
    if flags & _FLAG_AUTHENTICATED:
        sender_kid, b2 = _read_tlv(sender_block, 0)
        sender_pub, b3 = _read_tlv(sender_block, b2)
        signature, _ = _read_tlv(sender_block, b3)
        ssuite_id, claimed_kid, sig_parts = _parse_key(sender_pub, _ROLE_SIG_PUB)
        (sender_pk,) = sig_parts
        if sender_kid != claimed_kid:
            raise AltCodecError("sender key-id does not match the embedded sender key")
        ssuite = _suite(ssuite_id)
        ok = ssuite.sig.verify(sender_pk, pre_auth + claimed_kid, signature, _AUTH_CTX)
        if not ok:
            raise AltCodecError("sender signature verification failed")
        kdf_sender_kid = claimed_kid   # channel-bind the verified sender identity into the AEAD key
        if (expected_sender_public is not None
                and _sig_key_id(expected_sender_public) != claimed_kid):
            raise AltCodecError("authenticated sender is not the expected sender")
    elif expected_sender_public is not None:
        raise AltCodecError("expected an authenticated sender but envelope is anonymous")

    # --- hybrid combine + open (FORMAT.md §2.6 / §8.1) ---
    ss_classical = s.ecdh.exchange(x_priv, eph_pub)
    ss_pq = s.kem.decaps(kem_dk, kem_ct)
    key = _derive_key(s, ss_classical, ss_pq, pre_auth, kdf_sender_kid)
    try:
        return AESGCM(key).decrypt(nonce, sealed, header)
    except InvalidTag as exc:  # AEAD tag failure -> uniform AltCodecError (cause preserved)
        raise AltCodecError("AEAD open failed (tamper or wrong key)") from exc


# --------------------------------------------------------------------------- #
# Streaming VRST decode — FORMAT.md §4 (BONUS; same independent construction).
# --------------------------------------------------------------------------- #
def open_stream(envelope: bytes, recipient_private_bundle: bytes) -> bytes:
    """Independently decode + decrypt a ``VRST`` stream, or raise on tamper.

    Implements the counter+final anti-truncation/anti-reorder construction from
    FORMAT.md §4.3/§4.4. Bonus scope; the corpus does not depend on it.
    """
    if not isinstance(envelope, (bytes, bytearray)):
        raise AltCodecError("envelope must be bytes")
    envelope = bytes(envelope)

    if len(envelope) < 7 or envelope[:4] != _STREAM_MAGIC:
        raise AltCodecError("not a VORLATH Shield stream")
    if envelope[4] != _VERSION:
        raise AltCodecError(f"unsupported Shield stream version {envelope[4]}")
    suite_id, flags = envelope[5], envelope[6]
    s = _suite(suite_id)

    off = 7
    recipient_key_id, off = _read_tlv(envelope, off)
    eph_pub, off = _read_tlv(envelope, off)
    kem_ct, off = _read_tlv(envelope, off)
    base_nonce, off = _read_tlv(envelope, off)
    if off + 4 > len(envelope):
        raise AltCodecError("truncated stream header")
    off += 4   # chunk_size — advisory, not needed to decrypt (FORMAT.md §4.2)
    header = envelope[:off]

    sid, priv_key_id, priv_parts = _parse_key(recipient_private_bundle, _ROLE_KEM_PRIV)
    if sid != suite_id:
        raise AltCodecError("recipient key suite does not match stream suite")
    if priv_key_id != recipient_key_id:
        raise AltCodecError("wrong recipient key (key-id mismatch)")
    x_priv, kem_dk = priv_parts

    pre_auth = _pre_auth_transcript(suite_id, flags, recipient_key_id,
                                    eph_pub, kem_ct, base_nonce)
    ss_classical = s.ecdh.exchange(x_priv, eph_pub)
    ss_pq = s.kem.decaps(kem_dk, kem_ct)
    aead = AESGCM(_derive_key(s, ss_classical, ss_pq, pre_auth))

    blobs: list[bytes] = []
    while off < len(envelope):
        if off + 4 > len(envelope):
            raise AltCodecError("truncated stream: missing chunk length")
        (clen,) = struct.unpack_from(">I", envelope, off)
        off += 4
        if off + clen > len(envelope):
            raise AltCodecError("truncated stream: chunk runs past end")
        blobs.append(envelope[off:off + clen])
        off += clen
    if not blobs:
        raise AltCodecError("empty stream")

    out = bytearray()
    last = len(blobs) - 1
    for idx, blob in enumerate(blobs):
        final = 1 if idx == last else 0
        ctr = struct.pack(">I", idx) + bytes([final])  # FORMAT.md §4.4
        try:
            out += aead.decrypt(base_nonce + ctr, blob, header + ctr)
        except InvalidTag as exc:  # only the AEAD tag failure is wrapped; others propagate
            raise AltCodecError("stream chunk open failed (tamper/reorder/truncation)") from exc
    return bytes(out)
