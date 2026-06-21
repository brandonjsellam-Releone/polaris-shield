"""VORLATH Shield v2 — a real, runnable, algorithm-agile post-quantum hybrid core.

Implements the CNSA 2.0 hybrid pattern on finalized U.S. federal standards, with a
self-describing wire format, downgrade-resistant suite negotiation, an SP 800-56C
length-framed combiner, and optional sender authentication.

CRYPTOGRAPHIC SUITES (the recipient key selects the suite; senders cannot downgrade)
  0x01  CNSA-compat : X25519 + ML-KEM-768  + ML-DSA-65 + HKDF-SHA256 + AES-256-GCM
  0x02  APEX        : X448   + ML-KEM-1024  + ML-DSA-87 + HKDF-SHA384 + AES-256-GCM   (default)

  * FIPS 203  ML-KEM   (key encapsulation)   via kyber-py
  * FIPS 204  ML-DSA   (digital signatures)  via dilithium-py
  * RFC 7748  X25519 / X448 ECDH (classical) via `cryptography`
  * SP 800-56C HKDF combiner + SP 800-38D AES-256-GCM AEAD

Confidentiality is "defense in depth": the AEAD key is derived from BOTH a classical
ECDH secret AND a post-quantum ML-KEM secret, length-framed and bound to the full
handshake transcript. An adversary must break BOTH to recover plaintext, so a future
cryptographically relevant quantum computer (CRQC) that breaks the classical leg still
cannot open a Shield envelope ("harvest-now, decrypt-later" is defeated — assuming ML-KEM
remains IND-CCA-secure; this hybrid-soundness property is established symbolically in formal/).

Downgrade resistance: suite_id and flags are bound into the AEAD associated data and the
key-derivation transcript, so any tampering with the negotiated algorithms is rejected.

HONEST CAVEATS (read tech/README.md and SECURITY.md):
  * kyber-py / dilithium-py are clean reference implementations that TRACK FIPS 203/204;
    they are NOT FIPS 140-3 (CAVP/CMVP) validated and are NOT hardened against timing or
    other side channels. This is an evaluation / reference tool, not a certified production
    cryptographic module. Use a validated module (AWS-LC, OpenSSL 3.5+, liboqs in a
    validated configuration) for real deployment.
"""
from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from dilithium_py.ml_dsa import ML_DSA_65, ML_DSA_87
from kyber_py.ml_kem import ML_KEM_768, ML_KEM_1024

MAGIC = b"VRSH"
VERSION = 2
KEY_MAGIC = b"VRSK"
KEY_VERSION = 2

NONCE = 12                      # AES-256-GCM nonce length
KEY_ID_LEN = 32                 # SHAKE-256 key fingerprint (256-bit, matches the apex tier)
FLAG_AUTHENTICATED = 0x01       # envelope carries a sender signature
FLAG_PPK = 0x02                 # AEAD key additionally mixes an out-of-band pre-shared key (RFC 8784-style)

# domain-separation labels (never reused across contexts)
_COMBINER_LABEL = b"VORLATH-Shield/2 hybrid-kem combiner"
_COMBINER_SALT = b"VORLATH-Shield-combiner/v2"
SIG_CTX = b"VORLATH-Shield/sig/v1"     # detached document signatures
AUTH_CTX = b"VORLATH-Shield/auth/v2"   # authenticated-handshake signatures

# key-bundle roles
_ROLE_KEM_PUB, _ROLE_KEM_PRIV, _ROLE_SIG_PUB, _ROLE_SIG_PRIV = 1, 2, 3, 4


# ----------------------------------------------------------------- ECDH adapters
class _XWrap:
    """Uniform X25519/X448 interface so suites differ only by a table entry."""

    def __init__(self, priv_cls, pub_cls):
        self._priv, self._pub = priv_cls, pub_cls

    def generate_private(self):
        return self._priv.generate()

    def public_raw(self, priv) -> bytes:
        return priv.public_key().public_bytes_raw()

    def private_raw(self, priv) -> bytes:
        return priv.private_bytes_raw()

    def exchange(self, priv, peer_pub_raw: bytes) -> bytes:
        return priv.exchange(self._pub.from_public_bytes(peer_pub_raw))

    def from_private(self, raw: bytes):
        return self._priv.from_private_bytes(raw)


_X25519 = _XWrap(X25519PrivateKey, X25519PublicKey)
_X448 = _XWrap(X448PrivateKey, X448PublicKey)


class _NullX:
    """No classical leg (pure-PQC suite 0x03). Every classical value is empty, so the
    combiner's length-framed classical contribution is zero-length and the derived key
    rests SOLELY on the ML-KEM leg. This is the NSA-preferred pure-PQC NSS end-state
    (CNSA 2.0); it deliberately trades the hybrid's "survives a classical OR a PQ break"
    property for the pure-PQC posture. Its confidentiality is then exactly the single-leg
    (PQ-only) case the four formal lineages already prove (secrecy_under_classical_break)."""

    is_null = True

    def generate_private(self):
        return b""

    def public_raw(self, priv) -> bytes:
        return b""

    def private_raw(self, priv) -> bytes:
        return b""

    def exchange(self, priv, peer_pub_raw: bytes) -> bytes:
        return b""

    def from_private(self, raw: bytes):
        return b""


_NULLX = _NullX()


# ----------------------------------------------------------------- suite registry
@dataclass(frozen=True)
class Suite:
    suite_id: int
    name: str
    ecdh: _XWrap | _NullX
    kem: Any                  # ML_KEM_* module (no type stubs)
    sig: Any                  # ML_DSA_* module (no type stubs)
    hkdf_hash: Any            # cryptography hashes.* class
    ecdh_pub_len: int
    kem_ek_len: int
    kem_dk_len: int
    kem_ct_len: int


# NOTE on naming: CNSA 2.0 (NSA, CNSS AM 02-22) mandates the Category-5 set
# ML-KEM-1024 + ML-DSA-87 + AES-256 + SHA-384 — that is suite 0x02. Suite 0x01
# (ML-KEM-768 / ML-DSA-65) is FIPS-standard and good for interop, but is NOT a
# CNSA 2.0 parameter set, so it is labelled "FIPS-standard", not "CNSA". Suite 0x03 is
# the SAME Cat-5 algorithm set as 0x02 but PURE-PQC (no classical leg) — the NSA-preferred
# NSS end-state (see ../CNSA_MIGRATION.md). It deliberately drops hybrid defense-in-depth;
# its confidentiality rests solely on ML-KEM-1024 (the secrecy_under_classical_break case
# the four proof lineages already establish). Hybrid (0x02) remains the default.
SUITES = {
    0x01: Suite(0x01, "FIPS-standard X25519+ML-KEM-768+ML-DSA-65 HKDF-SHA256 AES-256-GCM",
                _X25519, ML_KEM_768, ML_DSA_65, hashes.SHA256, 32, 1184, 2400, 1088),
    0x02: Suite(0x02, "CNSA-2.0 X448+ML-KEM-1024+ML-DSA-87 HKDF-SHA384 AES-256-GCM",
                _X448, ML_KEM_1024, ML_DSA_87, hashes.SHA384, 56, 1568, 3168, 1568),
    0x03: Suite(0x03, "CNSA-2.0-pure ML-KEM-1024+ML-DSA-87 HKDF-SHA384 AES-256-GCM (no classical leg)",
                _NULLX, ML_KEM_1024, ML_DSA_87, hashes.SHA384, 0, 1568, 3168, 1568),
}
DEFAULT_SUITE_ID = 0x02
# Back-compat constant: human-readable description of the default (apex) suite.
# "CNSA-2.0" here denotes the ALGORITHM SET, not a validated/certified module.
SUITE = ("VORLATH-Shield/2 " + SUITES[DEFAULT_SUITE_ID].name).encode()


def _suite(suite_id: int) -> Suite:
    s = SUITES.get(suite_id)
    if s is None:
        raise ValueError(f"unknown VORLATH Shield suite_id 0x{suite_id:02x}")
    return s


# ----------------------------------------------------------------- TLV helpers (bounds-checked)
def _tlv(b: bytes) -> bytes:
    if len(b) > 0xFFFF:
        raise ValueError("TLV field exceeds 65535 bytes")
    return struct.pack(">H", len(b)) + b


def _read_tlv(buf: bytes, off: int) -> tuple[bytes, int]:
    if off + 2 > len(buf):
        raise ValueError("truncated envelope: missing TLV length")
    (n,) = struct.unpack_from(">H", buf, off)
    start = off + 2
    end = start + n
    if end > len(buf):
        raise ValueError("truncated envelope: TLV value runs past end")
    return buf[start:end], end


# ----------------------------------------------------------------- key serialization
def _shake16(*parts: bytes) -> bytes:
    h = hashlib.shake_256()
    for p in parts:
        h.update(p)
    return h.digest(KEY_ID_LEN)


def _serialize_key(suite_id: int, role: int, key_id: bytes, *parts: bytes) -> bytes:
    out = KEY_MAGIC + bytes([KEY_VERSION, suite_id, role]) + _tlv(key_id)
    for p in parts:
        out += _tlv(p)
    return out


def _parse_key(bundle: bytes, expect_role: int) -> tuple[int, bytes, list[bytes]]:
    if len(bundle) < 7 or bundle[:4] != KEY_MAGIC:
        raise ValueError("not a VORLATH Shield key bundle")
    if bundle[4] != KEY_VERSION:
        raise ValueError(f"unsupported key version {bundle[4]}")
    suite_id, role = bundle[5], bundle[6]
    if role != expect_role:
        raise ValueError(f"wrong key role: expected {expect_role}, got {role}")
    key_id, off = _read_tlv(bundle, 7)
    parts = []
    while off < len(bundle):
        part, off = _read_tlv(bundle, off)
        parts.append(part)
    return suite_id, key_id, parts


def kem_key_id(public_bundle: bytes) -> bytes:
    """Stable 32-byte SHAKE-256 fingerprint of a recipient (KEM) public bundle."""
    suite_id, kid, _ = _parse_key(public_bundle, _ROLE_KEM_PUB)
    return kid


def sig_key_id(public_bundle: bytes) -> bytes:
    suite_id, kid, _ = _parse_key(public_bundle, _ROLE_SIG_PUB)
    return kid


def suite_of(bundle: bytes) -> Suite:
    """Return the Suite a key bundle is bound to (without revealing private parts)."""
    if len(bundle) < 7 or bundle[:4] != KEY_MAGIC:
        raise ValueError("not a VORLATH Shield key bundle")
    return _suite(bundle[5])


# ----------------------------------------------------------------- key generation
def generate_recipient_keys(suite_id: int = DEFAULT_SUITE_ID) -> tuple[bytes, bytes]:
    """Hybrid KEM identity for `suite_id`. Returns (public_bundle, private_bundle)."""
    s = _suite(suite_id)
    eph = s.ecdh.generate_private()
    x_pub, x_priv = s.ecdh.public_raw(eph), s.ecdh.private_raw(eph)
    ek, dk = s.kem.keygen()
    kid = _shake16(b"VRSK-kem-pub", bytes([suite_id]), x_pub, ek)
    public_bundle = _serialize_key(suite_id, _ROLE_KEM_PUB, kid, x_pub, ek)
    private_bundle = _serialize_key(suite_id, _ROLE_KEM_PRIV, kid, x_priv, dk)
    return public_bundle, private_bundle


def generate_signing_keys(suite_id: int = DEFAULT_SUITE_ID) -> tuple[bytes, bytes]:
    """ML-DSA signing identity for `suite_id`. Returns (public_bundle, private_bundle)."""
    s = _suite(suite_id)
    pk, sk = s.sig.keygen()
    kid = _shake16(b"VRSK-sig-pub", bytes([suite_id]), pk)
    public_bundle = _serialize_key(suite_id, _ROLE_SIG_PUB, kid, pk)
    private_bundle = _serialize_key(suite_id, _ROLE_SIG_PRIV, kid, sk)
    return public_bundle, private_bundle


# ----------------------------------------------------------------- combiner (SP 800-56C shaped)
def _derive_key(suite: Suite, ss_classical: bytes, ss_pq: bytes, pre_auth: bytes,
                ppk: bytes = b"", sender_kid: bytes = b"") -> bytes:
    """HKDF over length-framed (ss_classical || ss_pq [|| ppk]), bound to the full transcript.

    Length-framing makes the concatenation injective across suites; the transcript is
    fed as HKDF FixedInfo so the derived key is unique to this exact handshake. When a
    non-empty `ppk` (RFC 8784-style out-of-band pre-shared key) is supplied it is appended
    as a THIRD length-framed secret, so the derived key still holds even if BOTH the
    classical and the ML-KEM legs are broken; its presence is also bound via FLAG_PPK in
    `pre_auth`, so an attacker cannot strip it without invalidating the transcript/AAD.

    In authenticated mode the sender's key-id `sender_kid` is ALSO bound into the HKDF
    FixedInfo (channel binding, HPKE RFC 9180 / TLS 1.3 style), so the derived AEAD key
    itself witnesses the sender identity - not only the ML-DSA signature; the two transcripts
    (signature and key) no longer diverge on sender identity. FLAG_AUTHENTICATED (carried in
    `pre_auth`) disambiguates the empty (anonymous) case from the 32-byte (authenticated) one.
    """
    ikm = struct.pack(">H", len(ss_classical)) + ss_classical + \
        struct.pack(">H", len(ss_pq)) + ss_pq
    if ppk:
        ikm += struct.pack(">H", len(ppk)) + ppk
    info = _COMBINER_LABEL + bytes([suite.suite_id]) + pre_auth + sender_kid
    return HKDF(algorithm=suite.hkdf_hash(), length=32, salt=_COMBINER_SALT,
                info=info).derive(ikm)


def _pre_auth_transcript(suite_id: int, flags: int, recipient_key_id: bytes,
                         eph_pub: bytes, kem_ct: bytes, nonce: bytes) -> bytes:
    return bytes([suite_id, flags]) + recipient_key_id + eph_pub + kem_ct + nonce


# ----------------------------------------------------------------- AEAD seal / open
def encrypt(plaintext: bytes, recipient_public_bundle: bytes,
            sender_signing_private: bytes | None = None,
            sender_signing_public: bytes | None = None,
            ppk: bytes | None = None) -> bytes:
    """Hybrid-encapsulate to the recipient and seal with AES-256-GCM.

    If a sender signing identity is supplied, the handshake transcript is signed
    (authenticated mode), binding the message to the sender and defeating spoofing /
    unknown-key-share. The suite is taken from the recipient's key (no downgrade).
    """
    suite_id, recipient_key_id, (x_pub, kem_ek) = _parse_key(
        recipient_public_bundle, _ROLE_KEM_PUB)
    s = _suite(suite_id)

    eph = s.ecdh.generate_private()
    eph_pub = s.ecdh.public_raw(eph)
    ss_classical = s.ecdh.exchange(eph, x_pub)
    ss_pq, kem_ct = s.kem.encaps(kem_ek)
    nonce = os.urandom(NONCE)

    authenticated = sender_signing_private is not None
    flags = (FLAG_AUTHENTICATED if authenticated else 0) | (FLAG_PPK if ppk else 0)
    pre_auth = _pre_auth_transcript(suite_id, flags, recipient_key_id, eph_pub, kem_ct, nonce)

    sender_block = b""
    sender_kid = b""
    if sender_signing_private is not None:
        if sender_signing_public is None:
            raise ValueError("sender_signing_public is required for authenticated mode")
        sid, sender_kid, (sk_raw,) = _parse_key(sender_signing_private, _ROLE_SIG_PRIV)
        # SIGMA-style: the signer binds ITS OWN identity into the signed transcript, so a
        # signature can never be re-attributed to a different sender (UKS / misbinding).
        signature = s.sig.sign(sk_raw, pre_auth + sender_kid, AUTH_CTX)
        sender_block = _tlv(sender_kid) + _tlv(sender_signing_public) + _tlv(signature)

    header = (MAGIC + bytes([VERSION, suite_id, flags])
              + _tlv(recipient_key_id) + _tlv(eph_pub) + _tlv(kem_ct)
              + _tlv(nonce) + _tlv(sender_block))

    key = _derive_key(s, ss_classical, ss_pq, pre_auth, ppk or b"", sender_kid)
    sealed = AESGCM(key).encrypt(nonce, plaintext, header)   # ct||tag, AAD = header
    return header + struct.pack(">I", len(sealed)) + sealed


def decrypt(envelope: bytes, recipient_private_bundle: bytes,
            expected_sender_public: bytes | None = None,
            ppk: bytes | None = None) -> bytes:
    """Reverse of encrypt(); raises on tamper, wrong key, bad sender, or malformed input.

    If `expected_sender_public` is given, the envelope MUST be authenticated by exactly
    that sender or decryption is refused.
    """
    if not isinstance(envelope, (bytes, bytearray)):
        raise ValueError("envelope must be bytes")
    if len(envelope) < 7 or envelope[:4] != MAGIC:
        raise ValueError("not a VORLATH Shield envelope")
    if envelope[4] != VERSION:
        raise ValueError(f"unsupported Shield envelope version {envelope[4]}")
    suite_id, flags = envelope[5], envelope[6]
    s = _suite(suite_id)

    off = 7
    recipient_key_id, off = _read_tlv(envelope, off)
    eph_pub, off = _read_tlv(envelope, off)
    kem_ct, off = _read_tlv(envelope, off)
    nonce, off = _read_tlv(envelope, off)
    sender_block, off = _read_tlv(envelope, off)
    header = envelope[:off]

    if off + 4 > len(envelope):
        raise ValueError("truncated envelope: missing ciphertext length")
    (clen,) = struct.unpack_from(">I", envelope, off)
    off += 4
    if off + clen != len(envelope):
        raise ValueError("envelope length mismatch (truncated or trailing bytes)")
    sealed = envelope[off:off + clen]

    sid, priv_key_id, (x_priv, kem_dk) = _parse_key(recipient_private_bundle, _ROLE_KEM_PRIV)
    if sid != suite_id:
        raise ValueError("recipient key suite does not match envelope suite")
    if priv_key_id != recipient_key_id:
        raise ValueError("wrong recipient key (key-id mismatch)")

    pre_auth = _pre_auth_transcript(suite_id, flags, recipient_key_id, eph_pub, kem_ct, nonce)

    kdf_sender_kid = b""
    if flags & FLAG_AUTHENTICATED:
        sender_kid, b2 = _read_tlv(sender_block, 0)
        sender_pub, b3 = _read_tlv(sender_block, b2)
        signature, b4 = _read_tlv(sender_block, b3)
        if b4 != len(sender_block):
            raise ValueError("sender_block has trailing bytes (non-canonical encoding)")
        ssuite_id, claimed_kid, (sender_pk,) = _parse_key(sender_pub, _ROLE_SIG_PUB)
        if sender_kid != claimed_kid:
            raise ValueError("sender key-id does not match the embedded sender key")
        if not _suite(ssuite_id).sig.verify(sender_pk, pre_auth + claimed_kid, signature, AUTH_CTX):
            raise ValueError("sender signature verification failed")
        kdf_sender_kid = claimed_kid   # channel-bind the VERIFIED sender identity into the AEAD key
        if expected_sender_public is not None and \
                sig_key_id(expected_sender_public) != claimed_kid:
            raise ValueError("authenticated sender is not the expected sender")
    elif expected_sender_public is not None:
        raise ValueError("expected an authenticated sender but envelope is anonymous")

    if flags & FLAG_PPK:
        if not ppk:
            raise ValueError("envelope is PPK-bound (FLAG_PPK) but no pre-shared key was supplied")
        effective_ppk = ppk
    else:
        effective_ppk = b""

    ss_classical = s.ecdh.exchange(s.ecdh.from_private(x_priv), eph_pub)
    ss_pq = s.kem.decaps(kem_dk, kem_ct)
    key = _derive_key(s, ss_classical, ss_pq, pre_auth, effective_ppk, kdf_sender_kid)
    try:
        return AESGCM(key).decrypt(nonce, sealed, header)
    except InvalidTag as e:
        raise ValueError("AEAD open failed (tamper or wrong key)") from e


# convenience wrappers (explicit names for the authenticated handshake)
def encrypt_authenticated(plaintext: bytes, recipient_public_bundle: bytes,
                          sender_signing_private: bytes, sender_signing_public: bytes,
                          ppk: bytes | None = None) -> bytes:
    return encrypt(plaintext, recipient_public_bundle,
                   sender_signing_private, sender_signing_public, ppk)


def decrypt_authenticated(envelope: bytes, recipient_private_bundle: bytes,
                          expected_sender_public: bytes, ppk: bytes | None = None) -> bytes:
    """Open an envelope and require it to be authenticated by `expected_sender_public`.

    Proves sender identity and integrity but NOT freshness: a stateless one-pass open does
    not prevent replay of a captured envelope. Callers needing replay resistance must add an
    application-layer check (nonce/transcript dedup or an in-plaintext challenge/timestamp).
    """
    return decrypt(envelope, recipient_private_bundle, expected_sender_public, ppk)


# ----------------------------------------------------------------- detached signatures
def sign(private_bundle: bytes, message: bytes, ctx: bytes = SIG_CTX,
         deterministic: bool = False) -> bytes:
    """ML-DSA detached signature over `message` with a domain-separation context."""
    suite_id, _kid, (sk_raw,) = _parse_key(private_bundle, _ROLE_SIG_PRIV)
    return _suite(suite_id).sig.sign(sk_raw, message, ctx, deterministic)


def verify(public_bundle: bytes, message: bytes, signature: bytes, ctx: bytes = SIG_CTX) -> bool:
    """Verify an ML-DSA detached signature. Returns False on a bad signature; raises only
    on a malformed key bundle is avoided — callers get a clean boolean."""
    try:
        suite_id, _kid, (pk_raw,) = _parse_key(public_bundle, _ROLE_SIG_PUB)
        return bool(_suite(suite_id).sig.verify(pk_raw, message, signature, ctx))
    except (ValueError, TypeError):
        return False


# ----------------------------------------------------------------- classical-only (HNDL contrast)
def encrypt_classical_only(plaintext: bytes, recipient_public_bundle: bytes) -> bytes:
    """ECDH-ONLY seal — what most systems ship today. Quantum-vulnerable BY DESIGN; used
    only to demonstrate harvest-now-decrypt-later versus the hybrid Shield."""
    suite_id, _kid, (x_pub, _ek) = _parse_key(recipient_public_bundle, _ROLE_KEM_PUB)
    s = _suite(suite_id)
    if getattr(s.ecdh, "is_null", False):
        raise ValueError(
            f"suite 0x{suite_id:02x} is pure-PQC (no classical leg); a classical-only seal is undefined")
    eph = s.ecdh.generate_private()
    eph_pub = s.ecdh.public_raw(eph)
    ss = s.ecdh.exchange(eph, x_pub)
    key = HKDF(algorithm=s.hkdf_hash(), length=32, salt=None,
               info=b"classical-only-ecdh").derive(ss)
    nonce = os.urandom(NONCE)
    sealed = AESGCM(key).encrypt(nonce, plaintext, b"classical")
    return b"X25O" + bytes([suite_id]) + eph_pub + nonce + sealed


# ----------------------------------------------------------------- streaming AEAD (large files)
STREAM_MAGIC = b"VRST"
DEFAULT_CHUNK = 64 * 1024
_NONCE_PREFIX = 7   # base_nonce; full per-chunk nonce = prefix(7) || counter(4) || final(1) = 12


def seal_stream(plaintext: bytes, recipient_public_bundle: bytes,
                chunk_size: int = DEFAULT_CHUNK) -> bytes:
    """Hybrid-seal a large message as an ordered sequence of AEAD chunks (STREAM construction).

    Each chunk's nonce is base_nonce || counter || final-flag, so dropping the final chunk
    (truncation), reordering, or dropping any chunk is detected on open — not just bit-flips.
    """
    if not (1 <= chunk_size <= 0xFFFFFFFF):
        raise ValueError("chunk_size out of range")
    suite_id, recipient_key_id, (x_pub, kem_ek) = _parse_key(recipient_public_bundle, _ROLE_KEM_PUB)
    s = _suite(suite_id)
    eph = s.ecdh.generate_private()
    eph_pub = s.ecdh.public_raw(eph)
    ss_classical = s.ecdh.exchange(eph, x_pub)
    ss_pq, kem_ct = s.kem.encaps(kem_ek)
    base_nonce = os.urandom(_NONCE_PREFIX)
    flags = 0
    pre_auth = _pre_auth_transcript(suite_id, flags, recipient_key_id, eph_pub, kem_ct, base_nonce)
    header = (STREAM_MAGIC + bytes([VERSION, suite_id, flags])
              + _tlv(recipient_key_id) + _tlv(eph_pub) + _tlv(kem_ct)
              + _tlv(base_nonce) + struct.pack(">I", chunk_size))
    aead = AESGCM(_derive_key(s, ss_classical, ss_pq, pre_auth))

    chunks = [plaintext[i:i + chunk_size] for i in range(0, len(plaintext), chunk_size)] or [b""]
    if len(chunks) > 0xFFFFFFFF:
        raise ValueError("too many chunks")
    out = bytearray(header)
    last = len(chunks) - 1
    for idx, ch in enumerate(chunks):
        final = 1 if idx == last else 0
        ctr = struct.pack(">I", idx) + bytes([final])
        sealed = aead.encrypt(base_nonce + ctr, ch, header + ctr)   # AAD binds header + counter + final
        out += struct.pack(">I", len(sealed)) + sealed
    return bytes(out)


def open_stream(envelope: bytes, recipient_private_bundle: bytes) -> bytes:
    """Reverse of seal_stream(); raises on tamper, wrong key, reorder, dropped or truncated chunks."""
    if not isinstance(envelope, (bytes, bytearray)):
        raise ValueError("envelope must be bytes")
    if len(envelope) < 7 or envelope[:4] != STREAM_MAGIC:
        raise ValueError("not a VORLATH Shield stream")
    if envelope[4] != VERSION:
        raise ValueError(f"unsupported Shield stream version {envelope[4]}")
    suite_id, flags = envelope[5], envelope[6]
    s = _suite(suite_id)
    off = 7
    recipient_key_id, off = _read_tlv(envelope, off)
    eph_pub, off = _read_tlv(envelope, off)
    kem_ct, off = _read_tlv(envelope, off)
    base_nonce, off = _read_tlv(envelope, off)
    if off + 4 > len(envelope):
        raise ValueError("truncated stream header")
    off += 4   # chunk_size (advisory; not needed to decrypt)
    header = envelope[:off]

    sid, priv_key_id, (x_priv, kem_dk) = _parse_key(recipient_private_bundle, _ROLE_KEM_PRIV)
    if sid != suite_id:
        raise ValueError("recipient key suite does not match stream suite")
    if priv_key_id != recipient_key_id:
        raise ValueError("wrong recipient key (key-id mismatch)")
    pre_auth = _pre_auth_transcript(suite_id, flags, recipient_key_id, eph_pub, kem_ct, base_nonce)
    ss_classical = s.ecdh.exchange(s.ecdh.from_private(x_priv), eph_pub)
    ss_pq = s.kem.decaps(kem_dk, kem_ct)
    aead = AESGCM(_derive_key(s, ss_classical, ss_pq, pre_auth))

    blobs = []
    while off < len(envelope):
        if off + 4 > len(envelope):
            raise ValueError("truncated stream: missing chunk length")
        (clen,) = struct.unpack_from(">I", envelope, off)
        off += 4
        if off + clen > len(envelope):
            raise ValueError("truncated stream: chunk runs past end")
        blobs.append(envelope[off:off + clen])
        off += clen
    if not blobs:
        raise ValueError("empty stream")

    out = bytearray()
    last = len(blobs) - 1
    for idx, blob in enumerate(blobs):
        final = 1 if idx == last else 0
        ctr = struct.pack(">I", idx) + bytes([final])
        try:
            out += aead.decrypt(base_nonce + ctr, blob, header + ctr)   # raises on any mismatch
        except InvalidTag as e:
            raise ValueError("stream chunk AEAD open failed (tamper or wrong key)") from e
    return bytes(out)
