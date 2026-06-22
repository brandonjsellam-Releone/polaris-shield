"""VORLATH Shield — high-assurance, algorithm-diversified signatures (FIPS 205 SLH-DSA).

OPT-IN. The core uses lattice ML-DSA (FIPS 204). This module adds **SLH-DSA** (FIPS 205),
a *stateless hash-based* signature with a fundamentally different mathematical basis. Used
in `dual_*` mode, a forgery requires breaking BOTH a lattice AND a hash-based scheme — a
hedge against a future cryptanalytic break of either family, for long-lived roots of trust
(evidence records, firmware/release signing).

Trade-offs (by design): SLH-DSA signatures are large (~29 KB at the 256s set) and signing
is deliberately slow (seconds). Sign rarely; verify is fast. Not on the critical path and
NOT the default. Reference implementation (`slhdsa`, pure Python) — NOT FIPS 140-3 validated.
"""
from __future__ import annotations

import struct
from typing import Any

import slhdsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed448, ed25519

from . import shield

_HA_MAGIC = b"PLHA"      # high-assurance SLH-DSA key bundle
_EC_MAGIC = b"PLEC"      # classical EdDSA (Ed25519/Ed448) key bundle
_DUAL_MAGIC = b"PLDU"    # dual (ML-DSA + SLH-DSA) signature
_TRIPLE_MAGIC = b"PLTR"  # triple (ML-DSA + SLH-DSA + EdDSA) signature
_ROLE_PUB, _ROLE_PRIV = 0, 1
HA_CTX = b"VORLATH-Shield/ha-sig/v1"

# param_id -> (slhdsa parameter, human name)
_HA_PARAMS: dict[int, tuple[Any, str]] = {
    0x01: (slhdsa.shake_256s, "SLH-DSA-SHAKE-256s (FIPS 205, Category 5)"),
    0x02: (slhdsa.shake_128s, "SLH-DSA-SHAKE-128s (FIPS 205, Category 1, faster)"),
}
DEFAULT_HA_ID = 0x01


def _param(pid: int):
    p = _HA_PARAMS.get(pid)
    if p is None:
        raise ValueError(f"unknown SLH-DSA param id 0x{pid:02x}")
    return p[0]


def ha_param_name(bundle: bytes) -> str:
    if len(bundle) < 6 or bundle[:4] != _HA_MAGIC:
        raise ValueError("not a VORLATH Shield high-assurance key bundle")
    return _HA_PARAMS[bundle[4]][1]


def generate_high_assurance_keys(param_id: int = DEFAULT_HA_ID) -> tuple[bytes, bytes]:
    """SLH-DSA signing identity. Returns (public_bundle, private_bundle). Slow (hash-based)."""
    param = _param(param_id)
    kp = slhdsa.KeyPair.gen(param)
    pub = _HA_MAGIC + bytes([param_id, _ROLE_PUB]) + kp.pub.digest()
    priv = _HA_MAGIC + bytes([param_id, _ROLE_PRIV]) + kp.digest()
    return pub, priv


def _parse_ha(bundle: bytes, role: int) -> tuple[int, bytes]:
    if len(bundle) < 6 or bundle[:4] != _HA_MAGIC:
        raise ValueError("not a VORLATH Shield high-assurance key bundle")
    if bundle[5] != role:
        raise ValueError("wrong high-assurance key role")
    return bundle[4], bundle[6:]


def _framed(ctx: bytes, message: bytes) -> bytes:
    """FIPS 205-style injective domain separation: len(ctx) || ctx || message.

    The single-byte length frame makes `(ctx, message)` unambiguous: unlike the old
    `ctx || b"\\x00" || message`, no ctx containing a NUL can collide with another
    `(ctx, message)` pair. FIPS 205 caps a signing context at 255 bytes, so the frame
    is exactly one byte; we enforce that bound here.
    """
    if len(ctx) > 255:
        raise ValueError("SLH-DSA context must be <= 255 bytes (FIPS 205)")
    return bytes([len(ctx)]) + ctx + message


def high_assurance_sign(private_bundle: bytes, message: bytes, ctx: bytes = HA_CTX) -> bytes:
    """SLH-DSA signature over `message`, domain-separated by `ctx`."""
    pid, digest = _parse_ha(private_bundle, _ROLE_PRIV)
    kp = slhdsa.KeyPair.from_digest(digest, _param(pid))
    return kp.sign(_framed(ctx, message))


def high_assurance_verify(public_bundle: bytes, message: bytes, signature: bytes,
                          ctx: bytes = HA_CTX) -> bool:
    try:
        pid, digest = _parse_ha(public_bundle, _ROLE_PUB)
        pub = slhdsa.PublicKey.from_digest(digest, _param(pid))
        return bool(pub.verify(_framed(ctx, message), signature))
    except Exception:
        return False


# ----------------------------------------------------------------- dual (diversified) signatures
def dual_sign(mldsa_private_bundle: bytes, ha_private_bundle: bytes, message: bytes) -> bytes:
    """Sign with BOTH ML-DSA (lattice) and SLH-DSA (hash-based). Forgery needs breaking both."""
    ml = shield.sign(mldsa_private_bundle, message)
    ha = high_assurance_sign(ha_private_bundle, message)
    return _DUAL_MAGIC + struct.pack(">I", len(ml)) + ml + struct.pack(">I", len(ha)) + ha


def dual_verify(mldsa_public_bundle: bytes, ha_public_bundle: bytes,
                message: bytes, dual_signature: bytes) -> bool:
    """True only if BOTH the ML-DSA and the SLH-DSA signatures verify."""
    try:
        if dual_signature[:4] != _DUAL_MAGIC:
            return False
        off = 4
        (ml_len,) = struct.unpack_from(">I", dual_signature, off); off += 4
        ml = dual_signature[off:off + ml_len]; off += ml_len
        (ha_len,) = struct.unpack_from(">I", dual_signature, off); off += 4
        ha = dual_signature[off:off + ha_len]
        if off + ha_len != len(dual_signature):
            return False
    except Exception:
        return False
    return (shield.verify(mldsa_public_bundle, message, ml)
            and high_assurance_verify(ha_public_bundle, message, ha))


# ----------------------------------------------------------------- classical EdDSA leg (for the triple)
# param_id -> (private class, public class, name). Ed25519 ~ suite 0x01 level; Ed448 ~ suite 0x02 / X448.
_EC_ALGOS: dict[int, tuple[Any, Any, str]] = {
    0x01: (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey, "Ed25519 (EdDSA, ~128-bit classical)"),
    0x02: (ed448.Ed448PrivateKey, ed448.Ed448PublicKey, "Ed448 (EdDSA, ~224-bit classical)"),
}
DEFAULT_EC_ID = 0x01


def _ec_classes(pid: int):
    c = _EC_ALGOS.get(pid)
    if c is None:
        raise ValueError(f"unknown EdDSA param id 0x{pid:02x}")
    return c


def _parse_ec(bundle: bytes, role: int) -> tuple[int, bytes]:
    if len(bundle) < 6 or bundle[:4] != _EC_MAGIC:
        raise ValueError("not a VORLATH Shield EdDSA key bundle")
    if bundle[5] != role:
        raise ValueError("wrong EdDSA key role")
    return bundle[4], bundle[6:]


def ec_param_name(bundle: bytes) -> str:
    if len(bundle) < 6 or bundle[:4] != _EC_MAGIC:
        raise ValueError("not a VORLATH Shield EdDSA key bundle")
    return _ec_classes(bundle[4])[2]


def generate_ec_keys(param_id: int = DEFAULT_EC_ID) -> tuple[bytes, bytes]:
    """Classical EdDSA signing identity (Ed25519 / Ed448). Returns (public_bundle, private_bundle)."""
    priv_cls = _ec_classes(param_id)[0]
    sk = priv_cls.generate()
    raw_priv = sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                serialization.NoEncryption())
    raw_pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return (_EC_MAGIC + bytes([param_id, _ROLE_PUB]) + raw_pub,
            _EC_MAGIC + bytes([param_id, _ROLE_PRIV]) + raw_priv)


def ec_sign(private_bundle: bytes, message: bytes, ctx: bytes = HA_CTX) -> bytes:
    """EdDSA signature over `message`, domain-separated by `ctx` (same framing as the SLH-DSA leg)."""
    pid, raw = _parse_ec(private_bundle, _ROLE_PRIV)
    sk = _ec_classes(pid)[0].from_private_bytes(raw)
    return sk.sign(_framed(ctx, message))


def ec_verify(public_bundle: bytes, message: bytes, signature: bytes, ctx: bytes = HA_CTX) -> bool:
    try:
        pid, raw = _parse_ec(public_bundle, _ROLE_PUB)
        pk = _ec_classes(pid)[1].from_public_bytes(raw)
        pk.verify(signature, _framed(ctx, message))
        return True
    except Exception:
        return False


# ----------------------------------------------------------------- triple (ML-DSA + SLH-DSA + EdDSA)
def triple_sign(mldsa_private_bundle: bytes, ha_private_bundle: bytes,
                ec_private_bundle: bytes, message: bytes) -> bytes:
    """Sign with ML-DSA (lattice) + SLH-DSA (hash-based) + EdDSA (mature classical).

    The strongest hedge in the Shield: a forgery must break a lattice scheme AND a hash-based
    scheme AND a decades-hardened classical scheme. This is the ML-DSA+SLH-DSA+EC "triple" named
    in TNO_PQC_HANDBOOK_ALIGNMENT.md -- it carries BOTH the Handbook's literal ML-DSA+EdDSA
    recommendation (Table 4.1 fn 2) and the post-quantum SLH-DSA diversification at once. Larger and
    slower than dual; for the rare, long-lived root signatures where maximal hedging is worth it.
    """
    ml = shield.sign(mldsa_private_bundle, message)
    ha = high_assurance_sign(ha_private_bundle, message)
    ec = ec_sign(ec_private_bundle, message)
    return (_TRIPLE_MAGIC
            + struct.pack(">I", len(ml)) + ml
            + struct.pack(">I", len(ha)) + ha
            + struct.pack(">I", len(ec)) + ec)


def triple_verify(mldsa_public_bundle: bytes, ha_public_bundle: bytes, ec_public_bundle: bytes,
                  message: bytes, triple_signature: bytes) -> bool:
    """True only if ALL THREE legs (ML-DSA, SLH-DSA, EdDSA) verify. Fail-closed, canonical parse.

    Domain separation is safe despite the per-leg framing (ML-DSA signs the raw `message` via
    `shield.sign`; SLH-DSA and EdDSA sign `_framed(ctx, message)`): each leg *independently* binds
    `message`, and ALL three are required over the *same* `message`, so the ML-DSA leg alone already
    forces the verified message — no cross-leg substitution is possible. The EdDSA curve is fixed by
    the bundle's param-id (Ed25519 vs Ed448, which also differ in raw length), so no cross-curve
    confusion. (Reviewed by the AI council; both points were raised and shown not to yield an attack.)
    """
    try:
        if triple_signature[:4] != _TRIPLE_MAGIC:
            return False
        off = 4
        (ml_len,) = struct.unpack_from(">I", triple_signature, off); off += 4
        ml = triple_signature[off:off + ml_len]; off += ml_len
        (ha_len,) = struct.unpack_from(">I", triple_signature, off); off += 4
        ha = triple_signature[off:off + ha_len]; off += ha_len
        (ec_len,) = struct.unpack_from(">I", triple_signature, off); off += 4
        ec = triple_signature[off:off + ec_len]; off += ec_len
        if off != len(triple_signature):
            return False
    except Exception:
        return False
    return (shield.verify(mldsa_public_bundle, message, ml)
            and high_assurance_verify(ha_public_bundle, message, ha)
            and ec_verify(ec_public_bundle, message, ec))
