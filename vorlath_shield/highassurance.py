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

from . import shield

_HA_MAGIC = b"PLHA"      # high-assurance SLH-DSA key bundle
_DUAL_MAGIC = b"PLDU"    # dual (ML-DSA + SLH-DSA) signature
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
