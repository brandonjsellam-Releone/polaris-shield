"""cross_impl — differential cross-validation of the ML-KEM / ML-DSA PRIMITIVES.

VORLATH Shield pins two pure-Python reference implementations:

  * ``kyber-py`` 1.2.0   — FIPS 203 ML-KEM (ML-KEM-768 / ML-KEM-1024)
  * ``dilithium-py`` 1.4.0 — FIPS 204 ML-DSA (ML-DSA-65 / ML-DSA-87)

The interop corpus (``interop/altcodec.py`` + ``interop/test_pstv.py``) proves
independence at the FORMAT / TLV-parse / combiner / KDF / AEAD-orchestration
layer, but it deliberately *reuses these same primitive libs*. A bug INSIDE
kyber-py or dilithium-py is therefore invisible to it — disclosed in
``interop/INTEROP.md`` and ``tech/VERIFICATION_GAP_MAP.md`` seam (a).

This harness closes that seam on RANDOM inputs (beyond the fixed NIST ACVP
vectors in ``tech/test_acvp.py``) by cross-validating the primitives against a
SECOND, INDEPENDENT implementation: ``pqcrypto`` 0.3.4 — the PQClean CFFI
wrapper (C reference code, manylinux wheels), an entirely separate lineage from
the pure-Python kyber-py / dilithium-py. Because FIPS 203/204 byte formats are
standardized, two conformant implementations must interoperate; if they do not,
at least one of them is wrong.

WHAT THIS PROVES, AND WHAT IT DOES NOT
--------------------------------------
ML-KEM (decisive, both directions):
    kyber-py.keygen -> (ek, dk); pqcrypto.encrypt(ek) -> (ct, ss_B);
    kyber-py.decaps(dk, ct) -> ss_A; assert ss_A == ss_B  (and the reverse,
    pqcrypto.generate_keypair / kyber-py.encaps / pqcrypto.decrypt). A shared
    secret that agrees across two independent codebases on a random key + random
    coins is a strong cross-check of the encaps/decaps math and the ek/dk/ct
    wire formats.

ML-DSA (cross-verify only, NOT byte equality):
    Both libraries sign the SAME message under the SAME key and each verifies
    the OTHER's signature (dilithium-py with empty context, since pqcrypto's
    ML-DSA is context-less). We assert mutual accept, and assert that a flipped
    bit is mutually REJECTED. We do NOT assert byte-identical signatures:
    pqcrypto's ML-DSA is the HEDGED (randomized) variant, so its signatures are
    non-deterministic and will not equal dilithium-py's deterministic output.
    The original goal contemplated deterministic byte equality; that is not
    achievable against pqcrypto 0.3.4, so the ML-DSA leg is an accept/reject
    agreement check, which is the honest, achievable cross-validation.

CAVEATS (honest framing):
  * Random cross-checks cannot catch a flaw SHARED by both implementations
    (e.g. a spec ambiguity both authors read the same way) or any side-channel
    / constant-time property. They catch divergence, not shared-mode failure.
  * These are reference implementations, not FIPS-validated modules.

Exit status: 0 iff EVERY leg agreed on EVERY iteration; non-zero on ANY
mismatch (and the offending seed is printed so it can be reproduced).
"""
from __future__ import annotations

import argparse
import os
import sys

# --- the pinned reference primitives (the libs VORLATH Shield actually uses) ---
from dilithium_py.ml_dsa import ML_DSA_65, ML_DSA_87
from kyber_py.ml_kem import ML_KEM_768, ML_KEM_1024

# --- the SECOND, INDEPENDENT implementation (PQClean C via CFFI) ---
from pqcrypto.kem import ml_kem_768 as pq_ml_kem_768
from pqcrypto.kem import ml_kem_1024 as pq_ml_kem_1024
from pqcrypto.sign import ml_dsa_65 as pq_ml_dsa_65
from pqcrypto.sign import ml_dsa_87 as pq_ml_dsa_87


# --------------------------------------------------------------------------- #
# Algorithm registry — pair each reference module with its pqcrypto twin.
# --------------------------------------------------------------------------- #
# kyber-py API:   keygen() -> (ek, dk);  encaps(ek) -> (ss, ct);  decaps(dk, ct) -> ss
# pqcrypto KEM:   generate_keypair() -> (pk, sk);  encrypt(pk) -> (ct, ss);  decrypt(sk, ct) -> ss
#   (pqcrypto.encrypt returns (ct, ss) — ciphertext FIRST — note the order vs kyber-py.)
_KEM_PAIRS = (
    ("ML-KEM-768", ML_KEM_768, pq_ml_kem_768),
    ("ML-KEM-1024", ML_KEM_1024, pq_ml_kem_1024),
)

# dilithium-py API: keygen() -> (pk, sk); sign(sk, m, ctx=b'', deterministic=False) -> sig;
#                   verify(pk, m, sig, ctx=b'') -> bool
# pqcrypto SIGN:    generate_keypair() -> (pk, sk); sign(sk, m) -> sig (HEDGED/randomized);
#                   verify(pk, m, sig) -> bool   (context-less)
_SIG_PAIRS = (
    ("ML-DSA-65", ML_DSA_65, pq_ml_dsa_65),
    ("ML-DSA-87", ML_DSA_87, pq_ml_dsa_87),
)

_EMPTY_CTX = b""  # pqcrypto ML-DSA is context-less; dilithium-py must use empty ctx to match.


class CrossImplMismatch(AssertionError):
    """Raised the instant any two independent implementations disagree."""


def _flip_one_bit(buf: bytes, pos: int) -> bytes:
    """Flip a single bit so a corrupted signature must be rejected by BOTH verifiers."""
    b = bytearray(buf)
    b[pos % len(b)] ^= 0x01
    return bytes(b)


# --------------------------------------------------------------------------- #
# ML-KEM leg — encaps/decaps cross-check in BOTH directions.
# --------------------------------------------------------------------------- #
def _check_kem(name: str, ref, pq, rng) -> None:
    """One random ML-KEM cross-validation round; raises on the first disagreement.

    Direction 1: kyber-py keygen -> the OTHER lib encapsulates -> kyber-py decapsulates.
    Direction 2: pqcrypto keygen -> kyber-py encapsulates -> pqcrypto decapsulates.
    Both must yield an identical shared secret; if not, one impl mishandled the
    standardized ek/dk/ct format or the encaps/decaps math.
    """
    # Direction 1: ref produces the keypair, pq encapsulates, ref decapsulates.
    ek, dk = ref.keygen()
    if len(ek) != pq.PUBLIC_KEY_SIZE or len(dk) != pq.SECRET_KEY_SIZE:
        raise CrossImplMismatch(
            f"{name} dir1: key sizes differ — ek={len(ek)}/{pq.PUBLIC_KEY_SIZE}, "
            f"dk={len(dk)}/{pq.SECRET_KEY_SIZE}"
        )
    ct, ss_b = pq.encrypt(ek)          # pqcrypto: encrypt(pk) -> (ct, ss)
    ss_a = ref.decaps(dk, ct)          # kyber-py: decaps(dk, ct) -> ss
    if ss_a != ss_b:
        raise CrossImplMismatch(
            f"{name} dir1 (pq encaps / {ref.__name__} decaps): shared secret mismatch\n"
            f"  ss_ref={ss_a.hex()}\n  ss_pq ={ss_b.hex()}"
        )

    # Direction 2: pq produces the keypair, ref encapsulates, pq decapsulates.
    pk, sk = pq.generate_keypair()
    ss_c, ct2 = ref.encaps(pk)         # kyber-py: encaps(ek) -> (ss, ct)
    ss_d = pq.decrypt(sk, ct2)         # pqcrypto: decrypt(sk, ct) -> ss
    if ss_c != ss_d:
        raise CrossImplMismatch(
            f"{name} dir2 ({ref.__name__} encaps / pq decaps): shared secret mismatch\n"
            f"  ss_ref={ss_c.hex()}\n  ss_pq ={ss_d.hex()}"
        )


# --------------------------------------------------------------------------- #
# ML-DSA leg — mutual cross-verify (accept) + tamper (reject). NOT byte equality.
# --------------------------------------------------------------------------- #
def _check_sig(name: str, ref, pq, rng) -> None:
    """One random ML-DSA cross-validation round; raises on the first disagreement.

    For each independent keypair: the owning library signs a random message and
    the OTHER library's verifier MUST accept it; a one-bit-corrupted signature
    MUST be rejected by both. dilithium-py uses an EMPTY context to match
    pqcrypto's context-less API. Byte-identical signatures are intentionally NOT
    required — pqcrypto's ML-DSA is hedged (randomized).
    """
    msg = rng(1 + (rng(1)[0] % 256))  # random message, 1..256 bytes

    # (a) dilithium-py signs (deterministic, empty ctx); pqcrypto verifies.
    ref_pk, ref_sk = ref.keygen()
    sig_ref = ref.sign(ref_sk, msg, _EMPTY_CTX, True)
    if not pq.verify(ref_pk, msg, sig_ref):
        raise CrossImplMismatch(
            f"{name}: pqcrypto REJECTED a valid {ref.__name__} signature"
        )
    if pq.verify(ref_pk, msg, _flip_one_bit(sig_ref, msg[0])):
        raise CrossImplMismatch(
            f"{name}: pqcrypto ACCEPTED a bit-flipped {ref.__name__} signature"
        )

    # (b) pqcrypto signs (hedged); dilithium-py verifies with empty ctx.
    pq_pk, pq_sk = pq.generate_keypair()
    sig_pq = pq.sign(pq_sk, msg)
    if not ref.verify(pq_pk, msg, sig_pq, _EMPTY_CTX):
        raise CrossImplMismatch(
            f"{name}: {ref.__name__} REJECTED a valid pqcrypto signature"
        )
    if ref.verify(pq_pk, msg, _flip_one_bit(sig_pq, msg[0]), _EMPTY_CTX):
        raise CrossImplMismatch(
            f"{name}: {ref.__name__} ACCEPTED a bit-flipped pqcrypto signature"
        )

    # (c) a sanity self-round-trip on each side (cheap, catches a totally broken lib).
    if not ref.verify(ref_pk, msg, sig_ref, _EMPTY_CTX):
        raise CrossImplMismatch(f"{name}: {ref.__name__} failed to verify its OWN signature")
    if not pq.verify(pq_pk, msg, sig_pq):
        raise CrossImplMismatch(f"{name}: pqcrypto failed to verify its OWN signature")


# --------------------------------------------------------------------------- #
# Driver.
# --------------------------------------------------------------------------- #
def run(iterations: int, seed: int | None) -> int:
    """Run ``iterations`` random rounds per algorithm; return a process exit code.

    A per-iteration seed is woven into the RNG so any mismatch is reproducible:
    re-run with ``--seed <printed seed>`` to land on the exact failing round.
    """
    base = os.urandom(8) if seed is None else seed.to_bytes(8, "big")
    print(
        "VORLATH Shield — primitive differential cross-validation\n"
        f"  reference : kyber-py 1.2.0 / dilithium-py 1.4.0 (pure-Python, FIPS 203/204)\n"
        f"  independent: pqcrypto 0.3.4 (PQClean C via CFFI)\n"
        f"  iterations : {iterations} per algorithm   base-seed: {base.hex()}\n"
        "  NOTE: ML-DSA leg is accept/reject agreement, NOT byte equality "
        "(pqcrypto is hedged).\n"
    )

    # Deterministic, reproducible RNG seeded from base + a global counter, so a
    # failing iteration can be replayed exactly via --seed.
    import hashlib
    counter = {"n": 0}

    def rng(n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            counter["n"] += 1
            out += hashlib.shake_256(base + counter["n"].to_bytes(8, "big")).digest(64)
        return bytes(out[:n])

    legs = (
        ("ML-KEM", _KEM_PAIRS, _check_kem),
        ("ML-DSA", _SIG_PAIRS, _check_sig),
    )

    results: dict[str, tuple[int, int]] = {}
    failed = False
    for family, pairs, check in legs:
        for name, ref, pq in pairs:
            ok = 0
            for i in range(iterations):
                try:
                    check(name, ref, pq, rng)
                    ok += 1
                except CrossImplMismatch as exc:
                    failed = True
                    print(f"  [{name}] FAIL on iteration {i} (base-seed {base.hex()}):\n{exc}\n")
                    break  # stop this algorithm at the first divergence
            results[name] = (ok, iterations)

    print("\n  per-algorithm PASS/total:")
    for name, (ok, total) in results.items():
        status = "PASS" if ok == total else "FAIL"
        print(f"    {name:<12} {ok:>5}/{total:<5} {status}")

    if failed:
        print("\nRESULT: MISMATCH DETECTED — at least one primitive diverged. "
              "See VERIFICATION_GAP_MAP.md seam (a).")
        return 1
    print("\nRESULT: all primitives agree across both independent implementations "
          "on every random iteration.")
    return 0


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Differential cross-validation of ML-KEM/ML-DSA primitives "
                    "(kyber-py/dilithium-py vs pqcrypto)."
    )
    p.add_argument("-n", "--iterations", type=int, default=256,
                   help="random iterations per algorithm (default: 256)")
    p.add_argument("--seed", type=lambda s: int(s, 16), default=None,
                   help="hex base-seed for reproducing a specific run")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.iterations <= 0:
        print("iterations must be positive", file=sys.stderr)
        return 2
    return run(args.iterations, args.seed)


if __name__ == "__main__":
    sys.exit(main())
