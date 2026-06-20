"""Deterministic KAT / conformance harness for the FIPS 203/204 primitives the Shield uses.

Re-drives the standards' deterministic internals from fixed seeds and asserts byte-exact
agreement with pinned vectors (kat_vectors.json). This proves:
  * the ML-KEM key-gen / encaps / decaps are deterministic and self-consistent,
  * ML-DSA deterministic signing is reproducible and verifies,
  * the installed kyber-py / dilithium-py have not drifted (regression guard).

HONEST SCOPE: these are determinism + regression vectors, NOT official NIST ACVP vectors.
Cross-validation against the NIST ACVP server vectors is the FIPS-conformance step on the
path to production (see SECURITY.md). Regenerate with: python gen_kat_vectors.py
"""
import hashlib
import json
import os

import pytest
from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87
from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = json.load(open(os.path.join(HERE, "kat_vectors.json"), encoding="utf-8"))
SEEDS = VECTORS["_meta"]["seeds"]
D = bytes.fromhex(SEEDS["d"]); Z = bytes.fromhex(SEEDS["z"]); M = bytes.fromhex(SEEDS["m"])
ZETA = bytes.fromhex(SEEDS["zeta"]); MSG = SEEDS["msg"].encode(); CTX = SEEDS["ctx"].encode()

KEMS = {"ML-KEM-512": ML_KEM_512, "ML-KEM-768": ML_KEM_768, "ML-KEM-1024": ML_KEM_1024}
DSAS = {"ML-DSA-44": ML_DSA_44, "ML-DSA-65": ML_DSA_65, "ML-DSA-87": ML_DSA_87}
# FIPS 203 byte sizes (Table 3): ek, dk, ct
FIPS203_SIZES = {"ML-KEM-512": (800, 1632, 768), "ML-KEM-768": (1184, 2400, 1088),
                 "ML-KEM-1024": (1568, 3168, 1568)}


@pytest.mark.parametrize("name", list(KEMS))
def test_ml_kem_kat(name):
    K = KEMS[name]; exp = VECTORS["ml_kem"][name]
    ek, dk = K._keygen_internal(D, Z)
    ss, ct = K._encaps_internal(ek, M)
    ss_dec = K._decaps_internal(dk, ct)
    assert sha256_hex(ek) == exp["ek_sha256"], "ML-KEM ek drift"
    assert sha256_hex(dk) == exp["dk_sha256"], "ML-KEM dk drift"
    assert sha256_hex(ct) == exp["ct_sha256"], "ML-KEM ct drift"
    assert ss.hex() == exp["ss"], "ML-KEM shared-secret drift"
    assert ss_dec == ss, "ML-KEM encaps/decaps disagree"
    assert (len(ek), len(dk), len(ct)) == FIPS203_SIZES[name], "ML-KEM size != FIPS 203"


@pytest.mark.parametrize("name", list(DSAS))
def test_ml_dsa_kat(name):
    Dsa = DSAS[name]; exp = VECTORS["ml_dsa"][name]
    pk, sk = Dsa._keygen_internal(ZETA)
    sig = Dsa.sign(sk, MSG, CTX, True)  # deterministic
    assert sha256_hex(pk) == exp["pk_sha256"], "ML-DSA pk drift"
    assert sha256_hex(sk) == exp["sk_sha256"], "ML-DSA sk drift"
    assert sha256_hex(sig) == exp["sig_sha256"], "ML-DSA deterministic-sig drift"
    assert Dsa.verify(pk, MSG, sig, CTX)
    assert not Dsa.verify(pk, MSG, sig, b"wrong-ctx"), "ctx separation broken"


@pytest.mark.parametrize("name", list(KEMS))
def test_ml_kem_is_deterministic(name):
    K = KEMS[name]
    assert K._keygen_internal(D, Z) == K._keygen_internal(D, Z)
    ek, _ = K._keygen_internal(D, Z)
    assert K._encaps_internal(ek, M) == K._encaps_internal(ek, M)


@pytest.mark.parametrize("name", list(DSAS))
def test_ml_dsa_deterministic_signing(name):
    Dsa = DSAS[name]
    pk, sk = Dsa._keygen_internal(ZETA)
    assert Dsa.sign(sk, MSG, CTX, True) == Dsa.sign(sk, MSG, CTX, True)
