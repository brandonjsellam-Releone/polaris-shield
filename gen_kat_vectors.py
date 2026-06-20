"""Generate deterministic KAT reference vectors for the POLARIS Shield conformance harness.

These are DETERMINISM / REGRESSION vectors: fixed seeds driven through the FIPS 203/204
deterministic internals, pinned so any drift in kyber-py/dilithium-py is caught byte-for-byte.
They are NOT a substitute for official NIST ACVP cross-validation (the production step).
Run: python gen_kat_vectors.py  -> writes kat_vectors.json
"""
import hashlib
import json
import os

from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87
from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024

# Fixed, reproducible seeds (documented constants, not secrets).
D = bytes(range(32))
Z = bytes(range(32, 64))
M = bytes([0xA5]) * 32
ZETA = bytes(range(32))
MSG = b"POLARIS KAT vector"
CTX = b"POLARIS-Shield/sig/v1"


def _h(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


vectors = {"_meta": {
    "kind": "deterministic regression/determinism vectors",
    "seeds": {"d": D.hex(), "z": Z.hex(), "m": M.hex(), "zeta": ZETA.hex(),
              "msg": MSG.decode(), "ctx": CTX.decode()},
    "note": "NOT official NIST ACVP vectors; cross-validate against ACVP for FIPS conformance.",
}, "ml_kem": {}, "ml_dsa": {}}

for name, K in [("ML-KEM-512", ML_KEM_512), ("ML-KEM-768", ML_KEM_768), ("ML-KEM-1024", ML_KEM_1024)]:
    ek, dk = K._keygen_internal(D, Z)
    ss, ct = K._encaps_internal(ek, M)
    ss_dec = K._decaps_internal(dk, ct)
    assert ss == ss_dec, f"{name} encaps/decaps mismatch"
    vectors["ml_kem"][name] = {"ek_sha256": _h(ek), "dk_sha256": _h(dk),
                               "ct_sha256": _h(ct), "ss": ss.hex(),
                               "ek_len": len(ek), "dk_len": len(dk), "ct_len": len(ct)}

for name, Dsa in [("ML-DSA-44", ML_DSA_44), ("ML-DSA-65", ML_DSA_65), ("ML-DSA-87", ML_DSA_87)]:
    pk, sk = Dsa._keygen_internal(ZETA)
    sig = Dsa.sign(sk, MSG, CTX, True)  # deterministic
    assert Dsa.verify(pk, MSG, sig, CTX), f"{name} verify failed"
    vectors["ml_dsa"][name] = {"pk_sha256": _h(pk), "sk_sha256": _h(sk),
                               "sig_sha256": _h(sig), "sig_len": len(sig)}

out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "kat_vectors.json")
with open(out, "w", encoding="utf-8") as f:
    json.dump(vectors, f, indent=2)
print("WROTE", out)
print(json.dumps(vectors, indent=2))
