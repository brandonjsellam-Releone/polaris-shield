"""NIST ACVP conformance — validate the FIPS 203/204 primitives the Shield uses against
OFFICIAL NIST ACVP vectors (vendored subset in acvp/acvp_vectors.json).

Coverage: ML-KEM keyGen / encapsulation / decapsulation (FIPS 203), including the
non-happy paths — the FO-transform IMPLICIT-REJECTION branch (a modified ciphertext must
yield the deterministic secret K = J(z‖c), not an error) and the FIPS 203 encapsulation-
and decapsulation-KEY checks (malformed ek/dk must be rejected); ML-DSA keyGen, sigGen and
sigVer (FIPS 204 — external-pure and internal interfaces). A match proves the installed
kyber-py / dilithium-py compute the standard correctly, not merely deterministically. The
sigVer set deliberately mixes VALID and INTENTIONALLY-INVALID signatures (verify must return
True only for the valid ones); likewise the keyCheck set mixes valid and malformed keys, and
the implicit-rejection set carries both FO branches. (SLH-DSA / FIPS 205 sigVer lives in
test_acvp_slhdsa.py. ML-DSA has no key-check ACVP set and dilithium-py exposes no key
validation, so an ML-DSA keyCheck is intentionally absent — see README/SECURITY.)
Refresh with: python scripts/fetch_acvp.py
"""
import json
import os

import pytest
from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87
from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024

HERE = os.path.dirname(os.path.abspath(__file__))
VEC = json.load(open(os.path.join(HERE, "acvp", "acvp_vectors.json"), encoding="utf-8"))
KEM = {"ML-KEM-512": ML_KEM_512, "ML-KEM-768": ML_KEM_768, "ML-KEM-1024": ML_KEM_1024}
DSA = {"ML-DSA-44": ML_DSA_44, "ML-DSA-65": ML_DSA_65, "ML-DSA-87": ML_DSA_87}


def _ids(section):
    return [f"{i}-{v['param']}" for i, v in enumerate(VEC[section])]


def _b(h):
    return bytes.fromhex(h or "")


@pytest.mark.parametrize("v", VEC["ML-KEM keyGen"], ids=_ids("ML-KEM keyGen"))
def test_ml_kem_keygen_acvp(v):
    ek, dk = KEM[v["param"]]._keygen_internal(_b(v["d"]), _b(v["z"]))
    assert ek.hex().lower() == v["ek"].lower()
    assert dk.hex().lower() == v["dk"].lower()


@pytest.mark.parametrize("v", VEC["ML-KEM encaps"], ids=_ids("ML-KEM encaps"))
def test_ml_kem_encaps_acvp(v):
    k, c = KEM[v["param"]]._encaps_internal(_b(v["ek"]), _b(v["m"]))
    assert c.hex().lower() == v["c"].lower()
    assert k.hex().lower() == v["k"].lower()


@pytest.mark.parametrize("v", VEC["ML-KEM decaps"], ids=_ids("ML-KEM decaps"))
def test_ml_kem_decaps_acvp(v):
    k = KEM[v["param"]]._decaps_internal(_b(v["dk"]), _b(v["c"]))
    assert k.hex().lower() == v["k"].lower()


@pytest.mark.parametrize(
    "v", VEC["ML-KEM decaps implicit-rejection"], ids=_ids("ML-KEM decaps implicit-rejection")
)
def test_ml_kem_decaps_implicit_rejection_acvp(v):
    # IND-CCA root: an invalid/modified ciphertext must NOT raise — FIPS 203 Alg. 18
    # returns the deterministic implicit-rejection secret K = J(z || c) (kyber-py's FO
    # transform: select_bytes(K_bar, K_prime, c == c')). For BOTH normal and
    # implicit-rejection ciphertexts the recovered K must equal the official NIST K.
    k = KEM[v["param"]]._decaps_internal(_b(v["dk"]), _b(v["c"]))
    assert k.hex().lower() == v["k"].lower()
    # Cross-check the branch label against the library's own FO comparison so the
    # implicit-rejection cases are provably the implicit-rejection branch, not happy paths.
    K = KEM[v["param"]]
    dk = _b(v["dk"])
    dk_pke, ek_pke = dk[: 384 * K.k], dk[384 * K.k : 768 * K.k + 32]
    h = dk[768 * K.k + 32 : 768 * K.k + 64]
    m_prime = K._k_pke_decrypt(dk_pke, _b(v["c"]))
    _, r_prime = K._G(m_prime + h)
    rejected = K._k_pke_encrypt(ek_pke, m_prime, r_prime) != _b(v["c"])
    assert rejected is (v["branch"] == "implicit-rejection")


@pytest.mark.parametrize("v", VEC["ML-KEM keyCheck"], ids=_ids("ML-KEM keyCheck"))
def test_ml_kem_key_check_acvp(v):
    # FIPS 203 input validation (the non-happy path malformed ek/dk must be REJECTED).
    # kyber-py performs the genuine checks inside its real entry points:
    #   * ek: type (length) + modulus (canonical t_hat encoding), via _encaps_internal.
    #   * dk: type (length) + hash (H(ek_pke) == stored h), via _decaps_internal.
    # A malformed key raises ValueError; a valid key does not. We assert acceptance/
    # rejection matches the official testPassed flag — not a re-implemented check.
    K = KEM[v["param"]]
    if v["kind"] == "ek":
        def run():
            K._encaps_internal(_b(v["key"]), bytes(32))
    else:  # dk: drive the real decaps validation with a correctly-sized dummy ciphertext;
        # the dk type-check and hash-check both run before any ciphertext-dependent work.
        dummy_c = bytes(32 * (K.du * K.k + K.dv))

        def run():
            K._decaps_internal(_b(v["key"]), dummy_c)

    if v["testPassed"]:
        run()  # valid key: must not raise
    else:
        with pytest.raises(ValueError):
            run()  # malformed key: FIPS 203 validation must reject


@pytest.mark.parametrize("v", VEC["ML-DSA keyGen"], ids=_ids("ML-DSA keyGen"))
def test_ml_dsa_keygen_acvp(v):
    pk, sk = DSA[v["param"]]._keygen_internal(_b(v["seed"]))
    assert pk.hex().lower() == v["pk"].lower()
    assert sk.hex().lower() == v["sk"].lower()


@pytest.mark.parametrize("v", VEC["ML-DSA sigGen"], ids=_ids("ML-DSA sigGen"))
def test_ml_dsa_siggen_acvp(v):
    D = DSA[v["param"]]
    if v["iface"] == "external":
        sig = D.sign(_b(v["sk"]), _b(v["message"]), _b(v.get("context", "")), True)
    else:  # internal interface, deterministic (rnd = 32 zero bytes)
        sig = D._sign_internal(_b(v["sk"]), _b(v["message"]), bytes(32))
    assert sig.hex().lower() == v["signature"].lower()


@pytest.mark.parametrize("v", VEC["ML-DSA sigVer"], ids=_ids("ML-DSA sigVer"))
def test_ml_dsa_sigver_acvp(v):
    # Mirror the sigGen collector's interface split: external-pure -> D.verify,
    # internal (non-externalMu) -> D._verify_internal. Some vectors carry an
    # INTENTIONALLY-INVALID signature; verify must return exactly testPassed.
    D = DSA[v["param"]]
    if v["iface"] == "external":
        got = D.verify(_b(v["pk"]), _b(v["message"]), _b(v["signature"]), _b(v.get("context", "")))
    else:  # internal interface
        got = D._verify_internal(_b(v["pk"]), _b(v["message"]), _b(v["signature"]))
    assert got is v["testPassed"]


def test_vectors_are_official():
    assert "NIST ACVP" in VEC["_meta"]["source"]
    for sec in ("ML-KEM keyGen", "ML-KEM encaps", "ML-KEM decaps", "ML-DSA keyGen", "ML-DSA sigGen"):
        assert len(VEC[sec]) >= 9
    # sigVer sections must carry BOTH valid and invalid signatures.
    for sec in ("ML-DSA sigVer", "SLH-DSA sigVer"):
        flags = {v["testPassed"] for v in VEC[sec]}
        assert flags == {True, False}, f"{sec} must mix valid + invalid signatures"
    # The decaps implicit-rejection section must exercise BOTH FO branches for EACH
    # parameter set — otherwise it would only re-cover the happy path.
    ir = VEC["ML-KEM decaps implicit-rejection"]
    assert {v["branch"] for v in ir} == {"normal", "implicit-rejection"}
    for param in KEM:
        branches = {v["branch"] for v in ir if v["param"] == param}
        assert branches == {"normal", "implicit-rejection"}, f"{param} missing an FO branch"
    # The keyCheck section must carry BOTH valid and malformed ek AND dk per parameter set.
    kc = VEC["ML-KEM keyCheck"]
    for param in KEM:
        for kind in ("ek", "dk"):
            flags = {v["testPassed"] for v in kc if v["param"] == param and v["kind"] == kind}
            assert flags == {True, False}, f"{param} {kind} keyCheck must mix valid + malformed"
