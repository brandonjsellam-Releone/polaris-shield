"""TNO PQC Migration Handbook conformance — machine-check the Shield's crypto inventory in CI.

Backs the "CONFORM" claims in TNO_PQC_HANDBOOK_ALIGNMENT.md with code, not prose. Every primitive
the Shield's CBOM lists must sit in the TNO Handbook (2nd ed., Dec 2024) Table 4.1 Recommended /
Acceptable columns; the quantum-vulnerable classical primitives (ECDH / EdDSA) are allowed ONLY as
hybrid legs (Table 4.1 footnote 3: "secure against classical attacks and can be part of a hybrid
scheme"), never standalone. This FAILS the build the moment a TNO-deprecated primitive (MD5, SHA-1,
3DES, RC4, plain ECDH/RSA used alone, ...) or a standalone classical primitive is added.

Run: cd tech && python -m pytest -q test_tno_conformance.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pytest  # noqa: E402

CBOM = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cbom", "cbom.cdx.json")

# TNO Handbook 2nd ed. (Dec 2024), Table 4.1, keyed by the Shield's CBOM asset name.
#   "recommended" / "acceptable" : usable as listed.
#   "hybrid-leg" : Shor-broken and DEPRECATED standalone, but Table 4.1 fn 3 allows it as a hybrid
#                  leg. Enforced hybrid-only below.
#   (absence) : not classified -> a new asset must be consciously placed before it can ship.
TNO_TABLE_4_1 = {
    # post-quantum KEMs (ML-KEM = Recommended; §4.2.1)
    "ML-KEM-768": "recommended", "ML-KEM-1024": "recommended",
    # post-quantum signatures (ML-DSA + SLH-DSA = Recommended; "ML-DSA and SLH-DSA over FN-DSA")
    "ML-DSA-65": "recommended", "ML-DSA-87": "recommended", "SLH-DSA": "recommended",
    # classical legs: Deprecated standalone, hybrid-OK (Table 4.1 fn 3)
    "X25519": "hybrid-leg", "X448": "hybrid-leg", "Ed25519": "hybrid-leg", "Ed448": "hybrid-leg",
    # symmetric / hash / KDF
    "AES-256-GCM": "recommended",                    # AEAD: AES-GCM Recommended
    "SHA-256": "recommended", "SHA-384": "recommended",  # SHA-2 Recommended
    "SHAKE-256": "recommended",                      # SHA-3 family Recommended
    "HKDF-SHA256": "recommended", "HKDF-SHA384": "recommended",  # HMAC-SHA-2 (MAC) / SP 800-56C KDF
    "scrypt": "acceptable",                          # memory-hard pw-KDF (RFC 7914); TNO cites Argon2 as the example
}
ALLOWED = {"recommended", "acceptable", "hybrid-leg"}


def _assets():
    with open(CBOM, encoding="utf-8") as f:
        return json.load(f)["components"]


def _props(component):
    return {p["name"]: p["value"] for p in component.get("properties", [])}


def test_cbom_present_and_nonempty():
    assert len(_assets()) >= 14


def test_every_primitive_is_tno_classified():
    # Forces a conscious TNO decision on any newly-added crypto asset (no silent additions).
    unknown = [c["name"] for c in _assets() if c["name"] not in TNO_TABLE_4_1]
    assert not unknown, f"primitives not classified against TNO Table 4.1: {unknown}"


def test_no_tno_deprecated_primitive():
    bad = [c["name"] for c in _assets() if TNO_TABLE_4_1.get(c["name"]) not in ALLOWED]
    assert not bad, f"TNO-deprecated primitive present in the Shield: {bad}"


def test_pq_primitives_are_recommended_not_merely_acceptable():
    for c in _assets():
        n = c["name"]
        if n.startswith(("ML-KEM", "ML-DSA", "SLH-DSA")):
            assert TNO_TABLE_4_1[n] == "recommended", f"{n} should be TNO-Recommended"


def test_classical_legs_are_hybrid_only():
    # Every Shor-broken classical primitive must be quantum-vulnerable AND used only in a hybrid
    # context (a wire suite, or the opt-in triple-sign) — never as a standalone primitive.
    for c in _assets():
        n = c["name"]
        if TNO_TABLE_4_1.get(n) == "hybrid-leg":
            p = _props(c)
            assert p.get("vorlath:quantum-resistant") == "false", f"{n} should be marked classical"
            usage = p.get("vorlath:used-in-suite", "")
            assert ("0x0" in usage) or ("hybrid" in usage) or ("triple" in usage), \
                f"{n} must be hybrid-only; CBOM usage = {usage!r}"


def test_at_least_two_disjoint_pq_signature_families():
    # The Shield must carry both a lattice (ML-DSA) and a hash-based (SLH-DSA) PQ signature, so the
    # high-assurance dual/triple hedge is actually instantiable (TNO defense-in-depth intent).
    names = {c["name"] for c in _assets()}
    assert any(n.startswith("ML-DSA") for n in names), "no lattice PQ signature"
    assert "SLH-DSA" in names, "no hash-based PQ signature"
