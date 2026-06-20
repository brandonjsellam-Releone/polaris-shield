"""NIST ACVP conformance for SLH-DSA (FIPS 205) — the hash-based scheme the Shield's
high-assurance / dual-signature mode (vorlath_shield/highassurance.py) is built on.

Coverage: SLH-DSA sigVer, external-pure interface, for EXACTLY the parameter sets the
high-assurance module deploys — SHAKE-256s (the default) and SHAKE-128s. A handful of
vectors that deliberately mix VALID and INTENTIONALLY-INVALID signatures —
slhdsa.PublicKey.verify_pure must return exactly the ACVP testPassed flag. sigVer is fast
(verification is cheap even when signing is slow), so this stays well under a second.

keyGen is intentionally NOT covered: the pinned slhdsa==0.2.3 exposes only random keygen
(no seed-based interface), so it cannot reproduce ACVP keyGen vectors deterministically.
Vectors are the vendored subset in acvp/acvp_vectors.json. Refresh with:
python scripts/fetch_acvp.py
"""
import json
import os

import pytest
import slhdsa

HERE = os.path.dirname(os.path.abspath(__file__))
VEC = json.load(open(os.path.join(HERE, "acvp", "acvp_vectors.json"), encoding="utf-8"))
# The deployed high-assurance sets (vorlath_shield/highassurance.py): 256s default + 128s.
SLH_PARAMS = {"SLH-DSA-SHAKE-256s": slhdsa.shake_256s, "SLH-DSA-SHAKE-128s": slhdsa.shake_128s}


def _b(h):
    return bytes.fromhex(h or "")


def _ids(section):
    return [f"{i}-{v['param']}-{'valid' if v['testPassed'] else 'invalid'}"
            for i, v in enumerate(VEC[section])]


@pytest.mark.parametrize("v", VEC["SLH-DSA sigVer"], ids=_ids("SLH-DSA sigVer"))
def test_slh_dsa_sigver_acvp(v):
    pub = slhdsa.PublicKey.from_digest(_b(v["pk"]), SLH_PARAMS[v["param"]])
    got = pub.verify_pure(_b(v["message"]), _b(v["signature"]), _b(v.get("context", "")))
    assert got is v["testPassed"]


def test_slhdsa_vectors_present_and_mixed():
    assert "NIST ACVP" in VEC["_meta"]["source"]
    sec = VEC["SLH-DSA sigVer"]
    assert len(sec) >= 3
    assert {v["testPassed"] for v in sec} == {True, False}


def test_slhdsa_acvp_covers_the_deployed_sets():
    # The ACVP sigVer vectors must cover EXACTLY the SLH-DSA sets the product ships, so the
    # 'ACVP-validated' claim cannot drift away from what highassurance.py actually deploys.
    from vorlath_shield import highassurance as ha

    deployed = {name.split(" ", 1)[0] for _param, name in ha._HA_PARAMS.values()}
    assert deployed == {"SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-128s"}
    covered = {v["param"] for v in VEC["SLH-DSA sigVer"]}
    assert covered == deployed
