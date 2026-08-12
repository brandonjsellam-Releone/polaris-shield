"""The TNO conformance claim, enforced against the CODE rather than against a second literal.

WHY THIS FILE EXISTS
────────────────────────────────────────────────────────────────────────────────────────────────
`test_tno_conformance.py` says it "FAILS the build the moment a TNO-deprecated primitive (MD5,
SHA-1, 3DES, RC4, ...) is added", and `TNO_PQC_SELF_ASSESSMENT.md` repeats that to a
government-facing audience as a "(CI gate)". It does not do this.

Its six tests compare `cbom/cbom.cdx.json` against `TNO_TABLE_4_1`, a dict in the test file.
The JSON is produced by `cbom/make_cbom.py`, whose `ASSETS` is a hand-typed literal whose own
docstring says it is "generated from the DESIGN ... not a binary scan". So the chain is

    literal ASSETS  ->  committed JSON  ->  literal TNO table

three hardcoded artifacts compared to each other, with **no input from vorlath_shield/*.py**.
`test_tno_conformance.py` never imports the package. Adding `hashlib.md5(...)` to shield.py
leaves all six tests green: the suite fails only if a developer volunteers the violation by
hand-editing ASSETS and regenerating.

This module closes that by reading the source. It walks the shipped package with `ast` and
answers two questions the literal-to-literal chain cannot:

  1. Does the code reference a TNO-deprecated primitive?  -> fail, loudly, naming it.
  2. Does the code use a primitive the CBOM does not declare?  -> fail; an inventory that
     omits what the code actually calls is not an inventory.

An `ast` walk over source is deliberately chosen over importing and introspecting: it sees
code on paths that are never executed, which is exactly where a stray primitive hides.

LIMITS, stated so this is not over-read. This is a lexical/AST scan, not a proof. It sees
`hashlib.md5`, `from hashlib import md5`, and deprecated names in string literals used as
algorithm selectors. It does NOT see a primitive reached through `getattr(hashlib, name)` with a
computed name, through a C extension, or inside a dependency. Depth here buys little: the
threat is an accidental addition by a maintainer, not an adversary hiding one from the scanner.
"""

import ast
import json
import pathlib

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent
_PKG = _ROOT / "vorlath_shield"
_CBOM = _ROOT / "cbom" / "cbom.cdx.json"

# TNO PQC Handbook Table 4.1 "Deprecated" / classically broken. Names as they appear in code:
# attribute names (hashlib.md5), import names, and the strings used as algorithm selectors.
_DEPRECATED = {
    "md5": "MD5 - collision-broken (TNO Table 4.1 Deprecated)",
    "md4": "MD4 - broken",
    "sha1": "SHA-1 - SHAttered / chosen-prefix collisions (Deprecated)",
    "rc4": "RC4 - biased keystream (Deprecated)",
    "des": "DES - 56-bit key (Deprecated)",
    "3des": "3DES - Sweet32, 64-bit block (Deprecated)",
    "tripledes": "3DES (Deprecated)",
    "blowfish": "Blowfish - 64-bit block (Deprecated)",
    "cast5": "CAST5 - 64-bit block (Deprecated)",
    "idea": "IDEA (Deprecated)",
    "arc4": "ARC4 (Deprecated)",
}

# What each CBOM component name looks like when it appears in code. Only entries that are
# genuinely observable in source are listed; a component with no observable form is not
# evidence of anything and is skipped rather than faked.
_CBOM_CODE_FORMS = {
    "ML-KEM-768": {"ML_KEM_768"},
    "ML-KEM-1024": {"ML_KEM_1024"},
    "ML-DSA-65": {"ML_DSA_65"},
    "ML-DSA-87": {"ML_DSA_87"},
    "X25519": {"X25519PrivateKey", "X25519PublicKey"},
    "X448": {"X448PrivateKey", "X448PublicKey"},
    "AES-256-GCM": {"AESGCM"},
    "SHA-256": {"SHA256", "sha256"},
    "SHA-384": {"SHA384", "sha384"},
    "SHAKE-256": {"shake_256"},
    "HKDF-SHA256": {"HKDF"},
    "HKDF-SHA384": {"HKDF"},
    "scrypt": {"scrypt"},
    "SLH-DSA": {"slhdsa"},
}


def _sources() -> list[pathlib.Path]:
    files = sorted(_PKG.rglob("*.py"))
    assert files, f"no sources found under {_PKG} - this guard would pass vacuously"
    return files


def _names_in(path: pathlib.Path) -> set[str]:
    """Every identifier-ish token the AST exposes: attributes, imported names, and string
    literals (algorithm selectors are routinely strings)."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            found.add(node.attr)
        elif isinstance(node, ast.Name):
            found.add(node.id)
        elif isinstance(node, ast.alias):
            found.add(node.name.rsplit(".", 1)[-1])
            if node.asname:
                found.add(node.asname)
        elif isinstance(node, ast.Import):
            for a in node.names:
                found.update(a.name.split("."))
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                found.update(node.module.split("."))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            found.add(node.value)
    return found


def _normalise(token: str) -> str:
    return token.lower().replace("-", "").replace("_", "")


@pytest.mark.parametrize("path", _sources(), ids=lambda p: p.name)
def test_no_deprecated_primitive_in_shipped_code(path):
    """The claim `test_tno_conformance.py` makes, actually enforced against the source."""
    hits = []
    for token in _names_in(path):
        norm = _normalise(token)
        for bad, why in _DEPRECATED.items():
            # Exact match after normalisation. Substring matching produces nonsense - "sha1"
            # would fire on "sha1024", and "des" on "describe" - and a guard that cries wolf
            # gets switched off, which is worse than not having it.
            if norm == bad:
                hits.append(f"{token!r}: {why}")
    assert not hits, (
        f"TNO-deprecated primitive referenced in {path.relative_to(_ROOT)}:\n  "
        + "\n  ".join(sorted(set(hits)))
        + "\n\nTNO_PQC_SELF_ASSESSMENT.md states to a government-facing reader that this fails "
        "CI. Removing the primitive is the fix; editing this list is not."
    )


def test_every_primitive_the_code_uses_is_declared_in_the_cbom():
    """An inventory that omits what the code actually calls is not an inventory.

    The direction matters: `test_tno_conformance.py` checks CBOM-against-table, so a component
    declared but unused is caught. The reverse - used but undeclared - is what this covers, and
    is the direction a new primitive actually arrives from.
    """
    declared = {c["name"] for c in json.loads(_CBOM.read_text(encoding="utf-8"))["components"]}
    tokens = set()
    for path in _sources():
        tokens |= {_normalise(t) for t in _names_in(path)}

    missing = []
    for component, forms in _CBOM_CODE_FORMS.items():
        if component in declared:
            continue
        if any(_normalise(f) in tokens for f in forms):
            missing.append(component)
    assert not missing, (
        "the code references primitives the CBOM does not declare: " + ", ".join(sorted(missing))
    )


def test_the_scanner_can_actually_fail():
    """A guard that cannot fail is the defect this repo keeps finding. Prove this one can.

    Runs the extraction against synthetic source rather than trusting that the assertions above
    would fire - they pass today precisely because the code is clean, which is indistinguishable
    from a scanner that sees nothing.
    """
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        probe = pathlib.Path(td) / "probe.py"
        probe.write_text(
            "import hashlib\n"
            "def fingerprint(b):\n"
            "    return hashlib.md5(b).hexdigest()\n",
            encoding="utf-8",
        )
        tokens = {_normalise(t) for t in _names_in(probe)}
    assert "md5" in tokens, "the AST walk did not see hashlib.md5; the guards above are vacuous"
    assert "sha512" not in tokens, "the AST walk invented a token that is not in the source"
