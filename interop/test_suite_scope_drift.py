"""Cross-check altcodec's coverage against the reference implementation (TCE-20).

The problem this closes
-----------------------
`vorlath_shield.shield` defines suites {0x01, 0x02, 0x03} and flags
{FLAG_AUTHENTICATED, FLAG_PPK}. `interop/altcodec.py` implements suites {0x01, 0x02} and no
PPK at all. Nothing noticed:

  * `gen_pstv_vectors.py` hard-coded `SUITES = [0x01, 0x02]`, so the corpus could never grow a
    suite even in principle, while its own docstring said it "covers BOTH suites";
  * `altcodec`'s scope note named suites 0x01/0x02 in prose, which was accurate when written
    and became stale the moment 0x03 landed;
  * nothing mentioned `FLAG_PPK` anywhere in `interop/` (`grep -ri ppk interop/` -> nothing).

The consequence is a coverage gap, not a vulnerability: both paths fail closed, and altcodec
never accepts anything the reference rejects. But the two NEWEST crypto features -- the pure-PQC
suite that deliberately drops the classical leg, and the RFC 8784 PPK combiner leg -- are
precisely the two with no independent cross-check, which is the wrong way round.

What is enforced here
---------------------
Coverage may be partial; it may not be ACCIDENTAL. Every suite and flag the reference defines
must be either implemented by altcodec or listed in its `OUT_OF_SCOPE_*` tables with a reason.
Adding a suite or flag to `shield.py` now fails this file until someone makes that call.

And the declarations must be true: a table like this is only worth having if it cannot be used
to wave through something that is actually broken, so each entry is checked against behaviour.
"""

from __future__ import annotations

import ast
import inspect
import json
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (_ROOT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import altcodec  # noqa: E402
import gen_pstv_vectors  # noqa: E402
from vorlath_shield import shield  # noqa: E402

_VECTORS = json.load(open(os.path.join(_HERE, "pstv_vectors.json"), encoding="utf-8"))

# FORMAT.md 2.2 / altcodec.py:236 -- `suite_id, flags = envelope[5], envelope[6]`.
_SUITE_OFFSET, _FLAGS_OFFSET = 5, 6
_VRSH = b"VRSH"


def _reference_flags() -> dict[str, int]:
    """Every FLAG_* the reference defines, read off the module rather than hand-listed."""
    return {k: v for k, v in vars(shield).items() if k.startswith("FLAG_") and isinstance(v, int)}


def _positive_single_shot():
    """Corpus vectors that are meant to decode (not the 46 negatives), single-shot only."""
    for vec in _VECTORS["vectors"]:
        if vec["kind"] == "negative":
            continue
        env = bytes.fromhex(vec["envelope"])
        if env[:4] == _VRSH:
            yield vec, env


# --------------------------------------------------------------------------------------------
# Suites
# --------------------------------------------------------------------------------------------

def test_every_reference_suite_is_implemented_or_declared_out_of_scope() -> None:
    implemented = set(altcodec._SUITES)
    declared = set(altcodec.OUT_OF_SCOPE_SUITES)
    missing = set(shield.SUITES) - implemented - declared
    assert not missing, (
        f"shield defines suite(s) {sorted(hex(s) for s in missing)} that altcodec neither "
        f"implements nor declares out of scope. Either implement them in altcodec._SUITES or "
        f"add them to altcodec.OUT_OF_SCOPE_SUITES with a reason -- an undeclared gap means the "
        f"cross-check silently stops covering part of the format."
    )


def test_no_suite_is_both_implemented_and_declared_out_of_scope() -> None:
    overlap = set(altcodec._SUITES) & set(altcodec.OUT_OF_SCOPE_SUITES)
    assert not overlap, f"suite(s) {sorted(hex(s) for s in overlap)} are both implemented and declared out of scope"


def test_out_of_scope_suites_do_not_name_something_the_reference_dropped() -> None:
    """A stale exclusion is its own bug: it would hide a suite the reference no longer has."""
    stale = set(altcodec.OUT_OF_SCOPE_SUITES) - set(shield.SUITES)
    assert not stale, (
        f"altcodec declares suite(s) {sorted(hex(s) for s in stale)} out of scope, but the "
        f"reference does not define them at all -- delete the stale entry"
    )


@pytest.mark.parametrize("suite_id", sorted(altcodec.OUT_OF_SCOPE_SUITES))
def test_declared_out_of_scope_suite_is_genuinely_unsupported(suite_id: int) -> None:
    """Make the declaration earn its place: the suite must actually be rejected.

    Uses a real corpus envelope with only the suite byte patched, so this exercises the live
    parse path rather than asserting a dict lookup back to itself.
    """
    assert suite_id not in altcodec._SUITES

    vec, env = next(_positive_single_shot())
    patched = env[:_SUITE_OFFSET] + bytes([suite_id]) + env[_SUITE_OFFSET + 1:]
    priv = bytes.fromhex(vec["recipient_private"])

    with pytest.raises(altcodec.AltCodecError):
        altcodec.open_envelope(patched, priv)


# --------------------------------------------------------------------------------------------
# Flags
# --------------------------------------------------------------------------------------------

def test_every_reference_flag_is_declared_or_exercised_by_a_positive_vector() -> None:
    """Each flag the reference defines is either declared out of scope or actually cross-checked.

    "Exercised" is read off the envelope's flags byte, not off the vector's `kind` label -- a
    label is another hand-typed string that can drift from the bytes it describes.
    """
    covered = 0
    for _vec, env in _positive_single_shot():
        covered |= env[_FLAGS_OFFSET]

    declared = set(altcodec.OUT_OF_SCOPE_FLAGS)
    unchecked = {
        name: bit for name, bit in _reference_flags().items()
        if bit not in declared and not (covered & bit)
    }
    assert not unchecked, (
        f"shield defines {sorted(unchecked)} but no positive PSTV vector sets those bits, and "
        f"altcodec does not declare them out of scope. The cross-check reports success without "
        f"ever exercising that flag."
    )


def test_out_of_scope_flags_are_flags_the_reference_actually_defines() -> None:
    known = set(_reference_flags().values())
    stale = set(altcodec.OUT_OF_SCOPE_FLAGS) - known
    assert not stale, f"altcodec declares unknown flag bit(s) {sorted(hex(b) for b in stale)} out of scope"


def test_declared_out_of_scope_flag_is_genuinely_unsupported() -> None:
    """FLAG_PPK: altcodec has no way to supply a pre-shared key, so it cannot decode one.

    Checked against the real signature rather than a comment -- if someone adds `ppk` support,
    this fails and the exclusion has to be removed, which is the intended direction of travel.
    """
    assert shield.FLAG_PPK in altcodec.OUT_OF_SCOPE_FLAGS
    params = inspect.signature(altcodec.open_envelope).parameters
    assert "ppk" not in params, (
        "altcodec.open_envelope now accepts a `ppk` argument -- FLAG_PPK may be supported, so "
        "remove it from OUT_OF_SCOPE_FLAGS and add a positive PSTV vector for it"
    )


# --------------------------------------------------------------------------------------------
# The generator
# --------------------------------------------------------------------------------------------

def test_generator_suite_list_has_the_right_value() -> None:
    """Necessary but NOT sufficient -- see the AST test below for why."""
    expected = sorted(set(shield.SUITES) - set(altcodec.OUT_OF_SCOPE_SUITES))
    assert gen_pstv_vectors.SUITES == expected


def test_generator_suite_list_is_computed_rather_than_typed() -> None:
    """The value check above cannot see a regression, because today the answers coincide.

    `SUITES` was the literal `[0x01, 0x02]`, and the derived expression evaluates to exactly
    `[0x01, 0x02]` right now. So reverting to the literal would leave the value test green --
    a comparison whose two sides agree by construction, which is the defect shape this whole
    exercise is about. Assert on the SOURCE instead: the list must be computed.
    """
    src = ast.parse(
        open(os.path.join(_HERE, "gen_pstv_vectors.py"), encoding="utf-8").read(),
        filename="gen_pstv_vectors.py",
    )
    assigns = [
        node for node in src.body
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "SUITES" for t in node.targets)
    ]
    assert assigns, "gen_pstv_vectors.py no longer assigns SUITES at module level"
    for node in assigns:
        assert not isinstance(node.value, (ast.List, ast.Tuple, ast.Set)), (
            f"gen_pstv_vectors.py:{node.lineno}: SUITES is a hand-typed literal again. It must be "
            f"derived from shield.SUITES, or the corpus silently stops covering suites the "
            f"reference adds -- which is how 0x03 went uncovered."
        )


def test_generator_labels_every_suite_it_will_mint() -> None:
    """A derived SUITES with a hand-typed label table would KeyError on the next suite added."""
    missing = [hex(s) for s in gen_pstv_vectors.SUITES if s not in gen_pstv_vectors.SUITE_LABEL]
    assert not missing, f"no SUITE_LABEL for {missing}"


def test_corpus_metadata_agrees_with_the_corpus_contents() -> None:
    """`meta.suite_ids` is what an external implementer reads to learn what the corpus covers."""
    declared = {int(k, 16) for k in _VECTORS["meta"]["suite_ids"]}
    present = {vec["suite_id"] for vec in _VECTORS["vectors"] if vec["kind"] != "negative"}
    assert present <= declared, f"corpus contains suites {sorted(present - declared)} that meta does not list"
