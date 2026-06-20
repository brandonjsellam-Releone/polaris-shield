"""test_pstv — cross-implementation interoperability proof.

Reads the FROZEN ``interop/pstv_vectors.json`` corpus (never the generator) and,
for every vector, checks that two SEPARATELY-CODED implementations (which share the
same primitive libraries) agree:

  * the REFERENCE ``vorlath_shield`` (shield.decrypt / decrypt_authenticated /
    open_stream), and
  * the SEPARATELY-CODED ``interop.altcodec`` (written only from FORMAT.md; it shares
    the kyber-py / dilithium-py / cryptography primitive libraries by design).

The cross-check proves independence at the FORMAT / TLV-parse / combiner /
KDF-transcript / AEAD-orchestration layer over those shared primitives and the same
spec author — NOT a cross-validation of the ML-KEM / ML-DSA / AES-GCM primitives, and
not proof against a spec misreading shared by both.

Positives: both reproduce the exact committed plaintext.

Negatives: both REJECT, each driven through the CORRECT decode path
(anonymous / authenticated-pinned / stream) per its ``open_as`` field, and the
raised exception is mapped to a taxonomy category that MUST equal the vector's
``expected_error``. For ``expected_layer == "crypto"`` negatives the category is
additionally required to be a crypto-layer category (``aead`` / ``signature``):
a vector that is rejected by a mere structural parse error instead of the crypto
check therefore FAILS the test — that is the whole point of the hardening.

If these all pass, the spec in FORMAT.md is complete and unambiguous enough that a
second implementation built from it alone interoperates byte-for-byte AND rejects
tampering at the same layer.
"""
import json
import os
import struct
import sys

import pytest
from cryptography.exceptions import InvalidTag

# Mirror the repo's path shim so vorlath_shield + interop import under bare pytest.
_HERE = os.path.dirname(os.path.abspath(__file__))
_TECH = os.path.dirname(_HERE)
for _p in (_TECH, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from interop import altcodec  # noqa: E402
from vorlath_shield import shield  # noqa: E402

VECTORS_PATH = os.path.join(_HERE, "pstv_vectors.json")
with open(VECTORS_PATH, encoding="utf-8") as _fh:
    _CORPUS = json.load(_fh)

_ALL = _CORPUS["vectors"]
_POSITIVES = [v for v in _ALL if v["kind"] != "negative"]
_NEGATIVES = [v for v in _ALL if v["kind"] == "negative"]

# Crypto-layer categories: an ``expected_layer == "crypto"`` negative must land
# in one of these (not a structural parse error).
_CRYPTO_CATEGORIES = frozenset(_CORPUS["meta"]["crypto_categories"])
_TAXONOMY = frozenset(_CORPUS["meta"]["taxonomy"])


def _b(hexstr: str) -> bytes:
    # Hex comparison is case-insensitive; the corpus uses UPPERCASE hex.
    return bytes.fromhex(hexstr)


def _ids(vectors):
    return [v["id"] for v in vectors]


# --------------------------------------------------------------------------- #
# Exception -> taxonomy category, for EITHER implementation.
# --------------------------------------------------------------------------- #
# Prefer exception TYPE over message text:
#   * an AEAD failure is cryptography.exceptions.InvalidTag (the reference), or an
#     AltCodecError whose __cause__ is InvalidTag (altcodec)            -> "aead";
#   * everything else is a ValueError (reference) / AltCodecError (altcodec) whose
#     MESSAGE we match against the spec-stable phrases each layer emits. These
#     phrases are transcribed verbatim from FORMAT.md / shield.py and altcodec.py
#     and were confirmed identical (modulo the shared substring asserted here) across
#     both implementations during minting.
#
# The structural framing family is split into low-collision categories, each keyed on a
# full spec phrase (not a bare "truncated" prefix), so a magic/identity failure, a
# header under-run, an over-claiming inner TLV, and an exact-length (trailing/short)
# failure are kept DISTINCT rather than folded into one weak "truncation" bucket. Order
# matters: the specific phrases precede the generic "truncated" needle.
_MESSAGE_CATEGORY = (
    # (substring, category) — checked in order; first hit wins.
    ("sender signature verification failed", "signature"),
    ("sender key-id does not match", "sender_kid"),
    ("authenticated sender is not the expected sender", "sender_pin"),
    ("expected an authenticated sender but envelope is anonymous", "sender_pin"),
    ("wrong recipient key", "wrong_recipient"),
    ("recipient key suite does not match", "suite_mismatch"),
    # magic / version identity — a separate 'framing' category (not a length problem).
    ("not a VORLATH Shield", "framing"),
    ("unsupported Shield", "framing"),
    # exact-length (off+clen==len) bound — single-shot trailing-data / short-read.
    ("envelope length mismatch", "trailing_data"),
    # an inner TLV whose length over-claims and runs past the buffer end.
    ("TLV value runs past end", "inner_tlv"),
    # header / stream framing under-runs (missing length, truncated header, empty stream).
    ("truncated", "truncation"),
    ("empty stream", "truncation"),
)


def _category(exc: BaseException) -> str:
    """Map an exception raised by EITHER implementation to a taxonomy category.

    Raises ``AssertionError`` (failing the test) if the exception cannot be placed
    — an unmapped rejection is itself a finding, not a silent pass.
    """
    # AEAD failures: reference raises InvalidTag directly; altcodec wraps it in an
    # AltCodecError with __cause__ == InvalidTag. Match the crypto layer by TYPE.
    if isinstance(exc, InvalidTag):
        return "aead"
    cause = getattr(exc, "__cause__", None)
    if isinstance(cause, InvalidTag):
        return "aead"

    msg = str(exc)
    for needle, category in _MESSAGE_CATEGORY:
        if needle in msg:
            return category
    raise AssertionError(
        f"unmapped rejection: {type(exc).__module__}.{type(exc).__name__}: {msg!r}"
    )


# --------------------------------------------------------------------------- #
# Path drivers — open a negative the way its ``open_as`` field dictates.
# --------------------------------------------------------------------------- #
def _open_reference(vec, env, priv):
    open_as = vec["open_as"]
    if open_as == "stream":
        return shield.open_stream(env, priv)
    if open_as == "authenticated":
        esp = _b(vec["expected_sender_public"]) if "expected_sender_public" in vec else None
        return shield.decrypt(env, priv, esp)
    return shield.decrypt(env, priv)


def _open_altcodec(vec, env, priv):
    open_as = vec["open_as"]
    if open_as == "stream":
        return altcodec.open_stream(env, priv)
    if open_as == "authenticated":
        esp = _b(vec["expected_sender_public"]) if "expected_sender_public" in vec else None
        return altcodec.open_envelope(env, priv, expected_sender_public=esp)
    return altcodec.open_envelope(env, priv)


def test_corpus_is_frozen_and_documented():
    meta = _CORPUS["meta"]
    assert meta["frozen"] is True
    assert "authority" in meta and "FORMAT.md" in meta["spec"]
    # Sanity: both suites and all four kinds are represented.
    suites = {v["suite_id"] for v in _ALL}
    assert suites == {0x01, 0x02}
    kinds = {v["kind"] for v in _ALL}
    assert {"single_shot_anonymous", "single_shot_authenticated", "stream", "negative"} <= kinds
    # The taxonomy + crypto-category metadata the negatives assert against exist,
    # including the round-2 low-collision structural split.
    assert _CRYPTO_CATEGORIES == {"aead", "signature"}
    assert {
        "sender_kid", "sender_pin", "wrong_recipient", "suite_mismatch",
        "framing", "truncation", "inner_tlv", "trailing_data",
    } <= _TAXONOMY


def test_every_negative_is_well_formed():
    """Each negative carries the fields the hardened assertions require."""
    assert _NEGATIVES, "the corpus must contain negative vectors"
    for v in _NEGATIVES:
        assert v["open_as"] in ("anonymous", "authenticated", "stream"), v["id"]
        assert v["expected_error"] in _TAXONOMY, v["id"]
        assert v["expected_layer"] in ("crypto", "structural"), v["id"]
        if v["expected_layer"] == "crypto":
            assert v["expected_error"] in _CRYPTO_CATEGORIES, v["id"]
        if v["open_as"] == "authenticated":
            assert "expected_sender_public" in v, v["id"]


# The REQUIRED tamper tags every conformant PSTV corpus must carry, per suite — the
# round-1 set PLUS every round-2 addition. A stale or partially-minted corpus (e.g. a
# regen that crashed midway, or one minted from an older generator) is missing one of
# these and MUST fail loudly here rather than silently passing a thinner suite.
_REQUIRED_TAMPERS = frozenset({
    # round-1
    "ciphertext_bitflip", "tag_bitflip", "suite_id_mutated", "truncated",
    "wrong_recipient_key", "auth_flag_stripped", "sig_bitflip",
    "sender_kid_mismatch", "sender_pub_swapped", "wrong_sender_pin",
    "stream_chunk_bitflip", "stream_final_dropped", "stream_chunk_reordered",
    "stream_middle_dropped",
    # round-2 — renamed from suite_downgrade_crypto_binding
    "flags_downgrade_crypto_binding",
    # round-2 — new negatives
    "sig_misbinding", "auth_flag_set_empty_block",
    "stream_suite_mutated", "stream_wrong_recipient", "stream_header_truncated",
    "trailing_bytes", "malformed_inner_tlv", "stream_chunk_duplicated",
})


def test_corpus_is_complete():
    """A stale/incomplete corpus fails here instead of silently passing a thin suite."""
    # The retired name must NOT reappear (the rename in item F is load-bearing).
    all_tampers = {v["tamper"] for v in _NEGATIVES}
    assert "suite_downgrade_crypto_binding" not in all_tampers, (
        "suite_downgrade_crypto_binding was renamed to flags_downgrade_crypto_binding"
    )
    for suite_id in (0x01, 0x02):
        present = {v["tamper"] for v in _NEGATIVES if v["suite_id"] == suite_id}
        missing = _REQUIRED_TAMPERS - present
        assert not missing, f"suite 0x{suite_id:02x} corpus missing tampers: {sorted(missing)}"


# --------------------------------------------------------------------------- #
# Positives — both implementations reproduce the committed plaintext.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("vec", _POSITIVES, ids=_ids(_POSITIVES))
def test_reference_decodes_positive(vec):
    env = _b(vec["envelope"])
    priv = _b(vec["recipient_private"])
    expected = _b(vec["expected_plaintext"])

    if vec["kind"] == "single_shot_anonymous":
        assert shield.decrypt(env, priv) == expected
    elif vec["kind"] == "single_shot_authenticated":
        spk = _b(vec["sender_public"])
        assert shield.decrypt_authenticated(env, priv, spk) == expected
        # anonymous open of an authenticated envelope also works
        assert shield.decrypt(env, priv) == expected
    elif vec["kind"] == "stream":
        assert shield.open_stream(env, priv) == expected
    else:  # pragma: no cover - guarded by parametrization
        pytest.fail(f"unexpected positive kind {vec['kind']}")


@pytest.mark.parametrize("vec", _POSITIVES, ids=_ids(_POSITIVES))
def test_altcodec_decodes_positive(vec):
    env = _b(vec["envelope"])
    priv = _b(vec["recipient_private"])
    expected = _b(vec["expected_plaintext"])

    if vec["kind"] == "single_shot_anonymous":
        assert altcodec.open_envelope(env, priv) == expected
    elif vec["kind"] == "single_shot_authenticated":
        spk = _b(vec["sender_public"])
        # independent codec, pinned to the expected sender
        assert altcodec.open_envelope(env, priv, expected_sender_public=spk) == expected
        # and anonymous open (no pin) also reproduces the plaintext
        assert altcodec.open_envelope(env, priv) == expected
    elif vec["kind"] == "stream":
        assert altcodec.open_stream(env, priv) == expected
    else:  # pragma: no cover
        pytest.fail(f"unexpected positive kind {vec['kind']}")


@pytest.mark.parametrize("vec", _POSITIVES, ids=_ids(_POSITIVES))
def test_reference_and_altcodec_agree(vec):
    """The reference and the separately-coded altcodec produce the SAME plaintext."""
    env = _b(vec["envelope"])
    priv = _b(vec["recipient_private"])

    if vec["kind"] == "stream":
        ref = shield.open_stream(env, priv)
        alt = altcodec.open_stream(env, priv)
    else:
        ref = shield.decrypt(env, priv)
        alt = altcodec.open_envelope(env, priv)
    assert ref == alt == _b(vec["expected_plaintext"])


# --------------------------------------------------------------------------- #
# Negatives — both implementations reject, at the EXPECTED layer/category.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("vec", _NEGATIVES, ids=_ids(_NEGATIVES))
def test_reference_rejects_negative_at_expected_layer(vec):
    env = _b(vec["envelope"])
    priv = _b(vec["recipient_private"])
    with pytest.raises(Exception) as ei:
        _open_reference(vec, env, priv)
    category = _category(ei.value)
    assert category == vec["expected_error"], (
        f"{vec['id']}: reference rejected as {category!r}, expected {vec['expected_error']!r}"
    )
    if vec["expected_layer"] == "crypto":
        # NOTE: this is a DEFENSIVE RESTATEMENT of the equality invariant above, not an
        # independent probe — given category == expected_error and a well-formed corpus
        # (test_every_negative_is_well_formed pins expected_error in {aead,signature} for
        # crypto rows), it is already implied. It is kept so the crypto-layer guarantee
        # is asserted explicitly at the point of use.
        assert category in _CRYPTO_CATEGORIES, (
            f"{vec['id']}: expected a CRYPTO-layer rejection but got {category!r}"
        )


@pytest.mark.parametrize("vec", _NEGATIVES, ids=_ids(_NEGATIVES))
def test_altcodec_rejects_negative_at_expected_layer(vec):
    env = _b(vec["envelope"])
    priv = _b(vec["recipient_private"])
    with pytest.raises(Exception) as ei:
        _open_altcodec(vec, env, priv)
    category = _category(ei.value)
    assert category == vec["expected_error"], (
        f"{vec['id']}: altcodec rejected as {category!r}, expected {vec['expected_error']!r}"
    )
    if vec["expected_layer"] == "crypto":
        # Defensive restatement of the equality invariant above (see the reference twin),
        # not an independent probe — asserted explicitly at the point of use.
        assert category in _CRYPTO_CATEGORIES, (
            f"{vec['id']}: expected a CRYPTO-layer rejection but got {category!r}"
        )


@pytest.mark.parametrize("vec", _NEGATIVES, ids=_ids(_NEGATIVES))
def test_both_implementations_agree_on_negative(vec):
    """Reference and altcodec reject the SAME vector in the SAME category."""
    env = _b(vec["envelope"])
    priv = _b(vec["recipient_private"])
    with pytest.raises(Exception) as ref_ei:
        _open_reference(vec, env, priv)
    with pytest.raises(Exception) as alt_ei:
        _open_altcodec(vec, env, priv)
    assert _category(ref_ei.value) == _category(alt_ei.value) == vec["expected_error"]


# --------------------------------------------------------------------------- #
# Invariant pins — locks on the construction itself, not just the rejection.
# --------------------------------------------------------------------------- #
_STREAM_MAGIC = b"VRST"


def _stream_blob_count(env: bytes) -> int:
    """Count VRST chunk blobs by walking the wire form (FORMAT.md §4.2–§4.3).

    Walks the 4 header TLVs + the u32 chunk_size, then counts [u32 len][blob] frames.
    Returns 0 if the envelope is not a well-framed VRST stream (so a truncated-header
    negative is correctly excluded from the multi-chunk invariant below).
    """
    if len(env) < 7 or env[:4] != _STREAM_MAGIC:
        return 0
    off = 7
    try:
        for _ in range(4):
            (n,) = struct.unpack_from(">H", env, off)
            off += 2 + n
        off += 4  # chunk_size u32
        count = 0
        while off < len(env):
            (clen,) = struct.unpack_from(">I", env, off)
            off += 4 + clen
            count += 1
        return count if off == len(env) else 0
    except struct.error:
        return 0


_CRYPTO_STREAM_NEGS = [
    v for v in _NEGATIVES
    if v["open_as"] == "stream" and v["expected_layer"] == "crypto"
]


@pytest.mark.parametrize("vec", _CRYPTO_STREAM_NEGS, ids=_ids(_CRYPTO_STREAM_NEGS))
def test_crypto_stream_negative_is_multichunk(vec):
    """Every crypto-layer STREAM negative carries >= 2 chunk blobs.

    The anti-reorder / anti-drop / anti-duplication properties are only meaningful on a
    multi-chunk stream; this pins the invariant so a future regen with a too-small
    plaintext (one chunk) cannot silently neuter these negatives.
    """
    assert _stream_blob_count(_b(vec["envelope"])) >= 2, vec["id"]


@pytest.mark.parametrize("vec", _NEGATIVES, ids=_ids(_NEGATIVES))
def test_aead_altcodec_error_has_invalidtag_cause(vec):
    """Every AEAD-wrapped AltCodecError carries an InvalidTag __cause__.

    Locks the type-dispatch invariant: altcodec maps the crypto layer by exception TYPE
    (wrapped InvalidTag), never by message text. A structural AltCodecError must NOT
    carry an InvalidTag cause, and an aead one MUST.
    """
    env = _b(vec["envelope"])
    priv = _b(vec["recipient_private"])
    with pytest.raises(altcodec.AltCodecError) as ei:
        _open_altcodec(vec, env, priv)
    cause = ei.value.__cause__
    if vec["expected_error"] == "aead":
        assert isinstance(cause, InvalidTag), (
            f"{vec['id']}: aead negative must wrap InvalidTag, got {type(cause).__name__}"
        )
    else:
        assert not isinstance(cause, InvalidTag), (
            f"{vec['id']}: structural negative must NOT wrap InvalidTag"
        )


# --------------------------------------------------------------------------- #
# Caused-by sibling — proves the SPECIFIC binding caused the failure, not "a tag".
# --------------------------------------------------------------------------- #
_SIBLING_NEGS = [v for v in _NEGATIVES if "sibling_id" in v]


def test_crypto_downgrade_negatives_have_siblings():
    """The crypto-downgrade negatives are exactly the ones carrying a caused-by sibling."""
    have = {v["tamper"] for v in _SIBLING_NEGS}
    assert have == {"auth_flag_stripped", "flags_downgrade_crypto_binding"}, have


@pytest.mark.parametrize("vec", _SIBLING_NEGS, ids=_ids(_SIBLING_NEGS))
def test_crypto_downgrade_sibling_isolates_the_binding(vec):
    """The negative differs from its positive sibling by exactly the mutated byte(s),
    and the sibling OPENS — so the SPECIFIC flags/AAD/KDF binding (not some unrelated
    corruption) is what flips the open to a crypto-layer rejection."""
    neg = _b(vec["envelope"])
    sib = _b(vec["sibling_envelope"])
    priv = _b(vec["recipient_private"])
    sib_pt = _b(vec["sibling_plaintext"])

    # (1) same length, and differ by exactly one byte (the flags byte at offset 6).
    assert len(neg) == len(sib), vec["id"]
    diff = [i for i, (a, b) in enumerate(zip(neg, sib, strict=True)) if a != b]
    assert diff == [6], f"{vec['id']}: expected only the flags byte (offset 6) to differ, got {diff}"

    # (2) the sibling positive opens (both implementations), proving the base envelope is
    #     genuine and only the single flags-byte mutation causes the crypto rejection.
    assert shield.decrypt(sib, priv) == sib_pt, vec["id"]
    assert altcodec.open_envelope(sib, priv) == sib_pt, vec["id"]

    # (3) the sibling id resolves to a real positive vector in the corpus.
    assert vec["sibling_id"] in {p["id"] for p in _POSITIVES}, vec["id"]
