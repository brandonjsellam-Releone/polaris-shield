"""gen_pstv_vectors — mint the frozen "Portable Shield Test Vectors" (PSTV) corpus.

This generator produces a self-contained golden-vector file,
``interop/pstv_vectors.json``, that an INDEPENDENT implementer can consume to
prove byte-level interoperability with the POLARIS Shield ``PLSH`` wire format
(``tech/FORMAT.md``). It covers BOTH suites (0x01 FIPS-standard, 0x02 CNSA-2.0
default) and these cases:

  * anonymous single-shot encrypt/decrypt of a known plaintext
  * authenticated single-shot (ML-DSA sender signature), sender public included
  * a streaming envelope (seal_stream/open_stream), minted with a SMALL chunk
    size so the stream carries >= 3 chunks (needed for the streaming negatives)
  * a strengthened negative / tamper set — each derived from a genuine positive
    envelope by a precise transform, driven on open through the CORRECT path
    (anonymous / authenticated-pinned / stream) and expected to be REJECTED.

Each negative carries two extra fields that the test asserts against:

  * ``expected_error`` — the taxonomy CATEGORY the rejection must fall in
    (see ``EXPECTED_ERRORS`` / the ``meta.taxonomy`` block). The test maps the
    raised exception (from EITHER implementation) to a category and requires it
    to equal this value, so a vector that is rejected by the WRONG check fails.
  * ``expected_layer`` — ``"crypto"`` (the rejection MUST come from the AEAD or
    signature layer) or ``"structural"`` (a cheap parse / key-id / suite / pin
    cross-check). For ``expected_layer == "crypto"`` the test additionally
    requires the category to be a crypto-layer category (``aead`` / ``signature``)
    — i.e. a mere structural parse error does NOT satisfy a crypto negative.

Negatives also carry ``open_as`` so the test knows which decode path to drive:
``"anonymous"`` (shield.decrypt / altcodec.open_envelope, no pin),
``"authenticated"`` (same, but with ``expected_sender_public`` pinned), or
``"stream"`` (shield.open_stream / altcodec.open_stream). Authenticated-pin
negatives additionally carry ``expected_sender_public``.

DETERMINISM RULE (important): POLARIS Shield encryption uses fresh randomness
(``os.urandom``), so re-running this generator MINTS A DIFFERENT corpus every
time. The COMMITTED ``pstv_vectors.json`` is therefore the single authority: run
this ONCE, commit the JSON, and let the tests read the committed file. The tests
never call this generator.

All binary fields are UPPERCASE hex (see the ``meta`` block in the JSON).
"""
from __future__ import annotations

import json
import os
import struct
import sys

# Make the package importable whether run as "python interop/gen_pstv_vectors.py"
# from tech/ or as a module — mirrors the sys.path shim used by the repo's tests.
_HERE = os.path.dirname(os.path.abspath(__file__))
_TECH = os.path.dirname(_HERE)
if _TECH not in sys.path:
    sys.path.insert(0, _TECH)

from polaris_shield import shield  # noqa: E402  (after sys.path shim)

OUT_PATH = os.path.join(_HERE, "pstv_vectors.json")

SUITES = [0x01, 0x02]
SUITE_LABEL = {
    0x01: "FIPS-standard: X25519 + ML-KEM-768 + ML-DSA-65 + HKDF-SHA256 + AES-256-GCM",
    0x02: "CNSA-2.0 (default): X448 + ML-KEM-1024 + ML-DSA-87 + HKDF-SHA384 + AES-256-GCM",
}

ANON_PLAINTEXT = b"POLARIS Shield PSTV: anonymous single-shot known-answer vector."
AUTH_PLAINTEXT = b"POLARIS Shield PSTV: authenticated (ML-DSA) single-shot vector."
# A DIFFERENT authenticated plaintext: a second genuine envelope from the same signer
# whose signature (over a different pre_auth) is grafted onto envelope #1 to build the
# sig_misbinding (transcript-reuse) negative — see _negatives().
AUTH_MISBIND_PLAINTEXT = b"POLARIS Shield PSTV: second authenticated vector for sig misbinding."
STREAM_PLAINTEXT = os.urandom(64 * 1024 * 2 + 777)  # > 1 chunk at the default 64 KiB

# Small chunk + multi-chunk plaintext for the streaming NEGATIVES: a >= 3-chunk
# (here 5-chunk) stream so reorder/drop/truncate vectors are meaningful.
STREAM_NEG_CHUNK = 64
STREAM_NEG_PLAINTEXT = os.urandom(STREAM_NEG_CHUNK * 4 + 13)  # 5 chunks

# Taxonomy of rejection categories the test maps exceptions to. The crypto-layer
# categories are exactly {aead, signature}; everything else is structural. The
# structural framing family is deliberately split into low-collision categories so
# each carries discriminating power (a stale "truncation" bucket would not):
#   * framing        — magic / version identity (it is not a Shield envelope at all)
#   * truncation     — an under-run inside the header/stream framing
#   * inner_tlv      — an inner TLV length that runs past the buffer end
#   * trailing_data  — the single-shot exact-length (off+clen==len) bound fails
EXPECTED_ERRORS = (
    "aead",             # AES-256-GCM tag check failed (InvalidTag) — crypto
    "signature",        # ML-DSA sender signature verify failed — crypto
    "sender_kid",       # sender_kid != embedded claimed kid — structural
    "sender_pin",       # expected_sender_public pin mismatch — structural
    "wrong_recipient",  # recipient key-id mismatch — structural
    "suite_mismatch",   # recipient key suite != envelope suite — structural
    "framing",          # magic / version identity mismatch — structural
    "truncation",       # length / framing under-run — structural
    "inner_tlv",        # an inner TLV length runs past the buffer end — structural
    "trailing_data",    # exact-length (off+clen==len) framing bound fails — structural
)
CRYPTO_CATEGORIES = ("aead", "signature")


def _hex(b: bytes) -> str:
    """UPPERCASE hex, matching the project's vector convention."""
    return b.hex().upper()


# --------------------------------------------------------------------------- #
# Positive vectors
# --------------------------------------------------------------------------- #
def _positive_anon(suite_id: int) -> dict:
    pub, priv = shield.generate_recipient_keys(suite_id)
    env = shield.encrypt(ANON_PLAINTEXT, pub)
    assert shield.decrypt(env, priv) == ANON_PLAINTEXT
    return {
        "id": f"pstv-suite{suite_id:02x}-anon",
        "kind": "single_shot_anonymous",
        "suite_id": suite_id,
        "suite_label": SUITE_LABEL[suite_id],
        "recipient_public": _hex(pub),
        "recipient_private": _hex(priv),
        "envelope": _hex(env),
        "expected_plaintext": _hex(ANON_PLAINTEXT),
    }


def _positive_auth(suite_id: int) -> dict:
    pub, priv = shield.generate_recipient_keys(suite_id)
    spk, ssk = shield.generate_signing_keys(suite_id)
    env = shield.encrypt_authenticated(AUTH_PLAINTEXT, pub, ssk, spk)
    assert shield.decrypt_authenticated(env, priv, spk) == AUTH_PLAINTEXT
    return {
        "id": f"pstv-suite{suite_id:02x}-auth",
        "kind": "single_shot_authenticated",
        "suite_id": suite_id,
        "suite_label": SUITE_LABEL[suite_id],
        "recipient_public": _hex(pub),
        "recipient_private": _hex(priv),
        "sender_public": _hex(spk),
        "envelope": _hex(env),
        "expected_plaintext": _hex(AUTH_PLAINTEXT),
    }


def _positive_stream(suite_id: int) -> dict:
    pub, priv = shield.generate_recipient_keys(suite_id)
    env = shield.seal_stream(STREAM_PLAINTEXT, pub)
    assert shield.open_stream(env, priv) == STREAM_PLAINTEXT
    return {
        "id": f"pstv-suite{suite_id:02x}-stream",
        "kind": "stream",
        "suite_id": suite_id,
        "suite_label": SUITE_LABEL[suite_id],
        "recipient_public": _hex(pub),
        "recipient_private": _hex(priv),
        "envelope": _hex(env),
        "expected_plaintext": _hex(STREAM_PLAINTEXT),
    }


# --------------------------------------------------------------------------- #
# Tamper helpers — locate substructures within an envelope by walking its TLVs.
# --------------------------------------------------------------------------- #
def _walk_header_tlvs(env: bytes, count: int) -> tuple[list[tuple[int, int, int]], int]:
    """Return [(len_pos, val_pos, n), ...] for the first ``count`` header TLVs.

    Header TLVs begin at offset 7 (FORMAT.md §2.3 for PLSH, §4.2 for PLST).
    The returned final offset points just past the last walked TLV.
    """
    off = 7
    spans: list[tuple[int, int, int]] = []
    for _ in range(count):
        (n,) = struct.unpack_from(">H", env, off)
        spans.append((off, off + 2, n))
        off += 2 + n
    return spans, off


def _sealed_region(env: bytes) -> tuple[int, int]:
    """Return (start, length) of the single-shot ``sealed`` region (after the 5
    header TLVs and the u32 sealed_len). FORMAT.md §2.4."""
    _spans, off = _walk_header_tlvs(env, 5)
    (clen,) = struct.unpack_from(">I", env, off)
    return off + 4, clen


def _sender_block_span(env: bytes) -> tuple[int, int]:
    """Return (val_pos, n) of the 5th header TLV (sender_block). FORMAT.md §2.3/§3."""
    spans, _off = _walk_header_tlvs(env, 5)
    _len_pos, val_pos, n = spans[4]
    return val_pos, n


def _sender_subtlvs(sender_block: bytes) -> list[tuple[int, int]]:
    """Return [(val_off, n), ...] for sender_kid, sender_pub, signature within a
    sender_block (offsets RELATIVE to the sender_block). FORMAT.md §3."""
    out: list[tuple[int, int]] = []
    o = 0
    for _ in range(3):
        (n,) = struct.unpack_from(">H", sender_block, o)
        out.append((o + 2, n))
        o += 2 + n
    return out


def _stream_header_end(env: bytes) -> int:
    """Offset of the first stream chunk (after 4 header TLVs + u32 chunk_size).
    FORMAT.md §4.2."""
    _spans, off = _walk_header_tlvs(env, 4)
    return off + 4  # chunk_size u32 (advisory)


def _stream_chunks(env: bytes) -> list[tuple[int, int, int]]:
    """Return [(len_pos, blob_pos, blob_len), ...] for every PLST chunk.
    FORMAT.md §4.3."""
    off = _stream_header_end(env)
    spans: list[tuple[int, int, int]] = []
    while off < len(env):
        (clen,) = struct.unpack_from(">I", env, off)
        spans.append((off, off + 4, clen))
        off += 4 + clen
    return spans


# --------------------------------------------------------------------------- #
# Negative vectors
# --------------------------------------------------------------------------- #
def _negatives(suite_id: int) -> list[dict]:
    """Mint the strengthened tamper/negative set for one suite.

    Each negative is derived from a genuine positive envelope and mutated, then
    sanity-checked at mint time: the reference MUST reject it (so a committed
    negative is never a false negative), driven through the SAME path the test
    will use (``open_as``).
    """
    pub, priv = shield.generate_recipient_keys(suite_id)
    pub_other, priv_other = shield.generate_recipient_keys(suite_id)
    spk, ssk = shield.generate_signing_keys(suite_id)
    spk2, ssk2 = shield.generate_signing_keys(suite_id)

    anon = shield.encrypt(ANON_PLAINTEXT, pub)
    auth = shield.encrypt_authenticated(AUTH_PLAINTEXT, pub, ssk, spk)
    # A SECOND genuine authenticated envelope from the SAME signer (spk/ssk) to the
    # SAME recipient (pub), with DIFFERENT plaintext (and thus a fresh nonce ⇒ a
    # different pre_auth transcript). Used to mint sig_misbinding by transcript re-use.
    auth2 = shield.encrypt_authenticated(AUTH_MISBIND_PLAINTEXT, pub, ssk, spk)
    stream = shield.seal_stream(STREAM_NEG_PLAINTEXT, pub, chunk_size=STREAM_NEG_CHUNK)
    assert shield.decrypt(anon, priv) == ANON_PLAINTEXT
    assert shield.decrypt_authenticated(auth, priv, spk) == AUTH_PLAINTEXT
    assert shield.decrypt_authenticated(auth2, priv, spk) == AUTH_MISBIND_PLAINTEXT
    assert shield.open_stream(stream, priv) == STREAM_NEG_PLAINTEXT

    out: list[dict] = []

    def _record(tag: str, reason: str, env_bytes: bytes, *,
                expected_error: str, expected_layer: str, open_as: str,
                recipient_private: bytes = priv,
                expected_sender_public: bytes | None = None,
                sibling_id: str | None = None,
                sibling_envelope: bytes | None = None,
                sibling_plaintext: bytes | None = None) -> dict:
        assert expected_error in EXPECTED_ERRORS, expected_error
        assert expected_layer in ("crypto", "structural"), expected_layer
        if expected_layer == "crypto":
            assert expected_error in CRYPTO_CATEGORIES, (tag, expected_error)
        # Sanity-check at mint time: the reference must reject, via the right path.
        env_b = bytes(env_bytes)
        try:
            if open_as == "stream":
                shield.open_stream(env_b, recipient_private)
            elif open_as == "authenticated":
                shield.decrypt(env_b, recipient_private, expected_sender_public)
            else:
                shield.decrypt(env_b, recipient_private)
        except Exception:
            pass
        else:
            raise AssertionError(f"negative vector {tag} unexpectedly DECRYPTED")
        rec = {
            "id": f"pstv-suite{suite_id:02x}-neg-{tag}",
            "kind": "negative",
            "tamper": tag,
            "reason": reason,
            "suite_id": suite_id,
            "suite_label": SUITE_LABEL[suite_id],
            "open_as": open_as,
            "expected_error": expected_error,
            "expected_layer": expected_layer,
            "recipient_private": _hex(recipient_private),
            "envelope": _hex(env_b),
        }
        if expected_sender_public is not None:
            rec["expected_sender_public"] = _hex(expected_sender_public)
        if sibling_id is not None:
            # The caused-by sibling: the EXACT pre-mutation envelope this negative was
            # derived from, plus its plaintext. The test asserts the negative differs
            # from sibling_envelope by exactly the mutated byte(s) AND that the sibling
            # opens under this same recipient_private — proving the SPECIFIC crypto
            # binding (flags/AAD/KDF) caused the failure, not merely "a tag failed".
            assert sibling_envelope is not None and sibling_plaintext is not None, tag
            sib = bytes(sibling_envelope)
            assert shield.decrypt(sib, recipient_private) == bytes(sibling_plaintext), tag
            rec["sibling_id"] = sibling_id
            rec["sibling_envelope"] = _hex(sib)
            rec["sibling_plaintext"] = _hex(bytes(sibling_plaintext))
        return rec

    # ----------------------------------------------------------------- #
    # Structural negatives (kept from the original corpus + expected_*).
    # ----------------------------------------------------------------- #
    # ciphertext bit-flip — a byte inside the ciphertext body fails the GCM tag.
    csstart, _cslen = _sealed_region(anon)
    e = bytearray(anon)
    e[csstart] ^= 0x01
    out.append(_record(
        "ciphertext_bitflip",
        "one ciphertext byte flipped; AES-256-GCM tag check fails",
        e, expected_error="aead", expected_layer="crypto", open_as="anonymous"))

    # AEAD tag bit-flip — flip the last (tag) byte.
    e = bytearray(anon)
    e[-1] ^= 0x80
    out.append(_record(
        "tag_bitflip",
        "one GCM-tag byte flipped; authentication fails (InvalidTag)",
        e, expected_error="aead", expected_layer="crypto", open_as="anonymous"))

    # suite_id mutated — caught by the cheap recipient-suite cross-check.
    e = bytearray(anon)
    e[5] ^= 0x03  # 0x01<->0x02 region; yields a mismatched/unknown suite
    out.append(_record(
        "suite_id_mutated",
        "suite_id byte changed; rejected by the recipient-key suite cross-check",
        e, expected_error="suite_mismatch", expected_layer="structural",
        open_as="anonymous"))

    # truncated — cut so the u32 sealed_len is incomplete; the header framing
    # under-runs ("truncated envelope: missing ciphertext length") BEFORE the
    # exact-length bound, so this lands in the truncation bucket (distinct from
    # trailing_bytes, which exercises the off+clen==len bound — see below).
    _spans_h, h_off = _walk_header_tlvs(anon, 5)
    e = bytearray(anon)[:h_off + 2]  # 2 of the 4 sealed_len bytes present
    out.append(_record(
        "truncated",
        "envelope cut mid-sealed_len (u32 incomplete); the header framing under-runs "
        "with 'truncated envelope: missing ciphertext length' before any crypto",
        e, expected_error="truncation", expected_layer="structural",
        open_as="anonymous"))

    # wrong-recipient-key — a valid envelope opened with the OTHER key (key-id mismatch).
    out.append(_record(
        "wrong_recipient_key",
        "valid envelope opened with a different recipient's key; key-id mismatch",
        anon, expected_error="wrong_recipient", expected_layer="structural",
        open_as="anonymous", recipient_private=priv_other))

    # trailing_bytes — a VALID envelope with extra bytes appended. This exercises the
    # single-shot UPPER bound of the exact-length check (off + clen == len): the parse
    # is otherwise well-formed, so the dedicated trailing_data category (not the shared
    # truncation bucket) is what fails — distinct discriminating power from `truncated`.
    e = bytearray(anon) + b"\x00\x00\x00"
    out.append(_record(
        "trailing_bytes",
        "three extra bytes appended to a valid envelope; the off+clen==len exact-length "
        "framing bound rejects it ('envelope length mismatch') — the upper-bound twin of "
        "the truncated under-run",
        e, expected_error="trailing_data", expected_layer="structural",
        open_as="anonymous"))

    # malformed_inner_tlv — inflate the eph_pub TLV length field so its value claims
    # more bytes than remain; _read_tlv detects the inner TLV running past the buffer
    # end ('TLV value runs past end'). Distinct inner_tlv category, NOT folded into the
    # truncation bucket (a length that over-claims is a different failure mode).
    spans_inner, _off_inner = _walk_header_tlvs(anon, 2)
    eph_len_pos = spans_inner[1][0]  # (len_pos, val_pos, n) of eph_pub
    e = bytearray(anon)
    struct.pack_into(">H", e, eph_len_pos, 0xFFFF)
    out.append(_record(
        "malformed_inner_tlv",
        "the eph_pub TLV length field inflated to 0xFFFF; the inner TLV value runs past "
        "the buffer end and _read_tlv rejects it ('TLV value runs past end')",
        e, expected_error="inner_tlv", expected_layer="structural",
        open_as="anonymous"))

    # auth_flag_set_empty_block — the OTHER direction from auth_flag_stripped: SET
    # FLAG_AUTHENTICATED on an anonymous envelope whose sender_block is empty (len 0).
    # decrypt() then takes the authenticated branch and _read_tlv(sender_block, 0)
    # under-runs ('missing TLV length') BEFORE any crypto — a pure framing under-run.
    e = bytearray(anon)
    e[6] = 0x01  # set FLAG_AUTHENTICATED; sender_block is still the empty 5th TLV
    out.append(_record(
        "auth_flag_set_empty_block",
        "FLAG_AUTHENTICATED set (0x00->0x01) on an anonymous envelope with an empty "
        "sender_block; the authenticated branch's first _read_tlv under-runs the 0-length "
        "block ('missing TLV length') before any crypto runs (fail-closed framing)",
        e, expected_error="truncation", expected_layer="structural",
        open_as="anonymous"))

    # ----------------------------------------------------------------- #
    # Authenticated-downgrade / fail-closed (the most important gap).
    # ----------------------------------------------------------------- #
    # auth_flag_stripped — clear FLAG_AUTHENTICATED leaving sender_block intact,
    # then open via the ANONYMOUS path. flags is in AAD AND in pre_auth -> the key
    # and the tag both change -> InvalidTag (crypto), NOT a structural error.
    e = bytearray(auth)
    e[6] = 0x00
    out.append(_record(
        "auth_flag_stripped",
        "FLAG_AUTHENTICATED cleared (0x01->0x00); flags is bound in AAD+KDF, so the "
        "anonymous open derives a different key and the GCM tag fails (fail-closed)",
        e, expected_error="aead", expected_layer="crypto", open_as="anonymous",
        sibling_id=f"pstv-suite{suite_id:02x}-auth",
        sibling_envelope=auth, sibling_plaintext=AUTH_PLAINTEXT))

    # ----------------------------------------------------------------- #
    # Authenticated-path negatives (driven with the sender pin / auth path).
    # ----------------------------------------------------------------- #
    sb_val, sb_n = _sender_block_span(auth)
    sub = _sender_subtlvs(auth[sb_val:sb_val + sb_n])
    kid_voff, _kid_n = sub[0]
    pub_voff, pub_n = sub[1]
    sig_voff, _sig_n = sub[2]

    # sig_bitflip — flip a byte in the signature TLV value -> signature verify fails.
    e = bytearray(auth)
    e[sb_val + sig_voff + 5] ^= 0x01
    out.append(_record(
        "sig_bitflip",
        "one byte flipped inside the ML-DSA signature TLV; sender signature verify fails",
        e, expected_error="signature", expected_layer="crypto",
        open_as="authenticated", expected_sender_public=spk))

    # sig_misbinding — the SIGMA / unknown-key-share probe, built by TRANSCRIPT RE-USE
    # (NOT a kid collision — a SHAKE-256 collision is infeasible). Take envelope #1
    # (`auth`) and REPLACE ONLY its signature TLV value with envelope #2's (`auth2`)
    # signature — a genuine ML-DSA signature by the SAME signer X, but over pre_auth#2.
    # sender_kid and sender_pub are UNTOUCHED, so sender_kid == claimed_kid and the
    # structural kid-guard PASSES; the swapped signature then reaches verify(), which
    # checks it against pre_auth#1 + claimed_kid and returns False -> "signature" at the
    # crypto layer. This is the ONLY negative that exercises the SIGMA transcript-binding
    # property by reaching ML-DSA verify()->False (sender_kid_mismatch / sender_pub_swapped
    # are caught structurally at the kid-guard BEFORE verify() ever runs).
    sb2_val, sb2_n = _sender_block_span(auth2)
    sub2 = _sender_subtlvs(auth2[sb2_val:sb2_val + sb2_n])
    sig2_voff, sig2_n = sub2[2]
    _sig1_voff, sig1_n = sub[2]
    assert sig1_n == sig2_n, "same-signer ML-DSA signatures are equal length"
    e = bytearray(auth)
    e[sb_val + sig_voff:sb_val + sig_voff + sig1_n] = \
        auth2[sb2_val + sig2_voff:sb2_val + sig2_voff + sig2_n]
    out.append(_record(
        "sig_misbinding",
        "the signature TLV of envelope #1 replaced with a GENUINE ML-DSA signature by the "
        "SAME signer over a DIFFERENT transcript (envelope #2's pre_auth); sender_kid/pub "
        "are unchanged so the kid cross-check passes and the signature reaches ML-DSA "
        "verify(), which returns False because it was bound to pre_auth#2 not pre_auth#1 "
        "(SIGMA / unknown-key-share transcript binding)",
        e, expected_error="signature", expected_layer="crypto",
        open_as="authenticated", expected_sender_public=spk))

    # sender_kid_mismatch — corrupt the sender_kid TLV so it != embedded claimed kid.
    e = bytearray(auth)
    e[sb_val + kid_voff] ^= 0x01
    out.append(_record(
        "sender_kid_mismatch",
        "sender_kid TLV corrupted; no longer equals the embedded key's claimed kid",
        e, expected_error="sender_kid", expected_layer="structural",
        open_as="authenticated", expected_sender_public=spk))

    # sender_pub_swapped — replace the embedded sender public bundle with a DIFFERENT
    # valid signer's bundle. The signature bound the ORIGINAL kid, and the swapped
    # bundle has a different claimed kid -> sender_kid != claimed_kid rejects first.
    assert len(spk2) == pub_n, "same-suite signer bundles are the same length"
    e = bytearray(auth)
    e[sb_val + pub_voff:sb_val + pub_voff + pub_n] = spk2
    out.append(_record(
        "sender_pub_swapped",
        "embedded sender public bundle swapped for a different valid signer; the kid "
        "embedded in sender_kid no longer matches the swapped key's claimed kid",
        e, expected_error="sender_kid", expected_layer="structural",
        open_as="authenticated", expected_sender_public=spk))

    # wrong_sender_pin — a VALID authenticated envelope, opened pinned to a DIFFERENT
    # signer. Must raise the SPECIFIC sender-pin mismatch (FORMAT.md §3 step 4).
    out.append(_record(
        "wrong_sender_pin",
        "valid authenticated envelope opened with expected_sender_public = a different "
        "signer; the sender-pin cross-check (FORMAT.md §3 step 4) must reject it",
        auth, expected_error="sender_pin", expected_layer="structural",
        open_as="authenticated", expected_sender_public=spk2))

    # ----------------------------------------------------------------- #
    # Streaming (PLST) negatives — exercise counter+final anti-tamper logic.
    # ----------------------------------------------------------------- #
    chunks = _stream_chunks(stream)
    assert len(chunks) >= 3, f"need >=3 chunks, got {len(chunks)}"

    # stream_chunk_bitflip — flip a byte in a MIDDLE chunk blob -> chunk AEAD fails.
    mid = chunks[len(chunks) // 2]
    e = bytearray(stream)
    e[mid[1] + 1] ^= 0x01
    out.append(_record(
        "stream_chunk_bitflip",
        "one byte flipped inside a middle chunk's blob; that chunk's AEAD open fails",
        e, expected_error="aead", expected_layer="crypto", open_as="stream"))

    # stream_final_dropped — remove the last [len][blob]; the new last chunk carries
    # final=0 at its position so anti-truncation rejects.
    last = chunks[-1]
    e = bytearray(stream)[:last[0]]
    out.append(_record(
        "stream_final_dropped",
        "last [len][blob] chunk removed; the new tail chunk's final-flag (0) no longer "
        "matches the bound final-flag, so anti-truncation rejects (InvalidTag)",
        e, expected_error="aead", expected_layer="crypto", open_as="stream"))

    # stream_chunk_reordered — swap two chunks' [len][blob] segments -> counter mismatch.
    a, b = chunks[1], chunks[-2]
    assert a[2] == b[2], "pick two equal-length chunks for an in-place swap"
    seg_a = bytes(stream[a[0]:a[1] + a[2]])
    seg_b = bytes(stream[b[0]:b[1] + b[2]])
    e = bytearray(stream)
    e[a[0]:a[1] + a[2]] = seg_b
    e[b[0]:b[1] + b[2]] = seg_a
    out.append(_record(
        "stream_chunk_reordered",
        "two equal-length chunks swapped; each decrypts under the wrong counter nonce/AAD "
        "and the GCM tag fails (anti-reorder)",
        e, expected_error="aead", expected_layer="crypto", open_as="stream"))

    # stream_middle_dropped — remove a middle chunk -> subsequent counters shift.
    m = chunks[len(chunks) // 2]
    e = bytearray(stream)
    del e[m[0]:m[1] + m[2]]
    out.append(_record(
        "stream_middle_dropped",
        "a middle chunk removed; every later chunk shifts index, so all subsequent "
        "counters mismatch and the AEAD fails (anti-drop)",
        e, expected_error="aead", expected_layer="crypto", open_as="stream"))

    # stream_chunk_duplicated — insert a duplicate copy of a middle chunk's [len][blob].
    # The duplicate (and every chunk after it) decrypts under a shifted counter nonce/AAD,
    # so the AEAD tag fails (anti-duplication, same counter-binding family as anti-drop).
    dup = chunks[len(chunks) // 2]
    seg_dup = bytes(stream[dup[0]:dup[1] + dup[2]])  # the whole [u32 len][blob]
    e = bytearray(stream)
    e[dup[0]:dup[0]] = seg_dup
    out.append(_record(
        "stream_chunk_duplicated",
        "a middle chunk's [len][blob] duplicated in place; the duplicate and every later "
        "chunk shift index, so their counter nonce/AAD no longer match and the AEAD fails "
        "(anti-duplication)",
        e, expected_error="aead", expected_layer="crypto", open_as="stream"))

    # ----------------------------------------------------------------- #
    # Streaming (PLST) STRUCTURAL negatives — exercise open_stream's CHEAP
    # cross-checks (suite / recipient / header framing), which no crypto-layer
    # stream negative reaches. These are caught BEFORE any decapsulation.
    # ----------------------------------------------------------------- #
    # stream_suite_mutated — flip the suite_id byte; the recipient-key suite cross-check
    # rejects it ('recipient key suite does not match stream suite') before any crypto.
    e = bytearray(stream)
    e[5] ^= 0x03  # 0x01<->0x02 region; yields a mismatched/unknown suite
    out.append(_record(
        "stream_suite_mutated",
        "stream suite_id byte changed; rejected by the recipient-key suite cross-check "
        "in open_stream (structural, before decapsulation)",
        e, expected_error="suite_mismatch", expected_layer="structural", open_as="stream"))

    # stream_wrong_recipient — a VALID stream opened with the OTHER recipient's key;
    # the key-id cross-check rejects it ('wrong recipient key (key-id mismatch)').
    out.append(_record(
        "stream_wrong_recipient",
        "valid stream opened with a different recipient's key; open_stream's key-id "
        "cross-check rejects it (structural)",
        stream, expected_error="wrong_recipient", expected_layer="structural",
        open_as="stream", recipient_private=priv_other))

    # stream_header_truncated — cut so the u32 chunk_size is incomplete; open_stream's
    # header framing under-runs ('truncated stream header') before any crypto.
    _spans_s, s_off = _walk_header_tlvs(stream, 4)  # offset where chunk_size u32 begins
    e = bytearray(stream)[:s_off + 2]  # 2 of the 4 chunk_size bytes present
    out.append(_record(
        "stream_header_truncated",
        "stream cut mid-chunk_size (u32 incomplete); open_stream's header framing "
        "under-runs ('truncated stream header') before any decapsulation (structural)",
        e, expected_error="truncation", expected_layer="structural", open_as="stream"))

    # ----------------------------------------------------------------- #
    # BONUS — flags_downgrade_crypto_binding (caught ONLY by AAD/KDF binding).
    # A *pure suite* downgrade (mutate suite_id byte) is NOT constructible as a
    # crypto-binding-only bypass: the recipient key's own suite/key-id mismatch
    # catches it structurally first (see caveats / the generator probe). What IS
    # genuinely caught only by the crypto binding is the downgrade BIT in `flags`:
    # `flags` has NO structural equality cross-check (decrypt only tests the
    # FLAG_AUTHENTICATED bit), yet `flags` is bound in both the AAD and the HKDF
    # transcript. Setting an otherwise-unused flag bit therefore passes EVERY
    # structural cross-check (suite resolves, sid matches, key-id matches, still
    # parsed as anonymous) and is caught ONLY by the AEAD tag (InvalidTag). The tag
    # says FLAGS, not suite: it mutates a flags bit (0x80), not the suite_id byte.
    e = bytearray(anon)
    e[6] ^= 0x80  # set an unused flags bit; FLAG_AUTHENTICATED (0x01) untouched
    out.append(_record(
        "flags_downgrade_crypto_binding",
        "an unused flags bit set on an anonymous envelope: passes every cheap structural "
        "cross-check (suite resolves, recipient suite/key-id match, still anonymous) yet is "
        "caught ONLY by the AAD/KDF binding because flags feeds the AEAD AAD and the HKDF "
        "info — a different key is derived and the GCM tag fails (downgrade-bit fail-closed)",
        e, expected_error="aead", expected_layer="crypto", open_as="anonymous",
        sibling_id=f"pstv-suite{suite_id:02x}-anon",
        sibling_envelope=anon, sibling_plaintext=ANON_PLAINTEXT))

    return out


def build_corpus() -> dict:
    vectors: list[dict] = []
    for suite_id in SUITES:
        vectors.append(_positive_anon(suite_id))
        vectors.append(_positive_auth(suite_id))
        vectors.append(_positive_stream(suite_id))
        vectors.extend(_negatives(suite_id))

    return {
        "meta": {
            "name": "Portable Shield Test Vectors (PSTV)",
            "format": "POLARIS Shield v2 PLSH single-shot + PLST stream envelopes",
            "spec": "tech/FORMAT.md",
            "frozen": True,
            "authority": (
                "This committed JSON is the AUTHORITY. Encryption uses fresh "
                "randomness, so re-running interop/gen_pstv_vectors.py mints a "
                "DIFFERENT corpus. Tests read this file and never call the generator."
            ),
            "envelope_version": shield.VERSION,
            "suite_ids": {
                "0x01": SUITE_LABEL[0x01],
                "0x02": SUITE_LABEL[0x02],
            },
            "field_encoding": (
                "All binary fields are UPPERCASE hex (str.encode then .hex().upper()). "
                "Hex comparison is case-insensitive."
            ),
            "fields": {
                "recipient_public": "PLSK role-1 (KEM public) bundle",
                "recipient_private": "PLSK role-2 (KEM private) bundle",
                "sender_public": "PLSK role-3 (ML-DSA signing public) bundle (authenticated positives)",
                "expected_sender_public": (
                    "PLSK role-3 signing public bundle to PIN on open (authenticated negatives "
                    "driven through the pinned path)"
                ),
                "envelope": "full PLSH/PLST envelope bytes",
                "expected_plaintext": "decrypted plaintext (positives only)",
                "tamper": "negative-vector mutation tag (negatives only)",
                "reason": "why the negative vector must be rejected",
                "open_as": (
                    "negatives only: which decode path the test drives — 'anonymous' "
                    "(decrypt/open_envelope, no pin), 'authenticated' (pinned to "
                    "expected_sender_public), or 'stream' (open_stream)"
                ),
                "expected_error": (
                    "negatives only: the taxonomy CATEGORY the rejection must fall in "
                    "(see meta.taxonomy). The test maps the raised exception from EITHER "
                    "implementation to a category and requires equality."
                ),
                "expected_layer": (
                    "negatives only: 'crypto' (rejection MUST come from the AEAD or signature "
                    "layer) or 'structural' (a cheap parse / key-id / suite / pin cross-check). "
                    "For 'crypto', the category must be a crypto category (aead/signature) — a "
                    "structural parse error does NOT satisfy a crypto negative."
                ),
                "sibling_id": (
                    "crypto-downgrade negatives only: the id of the POSITIVE vector this "
                    "negative was derived from (its caused-by sibling)"
                ),
                "sibling_envelope": (
                    "crypto-downgrade negatives only: the EXACT pre-mutation envelope bytes; "
                    "the negative differs from it by exactly the mutated byte(s) and it opens "
                    "under the negative's recipient_private — proving the specific binding "
                    "(flags/AAD/KDF) caused the failure"
                ),
                "sibling_plaintext": (
                    "crypto-downgrade negatives only: the plaintext sibling_envelope decrypts to"
                ),
            },
            "kinds": [
                "single_shot_anonymous", "single_shot_authenticated", "stream", "negative",
            ],
            "taxonomy": {
                "aead": "AES-256-GCM tag check failed (InvalidTag) — crypto layer",
                "signature": "ML-DSA sender signature verification failed — crypto layer",
                "sender_kid": "sender_kid != the embedded key's claimed kid — structural",
                "sender_pin": "expected_sender_public pin mismatch (FORMAT.md §3 step 4) — structural",
                "wrong_recipient": "recipient key-id mismatch — structural",
                "suite_mismatch": "recipient key suite != envelope suite — structural",
                "framing": "magic / version identity mismatch (not a Shield envelope) — structural",
                "truncation": "header / stream framing under-run (missing length / past end) — structural",
                "inner_tlv": "an inner TLV length runs past the buffer end — structural",
                "trailing_data": "single-shot exact-length (off+clen==len) framing bound fails — structural",
            },
            "crypto_categories": list(CRYPTO_CATEGORIES),
            "honest_scope": (
                "Proves byte-level format interoperability and combiner/KDF/AEAD "
                "agreement between the reference and a second, separately-coded "
                "implementation (which shares the same primitive libraries), AND that "
                "each tamper is rejected at the EXPECTED layer (crypto vs structural), "
                "not merely 'rejected somehow'. The cross-check proves independence at "
                "the FORMAT / TLV-parse / combiner / KDF-transcript / AEAD-orchestration "
                "layer over SHARED primitive libs (kyber-py / dilithium-py / cryptography) "
                "and the same spec author; it does NOT cross-validate the ML-KEM / ML-DSA "
                "/ AES-GCM primitives themselves and does NOT catch a shared spec "
                "misreading. NOT a FIPS validation, NOT a side-channel claim. 'CNSA 2.0' "
                "= algorithm set, not a validated module. This is a project convention, "
                "not a standardized/registered protocol."
            ),
        },
        "vectors": vectors,
    }


def main() -> None:
    corpus = build_corpus()
    with open(OUT_PATH, "w", encoding="utf-8") as fh:
        json.dump(corpus, fh, indent=2, sort_keys=False)
        fh.write("\n")
    n_pos = sum(1 for v in corpus["vectors"] if v["kind"] != "negative")
    n_neg = sum(1 for v in corpus["vectors"] if v["kind"] == "negative")
    print(f"wrote {OUT_PATH}")
    print(f"  {len(corpus['vectors'])} vectors total: {n_pos} positive, {n_neg} negative")


if __name__ == "__main__":
    main()
