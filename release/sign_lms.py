#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VORLATH Shield -- SP 800-208 LMS release signature (self-checking round trip).

PURPOSE
  CNSA_MIGRATION.md section 3 mandates that "software/firmware signing migrates
  first" under CNSA 2.0. VORLATH Shield already ships a deterministic, content-
  addressed release bundle (tech/release/RELEASE_MANIFEST.json) whose single
  bundle_digest is a SHA-256 Merkle-style root over every assurance-critical
  artifact, and CI cosign-signs it (keyless OIDC) plus emits SLSA provenance.
  This script ADDITIONALLY signs that release with a stateful hash-based
  SP 800-208 LMS key, demonstrating the CNSA 2.0 firmware-signing-first workflow
  end to end on a genuinely low-volume signing surface (a handful of releases).

  ML-DSA-87 remains VORLATH's general-purpose signature, and stateless SLH-DSA
  is used wherever a long-lived signer is needed. LMS is confined to THIS narrow
  release-signing role precisely BECAUSE it is stateful.

  What it does: read bundle_digest from RELEASE_MANIFEST.json (fall back to a
  fixed self-test digest if the manifest is absent), generate a single-tree LMS
  key, sign the digest exactly once, write the signature + LMS public key, then
  VERIFY and exit nonzero on any failure.

=============================================================================
  CARDINAL RULE -- A ONE-TIME (LEAF) KEY MUST NEVER BE REUSED.
=============================================================================
  LMS/XMSS are STATEFUL hash-based signatures. Each leaf is a one-time key. If
  ANY leaf ever signs two different messages, an attacker who sees both
  signatures can forge -- ALL security is forfeited. This is catastrophic and
  irrecoverable. The mutable secret state lives in the .prv file, which pyhsslms
  rewrites with the advanced leaf index q BEFORE each sign() returns
  (fail-closed: a process crash burns the spent leaf rather than risking reuse).

  Therefore, treat the .prv as write-once-per-signature, single-writer state --
  NOT a normal key file:
    - NEVER restore the .prv from backup (the README warns verbatim that this
      "can cause a node in the tree to be used more than once, forfeiting all
      security").
    - NEVER run two signers against the same .prv (no file locking is provided).
    - NEVER snapshot-and-rewind a VM/filesystem holding the .prv.
    - NEVER commit the .prv to git.
    - NEVER add retry-on-failure logic that could re-sign with a possibly-spent
      leaf. A failed sign() is final; investigate, do not blindly retry.
  This one-shot demo sidesteps long-lived-state risk entirely by generating a
  FRESH single-use key per release (genkey refuses to overwrite an existing
  key pair, which is the built-in guard) and treating the .prv as spent
  afterward. By default the .prv is shredded after the verified round trip;
  pass --keep-prv only if you understand the never-reuse rule above.

HONEST CONFORMANCE POSTURE (see CNSA_MIGRATION.md section 3 + STANDARDS_POSITION.md)
  - Library: pyhsslms (Russ Housley), pure-Python, BSD-3-Clause, pip-installable.
  - It self-describes as an implementation of HSS/LMS as defined in RFC 8554.
    It does NOT print a literal "SP 800-208 conformant" string. Its SP 800-208
    alignment is INFERRED from parameter-set coverage: it ships the SHA-256/192
    (m24) truncated-hash sets and the SHAKE256 sets, which are exactly the
    additions SP 800-208 made on top of RFC 8554. Best described as
    "RFC 8554 plus the SP 800-208 parameter additions."
  - It is a SOFTWARE REFERENCE implementation. It is NOT FIPS 140-3 validated and
    is NOT on any CMVP/NIST validated-module list.
  - SP 800-208 requires that approved-deployment key generation and signing run
    inside a non-exporting hardware cryptographic module (HSM) with hardware-
    enforced state management. A pure-Python library CANNOT satisfy that. So this
    deliverable is a standards-ALIGNED demonstration of the CNSA 2.0 signing-
    first workflow -- NOT an 800-208-compliant signing service. Do not frame it
    as one.
  - Parameter set: lms_sha256_m24_h5 + lmots_sha256_n24_w8. SHA-256/192 (m24) is
    NSA's CNSA 2.0 preference within SP 800-208. levels=1 = single LMS tree
    (matches CNSA_MIGRATION.md "single-tree"); H5 = 32 one-time signatures, ample
    for a handful of releases. Once the tree is exhausted, sign() raises and the
    key is permanently dead -- by design.

USAGE
  python tech/release/sign_lms.py            # sign + verify the current bundle
  python tech/release/sign_lms.py --keep-prv # keep the spent .prv (advanced use)

OUTPUTS (in tech/release/release/)
  RELEASE_BUNDLE.lms.sig  - raw LMS/HSS signature bytes over the bundle_digest
  lms_pub.key             - serialized LMS public key (RFC 8554 wire format),
                            distribute this WITH the release for verification
  RELEASE_BUNDLE.lms.txt  - human-readable provenance (params, digest, posture)

EXIT CODES
  0 = key generated, signed once, and signature verified.
  nonzero = any failure (missing lib, exhausted/clobbered key, verify mismatch).

ASCII only. No arrow glyphs anywhere in emitted text (VORLATH glyph rule).
"""
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFEST = os.path.join(HERE, "RELEASE_MANIFEST.json")
OUT_DIR = os.path.join(HERE, "release")

# Basename pyhsslms uses for its key pair. genkey writes <KEY_BASENAME>.prv and
# <KEY_BASENAME>.pub; HssLmsPublicKey(<KEY_BASENAME>) loads <KEY_BASENAME>.pub.
KEY_BASENAME = os.path.join(OUT_DIR, "vorlath_release")
PRV_PATH = KEY_BASENAME + ".prv"
PUB_PATH = KEY_BASENAME + ".pub"

SIG_OUT = os.path.join(OUT_DIR, "RELEASE_BUNDLE.lms.sig")
PUB_OUT = os.path.join(OUT_DIR, "lms_pub.key")
TXT_OUT = os.path.join(OUT_DIR, "RELEASE_BUNDLE.lms.txt")

# Deterministic fallback so the self-test round trip works even with no manifest.
SELFTEST_DIGEST_HEX = (
    "0000000000000000000000000000000000000000000000000000000000000001"
)


def fail(msg, code=1):
    sys.stderr.write("FAIL: " + msg + "\n")
    sys.exit(code)


def load_bundle_digest():
    """Return (digest_bytes, source_label). Falls back to a fixed self-test
    digest if the manifest is absent or malformed -- the round trip must still
    prove the sign/verify path."""
    if not os.path.exists(MANIFEST):
        sys.stderr.write(
            "NOTE: %s not found; using fixed self-test digest.\n" % MANIFEST
        )
        return bytes.fromhex(SELFTEST_DIGEST_HEX), "self-test (manifest absent)"
    try:
        with open(MANIFEST, "rb") as f:
            data = json.load(f)
        hex_digest = data["bundle_digest"]
        digest = bytes.fromhex(hex_digest)
    except (ValueError, KeyError) as exc:
        sys.stderr.write(
            "NOTE: could not read bundle_digest (%s); using self-test digest.\n"
            % exc
        )
        return bytes.fromhex(SELFTEST_DIGEST_HEX), "self-test (manifest unreadable)"
    if len(digest) != 32:
        fail("bundle_digest is not 32 bytes (expected SHA-256).")
    return digest, "RELEASE_MANIFEST.json bundle_digest"


def main():
    keep_prv = "--keep-prv" in sys.argv[1:]

    try:
        import pyhsslms
    except ImportError:
        fail(
            "pyhsslms is not installed. Install the real, pip-installable lib:\n"
            "    pip install pyhsslms==2.0.0\n"
            "(pure-Python, BSD-3-Clause, RFC 8554 + SP 800-208 parameter sets; "
            "NOT FIPS-validated, NOT an HSM -- standards-aligned demo only)."
        )

    os.makedirs(OUT_DIR, exist_ok=True)

    digest, source = load_bundle_digest()
    digest_hex = digest.hex()

    print("VORLATH Shield -- SP 800-208 LMS release signing (demo, software-only)")
    print("  signed payload : bundle_digest (SHA-256), %d bytes" % len(digest))
    print("  digest source  : " + source)
    print("  bundle_digest  : " + digest_hex)
    print("  LMS param set  : lms_sha256_m24_h5 (single tree, 32 one-time sigs)")
    print("  LMOTS param    : lmots_sha256_n24_w8  (SHA-256/192, CNSA 2.0 pref)")
    print("  STATEFUL WARNING: each leaf signs ONCE; reuse forfeits ALL security.")

    # ------------------------------------------------------------------
    # KEYGEN. Fresh single-use key per release. genkey refuses to clobber an
    # existing pair (raises FileExistsError) -- that refusal IS our reuse guard.
    # If a stale pair exists, we STOP rather than risk reusing live state.
    # ------------------------------------------------------------------
    if os.path.exists(PRV_PATH) or os.path.exists(PUB_PATH):
        fail(
            "A key pair already exists at %s.{prv,pub}.\n"
            "REFUSING to proceed: an existing .prv may hold LIVE one-time state, "
            "and reusing a spent leaf is catastrophic. If this is genuinely a "
            "stale demo key, remove BOTH files MANUALLY and re-run -- never "
            "automate that deletion." % KEY_BASENAME
        )

    try:
        priv = pyhsslms.HssLmsPrivateKey.genkey(
            KEY_BASENAME,
            levels=1,
            lms_type=pyhsslms.lms_sha256_m24_h5,
            lmots_type=pyhsslms.lmots_sha256_n24_w8,
        )
    except FileExistsError as exc:
        fail("genkey refused to overwrite an existing key: %s" % exc)
    except Exception as exc:  # pragma: no cover - defensive
        fail("genkey failed: %s: %s" % (type(exc).__name__, exc))

    print("OK   keygen      : wrote %s and %s" % (PRV_PATH, PUB_PATH))

    # ------------------------------------------------------------------
    # SIGN exactly once. pyhsslms advances the leaf index q and rewrites the
    # .prv to disk BEFORE returning the signature (fail-closed). DO NOT retry.
    # ------------------------------------------------------------------
    try:
        sig = priv.sign(digest)
    except ValueError as exc:
        # Raised when the tree is exhausted -- the key is permanently dead.
        fail("sign refused (key exhausted or invalid state): %s" % exc)
    except Exception as exc:  # pragma: no cover - defensive
        fail("sign failed: %s: %s" % (type(exc).__name__, exc))

    if not isinstance(sig, (bytes, bytearray)) or len(sig) == 0:
        fail("sign returned no signature bytes.")
    print("OK   sign        : %d signature bytes (one leaf now SPENT)" % len(sig))

    # Emit signature + public key. Copy the serialized .pub to the published
    # name; keep KEY_BASENAME.pub in place so the verifier can load by basename.
    with open(SIG_OUT, "wb") as f:
        f.write(sig)
    with open(PUB_PATH, "rb") as f:
        pub_bytes = f.read()
    with open(PUB_OUT, "wb") as f:
        f.write(pub_bytes)
    print("OK   emit        : %s (%d B), %s (%d B)"
          % (SIG_OUT, len(sig), PUB_OUT, len(pub_bytes)))

    # ------------------------------------------------------------------
    # VERIFY -- the self-checking round trip. Load the public key by basename
    # and confirm the signature over the exact digest bytes.
    # ------------------------------------------------------------------
    try:
        pub = pyhsslms.HssLmsPublicKey(KEY_BASENAME)
        ok = pub.verify(digest, sig)
    except Exception as exc:  # pragma: no cover - defensive
        fail("verify raised: %s: %s" % (type(exc).__name__, exc))

    if ok is not True:
        fail("signature did NOT verify. Refusing to publish a bad signature.")

    # Negative control: a tampered digest MUST NOT verify.
    tampered = bytes([digest[0] ^ 0x01]) + digest[1:]
    if pub.verify(tampered, sig) is not False:
        fail("negative control FAILED: a tampered digest verified. Aborting.")

    print("OK   verify      : signature VALID over bundle_digest")
    print("OK   neg-control : tampered digest correctly REJECTED")

    # Human-readable provenance sidecar (ASCII only, no arrow glyphs).
    with open(TXT_OUT, "w", encoding="ascii", newline="\n") as f:
        f.write("VORLATH Shield LMS release signature (SP 800-208 aligned demo)\n")
        f.write("library        : pyhsslms 2.0.0 (RFC 8554 + SP 800-208 params)\n")
        f.write("posture        : software reference impl; NOT FIPS-validated;\n")
        f.write("                 NOT an HSM; standards-ALIGNED demo, not\n")
        f.write("                 800-208-compliant signing.\n")
        f.write("lms_type       : lms_sha256_m24_h5\n")
        f.write("lmots_type     : lmots_sha256_n24_w8\n")
        f.write("signed payload : bundle_digest (SHA-256)\n")
        f.write("digest source  : " + source + "\n")
        f.write("bundle_digest  : " + digest_hex + "\n")
        f.write("signature file : RELEASE_BUNDLE.lms.sig\n")
        f.write("public key     : lms_pub.key\n")
        f.write("STATEFUL NOTE  : one leaf signs once; reuse forfeits ALL\n")
        f.write("                 security. The .prv is single-use state, never\n")
        f.write("                 backed up, copied, or rewound.\n")
    print("OK   provenance  : " + TXT_OUT)

    # ------------------------------------------------------------------
    # Burn the spent one-time state. By default we shred the .prv so it cannot
    # be reused. The .pub remains for verification. --keep-prv overrides this.
    # ------------------------------------------------------------------
    if keep_prv:
        print("NOTE keep-prv    : spent .prv RETAINED at %s -- it is SPENT; do "
              "NOT sign with it again." % PRV_PATH)
    else:
        try:
            os.remove(PRV_PATH)
            print("OK   shred .prv  : spent one-time state removed (fail-safe).")
        except OSError as exc:  # pragma: no cover - defensive
            sys.stderr.write("WARN: could not remove spent .prv: %s\n" % exc)

    print("PASS: LMS release signed and verified (self-checking round trip).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
