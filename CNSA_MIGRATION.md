# VORLATH Shield — CNSA 2.0 migration & deployment posture

A self-assessment against the **public** US-government PQC migration framework, and the
gov-aligned modes that take the Shield from "standards-aligned reference implementation" toward an
NSS-deployable posture. Built only from public sources (see [`GOV_ALIGNMENT.md`](GOV_ALIGNMENT.md));
**no classified material, posture not certification.** The Shield is a reference implementation,
**NOT** FIPS 140-3 validated and **NOT** CSfC-listed. **Section 2 (pure-CNSA suite `0x03`), the
section-4 RFC 8784 PPK input, and the section-3 LMS signing-first workflow (software demo) are now
implemented/demonstrated and verified**; the CSfC dual-layer positioning and an HSM-backed,
800-208-*compliant* signing service remain **designs** (clearly marked), each naming what it requires.

## 1. CNSA 2.0 migration self-assessment matrix

The NSA CNSA 2.0 timeline (public CSA + FAQ): software/firmware **signing first**, exclusive by
2030; networking (IKE/TLS-class) by 2030; web/cloud, OS, and custom apps by 2033; all NSS
quantum-resistant by ~2035; a Jan 1 2027 acquisition-preference gate. Each Shield capability mapped
to the relevant dated target and its honest status:

| CNSA 2.0 category (public target) | Shield capability | Status |
|---|---|---|
| Algorithm set (Cat-5): ML-KEM-1024 + ML-DSA-87 + AES-256 + SHA-384 | Suite `0x02` IS exactly this set | **Aligned** (primitive parity; see CBOM) |
| Key establishment (networking, by 2030) | Hybrid X448 + ML-KEM-1024 via SP 800-56C combiner | **Aligned (hybrid)** — transition practice; pure mode is section 2 |
| Digital signatures | ML-DSA-87 (FIPS 204); opt-in SLH-DSA (FIPS 205) | **Aligned** |
| Software/firmware **signing-first** (exclusive 2030; SP 800-208 LMS/XMSS) | not yet a deployed code-signing path | **Gap — design in section 3** |
| Symmetric / hash | AES-256-GCM, SHA-384, SHAKE-256 | **Aligned** |
| Acquisition gate (Jan 1 2027) | algorithm-agility + the CBOM crypto inventory | **Supports** (an agency can inventory + select) |
| NSS deployment (CSfC listing / NSA vetting) | reference library | **Out of scope** — not a deployable product |

Machine-checkable: the matrix's algorithm rows are exactly the `cbom/cbom.cdx.json` assets with
their NIST levels; the dates are the published CNSA 2.0 values.

## 2. Pure-CNSA-2.0 mode (IMPLEMENTED 2026-06-20: suite `0x03`)

NSA's stated NSS **end state** is *pure* PQC; hybrid is treated as transition-only added complexity,
not the preferred NSS configuration (CNSA 2.0 & QC FAQ). VORLATH is hybrid by **default** (matching
NIST/IETF/commercial transition practice) and now **also ships the pure-PQC end-state** as an opt-in suite.

**Shipped.** Suite `0x03` (`CNSA-2.0-pure`): ML-KEM-1024 + ML-DSA-87 + AES-256-GCM + HKDF-SHA384, with
the classical X-DH leg **absent**. Because the implementation is **algorithm-agile** (the recipient's
key selects the suite; length-framed SP 800-56C combiner), it was a `_NullX` adapter plus one suite-
table entry, not a rewrite: the classical contribution to the combiner is zero-length, so the derived
key rests solely on the ML-KEM-1024 secret. The recipient's `0x03` key pins the suite, so downgrade
resistance is unchanged; a classical-only seal is refused for `0x03`.

**Verification (done, not promissory).** Suite `0x03` is exercised by the full **497-test** suite (the
per-suite parametrized tests now run for `0x01`/`0x02`/`0x03`, plus a dedicated pure-PQC test): round-
trip (anonymous + authenticated), downgrade rejection, and the classical-only refusal all pass. **No
new formal model was needed** — a pure-PQC suite's confidentiality is *exactly* the single-leg (PQ-only)
case the four lineages already prove (`secrecy_under_classical_break` / the ProVerif "secrecy under a
classical break" query). `FORMAT.md`, the suite table, and the CLI are updated.

**Honest tradeoff (do not oversell).** `0x03` is the standards **end-state**, not a strictly stronger
mode: it gives up the hybrid's "survives a classical *or* a PQ break" property. Hybrid `0x02` remains
the default precisely because, during the transition, belt-and-suspenders is the more conservative posture.

## 3. Signing-first: LMS for release artifacts (DEMONSTRATED 2026-06-20, software-only)

CNSA 2.0 migrates **firmware/software signing first**, using the stateful hash-based signatures
**LMS/XMSS** per **NIST SP 800-208** (single-tree; strict state management; non-exporting hardware
key generation; low-volume use only).

**Demonstrated.** `release/sign_lms.py` signs the release `bundle_digest` (the SHA-256 Merkle root
from `RELEASE_MANIFEST.json`) with an **LMS** key, alongside the existing cosign / SLSA provenance —
the "signing-first" workflow end-to-end on a genuinely low-volume surface. It uses **pyhsslms** (RFC
8554 + the SP 800-208 parameter additions) with the **CNSA-2.0-preferred SHA-256/192** set
(`lms_sha256_m24_h5` / `lmots_sha256_n24_w8`). The script is a self-checking round trip (keygen, sign,
verify, plus a tampered-digest negative control), refuses to proceed if prior one-time state is
present, and **shreds the spent `.prv` by default** so a one-time leaf can never be silently reused.
`make sign-lms`, or the hermetic gate `docker build -f release/lms.Dockerfile .` (build == pass).
Verified live: 784-byte signature, 52-byte public key, verify VALID / tampered REJECTED, exit 0.
ML-DSA-87 stays the general-purpose signature; LMS is *only* for this release role.

**Honest boundary (loud, by design).** This is a **software reference demonstration**, NOT an
800-208-*compliant* signing service: SP 800-208 requires key generation and signing inside a
**non-exporting hardware module (HSM)** with hardware-enforced state, which a pure-Python library
**categorically cannot** provide. The one-time-signature **state must never be reused** (one signature
per leaf — catastrophic on reuse). This is exactly why VORLATH uses **stateless** SLH-DSA elsewhere;
stateful LMS is justified *only* for the narrow, low-volume, carefully-state-managed release-signing
case, and a production deployment would move keygen + signing into an HSM.

## 4. CSfC dual-layer (design) + RFC 8784 PPK (IMPLEMENTED 2026-06-20)

NSA's **Commercial Solutions for Classified (CSfC)** protects classified data over commercial
products by composing **two independent encryption layers** (outer + inner) with implementation /
vendor diversity and distinct keys. VORLATH's in-line hybrid combiner is a single-protocol echo of
defense-in-depth, **not** two physically independent layers.

**CSfC dual-layer (design).** Position the Shield envelope as the **inner** quantum-resistant layer
beneath an independent outer tunnel (a different vendor/stack, distinct keys), documenting the
layer-independence CSfC requires; the Shield never claims to *be* a CSfC solution or to be on the
Components List. This positioning is documentation, not code.

**RFC 8784 PPK (shipped).** An optional **post-quantum pre-shared key (PPK)** is now injected as a
THIRD length-framed secret into the SP 800-56C combiner (`encrypt(..., ppk=...)` /
`decrypt(..., ppk=...)`; `FLAG_PPK = 0x02`). The derived key then depends on the classical leg, the
ML-KEM leg, **and** the out-of-band PPK — so confidentiality holds even if BOTH the classical and PQ
legs are broken, exactly the RFC 8784 transition rationale. The PPK's presence is bound via FLAG_PPK
in the signed / AEAD-AAD transcript (so it cannot be stripped without invalidating the envelope), and
it is **backward-compatible**: with no PPK the envelope bytes are unchanged, so every frozen
interop / KAT vector still verifies. Verified by the **497-test** suite (round-trip, wrong-PPK reject,
missing-PPK refusal, back-compat, and composition with authenticated mode + the pure-PQC suite 0x03).
No new formal model is required: a PPK only ADDS a length-framed leg to the same combiner the four
lineages already prove key-indistinguishable, so it can only strengthen — never weaken — the
"needs-all-legs" property.

## What is implemented vs designed

| | Implemented + verified today | Designed here (named requirement to ship) |
|---|---|---|
| Algorithm set | CNSA 2.0 Cat-5 (suite 0x02), CBOM inventory | — |
| Hybrid KE + signatures | yes (4 proof lineages, ACVP, interop) | — |
| Pure-CNSA mode | **suite 0x03 - shipped, 497-test verified** | — |
| LMS release signing | **sign_lms.py demonstrated (software, verified live)** | HSM-backed keygen/signing for an 800-208-*compliant* service |
| RFC 8784 PPK | **shipped, 497-test verified** (3rd combiner leg, FLAG_PPK) | — |
| CSfC dual-layer | transcript-binding combiner | section 4 positioning (doc only) |

This document is posture and roadmap, not a certification or a claim of deployed capability. The
honest line between "verified today" and "designed" is the whole point.
