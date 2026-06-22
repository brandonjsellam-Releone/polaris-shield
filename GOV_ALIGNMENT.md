# GOV_ALIGNMENT.md — VORLATH Shield: US-Government Posture Map

## Classified boundary statement

This document is built **exclusively from PUBLIC and DECLASSIFIED, citable US-government sources** — NSA/NIST/CISA/DoD/White House/OMB/GSA public pages and the FIPS, SP, NSM, OMB, CNSSP, and CSfC documents listed in the per-row sources. It claims **no access to classified material**, fabricates no document, capability, or "leaked" detail, and contains **no operational cryptanalysis or attack uplift**. All national-security framing is **policy / posture / standards-alignment only**. VORLATH Shield is a **reference implementation, NOT a FIPS 140-3 validated module, NOT CNSA-2.0 certified, NOT on the CSfC Components List, and NOT endorsed by NSA/NIST/CISA**. Algorithm-set parity is alignment, **not certification**. The VORLATH citadel is a **speculative, order-of-magnitude** concept and is honestly weaker than (not a substitute for) the public DARPA Quantum Benchmarking Initiative trajectory.

Status legend: **aligned** = Shield genuinely meets the public requirement at the posture/standards level; **partial** = supports/echoes it but does not satisfy it wholesale or carries an honest tension; **out-of-scope** = not a property a transport/envelope reference library can satisfy (certification, agency programs, full architectures).

---

## A. NSA / CNSA 2.0 + CSfC

| Public requirement | Source | Status | Gap or upgrade |
|---|---|---|---|
| CNSA 2.0 Category-5 algorithm set: ML-KEM-1024 (FIPS 203), ML-DSA-87 (FIPS 204), AES-256, SHA-384/512 | NSA CSA "Announcing CNSA 2.0" (2022; algorithms reissued May 2025) | aligned | Suite 0x02 IS exactly this set (ML-KEM-1024 + ML-DSA-87 + AES-256-GCM + HKDF-SHA384). Genuine primitive-level parity. |
| NSA stated end state for NSS mission systems is PURE PQC; hybrid treated as transition-only added complexity, NOT required/recommended | NSA CNSA 2.0 & Quantum Computing FAQ (Sep 2022, updated 2024) | partial | VORLATH is fundamentally hybrid (X25519/X448 + ML-KEM via SP 800-56C combiner). Honest tension: this matches NIST/IETF/commercial transition practice, NOT the CNSA-2.0-preferred pure-NSS configuration. Upgrade: add a one-flag "pure CNSA 2.0 Cat-5 mode" that disables the classical leg. Must NOT claim to be the CNSA-2.0-preferred NSS config. |
| Firmware/software signing migrates first, using stateful hash-based LMS/XMSS (SP 800-208, single-tree); exclusive by 2030 | NSA CNSA 2.0 CSA + SP 800-208 | partial | Shield references SLH-DSA but is a transport/envelope, not a deployed code-signing PKI. Upgrade: add an LMS/XMSS signing path for the Shield's own release artifacts to demonstrate the "signing-first" mandate, keeping ML-DSA-87 for general signatures. |
| CSfC dual-LAYER model: two independent commercial encryption components (outer + inner), implementation/vendor diversity, distinct keys | CSfC Capability Packages (MAC, WLAN, MA, DAR CP v5.0); CSfC Components List | partial | The Shield's in-line hybrid combiner is a single-protocol echo of defense-in-depth, NOT two physically independent layers. Upgrade: model the envelope as an inner layer beneath an independent outer tunnel (distinct vendor/keys), documenting layer-independence as CSfC requires. Explicitly note: not CSfC-listed. |
| CSfC PQC direction: inner layer carries quantum-resistant protection; RFC 8784 PPKs as sanctioned classical+PQC composition | CSfC PQC Guidance Addendum (draft); CSfC Symmetric Key Management Annex; RFC 8784 | partial | Upgrade: add optional RFC 8784-style quantum-resistant pre-shared-key (PPK) injection as an inner-layer key contribution — a transition composition NSA already endorses. |
| CNSSP-15: NSS use the CNSA public-standard algorithm set for interoperability | CNSSP-15 policy + fact sheet | partial | Algorithm choice conforms; CNSSP-15 is a binding policy for NSS deployment, which a reference implementation cannot satisfy by itself. Posture, not approval. |
| Jan 1 2027 acquisition gate; networking 2030; web/cloud + OS + custom apps 2033; all NSS quantum-resistant ~2035 | NSA CNSA 2.0 CSA + FAQ | partial | Upgrade: publish a CNSA 2.0 migration-milestone self-assessment matrix mapping each Shield mode to each dated category target — machine-checkable against published dates. |
| NSS deployment requires NSA product vetting / CSfC listing | CSfC program; CNSA 2.0 FAQ | out-of-scope | Not achievable by a reference library. State plainly as the gap between standards-aligned implementation and an NSS-deployable product. |

---

## B. NIST standards

| Public requirement | Source | Status | Gap or upgrade |
|---|---|---|---|
| Use FINAL FIPS PQC primitives: ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205), effective Aug 13 2024 | FIPS 203/204/205 final; Federal Register 2024-17956 | aligned | Suite uses FIPS 203/204 primitives faithfully; opt-in SLH-DSA is a faithful FIPS 205 use. **Correction required:** STANDARDS_POSITION.md calls these "live 2026 drafts" (line 5) — factually stale; they are FINAL FIPS since 2024-08-13. |
| KEM key derivation via approved KDF: SP 800-56C Rev.2 two-step extract-then-expand with FixedInfo/context binding | SP 800-56C Rev.2 (2020) | partial | Combiner is correctly SP 800-56C-SHAPED, but Rev.2 does not yet enumerate ML-KEM shared secrets as an approved input. Upgrade: re-anchor the KDF-input lineage to SP 800-227, not SP 800-56C alone. |
| Hybrid/composite KEMs: combine components via an approved key combiner preserving IND-CCA (secure if at least one component is secure); standard names SPECIFIC approved combiners | SP 800-227 (final Sept 2025; IPD Jan 2025); split-key-PRF paper | partial | The "secure if either leg holds" robustness claim is exactly SP 800-227's notion, but conformance means using a named approved instantiation. Upgrade: verify the combiner is an approved instantiation or document the precise delta — do not assert equivalence by shape alone. |
| Stateful hash signatures (XMSS/LMS) approved ONLY for low-volume firmware/software signing, strict state management, non-exporting hardware key-gen | SP 800-208 (2020) | partial (by design) | VORLATH deliberately chose STATELESS SLH-DSA over stateful XMSS/LMS. Upgrade: document this choice with the SP 800-208 constraints quoted, turning it into a standards-grounded justification. |
| FIPS-validated status requires CAVP algorithm testing (ACVP vectors) THEN CMVP FIPS 140-3 module validation; CAVP alone is necessary-but-not-sufficient | NIST CAVP/ACVP; CMVP FIPS 140-3 IG | partial / out-of-scope | Targeting ACVP vectors is the correct first leg and is genuine algorithm-level conformance evidence. It is NEVER module certification. Upgrade: obtain/publish ACVP certs and state CMVP FIPS 140-3 as named future work. Must not imply validated status. |
| Before migration, build cryptographic discovery/inventory; favor hybrid during transition (posture, not hard mandate) | NIST SP 1800-38 (NCCoE Migration to PQC) | aligned (posture) | The Shield's SBOM + reproducible build + signed transcript directly FEED an agency inventory. Upgrade: extend the SBOM into a machine-readable CBOM (crypto bill of materials). |
| Bind KDF FixedInfo to explicit versioned context (suite_id, spec version, transcript hash) for deterministic replay | SP 800-56C Rev.2 / SP 800-227 | aligned | Shield binds the full transcript as FixedInfo/AAD/KDF info. Upgrade: publish the exact KDF labeling so an external reviewer can replay the derivation deterministically. |

---

## C. Federal mandates

| Public requirement | Source | Status | Gap or upgrade |
|---|---|---|---|
| Migrate to quantum-resistant cryptography; NSS transition targeted complete by 2035; NSA sets NSS timelines | NSM-10 (May 4 2022) | partial (posture) | Algorithm choice and roadmap framing align; NSM-10 directs agencies/NSS programs, which a library does not execute. The hybrid design directly answers the harvest-now-decrypt-later rationale. |
| Each agency builds and maintains a prioritized inventory of quantum-vulnerable IT; reports to OMB/CISA/ONCD; develops migration plans within 1 year of NIST standards; Sense of Congress demands cryptographic agility | PL 117-260 (Quantum Computing Cybersecurity Preparedness Act; 6 USC 1526) | partial | Sec. 2(b) agility intent is directly satisfied: the Shield is algorithm-agile with suite negotiation. The inventory/reporting obligations belong to agencies; the Shield FEEDS them, does not satisfy them. NSS are statutorily exempt (Sec. 5) and follow CNSA 2.0 instead. |
| Annual prioritized cryptographic inventory (first due May 4 2023), named migration lead, HVA-first prioritization, funding assessment | OMB M-23-02 (Nov 18 2022) | partial | Shield is one library, not an agency program. Upgrade: ship a CBOM artifact that an agency can ingest directly to populate its M-23-02 inventory. |
| Operational playbook: quantum-readiness roadmap, cryptographic inventory, supply-chain/CBOM analysis, vendor engagement | CISA/NSA/NIST joint CSI "Quantum-Readiness" (Aug 2023) | partial | The Shield's SBOM + provenance support the supply-chain step. Upgrade: CBOM + per-handshake signed transcript give auditors machine-readable cryptographic-use evidence, supporting "automate migration tracking to the greatest extent practicable." |
| Standardize on FIPS algorithm names (ML-KEM, ML-DSA, SLH-DSA), not pre-standard CRYSTALS labels | OMB M-23-02; FIPS 203/204/205 | aligned | Shield uses the standardized FIPS names throughout. |
| Encryption-in-transit and inventory/visibility baseline; adopt NIST PQC when available | OMB M-22-09 (Zero Trust) | aligned (posture) | Per-session ephemeral encrypted handshake meets the encrypt-in-transit baseline; PQC primitives are adopted. |

---

## D. DoD / Zero Trust / AI

| Public requirement | Source | Status | Gap or upgrade |
|---|---|---|---|
| Secure all communication regardless of network location; authenticate every request per-session before resource access | NIST SP 800-207; DoD ZT Reference Architecture v2.0 | aligned | Per-session ephemeral handshake with signature verified BEFORE decapsulation (SIGMA-style) and signed transcript binding match the "encrypt-everything / authenticate-before-session" tenets. |
| Data-centric protection: encryption at rest and in transit plus rights management; Data pillar central; FY2027 Target / Advanced ZT | DoD Zero Trust Strategy (Nov 2022); DoD ZT RA v2.0 | partial | The Shield is the cryptographic spine of the Data/Network pillars, NOT a full 7-pillar / 152-activity ZT implementation (no identity, device, visibility, or orchestration pillars). Upgrade: publish a ZT-pillar crosswalk mapping Shield capabilities to specific Data/Network activities. |
| Strong, standardized cryptography for NSS (CNSA 2.0 Cat-5; LMS/XMSS or SLH-DSA for signing) | DoD ZT docs citing CNSA 2.0; FIPS 203/204/205 | aligned | Suite 0x02 instantiates the mandated set; opt-in SLH-DSA is a high-assurance signing-grade primitive consistent with the stateless direction. |
| AI "Secure and Resilient": adversarially robust AI, hardened federal systems, secure development/deployment frameworks (posture, not a crypto-conformance regime) | NIST AI RMF 1.0 (AI 100-1); June 2026 AI EO + NSPM | partial (posture) | The 508-test suite + ACVP conformance + machine-checked proofs + reproducible build + SBOM + SLSA provenance map to the assurance/secure-development intent. Upgrade: bind model/agent execution transcripts with the signed-transcript mechanism (tamper-evident execution logs) and map to AI RMF MEASURE/MANAGE — a posture-level "machine-age governance" artifact. |
| DoD/NSS operational crypto generally expects FIPS-validated modules (FISMA/CNSSP-15 ecosystem) | DoD ZT / FISMA / CNSSP-15 | out-of-scope | No public ZT doc requires FIPS 140-3 as a precondition of the architecture itself, but operational DoD/NSS use expects it. This is the single largest real deployment gap; state as "reference implementation, validation pending." |
| Sovereign fault-tolerant quantum-compute trajectory (public anchor) | DARPA Quantum Benchmarking Initiative | out-of-scope | The VORLATH citadel is speculative / order-of-magnitude and is honestly weaker than the public DARPA QBI program — a framing anchor, not a capability claim. |

---

## Where we genuinely exceed typical posture

These are real, checkable differentiators — the Shield does NOT merely assert alignment, it produces verifiable artifacts.

1. **Machine-checked proofs.** Verifpal/Tamarin/CryptoVerif (ProVerif 4th in verification) cover downgrade/mix-and-match unreachability, UKS/KCI resistance, and one-leg-break robustness. This directly answers the **Dual_EC_DRBG lesson** (NIST SP 800-90A withdrawal, 2014): trust must rest on open, independently-verifiable provenance, not assertion. The federal mandates require migration — they do NOT require proof — so publishing machine-checked proof bundles exceeds the baseline.

2. **Reproducibility and provenance.** Content-addressed reproducible build (SHA-256 Merkle root over source + proof models + vectors), cosign keyless-OIDC signature, SLSA provenance, and SBOM let any third party re-derive every security claim. This turns the historical "un-auditable primitive" failure mode into a positive differentiator and exceeds the bare SBOM diligence baseline.

3. **Algorithm-agility as a first-class compliance feature.** Suite negotiation with recipient-key-selected suites directly satisfies the **PL 117-260 Sec. 2(b) Sense of Congress** (easily-updatable, agile implementations) and pre-positions for the post-2035 "migrate hybrids to pure PQC" future NSA flagged — one codebase serving both the NIST/CISA hybrid transition posture and a pure-PQC CNSA-2.0 mode via a configurable, audited switch.

4. **SLH-DSA hedge beyond the mandate.** The opt-in SLH-DSA (FIPS 205) dual-signature mode for long-lived roots is an assurance upgrade BEYOND CNSA 2.0, which EXCLUDES SLH-DSA from its general suite — deliberate hash-based hedging, not a misread of the mandated set.

---

## Scope and limits (honest close)

VORLATH Shield is a **real reference implementation** whose suite 0x02 is the genuine CNSA 2.0 Category-5 algorithm set, whose combiner is SP 800-56C/SP 800-227-shaped, and whose assurance artifacts exceed typical vendor posture. It is **NOT** a FIPS 140-3 validated module, **NOT** CNSA-2.0 certified, **NOT** NIAP/CSfC-listed, **NOT** CNSSP-15-approved, and **NOT** endorsed by any standards body. It **cannot be deployed on real NSS** and must not imply otherwise. What is documented here is **alignment and posture**, not certification. The gates between this reference implementation and an NSS-deployable product — ACVP certificates, CMVP FIPS 140-3 validation, NIAP/CSfC listing, and NSA product vetting — are named as future work, not earned badges.