# VORLATH Shield — alignment with the AIVD/CWI/TNO *PQC Migration Handbook* (2nd ed., Dec 2024)

> **What this is.** A conformance **argument** mapping the Shield onto the technical
> recommendations of *The PQC Migration Handbook — Guidelines for Migrating to Post-Quantum
> Cryptography* (AIVD, CWI, TNO; 2nd edition, December 2024), the authoritative European
> migration guidance. Each claim is tied to a specific Handbook section. It is **not** a
> certification, an endorsement by AIVD/CWI/TNO, or a validation (see
> [`SECURITY.md`](SECURITY.md): the Shield is a reference implementation, **not** FIPS 140-3 /
> CAVP validated; "CNSA 2.0" names the algorithm set, never a certificate). The Handbook is a
> public document; this crosswalk neither reproduces it nor claims its authors' approval.
>
> **Why it exists.** The Handbook is the most concrete, vendor-neutral statement of *what good
> looks like* for a PQC migration — primitive choices (§4.2), forms of cryptographic agility
> (§4.4), no-regret moves (§1.6), and the personas that should act now (§2.1). It is the natural
> external yardstick for the Shield, which is a **Cryptography-Expert-persona** artifact: a
> library that supplies the post-quantum root of trust other systems migrate onto. This page
> shows the Shield already instantiates the Handbook's technical recommendations — and states,
> honestly, the one place it deliberately diverges.

## The Shield in one line (ground truth, `vorlath_shield/shield.py`)

Algorithm-agile hybrid PQC: suite `0x01` (X25519 + ML-KEM-768 + ML-DSA-65, HKDF-SHA-256),
suite `0x02` CNSA-2.0 default (X448 + ML-KEM-1024 + ML-DSA-87, HKDF-SHA-384), suite `0x03`
pure-PQC; SP 800-56C two-step HKDF combiner over length-framed secrets; AES-256-GCM; suite_id
bound in the AEAD AAD + KDF transcript + (auth mode) the signed `pre_auth`; optional dual
signature (ML-DSA **and** SLH-DSA) and LMS one-time signing in the high-assurance path.

## 1. Primitive recommendations — Handbook §4.2, Tables 4.1 & 4.2

| Handbook recommendation | Shield | Verdict |
|---|---|---|
| **KEM: ML-KEM**, *"deployed in a hybrid combination with ECDH"* (Table 4.1, fn 1; §4.2.1) | X25519+ML-KEM-768 / X448+ML-KEM-1024 via an SP 800-56C combiner | **CONFORM** — recommended primitive, in the recommended ECDH-hybrid form |
| **Signature: ML-DSA** (+ **SLH-DSA**), and *"ML-DSA and SLH-DSA over FN-DSA"* (§4.2.1) | ML-DSA-65/87; **opt-in SLH-DSA**; **no FN-DSA** | **CONFORM (primitive choice)** — exactly the recommended set; FN-DSA correctly avoided (its standard is not final) |
| ML-DSA *"in a hybrid combination with ECDSA/EdDSA"* (Table 4.1, fn 2) | ML-DSA is **pure-PQC**; diversified by **hash-based SLH-DSA** (dual-sign), not by an EC signature | **DELIBERATE DEVIATION** — see §4 below |
| **SLH-DSA** *need not* be hybridised (hash-based ⇒ conservative; §4.2.1) | SLH-DSA used standalone in the dual-sign path | **CONFORM** — matches the Handbook's explicit carve-out |
| **Stateful signatures: XMSS / LMS / HSS** with careful state management (§4.2.2) | `sign_lms.py` (LMS), one-time-key reuse rigorously prevented (fresh key/run, refuse-to-clobber, shred-spent) | **CONFORM** — recommended primitive, with the exact state-management discipline §4.2.2 demands |
| **AEAD: AES-GCM**; **block cipher: AES-256**; **hash: SHA-2/SHA-3**; **MAC: HMAC-SHA-2** (Tables 4.1/4.2) | AES-256-GCM; HKDF-**SHA-256/384** (HMAC-SHA-2) | **CONFORM** |
| **Parameter sets**: level 5 strongest, level 3 acceptable; *"NSA CNSA 2.0 requires level 5"* (Table 4.2, fn 3) | suite `0x02` = ML-KEM-1024 + ML-DSA-87 (**level 5**, default); suite `0x01` = ML-KEM-768 + ML-DSA-65 (**level 3**) | **CONFORM** — the default is the level-5 CNSA-2.0 set; level-3 offered as the Handbook's "acceptable" alternative |

## 2. Forms of Cryptographic Agility — Handbook §4.4 / §4.4.1

The Handbook frames agility as the central technical enabler. The Shield is built around it.

| Form (§4.4.1) | Shield evidence |
|---|---|
| **Migration agility** (replace one algorithm with another) | The 1-byte **suite_id** selects the whole primitive set; crypto calls are abstracted behind `_derive_key` / the suite table, so a new suite is one localized change. |
| **…without the downgrade risk §4.4.1 warns of** (`[NCSC-NL24]`: "OR-fashion" multi-algorithm support invites downgrade attacks) | The suite_id and flags are bound into the **AEAD AAD**, the **HKDF transcript**, and (auth mode) the **signed `pre_auth`** — a forced downgrade changes the transcript and fails AEAD/verification. This binding **meets the requirement** §4.4.1 flags as necessary before OR-fashion agility is safe (the Handbook states the requirement; it does not prescribe this exact mechanism). |
| **Compliance agility** (different regional/regulatory configs side by side) | suite `0x01` (FIPS-set) vs suite `0x02` (CNSA-2.0 level-5) selectable per message. |
| **Implementation agility** (swap the implementation, not the algorithm) | the `_NullX` classical adapter, the PQClean/C **cross-implementation differential** (`interop/cross_impl.py`), and CI gates make the implementation replaceable + continuously tested — the §4.4 "abstract the crypto, test it in CI/CD" guidance. |
| **Platform agility** | pure-Python reference runs anywhere Python does (honest caveat: **not** hardware-accelerated / side-channel-hardened — §4.4 notes PQC's larger keys/bandwidth and hardware fit as real constraints). |
| **Composability agility** (*"particularly useful … where hybrid-AND compositions are expected … mainly the cryptographic experts who actually build the cryptography"*, §4.4.1) | The Shield **is** a hybrid-AND combiner (SP 800-56C, length-framed injective IKM); composing classical+PQ (+optional PPK) is its core. This is exactly the Cryptography-Expert use the Handbook scopes it to. |
| **Retirement agility** | suites can be deprecated/removed; the Handbook's "remove OR-options once no longer needed" is supported by the explicit suite registry. |

## 3. No-regret moves & maturity — Handbook §1.6, §1.7, §2.3

| Handbook item | How the Shield serves it |
|---|---|
| **Establish Cryptographic Asset Management** (§1.6, §2.3) — an inventory is the first no-regret move and the foundation of agility | The Shield ships a **CBOM** (`cbom/cbom.cdx.json`) and **SBOM** (CycloneDX) — a machine-readable crypto inventory a migrating organisation can ingest directly. |
| **Cryptographic agility is a no-regret move** (§1.7) | the suite architecture above |
| **Cryptographic maturity** = complete asset overview + risk insight + policy + continuous monitoring (§1.7) | The Shield provides the *asset/agility* substrate; the *risk/policy/monitoring* loop is an **organisational** action the Shield supports but does not itself perform (scoped honestly, not overclaimed). |
| **PQC personas** (§2.1) | VORLATH is both an **Urgent Adopter** (long-lived sovereign infrastructure under harvest-now-decrypt-later) and a **Cryptography Expert** (it *supplies* the root of trust). The Shield is the Cryptography-Expert deliverable. |

## 4. The one deliberate deviation (stated plainly — and *not* unambiguously safer)

Table 4.1 footnote 2 recommends deploying **ML-DSA in a hybrid combination with an elliptic-curve
signature** (ECDSA/EdDSA), for defense-in-depth: a classical, decades-hardened fallback so a
*classical* cryptanalytic break of ML-DSA's lattices — one that could arrive **before** any quantum
computer — does not by itself break authentication.

The Shield's **KEM** follows this classical-hybrid pattern exactly (X25519/X448 **+** ML-KEM). On the
**signature** side it does not: it keeps ML-DSA pure-PQC and, in the high-assurance path, diversifies
it with a **hash-based SLH-DSA** co-signature (`highassurance.py` requires **both** legs) rather than
an EC signature. Stated plainly so a reviewer can weigh it — an AI-council review flagged an earlier
"arguably more conservative" framing here as an **overclaim**, and they were right:

- **What the SLH-DSA leg gains:** both signature legs are **quantum-safe**, so the pair survives a
  quantum adversary; and SLH-DSA rests on hash functions — a **different primary assumption** from
  ML-DSA's lattices (hash-based vs lattice; not fully disjoint, since ML-DSA uses SHAKE internally) —
  so a *lattice-only* break cannot forge.
- **What dropping the EC leg costs (honestly):** an EC signature carries **decades of classical
  cryptanalysis and battle-tested constant-time implementations**, and it is the leg that would still
  stand if ML-DSA fell to a **classical** attack before any quantum computer existed. SLH-DSA adds a
  *second post-quantum* assumption, **not** that mature classical fallback.
- **So this is a different tradeoff, not a strict improvement:** the Shield trades a proven classical
  fallback for a second (younger) post-quantum assumption. The strongest hedge against *any*
  single-family break is the **triple** ML-DSA + SLH-DSA + EC — quantum-safe *and* classically-hardened
  — but at the cost of more code, complexity and attack surface (a tradeoff the Handbook itself flags
  for hybrids), so it is not unconditionally "best".

Net: the Shield meets footnote 2's *intent* (signature defense-in-depth against a single-family break)
on a **post-quantum** axis, at the cost of the classical-maturity axis the EC leg provides. The
dual-sign interface can carry an EC leg, so a peer that wants the Handbook's literal ML-DSA+EdDSA — or
the full triple — can have it. We flag the deviation **with its real cost** so the choice is auditable,
not hidden.

## Net

Against the Handbook's technical chapters the Shield is a near-complete **instantiation** of the
recommended primitives (§4.2), the recommended *hybrid* deployment of ML-KEM (§4.2.1), the explicit
ML-DSA/SLH-DSA-over-FN-DSA choice (§4.2.1), disciplined LMS stateful signing (§4.2.2), and the full
spectrum of cryptographic-agility forms (§4.4) — including the downgrade-attack mitigation the
Handbook flags as a prerequisite for safe "OR-fashion" agility (§4.4.1). It supplies the
cryptographic-asset-management substrate the Handbook names as the first no-regret move (§1.6, §2.3).
It diverges from the EC-signature-hybrid recommendation **deliberately**, trading the classical-maturity
axis for a second post-quantum leg — a different tradeoff, not a strict improvement (§4 above).

**Honest limits.** This is a *conformance argument* to a public guidance document, not a validation,
not an AIVD/CWI/TNO endorsement, and not FIPS 140-3 / CAVP. The Shield remains a reference
implementation; for production traffic prefer a validated implementation and a standardized hybrid
profile (X-Wing, or hybrid TLS 1.3 / HPKE / MLS — see [`STANDARDS_ALIGNMENT.md`](STANDARDS_ALIGNMENT.md)).
The Handbook's organisational steps (diagnosis, risk assessment, planning, personas) are actions a
*migrating organisation* performs; the Shield is the technical artifact those steps migrate **onto**.

## Source

- AIVD, CWI, TNO. *The PQC Migration Handbook — Guidelines for Migrating to Post-Quantum Cryptography*,
  Revised and Extended **2nd Edition**, December 2024 (reprint August 2025). Sections cited: §1.6
  (No-Regret Moves), §1.7 (Cryptographic Maturity), §2.1 (PQC Personas), §2.3 (Cryptographic Asset
  Management), §4.2 + Tables 4.1/4.2 (Recommended Primitives), §4.4 / §4.4.1 (Cryptographic Agility),
  with `[NCSC-NL24]` on downgrade attacks.
