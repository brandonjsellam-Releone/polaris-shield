# VORLATH — PQC Migration Self-Assessment (the TNO Handbook's framework, applied to us)

> **What this is.** [`TNO_PQC_HANDBOOK_ALIGNMENT.md`](TNO_PQC_HANDBOOK_ALIGNMENT.md) shows the Shield's
> *primitives* conform to the AIVD/CWI/TNO *PQC Migration Handbook* (2nd ed., Dec 2024) §4.2. **This**
> document applies the Handbook's *migration process* — Step 1 Quantum-Vulnerability Diagnosis (Ch 2) and
> Step 2 Migration Planning (Ch 3) — to VORLATH itself. Most organisations cite a framework; few run it on
> themselves. We do, and we show our work.
>
> **Honest scope (read first).** The **VORLATH Shield is real and runnable**, so its half of this
> assessment is concrete and machine-checkable (a live CBOM, CI-gated). The **VORLATH citadel is a
> speculative concept**, so its data/supplier inventories are **illustrative** — the data *classes* a
> sovereign quantum facility would hold, not a deployed system's real data. Every "illustrative" line is
> labelled. This is a self-assessment, **not** an external audit.

## 0. PQC personas (Handbook §2.1)

VORLATH identifies as **two** personas — which is itself the honest answer:

| Persona | Why | What the Handbook asks of it |
|---|---|---|
| **Cryptography Expert** (§2.1) | VORLATH *supplies* cryptographic infrastructure — the Shield, the L9 root of trust other systems migrate onto. | Hold the crypto knowledge in-house; own the deepest agility/composability practice (§4.4.1). |
| **Urgent Adopter** (§2.1) | The citadel is *long-lived* sovereign infrastructure handling data that must stay secret for decades → **harvest-now-decrypt-later** applies. | Start the Quantum-Vulnerability Diagnosis **now**; establish the four documents below. |

*The **Cryptography-Expert** reading (the Shield) carries the concrete, verifiable evidence below; the
**Urgent-Adopter** reading (the citadel) frames the urgency but rests on the speculative concept — it adds
no independent evidentiary weight.*

## 1. Step 1 — Quantum-Vulnerability Diagnosis (Ch 2): the four Urgent-Adopter documents

The Handbook (Ch 2 Summary) requires an Urgent Adopter to establish four documents. Our status:

### 1a. Cryptographic asset inventory (§2.3) — **REAL, machine-readable, CI-gated**
The Shield ships a CycloneDX **CBOM** (`cbom/cbom.cdx.json`, 16 crypto assets) + an SBOM. Every primitive,
parameter set, role, governing standard, post-quantum status, and suite usage is *queryable* — and
[`test_tno_conformance.py`](test_tno_conformance.py) fails CI if a TNO-deprecated primitive is ever added.
This is the strongest part of the assessment: the §1.6 / §2.3 "establish cryptographic asset management"
no-regret move is **done**, not planned. Most migrating organisations are still building this.

### 1b. Data inventory — **ILLUSTRATIVE (the citadel is a concept)**
The data *classes* a sovereign quantum citadel would hold, all long-lived/sensitive → HNDL-exposed →
PQC-urgent: classified national-security workloads (L10), cryptographic key material (L9), quantum
sensing / PNT data (L8), compute-as-a-service tenant data. *Illustrative — no deployed system, no real
data; this is the concept's data model, stated so the risk logic is auditable.*

### 1c. Supplier inventory / cryptography supply chain (§1.6, §2.1) — **PARTIAL, real for the Shield**
The Shield's own crypto supply chain *is* inventoried: the reference primitive libraries (`kyber-py`,
`dilithium-py`, `slhdsa`; the `cryptography` lib for X25519/X448/Ed25519/Ed448), each **cross-validated
against a second lineage** (PQClean/C via `interop/cross_impl.py`). *Illustrative for the citadel: a
deployed VORLATH would add HSM vendors, a CA, hardware suppliers — not modelled here.*

### 1d. Risk assessment / Quantum Risk Assessment (§2.4) — **applied**
The Handbook's quantum risk rises with data shelf-life, system longevity, and threat level, and falls with
migration effort. For VORLATH every input is at the extreme:

| §2.4 factor | VORLATH value | Effect on the quantum risk score |
|---|---|---|
| Data shelf-life | decades (sovereign / classified) | **raises** (HNDL) |
| System longevity | ~25–30 yr (the citadel concept) | **raises** |
| Threat level | a nation-state adversary with a CRQC is *literally* the citadel's threat model | **raises** |
| Migration effort | **low for the root of trust** — the Shield is already hybrid PQC | **lowers** (mitigation in hand) |

Net: a **high** quantum risk score that says *migrate now* — and for its own root of trust, VORLATH
already has, because the Shield exists. *Caveat: the longevity and threat inputs are the citadel's
**speculative** concept, not a deployed system's measured risk; the **mitigation** (the Shield) is the
real, runnable part.*

## 2. Step 2 — Migration Planning (Ch 3)

- **When to start (§3.1):** now. As a Cryptography Expert + Urgent Adopter under HNDL, VORLATH has no
  "wait and see" option — and in fact has **already migrated its root of trust** (the Shield is the
  deployed L9), ahead of building the rest of the stack.
- **Strategy:** **hybrid** (classical + PQC), the stance NL/DE/FR advocate (§1.5) and exactly the Shield's
  design; with **algorithm-agility** (the suite registry) for the Handbook's "switch as standards evolve"
  requirement, and the downgrade-binding §4.4.1 flags as the prerequisite for safe agility.

## 3. Cryptographic maturity (§1.7) — honest self-score

The Handbook's maturity is an **organisational** measure — a complete asset overview, risk insight, a
crypto policy, and continuous monitoring, *backed by governance, roles, training and procurement*.
**VORLATH does not claim the full bar:** the Shield is a **reference library** (pure-Python, **not**
FIPS-validated, not side-channel-hardened — see [`SECURITY.md`](SECURITY.md)), not an organisation; the
citadel is a **concept**. What the Shield *does* have is the **technical substrate** of maturity — mature
crypto-asset-management *practice for a library*, CI-enforced:

| §1.7 property | Shield (reference library — *technical practice only*) | Citadel (concept) |
|---|---|---|
| Complete asset overview | **Yes, at library scope** — CBOM/SBOM, CI-gated | illustrative (L1–L11 model) |
| Risk insight | **Yes, at library scope** — `VERIFICATION_GAP_MAP.md` ranks its own seams | illustrative |
| Cryptographic policy | a **technical** policy — suite registry + CNSA-2.0 alignment + deprecation/agility discipline (**not** an org governance policy) | n/a (no deployed org) |
| Continuous monitoring | **Yes** — CI: 508 tests + 4 proof lineages + the TNO conformance gate, on every change | n/a |

So the Shield supplies the **technical substrate** of cryptographic maturity *for a library* — **not** the
full **organisational** maturity bar, which requires the governance, staff, training and procurement that
neither a reference library nor a speculative concept has. We do **not** claim VORLATH is a "crypto-mature
organisation"; that would be premature for a reference implementation and meaningless for a concept.

## 4. Honest limits

A self-assessment is not an external audit, and "we ran the framework on ourselves" is a transparency
exercise, not a certification. The Shield's half is concrete and re-runnable; the citadel's half is
illustrative because the citadel is a concept. The Handbook's organisational steps — governance,
stakeholder alignment, procurement, legal/regulatory policy — are actions a *deployed* VORLATH would
perform; here they are **modelled, not executed**. Where this assessment says "real," it is verifiable in
this repo; where it says "illustrative," it is the concept's design, labelled as such.

## Source

- AIVD, CWI, TNO. *The PQC Migration Handbook*, 2nd ed., Dec 2024 — §1.6 (No-Regret Moves), §1.7
  (Cryptographic Maturity), §2.1 (PQC Personas), §2.3 (Cryptographic Asset Management), §2.4 (Quantum Risk
  Assessment), Ch 3 (Migration Planning), §4.4 (Cryptographic Agility). Companion: this repo's
  [`TNO_PQC_HANDBOOK_ALIGNMENT.md`](TNO_PQC_HANDBOOK_ALIGNMENT.md) (primitive/agility conformance) and
  [`test_tno_conformance.py`](test_tno_conformance.py) (CI gate).
