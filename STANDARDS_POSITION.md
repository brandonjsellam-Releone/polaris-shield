# VORLATH Shield — standards positioning & combiner justification

A reviewer's first question is *"why this exact stack and not the obvious academic /
standards-track alternative?"* This note answers it up front, with citations to the **final**
NIST FIPS (203/204/205, effective Aug 2024), the live IETF *hybrid* drafts, and the federal
mandates, so the design choices read as deliberate rather than ad hoc.

> Scope: this is a *positioning* note, not a conformance claim. VORLATH Shield is a reference
> implementation; it is not a standardized protocol and not a validated module (see `SECURITY.md`).

## 1. The algorithm set is CNSA 2.0 (not a bespoke choice)

Suite `0x02` is exactly the **NSA CNSA 2.0 Category-5 set**: ML-KEM-1024 (FIPS 203) +
ML-DSA-87 (FIPS 204) + AES-256 + SHA-384, hybridised with X448. CNSA 2.0 / NSM-10 set the
U.S. national-security migration timeline (software/firmware signing prioritised first, broad
adoption through the late-2020s into 2030–2033). Building to the published government set —
rather than a novel parameterisation — is the point: it is the set a sovereign reviewer is
already mandated to move toward.

## 2. The combiner: SP 800-56C shape, GHP18 / X-Wing security argument

The AEAD key is derived from **both** the ECDH secret and the ML-KEM secret, length-framed and
bound to the full handshake transcript (`suite_id‖flags‖recipient_key_id‖eph_pub‖kem_ct‖nonce`).
Design rationale and the alternatives considered:

| Choice | What VORLATH Shield does | Why, vs. the alternative |
|---|---|---|
| **KEM combiner** | length-framed `ss_classical ‖ ss_pq` into an SP 800-56C-shaped KDF, transcript as FixedInfo | Matches the **dual-PRF / X-Wing (GHP18)** robustness argument: the output stays pseudorandom if *either* KEM is IND-CCA. A bare concatenation without length-framing is the classic mix-and-match pitfall; framing + domain separation closes it. |
| **Transcript binding** | whole transcript signed *and* used as AEAD AAD *and* in the KDF `info` | Makes downgrade/mix-and-match unreachable (machine-checked: `FORMAL_COVERAGE.md` rows 4–5), the same defence TLS 1.3 hybrid binds via the transcript hash. |
| **Signature placement** | ML-DSA over `pre_auth ‖ sender_key_id`, verified **before** decapsulation (SIGMA-style) | Binds the signer's *own* identity → no UKS / identity-misbinding; KCI-resistant (row 6). |
| **Suite selection** | the **recipient's key** selects the suite | A sender or attacker cannot negotiate a weaker suite — downgrade resistance is structural, not policy. |

## 3. Relationship to the live IETF / NIST hybrid drafts

VORLATH Shield is an envelope convention, deliberately *aligned in spirit* with — but not
claiming conformance to — the standards-track hybrid constructions a reviewer will know:

- **X-Wing** (`draft-connolly-cfrg-xwing-kem`) — the canonical X25519+ML-KEM-768 hybrid KEM;
  the security intuition VORLATH's combiner reuses (one-leg-break robustness via a PRF-modeled
  combiner). VORLATH generalises it to an algorithm-agile suite (adds the CNSA-2.0 X448 +
  ML-KEM-1024 tier).
- **TLS 1.3 hybrid key exchange** (`draft-ietf-tls-hybrid-design`, e.g. `X25519MLKEM768`) — the
  interoperable transport a production deployment should use; `SECURITY.md` points there
  explicitly rather than pretending the envelope is a wire standard.
- **PQ/T composite signatures** (`draft-ietf-lamps-pq-composite-sigs`) — the standards-track
  analogue of the Shield's opt-in `dual_sign` (ML-DSA **and** SLH-DSA) high-assurance mode for
  long-lived roots.
- **COSE/JOSE PQC hybrid HPKE** (`draft-reddy-cose-jose-pqc-hybrid-hpke`) — the message-layer
  direction; relevant if the envelope is ever mapped onto a standard object-security format.

## 4. Supply-chain & provenance posture (2026 baseline)

To match what a serious 2026 diligence desk now expects of any security-critical artifact:

- **SBOM** — CycloneDX 1.5, checked-in baseline (`sbom/sbom.cdx.json`), full transitive closure
  produced in CI (`release/README.md`).
- **Reproducible, content-addressed bundle** — `release/RELEASE_MANIFEST.json` (a SHA-256
  Merkle-style root over source + all proof models + vectors), signed with **cosign (keyless
  OIDC)** at release.
- **Build provenance** — **SLSA**-style provenance attestation generated in CI
  (`.github/workflows/provenance.yml`) so the published artifacts trace to the exact commit.
- **Coordinated disclosure** — `SECURITY-DISCLOSURE.md` + `/.well-known/security.txt`.

## 5. Honest boundaries

This note positions VORLATH Shield against the standards; it does **not** claim adoption,
conformance, certification, or endorsement by any standards body. The references above are to
public, in-progress drafts and published U.S. government guidance; treat them as the map of
where the design sits, not as a badge it has earned.
