# Coordinated vulnerability disclosure — VORLATH Shield

VORLATH Shield is a **reference implementation** published as part of the speculative
VORLATH concept. It is **not** a funded product and carries **no SLA**. This policy
exists so that a researcher who finds a defect has a clear, good-faith path to report it — and
so a diligence reviewer can see that one exists.

> Separate-project note: this concerns VORLATH Shield only. It is unaffiliated with the
> separate TRELYAN project. Do not route TRELYAN reports here.

## Scope

In scope: defects in the **cryptographic construction or its implementation** in `tech/` —
e.g. a transcript-binding bypass, a combiner mistake, a parsing/`FORMAT.md` ambiguity that
breaks the independent decoder, a downgrade path, an authentication bypass, or a KAT/ACVP
vector that the code mishandles.

Out of scope: the speculative dossier's financial/strategic content; anything requiring
operational-misuse cryptanalysis; side channels already documented as out of scope in
`SECURITY.md` / `CONSTANT_TIME.md` (report a *new* class, not the known timing leak); and
issues in upstream dependencies (report those upstream, then tell us so we can pin around them).

## How to report

1. Email **brandon.sellam@gmail.com**.
   Use the subject prefix `[VORLATH-SHIELD]`.
2. Include: the property violated (cite `THREAT_MODEL.md` / `FORMAL_COVERAGE.md` where you can),
   a minimal reproducing case, and the affected `bundle_digest` from
   `release/RELEASE_MANIFEST.json` if known.
3. Please give us a good-faith window before public disclosure (target **90 days**, or sooner by
   mutual agreement once a fix or a documented mitigation ships).

## What to expect

- Acknowledgement of a valid report as soon as we can — this is a best-effort, unfunded project,
  so treat timelines as good-faith, not contractual.
- A public, credited fix (or an honest "won't fix, here's why and the documented residual
  risk") referencing the corrected `bundle_digest`.

## Safe harbour (good-faith research)

We will not pursue or support action against researchers who act in good faith: who avoid
privacy violations and service disruption, who test only against their own keys/data, and who
give us the disclosure window above. This is a research artifact — please treat it like one.

See also `/.well-known/security.txt` on the published site.
