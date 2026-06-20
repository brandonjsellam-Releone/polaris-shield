# -*- coding: utf-8 -*-
"""Generate a CycloneDX 1.5 SBOM for POLARIS Shield from the DECLARED pinned deps.

This is the *deterministic, checked-in baseline* SBOM: it is generated only from
`requirements.txt` + `pyproject.toml`, so it contains exactly the direct dependencies
the project pins — no fabricated versions, no invented transitive tree. The full
transitive closure is produced in CI by the real `cyclonedx-py` tool against the
resolved environment (see ../release/README.md); this file is the human-auditable
floor that travels with the source.

    python tech/sbom/make_sbom.py          # writes tech/sbom/sbom.cdx.json

Deterministic by construction: components are sorted, and no wall-clock timestamp is
embedded (the CI SBOM carries the authoritative build timestamp + serialNumber).
"""
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
TECH = os.path.dirname(HERE)
OUT = os.path.join(HERE, "sbom.cdx.json")

# Curated, honest license map for the direct dependencies (SPDX ids; sources: each
# project's PyPI metadata). Kept explicit rather than scraped so the SBOM is offline-deterministic.
_LICENSES = {
    "kyber-py": "MIT",
    "dilithium-py": "MIT",
    "slh-dsa": "MIT",
    "cryptography": "Apache-2.0 OR BSD-3-Clause",
    "polaris-shield": "Apache-2.0",
}


def _parse_requirements(path):
    """Return [(name, version_spec)] from a requirements file (skip comments/blanks)."""
    out = []
    for line in open(path, encoding="utf-8"):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*([<>=!~].*)?$", line)
        if m:
            out.append((m.group(1), (m.group(2) or "").strip()))
    return out


def _pin(spec):
    """Exact pin '==X' -> 'X'; otherwise return the range spec verbatim (honest about ranges)."""
    m = re.match(r"^==\s*([^,\s]+)$", spec)
    return m.group(1) if m else spec


def _purl(name, version_spec):
    pin = _pin(version_spec)
    # Only emit a versioned purl for an exact pin; a range gets the bare package purl.
    return f"pkg:pypi/{name}@{pin}" if re.match(r"^==", version_spec) else f"pkg:pypi/{name}"


def component(name, version_spec, *, ctype="library"):
    pin = _pin(version_spec)
    comp = {
        "type": ctype,
        "name": name,
        "version": pin,
        "purl": _purl(name, version_spec),
        "scope": "required",
    }
    lic = _LICENSES.get(name)
    if lic:
        comp["licenses"] = [{"expression": lic}]
    if version_spec and not version_spec.startswith("=="):
        comp["properties"] = [{"name": "version:constraint", "value": version_spec}]
    return comp


def main():
    runtime = _parse_requirements(os.path.join(TECH, "requirements.txt"))
    # runtime deps only (drop the dev/test markers): everything before the '# dev / test' line
    deps = [(n, v) for (n, v) in runtime if n.lower() not in ("pytest",)]

    components = sorted(
        (component(n, v) for (n, v) in deps),
        key=lambda c: (c["name"], c["version"]),
    )

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            # No timestamp -> deterministic checked-in baseline. CI stamps the authoritative one.
            "component": {
                "type": "application",
                "name": "polaris-shield",
                "version": "2.0.0",
                "purl": "pkg:pypi/polaris-shield@2.0.0",
                "licenses": [{"expression": _LICENSES["polaris-shield"]}],
                "description": ("POLARIS Shield - algorithm-agile post-quantum hybrid security "
                                "(FIPS 203/204, CNSA 2.0 algorithm set). Reference implementation."),
                "externalReferences": [
                    {"type": "website", "url": "https://borealispolaris.io"},
                    {"type": "vcs", "url": "https://github.com/brandonjsellam-Releone/borealispolaris"},
                ],
            },
            "tools": [{"vendor": "POLARIS", "name": "make_sbom.py", "version": "1.0"}],
            "properties": [
                {"name": "sbom:scope", "value": "declared-direct-dependencies"},
                {"name": "sbom:note",
                 "value": "Transitive closure is resolved in CI via cyclonedx-py; this baseline lists pinned direct deps only."},
            ],
        },
        "components": components,
    }

    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(bom, f, indent=2, sort_keys=False)
        f.write("\n")
    print(f"wrote {os.path.relpath(OUT, TECH)} ({len(components)} direct components)")
    for c in components:
        print(f"  - {c['name']} {c['version']}  ({c['purl']})")


if __name__ == "__main__":
    main()
