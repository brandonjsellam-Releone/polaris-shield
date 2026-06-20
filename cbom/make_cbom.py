# -*- coding: utf-8 -*-
"""Generate a CycloneDX 1.6 CBOM (Cryptographic Bill of Materials) for POLARIS Shield.

A CBOM is the machine-readable cryptographic inventory that the US-federal PQC migration
mandates call for (NSM-10; OMB M-23-02; NIST NCCoE SP 1800-38 "Migration to PQC" discovery /
inventory). It enumerates every cryptographic ASSET the Shield uses - algorithm, parameter set,
primitive role, the governing NIST/IETF standard, post-quantum status, and which suite uses it -
so an agency (or a reviewer) can QUERY the crypto posture instead of trusting prose.

    python tech/cbom/make_cbom.py        # writes tech/cbom/cbom.cdx.json

Deterministic by construction (sorted assets, no embedded timestamp). This is generated from the
DESIGN (FORMAT.md / the suite table), not a binary scan; OIDs are the published NIST CSOR / RFC
values for the asset. It is an inventory, NOT a certification claim (see SECURITY.md / GOV_ALIGNMENT.md).
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "cbom.cdx.json")

# Each crypto asset of the Shield. nist_level = claimed NIST PQ security category (0 = no
# standalone post-quantum security, i.e. a classical leg broken by Shor; 1..5 = FIPS category).
# suites: which wire suite(s) use it. std: the governing standard. oid: published NIST CSOR / RFC.
ASSETS = [
    # name, primitive, paramset, functions, quantum_resistant, nist_level, std, suites, oid
    ("X25519", "key-agree", "Curve25519", ["keygen", "key-agreement"], False, 0,
     "RFC 7748", ["0x01"], "1.3.101.110"),
    ("X448", "key-agree", "Curve448", ["keygen", "key-agreement"], False, 0,
     "RFC 7748", ["0x02 (CNSA 2.0)"], "1.3.101.111"),
    ("ML-KEM-768", "kem", "ML-KEM-768", ["keygen", "encapsulate", "decapsulate"], True, 3,
     "FIPS 203", ["0x01"], "2.16.840.1.101.3.4.4.2"),
    ("ML-KEM-1024", "kem", "ML-KEM-1024", ["keygen", "encapsulate", "decapsulate"], True, 5,
     "FIPS 203", ["0x02 (CNSA 2.0)"], "2.16.840.1.101.3.4.4.3"),
    ("ML-DSA-65", "signature", "ML-DSA-65", ["keygen", "sign", "verify"], True, 3,
     "FIPS 204", ["0x01"], "2.16.840.1.101.3.4.3.18"),
    ("ML-DSA-87", "signature", "ML-DSA-87", ["keygen", "sign", "verify"], True, 5,
     "FIPS 204", ["0x02 (CNSA 2.0)"], "2.16.840.1.101.3.4.3.19"),
    ("SLH-DSA", "signature", "SLH-DSA (hash-based)", ["keygen", "sign", "verify"], True, 5,
     "FIPS 205", ["high-assurance (opt-in dual-sign)"], None),
    ("HKDF-SHA256", "kdf", "HKDF-SHA-256", ["key-derive"], True, 2,
     "RFC 5869 / SP 800-56C", ["0x01"], None),
    ("HKDF-SHA384", "kdf", "HKDF-SHA-384", ["key-derive"], True, 3,
     "RFC 5869 / SP 800-56C", ["0x02 (CNSA 2.0)"], None),
    ("AES-256-GCM", "ae", "AES-256-GCM", ["encrypt", "decrypt", "tag"], True, 5,
     "NIST SP 800-38D", ["0x01", "0x02"], "2.16.840.1.101.3.4.1.46"),
    ("SHA-256", "hash", "SHA-256", ["digest"], True, 2,
     "FIPS 180-4", ["0x01"], "2.16.840.1.101.3.4.2.1"),
    ("SHA-384", "hash", "SHA-384", ["digest"], True, 3,
     "FIPS 180-4", ["0x02 (CNSA 2.0)"], "2.16.840.1.101.3.4.2.2"),
    ("SHAKE-256", "xof", "SHAKE-256", ["digest", "xof"], True, 3,
     "FIPS 202", ["key-ids (both suites)"], "2.16.840.1.101.3.4.2.12"),
    ("scrypt", "kdf", "scrypt n=2^17", ["password-derive"], True, 2,
     "RFC 7914", ["at-rest private-key wrap"], None),
]


def component(a):
    name, primitive, paramset, funcs, qr, level, std, suites, oid = a
    cp = {
        "assetType": "algorithm",
        "algorithmProperties": {
            "primitive": primitive,
            "parameterSetIdentifier": paramset,
            "executionEnvironment": "software-plain-ram",
            "implementationPlatform": "generic",
            "certificationLevel": ["none"],   # reference impl: NOT FIPS 140-3 / CMVP validated
            "cryptoFunctions": funcs,
            "nistQuantumSecurityLevel": level,
        },
    }
    if oid:
        cp["oid"] = oid
    comp = {
        "type": "cryptographic-asset",
        "bom-ref": "alg:" + name.lower(),
        "name": name,
        "cryptoProperties": cp,
        "properties": [
            {"name": "polaris:standard", "value": std},
            {"name": "polaris:quantum-resistant", "value": "true" if qr else "false"},
            {"name": "polaris:used-in-suite", "value": ", ".join(suites)},
        ],
    }
    return comp


def main():
    comps = sorted((component(a) for a in ASSETS), key=lambda c: c["name"])
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application", "name": "polaris-shield", "version": "2.0.0",
                "description": "POLARIS Shield cryptographic inventory (CBOM) - algorithm-agile hybrid PQC.",
            },
            "tools": [{"vendor": "POLARIS", "name": "make_cbom.py", "version": "1.0"}],
            "properties": [
                {"name": "cbom:scope", "value": "design-derived cryptographic asset inventory (FORMAT.md suite table)"},
                {"name": "cbom:note",
                 "value": "Inventory only, NOT a certification claim. nistQuantumSecurityLevel 0 = a classical leg "
                          "with no standalone post-quantum security; the hybrid's PQ security comes from the ML-KEM leg, "
                          "bound to the classical leg by the SP 800-56C combiner so BOTH must break to recover plaintext."},
            ],
        },
        "components": comps,
    }
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(bom, f, indent=2)
        f.write("\n")
    pq = sum(1 for a in ASSETS if a[4])
    print(f"wrote {os.path.relpath(OUT, os.path.dirname(HERE))} ({len(comps)} crypto assets; {pq} quantum-resistant)")
    for a in ASSETS:
        print(f"  - {a[0]:<14} {a[1]:<10} {a[6]:<22} {'QR' if a[4] else 'classical'} (NIST level {a[5]})")


if __name__ == "__main__":
    main()
