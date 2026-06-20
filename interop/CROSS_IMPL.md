# Cross-implementation primitive differential (`cross_impl.py`)

The single largest gap this project named **against itself** (`../VERIFICATION_GAP_MAP.md`
seam (a)): the interop corpus (`altcodec.py`) independently re-implements the *wire format /
parser / combiner / KDF / AEAD orchestration*, **but it shares the same primitive libraries**
(`kyber-py`, `dilithium-py`). A bug *inside* those libraries would be present in **both**
implementations and invisible to every test here. ACVP (`../test_acvp.py`) checks the primitives
against NIST's **fixed** vectors — strong, but a fixed corpus.

`cross_impl.py` closes that seam on **random inputs** by cross-validating the primitives against a
**second, independent implementation from a different lineage**:

| | Reference (what the Shield ships) | Independent cross-check |
|---|---|---|
| Library | `kyber-py` 1.2.0 / `dilithium-py` 1.4.0 | `pqcrypto` 0.3.4 |
| Lineage | pure-Python, hand-written from FIPS 203/204 | **PQClean C reference**, via CFFI (manylinux wheel) |
| Author/project | independent author | a separate project entirely |

Because the FIPS 203/204 byte formats are standardized, two conformant implementations from
unrelated codebases **must interoperate**. If they disagree on a random key with random coins, at
least one of them is wrong — which is exactly the class of bug the format-layer interop corpus
cannot see.

## What it checks

- **ML-KEM (decisive, both directions).** `kyber-py` generates a keypair, `pqcrypto` encapsulates
  to it, `kyber-py` decapsulates — the shared secret must match; **and the reverse** (`pqcrypto`
  keypair, `kyber-py` encapsulates, `pqcrypto` decapsulates). A shared secret that agrees across two
  independent codebases on random inputs is a strong cross-check of the encaps/decaps math **and**
  the `ek`/`dk`/`ct` wire formats. Done for **ML-KEM-768 and ML-KEM-1024**.
- **ML-DSA (mutual accept + tamper-reject; NOT byte equality).** Each library signs a random
  message and the **other** library's verifier must accept it; a one-bit-corrupted signature must be
  rejected by both. Done for **ML-DSA-65 and ML-DSA-87**. We deliberately do **not** require
  byte-identical signatures: `pqcrypto` ships the **hedged (randomized)** ML-DSA, so its signatures
  are non-deterministic and will not equal `dilithium-py`'s deterministic output. Accept/reject
  agreement is the honest, achievable cross-validation here (`dilithium-py` is driven with an empty
  signing context to match `pqcrypto`'s context-less API).

## Result (verified live)

```
docker run --rm vorlath-shield-diff python cross_impl.py -n 500
  ML-KEM-768    500/500   PASS
  ML-KEM-1024   500/500   PASS
  ML-DSA-65     500/500   PASS
  ML-DSA-87     500/500   PASS
  RESULT: all primitives agree across both independent implementations on every random iteration.
```

The Docker build **is** the gate: `diff.Dockerfile` runs `cross_impl.py -n 300` as a build step, so
a non-zero exit (any mismatch) fails the build. Failure semantics print the algorithm, iteration,
base-seed, and offending hex, and the exit code is driven purely by the mismatch flag — a false
"PASS" cannot be masked. Re-run a specific failure with `--seed <hex>`.

## Honest limits (what this does NOT do)

- **Random, not exhaustive.** It catches **divergence** between the two implementations; it cannot
  catch a flaw they **share** (e.g. a spec ambiguity both authors resolved the same way). That
  residual is real and stays disclosed in `../VERIFICATION_GAP_MAP.md`.
- **No side channels.** This is a functional/value cross-check only — no timing, power, EM, or
  fault coverage (see `../sidechannel/`).
- **Not FIPS validation.** Both `kyber-py`/`dilithium-py` and `pqcrypto` are reference
  implementations, **not** FIPS 140-3 validated modules. Agreement across two reference stacks is a
  correctness cross-check, not a certification.

## Run it

```bash
# Hermetic Linux gate (the build runs the cross-validation; pqcrypto resolves to a manylinux wheel,
# so no apt/cmake/compiler is needed):
docker build -f tech/interop/diff.Dockerfile -t vorlath-shield-diff tech/interop
docker run --rm vorlath-shield-diff python cross_impl.py -n 1000

# Local (if kyber-py/dilithium-py/pqcrypto are installed; pqcrypto needs a Linux/manylinux host):
python tech/interop/cross_impl.py -n 300
python tech/interop/cross_impl.py --seed <hexseed>   # reproduce a specific run
```
