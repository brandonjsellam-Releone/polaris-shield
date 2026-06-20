# tech/release/lms.Dockerfile
# -----------------------------------------------------------------------------
# POLARIS Shield -- SP 800-208 LMS release-signing self-test container.
#
# Builds a minimal pure-Python image, installs the real pip-installable lib
# (pyhsslms by Russ Housley: RFC 8554 + the SP 800-208 parameter additions,
# BSD-3-Clause, zero non-stdlib runtime deps), then runs sign_lms.py which
# generates an LMS key, signs the release bundle_digest exactly once, and
# VERIFIES -- exiting nonzero on any failure so `docker build` fails loudly.
#
# HONEST POSTURE: pyhsslms is a SOFTWARE REFERENCE implementation; it is NOT
# FIPS 140-3 validated and is NOT an HSM. SP 800-208 requires non-exporting
# hardware keygen/signing with hardware state for approved deployment, so this
# is a standards-ALIGNED demonstration of the CNSA 2.0 firmware-signing-first
# workflow, NOT an 800-208-compliant signing service.
#
# Build (from tech/release/):
#   docker build -f lms.Dockerfile -t polaris-lms-signing .
# A successful build == the sign+verify round trip passed.
# -----------------------------------------------------------------------------
FROM python:3.12-slim

# Reproducible, quiet, no .pyc clutter.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Pin for the deterministic-bundle ethos. pyhsslms is pure Python: no compiler,
# no OpenSSL headers, no apt build-deps required.
RUN pip install --no-cache-dir pyhsslms==2.0.0

WORKDIR /work

# Bring in the signer and (if present) the real manifest. The COPY of the
# manifest is best-effort: sign_lms.py falls back to a fixed self-test digest
# when RELEASE_MANIFEST.json is absent, so the round trip runs either way.
COPY sign_lms.py /work/sign_lms.py
COPY RELEASE_MANIFEST.jso[n] /work/RELEASE_MANIFEST.json

# Self-test at build time: keygen -> sign once -> verify. Nonzero exit (bad
# verify, exhausted key, missing lib) fails the build.
RUN python /work/sign_lms.py

# Default runtime command repeats the self-test. NOTE: each run generates a
# FRESH single-use key (genkey refuses to clobber an existing pair), signs once,
# and shreds the spent .prv -- consistent with the never-reuse rule. Re-running
# is safe ONLY because a new key is minted each time; never re-sign with a
# spent .prv.
CMD ["python", "/work/sign_lms.py"]
