# Differential cross-validation image for the VORLATH Shield PRIMITIVES.
#
# This image stands up the pinned pure-Python reference primitives ALONGSIDE a
# second, INDEPENDENT implementation (pqcrypto = PQClean C via CFFI, Linux
# manylinux wheels) and runs interop/cross_impl.py to cross-validate ML-KEM and
# ML-DSA on random inputs. It closes VERIFICATION_GAP_MAP.md seam (a): a bug
# INSIDE kyber-py / dilithium-py is invisible to the format-layer interop corpus
# because that corpus shares those same libs; here a truly separate codebase
# (different language, different lineage) must agree on the standardized FIPS
# 203/204 wire formats, or the build fails.
#
# Build (the build IS the verification — a successful build == all four
# parameter sets agreed across both implementations on every iteration):
#
#     docker build -f tech/interop/diff.Dockerfile -t vorlath-shield-diff tech/interop
#
# Run more iterations / reproduce a specific seed interactively:
#
#     docker run --rm vorlath-shield-diff python cross_impl.py -n 1000
#     docker run --rm vorlath-shield-diff python cross_impl.py --seed <hexseed>
#
# pqcrypto ships manylinux wheels for these four parameter sets, so NO apt /
# cmake / compiler is needed — a single pip line on python:3.12-slim suffices.
FROM python:3.12-slim

ENV LANG=C.UTF-8 LC_ALL=C.UTF-8 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# The pinned reference primitives + the independent implementation, one layer,
# no system build deps (pqcrypto resolves to a prebuilt manylinux wheel).
RUN pip install --no-cache-dir \
      kyber-py==1.2.0 \
      dilithium-py==1.4.0 \
      pqcrypto==0.3.4

WORKDIR /diff
COPY cross_impl.py /diff/cross_impl.py

# Prove all three libraries import and expose the expected APIs before running.
RUN python -c "import kyber_py, dilithium_py, pqcrypto; \
from kyber_py.ml_kem import ML_KEM_768, ML_KEM_1024; \
from dilithium_py.ml_dsa import ML_DSA_65, ML_DSA_87; \
from pqcrypto.kem import ml_kem_768, ml_kem_1024; \
from pqcrypto.sign import ml_dsa_65, ml_dsa_87; \
print('all primitive libs import OK')"

# The cross-validation itself; a non-zero exit (ANY mismatch) fails the build.
# A few hundred iterations per algorithm is a strong default for a build gate.
RUN echo '>> ML-KEM / ML-DSA differential cross-validation' \
 && python cross_impl.py -n 300

# Default: re-run the cross-validation when the image is run with no args.
CMD ["python", "cross_impl.py", "-n", "300"]
