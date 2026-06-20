# Hermetic reproducibility image for the POLARIS Shield assurance stack.
#
# One command reproduces EVERY check green on Linux with the REAL pinned
# dependencies (resolves any host cryptography-version drift; proves Linux
# reproducibility of a Windows-developed project):
#
#     docker build -f tech/Dockerfile -t polaris-shield-verify tech
#
# A successful build == ruff + mypy + the full pytest suite + KAT reproducibility
# + the live demo + Verifpal (2 bounded models) + Tamarin (11 unbounded lemmas),
# ALL green, with cryptography>=48. The build IS the verification.
FROM python:3.13-slim@sha256:c33f0bc4364a6881bed1ec0cc2665e6c53c87a43e774aaeab88e6f17af105e4f

ENV LANG=C.UTF-8 LC_ALL=C.UTF-8 PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1

# Provers' system deps: Maude + Graphviz (Tamarin), curl/unzip (release binaries).
RUN apt-get update && apt-get install -y --no-install-recommends \
      maude graphviz curl ca-certificates unzip \
 && rm -rf /var/lib/apt/lists/*

# Pinned formal-verification provers (official GitHub release binaries).
# Each artifact is content-addressed: its SHA-256 is verified BEFORE extraction,
# so a tampered or silently re-published binary fails the build (hermeticity).
RUN curl -fsSL -o /tmp/vp.zip https://github.com/symbolicsoft/verifpal/releases/download/v0.52.0/verifpal_0.52.0_linux_amd64.zip \
 && echo "e75e6b6737ba1c5965ad9dc71daec0993ded44d553dfb682f9dac182654700c1  /tmp/vp.zip" | sha256sum -c - \
 && unzip -oq /tmp/vp.zip -d /tmp/vp \
 && install -m0755 "$(find /tmp/vp -name verifpal -type f | head -1)" /usr/local/bin/verifpal \
 && curl -fsSL -o /tmp/t.tgz https://github.com/tamarin-prover/tamarin-prover/releases/download/1.12.0/tamarin-prover-1.12.0-linux64-ubuntu.tar.gz \
 && echo "201be06f469e47cff554df6ca93db8366fc2c69d70c61fcbd1370a1074b469c6  /tmp/t.tgz" | sha256sum -c - \
 && mkdir -p /tmp/t && tar xzf /tmp/t.tgz -C /tmp/t \
 && install -m0755 "$(find /tmp/t -name tamarin-prover -type f | head -1)" /usr/local/bin/tamarin-prover \
 && rm -rf /tmp/vp* /tmp/t* \
 && verifpal --version && tamarin-prover --version | head -1

WORKDIR /shield
COPY . /shield

# Install with the REAL pinned dependencies and PROVE the cryptography pin is met
# (the host dev env may carry an older cryptography; here we use the real pin).
RUN pip install --no-cache-dir -e ".[dev]" \
 && python -c "import cryptography,sys; v=int(cryptography.__version__.split('.')[0]); print('cryptography', cryptography.__version__); sys.exit(0 if v>=48 else 1)"

# --- the assurance stack; any non-zero exit fails the build ---
RUN echo '>> ruff'   && ruff check .
RUN echo '>> mypy'   && mypy polaris_shield
RUN echo '>> pytest' && pytest -q -p no:cacheprovider
RUN echo '>> KAT reproducibility' \
 && cp kat_vectors.json /tmp/kat.orig && python gen_kat_vectors.py \
 && diff --strip-trailing-cr -q kat_vectors.json /tmp/kat.orig && echo 'KAT vectors reproducible'
RUN echo '>> live demo' && python -m polaris_shield demo >/dev/null && echo 'demo ok'
RUN echo '>> Verifpal (bounded)' \
 && verifpal verify formal/shield.vp    2>&1 | tee /tmp/v1 && grep -q 'queries pass' /tmp/v1 \
 && verifpal verify formal/shield_pq.vp 2>&1 | tee /tmp/v2 && grep -q 'queries pass' /tmp/v2
RUN echo '>> Tamarin (unbounded)' \
 && tamarin-prover --prove formal/shield.spthy 2>&1 | tee /tmp/tam.log \
 && ! grep -qiE 'falsified|analysis incomplete' /tmp/tam.log \
 && [ "$(grep -cE 'verified \([0-9]+ steps\)' /tmp/tam.log)" -ge 11 ]
RUN echo '==================================================================' \
 && echo ' ALL POLARIS SHIELD ASSURANCE CHECKS GREEN (Linux, cryptography>=48)' \
 && echo '=================================================================='

# Default: re-run the fast suite when the image is run.
CMD ["pytest", "-q", "-p", "no:cacheprovider"]
