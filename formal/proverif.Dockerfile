# ProVerif third-lineage prover image for the POLARIS Shield handshake (tech/formal/shield.pv).
# A third independent symbolic lineage alongside Verifpal (bounded) and Tamarin (unbounded).
#   docker build -t polaris-proverif -f tech/formal/proverif.Dockerfile .
#   docker run --rm -v "$PWD/tech/formal:/work" polaris-proverif shield.pv
FROM ocaml/opam:debian-12-ocaml-4.14
# opam's depext installs ProVerif's GTK system deps via apt during `opam install`, so the apt
# lists must stay available THROUGH that step (clearing them first caused exit 20). One RUN, then clean.
RUN sudo apt-get update \
 && sudo apt-get install -y --no-install-recommends m4 \
 && opam install -y proverif \
 && sudo rm -rf /var/lib/apt/lists/*
WORKDIR /work
ENTRYPOINT ["opam", "exec", "--", "proverif"]
