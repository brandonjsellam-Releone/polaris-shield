"""VORLATH Shield — cross-implementation interoperability corpus (PSTV) + an
independent decoder (``altcodec``).

This subpackage is the apex *interoperability* component: it proves the wire-format
specification in ``tech/FORMAT.md`` is complete and unambiguous enough that a SECOND
implementation, written only from the spec, can verify and decrypt the same envelopes
the reference ``vorlath_shield`` produces.

Contents
--------
* ``gen_pstv_vectors`` — mints the frozen "Portable Shield Test Vectors" corpus
  (``pstv_vectors.json``). Run once; the committed JSON is the authority.
* ``altcodec``         — an INDEPENDENT VRSH decoder built from FORMAT.md alone
  (no reuse of ``vorlath_shield``'s envelope/combiner/KDF code). It reuses only the
  underlying primitive libraries (kyber-py, dilithium-py, cryptography).
* ``test_pstv``        — pytest cross-validation: for each frozen vector both the
  reference and ``altcodec`` agree (positives) or both reject (negatives).

This is a PROJECT CONVENTION, not a standardized/registered protocol. "CNSA 2.0"
denotes the algorithm set, never a validated module. See ``interop/INTEROP.md``.
"""
