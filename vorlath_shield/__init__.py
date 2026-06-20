"""VORLATH Shield v2 — real post-quantum hybrid security (FIPS 203 + 204, CNSA 2.0).

Algorithm-agile hybrid KEM (X25519/X448 + ML-KEM-768/1024), SP 800-56C combiner,
AES-256-GCM AEAD, ML-DSA-65/87 signatures, optional authenticated handshake, and a
self-describing, downgrade-resistant wire format.
"""
from .highassurance import (
    DEFAULT_HA_ID,
    dual_sign,
    dual_verify,
    generate_high_assurance_keys,
    ha_param_name,
    high_assurance_sign,
    high_assurance_verify,
)
from .shield import (
    DEFAULT_CHUNK,
    DEFAULT_SUITE_ID,
    SUITE,
    SUITES,
    VERSION,
    Suite,
    decrypt,
    decrypt_authenticated,
    encrypt,
    encrypt_authenticated,
    encrypt_classical_only,
    generate_recipient_keys,
    generate_signing_keys,
    kem_key_id,
    open_stream,
    seal_stream,
    sig_key_id,
    sign,
    suite_of,
    verify,
)

__all__ = [
    "generate_recipient_keys", "generate_signing_keys",
    "encrypt", "decrypt", "encrypt_authenticated", "decrypt_authenticated",
    "seal_stream", "open_stream",
    "sign", "verify", "encrypt_classical_only",
    "kem_key_id", "sig_key_id", "suite_of",
    "SUITE", "SUITES", "VERSION", "DEFAULT_SUITE_ID", "DEFAULT_CHUNK", "Suite",
    "generate_high_assurance_keys", "high_assurance_sign", "high_assurance_verify",
    "dual_sign", "dual_verify", "ha_param_name", "DEFAULT_HA_ID",
]
