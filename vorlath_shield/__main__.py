"""VORLATH Shield CLI (v2).

    cd tech
    python -m vorlath_shield demo
    python -m vorlath_shield keygen  --prefix alice [--suite 2] [--passphrase pw]
    python -m vorlath_shield encrypt --to alice.kem.pub --in secret.txt --out secret.trsh \
                                     [--sign-key bob.sig.key --sign-pub bob.sig.pub]
    python -m vorlath_shield decrypt --key alice.kem.key --in secret.trsh --out out.txt \
                                     [--expect-sender bob.sig.pub] [--passphrase pw]
    python -m vorlath_shield sign    --key alice.sig.key --in doc.pdf --out doc.sig [--passphrase pw]
    python -m vorlath_shield verify  --pub alice.sig.pub --in doc.pdf --sig doc.sig
    python -m vorlath_shield info    --in secret.trsh
"""
import argparse
import base64
import getpass
import hashlib
import os
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import shield

_WRAP_MAGIC = b"PLSW"   # passphrase-wrapped private key (scrypt -> AES-256-GCM)
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**17, 8, 1   # OWASP-recommended minimum (n=2^17)
_SCRYPT_MAXMEM = 128 * _SCRYPT_N * _SCRYPT_R * _SCRYPT_P + (1 << 20)   # headroom over OpenSSL's cap


def _scrypt(passphrase: str, salt: bytes) -> bytes:
    return hashlib.scrypt(passphrase.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R,
                          p=_SCRYPT_P, dklen=32, maxmem=_SCRYPT_MAXMEM)


# ----------------------------------------------------------------- file + key I/O
def _w(path, data: bytes):
    with open(path, "w", encoding="ascii") as f:
        f.write(base64.b64encode(data).decode())


def _r(path) -> bytes:
    with open(path, encoding="ascii") as f:
        return base64.b64decode(f.read())


def _wrap_private(bundle: bytes, passphrase: str) -> bytes:
    salt = os.urandom(16)
    key = _scrypt(passphrase, salt)
    nonce = os.urandom(12)
    sealed = AESGCM(key).encrypt(nonce, bundle, _WRAP_MAGIC)
    return _WRAP_MAGIC + salt + nonce + sealed


def _maybe_unwrap(data: bytes, passphrase) -> bytes:
    if data[:4] != _WRAP_MAGIC:
        return data
    if not passphrase:
        passphrase = getpass.getpass("private-key passphrase: ")
    salt, nonce, sealed = data[4:20], data[20:32], data[32:]
    key = _scrypt(passphrase, salt)
    return AESGCM(key).decrypt(nonce, sealed, _WRAP_MAGIC)


def _read_private(path, passphrase) -> bytes:
    return _maybe_unwrap(_r(path), passphrase)


# ----------------------------------------------------------------- commands
def cmd_keygen(a):
    pub, priv = shield.generate_recipient_keys(a.suite)
    spk, ssk = shield.generate_signing_keys(a.suite)
    if a.passphrase:
        priv, ssk = _wrap_private(priv, a.passphrase), _wrap_private(ssk, a.passphrase)
    _w(a.prefix + ".kem.pub", pub); _w(a.prefix + ".kem.key", priv)
    _w(a.prefix + ".sig.pub", spk); _w(a.prefix + ".sig.key", ssk)
    s = shield.SUITES[a.suite]
    kid = shield.kem_key_id(pub).hex()
    print(f"suite 0x{a.suite:02x}  {s.name}")
    print(f"wrote {a.prefix}.kem.pub / .kem.key  (key-id {kid})")
    print(f"wrote {a.prefix}.sig.pub / .sig.key  (ML-DSA)")
    if a.passphrase:
        print("private keys wrapped at rest (scrypt n=2^17 -> AES-256-GCM)")
    else:
        print("WARNING: private keys stored unwrapped; use --passphrase to protect at rest")


def cmd_encrypt(a):
    pt = open(a.infile, "rb").read()
    if getattr(a, "stream", False):
        if a.sign_key:
            sys.exit("--stream is anonymous; it does not support --sign-key")
        env = shield.seal_stream(pt, _r(a.to))
        open(a.outfile, "wb").write(env)
        print(f"sealed {len(pt)} -> {a.outfile} ({len(env)} bytes) [streamed, {shield.SUITES[env[5]].name}]")
        return
    sk = sp = None
    if a.sign_key:
        if not a.sign_pub:
            sys.exit("--sign-key requires --sign-pub")
        sk, sp = _read_private(a.sign_key, a.passphrase), _r(a.sign_pub)
    env = shield.encrypt(pt, _r(a.to), sk, sp)
    open(a.outfile, "wb").write(env)
    mode = "authenticated" if sk else "anonymous"
    s = shield.SUITES[env[5]]
    print(f"sealed {len(pt)} -> {a.outfile} ({len(env)} bytes) [{mode}, {s.name}]")


def cmd_decrypt(a):
    env = open(a.infile, "rb").read()
    key = _read_private(a.key, a.passphrase)
    if env[:4] == shield.STREAM_MAGIC:
        if a.expect_sender:
            sys.exit("streams are anonymous; --expect-sender does not apply")
        pt = shield.open_stream(env, key)
    else:
        exp = _r(a.expect_sender) if a.expect_sender else None
        pt = shield.decrypt(env, key, exp)
    open(a.outfile, "wb").write(pt)
    print(f"opened -> {a.outfile} ({len(pt)} bytes)")


def cmd_sign(a):
    sig = shield.sign(_read_private(a.key, a.passphrase), open(a.infile, "rb").read())
    _w(a.outfile, sig)
    print(f"signed -> {a.outfile} ({len(sig)} bytes)")


def cmd_verify(a):
    ok = shield.verify(_r(a.pub), open(a.infile, "rb").read(), _r(a.sig))
    print("VERIFIED" if ok else "INVALID - signature does not match")
    sys.exit(0 if ok else 1)


def cmd_info(a):
    env = open(a.infile, "rb").read()
    if env[:4] == shield.STREAM_MAGIC:
        s = shield.SUITES.get(env[5])
        print(f"VORLATH Shield STREAM v{env[4]}")
        print(f"  suite        0x{env[5]:02x}  {s.name if s else 'UNKNOWN'}")
        print(f"  total size    {len(env)} bytes (chunked)")
        return
    if env[:4] != shield.MAGIC:
        sys.exit("not a VORLATH Shield envelope")
    suite_id, flags = env[5], env[6]
    s = shield.SUITES.get(suite_id)
    print(f"VORLATH Shield envelope v{env[4]}")
    print(f"  suite        0x{suite_id:02x}  {s.name if s else 'UNKNOWN'}")
    print(f"  authenticated {'yes' if flags & shield.FLAG_AUTHENTICATED else 'no'}")
    print(f"  total size    {len(env)} bytes")


def cmd_demo(a):
    line = "=" * 70
    s = shield.SUITES[a.suite]
    print(line)
    print("  VORLATH SHIELD v2 - live post-quantum demonstration")
    print("  " + s.name)
    print(line)
    msg = b"TOP SECRET // VALYON VORLATH // sovereign key material 2026"
    pub, priv = shield.generate_recipient_keys(a.suite)
    print(f"\n  recipient key-id: {shield.kem_key_id(pub).hex()}")

    print("\n[1] Harvest-now, decrypt-later (the apex threat)")
    classical = shield.encrypt_classical_only(msg, pub)
    print(f"    A classical ECDH-only ciphertext ({len(classical)} bytes) is recorded by an")
    print("    adversary TODAY. Safe today - but a future CRQC breaks the classical leg")
    print("    and recovers the plaintext.")

    print(f"\n[2] The Shield: hybrid {s.name.split()[0]}")
    env = shield.encrypt(msg, pub)
    print(f"    Shield envelope: {len(env)} bytes. The AES-256 key is derived from BOTH a")
    print("    classical AND a post-quantum (ML-KEM) secret, length-framed and bound to")
    print("    the transcript. Even if the classical leg falls, ML-KEM still seals the key.")
    print(f"    Legitimate recipient opens it: {shield.decrypt(env, priv) == msg}")

    print("\n[3] Tamper-evidence + downgrade-resistance (AES-256-GCM over the full header)")
    bad = bytearray(env); bad[-1] ^= 0x01
    try:
        shield.decrypt(bytes(bad), priv); print("    FAIL: tamper not detected")
    except Exception:
        print("    A single flipped ciphertext bit is rejected: True")
    dg = bytearray(env); dg[5] ^= 0x03   # flip suite_id in the bound header
    try:
        shield.decrypt(bytes(dg), priv); print("    FAIL: downgrade not detected")
    except Exception:
        print("    A flipped suite_id (downgrade attempt) is rejected: True")

    print("\n[4] Authenticated handshake: signed sender identity (ML-DSA)")
    spk, ssk = shield.generate_signing_keys(a.suite)
    aenv = shield.encrypt_authenticated(msg, pub, ssk, spk)
    print(f"    authenticated envelope: {len(aenv)} bytes | opens as expected sender: "
          f"{shield.decrypt_authenticated(aenv, priv, spk) == msg}")
    wpk, _ = shield.generate_signing_keys(a.suite)
    try:
        shield.decrypt_authenticated(aenv, priv, wpk); print("    FAIL: wrong sender accepted")
    except Exception:
        print("    A forged/wrong sender identity is rejected: True")

    print("\n[5] Sovereign document signatures (ML-DSA, context-bound)")
    sig = shield.sign(ssk, msg)
    print(f"    signature {len(sig)} bytes | verify: {shield.verify(spk, msg, sig)}"
          f" | forged-message rejected: {not shield.verify(spk, b'forged', sig)}")

    print("\n[6] Streaming AEAD for large files (truncation-resistant)")
    big = os.urandom(200_000)
    stream_env = shield.seal_stream(big, pub, chunk_size=64 * 1024)
    print(f"    {len(big)} bytes sealed as a {len(stream_env)}-byte chunked stream; "
          f"opens: {shield.open_stream(stream_env, priv) == big}")
    try:
        shield.open_stream(stream_env[:-200], priv); print("    FAIL: truncation not detected")
    except Exception:
        print("    A truncated stream is rejected: True")

    print("\n" + line)
    print("  Real federal standards, running locally. Reference implementation -")
    print("  NOT FIPS 140-3 validated, not side-channel hardened; see tech/README.md.")
    print(line)


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="vorlath-shield",
        description="VORLATH Shield v2 - post-quantum hybrid security (FIPS 203/204, CNSA 2.0).")
    sub = p.add_subparsers(dest="cmd", required=True)

    def suite_arg(sp):
        sp.add_argument("--suite", type=lambda x: int(x, 0), default=shield.DEFAULT_SUITE_ID,
                        choices=list(shield.SUITES),
                        help="1=FIPS-standard, 2=CNSA-2.0 hybrid (default), 3=CNSA-2.0 pure-PQC")

    s = sub.add_parser("keygen"); s.add_argument("--prefix", required=True)
    suite_arg(s); s.add_argument("--passphrase"); s.set_defaults(fn=cmd_keygen)
    s = sub.add_parser("encrypt"); s.add_argument("--to", required=True)
    s.add_argument("--in", dest="infile", required=True); s.add_argument("--out", dest="outfile", required=True)
    s.add_argument("--sign-key"); s.add_argument("--sign-pub"); s.add_argument("--passphrase")
    s.add_argument("--stream", action="store_true", help="chunked streaming AEAD for large files (anonymous)")
    s.set_defaults(fn=cmd_encrypt)
    s = sub.add_parser("decrypt"); s.add_argument("--key", required=True)
    s.add_argument("--in", dest="infile", required=True); s.add_argument("--out", dest="outfile", required=True)
    s.add_argument("--expect-sender"); s.add_argument("--passphrase"); s.set_defaults(fn=cmd_decrypt)
    s = sub.add_parser("sign"); s.add_argument("--key", required=True)
    s.add_argument("--in", dest="infile", required=True); s.add_argument("--out", dest="outfile", required=True)
    s.add_argument("--passphrase"); s.set_defaults(fn=cmd_sign)
    s = sub.add_parser("verify"); s.add_argument("--pub", required=True)
    s.add_argument("--in", dest="infile", required=True); s.add_argument("--sig", required=True)
    s.set_defaults(fn=cmd_verify)
    s = sub.add_parser("info"); s.add_argument("--in", dest="infile", required=True); s.set_defaults(fn=cmd_info)
    s = sub.add_parser("demo"); suite_arg(s); s.set_defaults(fn=cmd_demo)

    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
