# POLARIS Shield v2 — wire-format specification

This document specifies, **byte for byte**, the on-the-wire and on-disk formats produced and
consumed by the POLARIS Shield reference implementation. Every field below is derived directly
from the source: `polaris_shield/shield.py` (envelopes, streams, KEM/signing key bundles) and
`polaris_shield/highassurance.py` (the high-assurance SLH-DSA key bundle and the dual signature).
Function names are cited inline so each claim can be checked against the code.

This is a **project convention**, not a standardized interoperable protocol. As stated in
[SECURITY.md](SECURITY.md), "CNSA 2.0" here denotes the **algorithm set**, never a validated
module; for interoperable traffic use TLS 1.3 hybrid key-exchange or HPKE. The format is documented
here so an independent implementation can be written and so the security properties can be audited.

All multi-byte integers are **big-endian** (network byte order). All `struct` format strings cited
below use `>` (big-endian): `">H"` is a u16, `">I"` is a u32. Conventions:

- "u8" / "u16" / "u32" — unsigned 8/16/32-bit big-endian integer.
- "TLV(x)" — the value `x` wrapped in the 2-byte-length TLV primitive defined in section 1.
- A `||` denotes concatenation; an en-dash (–) denotes an inclusive byte range.

---

## 1. The TLV primitive

Every variable-length field inside a key bundle, envelope header, or sender block is a **TLV**:
a 2-byte big-endian length followed by that many value bytes. There is no explicit "type" tag —
fields are positional, so a TLV here is really a length-value pair; ordering carries the type.

Encoding is `_tlv()` in `shield.py`:

```
TLV(value) = struct.pack(">H", len(value)) || value
```

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 2 | length `n` | u16 big-endian; **hard cap 0xFFFF (65535)** — `_tlv` raises `ValueError("TLV field exceeds 65535 bytes")` if exceeded |
| 2 | `n` | value | exactly `n` bytes |

Decoding is `_read_tlv(buf, off)`. It is **bounds-checked on both ends**:

- if `off + 2 > len(buf)` it raises `"truncated envelope: missing TLV length"`;
- it reads `n` via `struct.unpack_from(">H", buf, off)`;
- if `start + n > len(buf)` it raises `"truncated envelope: TLV value runs past end"`;
- on success it returns `(value, new_offset)` where `new_offset = off + 2 + n`.

A reader therefore can never be walked off the end of the buffer by a malicious length field.

---

## 2. The single-shot envelope — `PLSH`

Produced by `encrypt()` (and its alias `encrypt_authenticated()`), consumed by `decrypt()` /
`decrypt_authenticated()`. The wire layout is exactly the `header + struct.pack(">I", len(sealed)) +
sealed` returned at the end of `encrypt()`.

### 2.1 Top-level structure

```
PLSH envelope = header || u32 sealed_len || sealed
```

where `sealed = AES-256-GCM ciphertext || 16-byte GCM tag` and `header` is the byte string built in
`encrypt()`:

```
header = MAGIC || VERSION || suite_id || flags
       || TLV(recipient_key_id) || TLV(eph_pub) || TLV(kem_ct)
       || TLV(nonce) || TLV(sender_block)
```

### 2.2 Fixed prefix (offsets 0–6)

| Offset | Size | Field | Value / source |
|---|---|---|---|
| 0 | 4 | `MAGIC` | ASCII `"PLSH"` (`MAGIC = b"PLSH"`) |
| 4 | 1 | `VERSION` | `0x02` (`VERSION = 2`) |
| 5 | 1 | `suite_id` | `0x01`, `0x02`, or `0x03` — selects the cipher suite (section 6) |
| 6 | 1 | `flags` | bitfield: `FLAG_AUTHENTICATED = 0x01` (sender block present), `FLAG_PPK = 0x02` (AEAD key mixes an out-of-band RFC 8784 pre-shared key) |

`decrypt()` rejects the input before parsing if `len(envelope) < 7`, if `envelope[:4] != MAGIC`,
or if `envelope[4] != VERSION`. The `suite_id` is then resolved via `_suite()`, which raises on an
unknown id.

### 2.3 Ordered header TLVs (from offset 7)

These five TLVs are read back, in this exact order, by `decrypt()` (`_read_tlv` calls on
`recipient_key_id`, `eph_pub`, `kem_ct`, `nonce`, `sender_block`):

| # | Field | Value | Length (suite 0x02 / 0x01) |
|---|---|---|---|
| 1 | `recipient_key_id` | 32-byte SHAKE-256 key fingerprint of the recipient KEM bundle | 32 / 32 |
| 2 | `eph_pub` | sender's ephemeral ECDH public key (raw) | 56 / 32 |
| 3 | `kem_ct` | ML-KEM ciphertext from `kem.encaps(kem_ek)` | 1568 / 1088 |
| 4 | `nonce` | AES-256-GCM nonce, `os.urandom(NONCE)`, `NONCE = 12` | 12 / 12 |
| 5 | `sender_block` | authenticated sender sub-structure (section 3); **empty (length 0) when anonymous** | see §3 |

Each is preceded by its 2-byte TLV length, so on the wire field #2 in suite 0x02 occupies
`2 + 56 = 58` bytes, etc. The byte at which the ciphertext-length u32 begins is the running offset
`off` after the fifth TLV — call it `H` (the full header length). `header = envelope[:H]`.

### 2.4 Ciphertext framing (from offset `H`)

| Offset | Size | Field | Source |
|---|---|---|---|
| `H` | 4 | `sealed_len` | `struct.pack(">I", len(sealed))` — u32 length of the AEAD output |
| `H+4` | `sealed_len` | `sealed` | `AESGCM(key).encrypt(nonce, plaintext, header)` = ciphertext `||` 16-byte tag |

`decrypt()` enforces three exactness checks here:

- `off + 4 > len(envelope)` to `"truncated envelope: missing ciphertext length"`;
- `(clen,) = struct.unpack_from(">I", envelope, off)`;
- `off + clen != len(envelope)` to `"envelope length mismatch (truncated or trailing bytes)"`.

The third check makes the envelope **exact-length**: no trailing bytes, no short read.

### 2.5 Concrete byte-offset table (suite 0x02, anonymous)

For the default apex suite with `flags = 0x00` (no sender block), the header has a fixed shape.
Verified against a live `encrypt()` call (total envelope length 1710 bytes for a 5-byte plaintext):

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | `MAGIC` = `PLSH` |
| 4 | 1 | `VERSION` = `0x02` |
| 5 | 1 | `suite_id` = `0x02` |
| 6 | 1 | `flags` = `0x00` |
| 7 | 2 | TLV len = `0x0020` (32) |
| 9 | 32 | `recipient_key_id` |
| 41 | 2 | TLV len = `0x0038` (56) |
| 43 | 56 | `eph_pub` (X448) |
| 99 | 2 | TLV len = `0x0620` (1568) |
| 101 | 1568 | `kem_ct` (ML-KEM-1024) |
| 1669 | 2 | TLV len = `0x000C` (12) |
| 1671 | 12 | `nonce` |
| 1683 | 2 | TLV len = `0x0000` (0) |
| 1685 | 0 | `sender_block` (empty) |
| 1685 | 4 | `sealed_len` (u32) |
| 1689 | `sealed_len` | `sealed` (ciphertext `||` tag) |

`H = 1685` here. For suite 0x01 the same layout holds with `eph_pub` 32 bytes and `kem_ct` 1088
bytes, shifting later offsets accordingly.

### 2.6 AAD and the HKDF transcript — what binds what

Two distinct transcripts are computed, and the relationship between them is the heart of the
construction. Both are built from the same primitive, `_pre_auth_transcript()`:

```
pre_auth = bytes([suite_id, flags]) || recipient_key_id || eph_pub || kem_ct || nonce
```

Note `pre_auth` is a **flat concatenation** of the raw values (no TLV framing) and is computed
identically by `encrypt()` and `decrypt()`. Because the field lengths are fixed per suite, this
concatenation is unambiguous within a suite.

**(a) AEAD associated data (AAD).** The AAD passed to AES-256-GCM is the **entire `header`** byte
string — `AESGCM(key).encrypt(nonce, plaintext, header)` in `encrypt()`, and the matching
`AESGCM(key).decrypt(nonce, sealed, header)` in `decrypt()`. The header includes `MAGIC`, `VERSION`,
`suite_id`, `flags`, and all five TLVs (including the framed `sender_block`). Any single-bit change
to the header fails GCM tag verification on open.

**(b) HKDF FixedInfo (the key-derivation transcript).** The AEAD **key itself** is derived in
`_derive_key()`:

```
ikm  = struct.pack(">H", len(ss_classical)) || ss_classical
     || struct.pack(">H", len(ss_pq))       || ss_pq
info = _COMBINER_LABEL || bytes([suite.suite_id]) || pre_auth
key  = HKDF(algorithm = suite.hkdf_hash(), length = 32,
            salt = _COMBINER_SALT, info = info).derive(ikm)
```

with `_COMBINER_LABEL = b"POLARIS-Shield/2 hybrid-kem combiner"` and
`_COMBINER_SALT  = b"POLARIS-Shield-combiner/v2"`. The HKDF **info (FixedInfo)** carries the
domain-separation label, the `suite_id` byte, and the full `pre_auth` transcript. The input keying
material is the **length-framed** concatenation of the classical ECDH secret and the post-quantum
ML-KEM secret (SP 800-56C-shaped combiner — the u16 length prefixes make the concatenation injective
so two different secret pairs can never collide into the same `ikm`).

### 2.7 The suite_id-in-AAD-and-KDF downgrade binding

`suite_id` is bound in **three** independent places, which is what makes downgrade attacks fail
closed rather than silently:

1. inside `header` (offset 5), and `header` is the GCM AAD — so flipping `suite_id` on the wire
   breaks the AEAD tag;
2. inside `pre_auth` (its first byte), and `pre_auth` is the HKDF `info` — so a different `suite_id`
   derives a **different key** entirely;
3. as a standalone `bytes([suite.suite_id])` segment of the HKDF `info`, immediately after the label.

Because the recipient takes the suite from **its own private key** (`_parse_key(...,
_ROLE_KEM_PRIV)` yields `sid`, and `decrypt()` raises `"recipient key suite does not match envelope
suite"` if `sid != suite_id`), a sender or man-in-the-middle cannot negotiate a weaker suite: the
suite is pinned to the recipient identity, then cross-checked, then bound into both the AAD and the
derived key. `flags` is bound the same way (it is in `pre_auth` and in `header`), so an attacker
cannot strip the `FLAG_AUTHENTICATED` bit to demote an authenticated envelope to anonymous without
breaking the tag and changing the key.

---

## 3. The authenticated `sender_block`

When a sender signing identity is supplied, `encrypt()` sets `flags = FLAG_AUTHENTICATED (0x01)` and
builds a non-empty `sender_block` from three sub-TLVs (in this order):

```
sender_block = TLV(sender_kid) || TLV(sender_signing_public) || TLV(signature)
```

| # | Sub-TLV | Value | Length (suite 0x02 / 0x01) |
|---|---|---|---|
| 1 | `sender_kid` | 32-byte SHAKE-256 key-id of the sender's ML-DSA signing public bundle | 32 / 32 |
| 2 | `sender_signing_public` | the sender's full `PLSK` sig-pub key bundle (section 5) | 2635 / 1995 |
| 3 | `signature` | ML-DSA signature over `pre_auth || sender_kid`, context `AUTH_CTX` | 4627 / 3309 |

The signature is produced by `s.sig.sign(sk_raw, pre_auth + sender_kid, AUTH_CTX)` with
`AUTH_CTX = b"POLARIS-Shield/auth/v2"`. **The signer binds its own key-id into the signed message**
(`pre_auth + sender_kid`) — this is the SIGMA-style identity binding that prevents a captured
signature from being re-attributed to a different sender (unknown-key-share / misbinding).

The whole `sender_block` is itself wrapped as the fifth header TLV (section 2.3), so it is part of
the AEAD AAD as well as being independently signature-verified.

On open, `decrypt()` parses the sub-TLVs from offset 0 of `sender_block` with three chained
`_read_tlv` calls, then:

1. parses `sender_signing_public` as a `_ROLE_SIG_PUB` bundle, yielding `ssuite_id`, `claimed_kid`,
   `sender_pk`;
2. requires `sender_kid == claimed_kid` (else `"sender key-id does not match the embedded sender
   key"`);
3. requires `_suite(ssuite_id).sig.verify(sender_pk, pre_auth + claimed_kid, signature, AUTH_CTX)`
   (else `"sender signature verification failed"`) — verified **before** decapsulation;
4. if the caller pinned `expected_sender_public`, requires `sig_key_id(expected_sender_public) ==
   claimed_kid` (else `"authenticated sender is not the expected sender"`).

If `flags` does **not** carry `FLAG_AUTHENTICATED` but the caller passed `expected_sender_public`,
`decrypt()` raises `"expected an authenticated sender but envelope is anonymous"`. Authentication
proves sender identity and integrity but **not freshness** — see the `decrypt_authenticated`
docstring; replay resistance is an application-layer concern.

---

## 4. The streaming format — `PLST`

Produced by `seal_stream()`, consumed by `open_stream()`. For large messages encrypted as an ordered
sequence of independently-sealed AEAD chunks, where dropping the last chunk (truncation), reordering,
or dropping any chunk is detected on open — not just bit-flips.

### 4.1 Top-level structure

```
PLST stream = header || chunk[0] || chunk[1] || ... || chunk[last]
chunk[i]    = u32 blob_len || blob          # blob = AES-256-GCM ciphertext || 16-byte tag
```

### 4.2 Stream header

Built by `seal_stream()` as:

```
header = STREAM_MAGIC || VERSION || suite_id || flags
       || TLV(recipient_key_id) || TLV(eph_pub) || TLV(kem_ct)
       || TLV(base_nonce) || struct.pack(">I", chunk_size)
```

| Offset | Size | Field | Value / source |
|---|---|---|---|
| 0 | 4 | `STREAM_MAGIC` | ASCII `"PLST"` (`STREAM_MAGIC = b"PLST"`) |
| 4 | 1 | `VERSION` | `0x02` |
| 5 | 1 | `suite_id` | `0x01` / `0x02` |
| 6 | 1 | `flags` | always `0x00` here — `seal_stream` sets `flags = 0` (the stream format has no authenticated-sender mode) |
| 7 | 2+`n₁` | TLV(`recipient_key_id`) | 32-byte key-id |
| … | 2+`n₂` | TLV(`eph_pub`) | raw ECDH public (56 / 32) |
| … | 2+`n₃` | TLV(`kem_ct`) | ML-KEM ciphertext (1568 / 1088) |
| … | 2+`n₄` | TLV(`base_nonce`) | **7-byte** base nonce, `os.urandom(_NONCE_PREFIX)`, `_NONCE_PREFIX = 7` |
| `H-4` | 4 | `chunk_size` | u32; the writer's chunk size. **Advisory** — `open_stream` skips it (`off += 4 # chunk_size (advisory; not needed to decrypt)`) |

`H` is the running offset after `chunk_size`; `header = envelope[:H]`. `seal_stream` validates
`1 <= chunk_size <= 0xFFFFFFFF` up front.

### 4.3 Per-chunk framing

After the header, the body is a flat sequence of length-prefixed blobs. `open_stream` walks it with:

```
while off < len(envelope):
    (clen,) = struct.unpack_from(">I", envelope, off); off += 4   # blob_len
    blob = envelope[off:off+clen]; off += clen
```

| Field | Size | Notes |
|---|---|---|
| `blob_len` | 4 | u32 length of the sealed blob; reader raises `"truncated stream: missing chunk length"` / `"... chunk runs past end"` on under-run |
| `blob` | `blob_len` | `aead.encrypt(base_nonce || ctr, chunk, header || ctr)` = ciphertext `||` 16-byte tag |

There is always **at least one** chunk: `seal_stream` uses `[...] or [b""]`, so an empty plaintext
seals a single empty chunk. `open_stream` raises `"empty stream"` if no blobs are present.

### 4.4 Per-chunk nonce and the counter+final binding

This is the anti-truncation / anti-reorder mechanism. For chunk index `idx` out of `last =
len(chunks) - 1`:

```
final = 1 if idx == last else 0            # u8 final-flag
ctr   = struct.pack(">I", idx) || bytes([final])   # 4-byte counter || 1-byte final-flag = 5 bytes
nonce_i = base_nonce(7) || ctr(5)          # = 12 bytes, the AES-256-GCM nonce
aad_i   = header || ctr                     # header bound into every chunk's AAD, plus ctr
blob    = AESGCM(key).encrypt(nonce_i, chunk, aad_i)
```

So the 12-byte GCM nonce is `prefix(7) || counter(4) || final(1)` (see the comment on
`_NONCE_PREFIX`), and **the same `ctr` is bound in two places at once**: it is part of the nonce
*and* appended to the AAD (`header || ctr`). `open_stream` recomputes `final`, `ctr`, `nonce_i`, and
`aad_i` from each blob's **position in the received stream** and calls `aead.decrypt(base_nonce ||
ctr, blob, header || ctr)`, which "raises on any mismatch."

Consequences, all enforced cryptographically rather than by a length field an attacker controls:

- **Reorder** — a blob moved to a different index decrypts under the wrong `ctr` (wrong nonce *and*
  wrong AAD) and the GCM tag fails.
- **Drop a middle chunk** — every subsequent chunk shifts index, so all of them fail.
- **Truncation (drop the tail)** — the chunk that *was* final carried `final = 1`; after truncation
  the new last received chunk carries `final = 0` at its position, so the receiver never sees a
  `final = 1` blob at the end. Because the final-flag is bound into the nonce and AAD, the message
  cannot be silently shortened: the (now-missing) final chunk's distinct nonce/AAD cannot be forged.

The `chunk_size` field is advisory only and is **not** trusted for decryption integrity; integrity
comes entirely from the per-chunk AEAD with counter+final binding.

---

## 5. Key-bundle format — `PLSK`

All long-term key material (KEM and signing, public and private) shares one self-describing bundle
format, built by `_serialize_key()` and parsed by `_parse_key()`.

```
PLSK bundle = KEY_MAGIC || KEY_VERSION || suite_id || role || TLV(key_id) || TLV(part_0) || TLV(part_1) ...
```

| Offset | Size | Field | Value / source |
|---|---|---|---|
| 0 | 4 | `KEY_MAGIC` | ASCII `"PLSK"` (`KEY_MAGIC = b"PLSK"`) |
| 4 | 1 | `KEY_VERSION` | `0x02` (`KEY_VERSION = 2`) |
| 5 | 1 | `suite_id` | `0x01` / `0x02`, binding the key to its suite |
| 6 | 1 | `role` | one of `1,2,3,4` (below) |
| 7 | 2+`k` | TLV(`key_id`) | the 32-byte SHAKE-256 fingerprint (see §5.2) |
| 9+`k` | … | one or more TLV(`part`) | role-specific payload(s) |

`_parse_key()` rejects the bundle if `len < 7` or `bundle[:4] != KEY_MAGIC`, if
`bundle[4] != KEY_VERSION`, or if the embedded `role` byte does not match the role the caller
expected (`"wrong key role: expected …, got …"`). After the mandatory `key_id` TLV it reads parts in
a loop until the buffer is exhausted (`while off < len(bundle)`), so the part count is implicit in
the role.

### 5.1 Roles and payloads

`_ROLE_KEM_PUB, _ROLE_KEM_PRIV, _ROLE_SIG_PUB, _ROLE_SIG_PRIV = 1, 2, 3, 4`.

| `role` | Constant | Built by | TLV parts after `key_id` |
|---|---|---|---|
| 1 | `_ROLE_KEM_PUB` | `generate_recipient_keys` | `x_pub` (ECDH public, raw), `ek` (ML-KEM encaps key) |
| 2 | `_ROLE_KEM_PRIV` | `generate_recipient_keys` | `x_priv` (ECDH private, raw), `dk` (ML-KEM decaps key) |
| 3 | `_ROLE_SIG_PUB` | `generate_signing_keys` | `pk` (ML-DSA public) |
| 4 | `_ROLE_SIG_PRIV` | `generate_signing_keys` | `sk` (ML-DSA private) |

Per-suite payload sizes (raw, before TLV framing):

| Part | Suite 0x02 | Suite 0x01 | Source field |
|---|---|---|---|
| `x_pub` / `x_priv` | 56 | 32 | `Suite.ecdh_pub_len` |
| `ek` (KEM encaps) | 1568 | 1184 | `Suite.kem_ek_len` |
| `dk` (KEM decaps) | 3168 | 2400 | `Suite.kem_dk_len` |
| `pk` (ML-DSA public) | 2592 | 1952 | (ML-DSA-87 / 65) |
| `sk` (ML-DSA private) | 4896 | 4032 | (ML-DSA-87 / 65) |

Example total bundle lengths (verified live, suite 0x02): KEM public `1669` bytes
(`4+3 + (2+32) + (2+56) + (2+1568)`), signing public `2635`, signing private `4939`.

### 5.2 The key-id

`key_id` is computed by `_shake16()`, which despite its name emits **`KEY_ID_LEN = 32` bytes**
(SHAKE-256 with a 32-byte / 256-bit output — the apex-tier fingerprint width noted in the source
comment). It is computed over a domain-separated set of parts:

- KEM public: `_shake16(b"PLSK-kem-pub", bytes([suite_id]), x_pub, ek)`;
- signing public: `_shake16(b"PLSK-sig-pub", bytes([suite_id]), pk)`.

The **private** bundle reuses the **same** `key_id` as its matching public bundle (both are built in
the same `generate_*` call from the one `kid`), which is how `decrypt()` matches a private key to an
envelope: `priv_key_id != recipient_key_id` to `"wrong recipient key (key-id mismatch)"`.

Helper accessors: `kem_key_id(public_bundle)` (asserts role 1), `sig_key_id(public_bundle)` (asserts
role 3), and `suite_of(bundle)` (returns the `Suite` from `bundle[5]` without parsing private parts).

### 5.3 At-rest passphrase wrapping — `PLSW` (CLI only)

The CLI (`polaris_shield/__main__.py`) optionally wraps a private bundle at rest. This is **not**
part of the cryptographic core in `shield.py`; it is a storage envelope applied by `_wrap_private()`
when `--passphrase` is given, and transparently unwrapped by `_maybe_unwrap()` (which is a no-op if
the leading magic is absent). The KEK is derived with scrypt and the bundle sealed with AES-256-GCM.

```
PLSW wrapped = _WRAP_MAGIC || salt(16) || nonce(12) || sealed
```

| Offset | Size | Field | Source |
|---|---|---|---|
| 0 | 4 | `_WRAP_MAGIC` | ASCII `"PLSW"` |
| 4 | 16 | `salt` | `os.urandom(16)`, scrypt salt |
| 20 | 12 | `nonce` | `os.urandom(12)`, AES-256-GCM nonce |
| 32 | rest | `sealed` | `AESGCM(scrypt_key).encrypt(nonce, bundle, _WRAP_MAGIC)` — AAD is the 4-byte magic |

The wrapping key is `scrypt(passphrase, salt, n=2¹⁷, r=8, p=1, dklen=32)`. As SECURITY.md notes, this
is **passphrase wrapping** (protecting a key with a human secret), not NIST AES-KW; for
machine-to-machine wrapping use a validated AES-KW / KMS. On-disk, the CLI base64-encodes the whole
thing (ASCII), but that is a file-encoding convention, not part of the binary format.

---

## 6. The high-assurance and dual formats — `PLHA` / `PLDU`

Defined in `highassurance.py`. Opt-in SLH-DSA (FIPS 205) diversification, **not** the default.

### 6.1 SLH-DSA key bundle — `PLHA`

Built by `generate_high_assurance_keys()` and parsed by `_parse_ha()`. Unlike `PLSK`, this bundle has
**no TLV framing** — the key digest is the entire remaining tail, because SLH-DSA digests are
fixed-size per parameter set.

```
PLHA bundle = _HA_MAGIC || param_id || role || digest
```

| Offset | Size | Field | Value / source |
|---|---|---|---|
| 0 | 4 | `_HA_MAGIC` | ASCII `"PLHA"` |
| 4 | 1 | `param_id` | `0x01` = SLH-DSA-SHAKE-256s (default), `0x02` = SLH-DSA-SHAKE-128s |
| 5 | 1 | `role` | `_ROLE_PUB = 0` or `_ROLE_PRIV = 1` (note: **different role numbering than `PLSK`**) |
| 6 | rest | `digest` | `kp.pub.digest()` for public, `kp.digest()` for private (raw `slhdsa` serialization) |

`_parse_ha()` rejects `len < 6`, wrong magic, or wrong role, returning `(param_id, bundle[6:])`. The
param-set table is `_HA_PARAMS = {0x01: shake_256s, 0x02: shake_128s}`; `DEFAULT_HA_ID = 0x01`.

`high_assurance_sign()` signs `ctx + b"\x00" + message` (default `ctx = HA_CTX =
b"POLARIS-Shield/ha-sig/v1"`); the `\x00` separator domain-separates the context from the message.
`high_assurance_verify()` mirrors this and returns `False` on any exception.

### 6.2 Dual signature — `PLDU`

Built by `dual_sign()`, which signs the **same message** with both the lattice ML-DSA leg
(`shield.sign`, default context `SIG_CTX = b"POLARIS-Shield/sig/v1"`) and the hash-based SLH-DSA leg.
Both component signatures are length-framed with a u32:

```
PLDU signature = _DUAL_MAGIC || u32 ml_len || ml_sig || u32 ha_len || ha_sig
```

| Offset | Size | Field | Source |
|---|---|---|---|
| 0 | 4 | `_DUAL_MAGIC` | ASCII `"PLDU"` |
| 4 | 4 | `ml_len` | `struct.pack(">I", len(ml))` — u32 length of the ML-DSA signature |
| 8 | `ml_len` | `ml_sig` | `shield.sign(mldsa_private_bundle, message)` |
| 8+`ml_len` | 4 | `ha_len` | `struct.pack(">I", len(ha))` — u32 length of the SLH-DSA signature |
| 12+`ml_len` | `ha_len` | `ha_sig` | `high_assurance_sign(ha_private_bundle, message)` |

`dual_verify()` checks the magic, reads `ml_len` / `ml`, then `ha_len` / `ha`, and enforces
`off + ha_len == len(dual_signature)` (no trailing bytes). It returns `True` **only if both** legs
verify: `shield.verify(...) and high_assurance_verify(...)`. A forgery therefore requires breaking a
lattice **and** a hash-based scheme. Any structural error returns `False` (the whole parse is wrapped
in `try/except`).

---

## 7. Cipher-suite table

The suite registry is `SUITES` in `shield.py`. The recipient's key selects the suite; senders cannot
downgrade (section 2.7). `DEFAULT_SUITE_ID = 0x02`.

| `suite_id` | Label | ECDH | KEM (FIPS 203) | Signature (FIPS 204) | KDF hash | AEAD | `eph_pub` | `kem_ct` |
|---|---|---|---|---|---|---|---|---|
| `0x01` | FIPS 203/204 algorithm set (algorithm IDs only; not a validated module) | X25519 | ML-KEM-768 | ML-DSA-65 | HKDF-SHA256 | AES-256-GCM | 32 B | 1088 B |
| `0x02` | CNSA-2.0 algorithm set (default; not a validated module) | X448 | ML-KEM-1024 | ML-DSA-87 | HKDF-SHA384 | AES-256-GCM | 56 B | 1568 B |
| `0x03` | CNSA-2.0 **pure-PQC** end-state (no classical leg; not a validated module) | none | ML-KEM-1024 | ML-DSA-87 | HKDF-SHA384 | AES-256-GCM | 0 B | 1568 B |

Per-suite raw lengths (from the `Suite` dataclass fields `ecdh_pub_len`, `kem_ek_len`, `kem_dk_len`,
`kem_ct_len`):

| Field | 0x01 | 0x02 | 0x03 |
|---|---|---|---|
| `ecdh_pub_len` | 32 | 56 | 0 |
| `kem_ek_len` | 1184 | 1568 | 1568 |
| `kem_dk_len` | 2400 | 3168 | 3168 |
| `kem_ct_len` | 1088 | 1568 | 1568 |

Suite 0x02 is the **CNSA 2.0 algorithm set** (Category 5). Per SECURITY.md, "CNSA 2.0" denotes the
algorithm set, not a FIPS-validated module: `kyber-py` / `dilithium-py` / `slhdsa` are reference
implementations that track the standards but are not CAVP/CMVP validated and are not side-channel
hardened.

Suite 0x03 is the **pure-PQC** form of the same Category-5 set: the classical (ECDH) leg is absent,
so `eph_pub` and the recipient key's classical public are zero-length and the combiner's classical
contribution is empty (`struct.pack(">H", 0)` framing) — the derived key rests solely on ML-KEM-1024.
This is the NSA-preferred pure-PQC NSS end-state (see [CNSA_MIGRATION.md](CNSA_MIGRATION.md)); it
deliberately gives up the hybrid's "survives a classical OR a PQ break" property. Its confidentiality
is exactly the single-leg (PQ-only) case the four formal lineages already establish
(`secrecy_under_classical_break`). A classical-only seal is undefined for 0x03 and is refused.

---

## 8. Security properties & how the format enforces them

This section ties the byte layout above to the properties the construction claims. Every mechanism
is a property of the encoding, not of an out-of-band assumption.

### 8.1 Hybrid confidentiality (harvest-now / decrypt-later resistance)

The AEAD key from `_derive_key()` is HKDF over the **length-framed concatenation of both** the
classical ECDH secret and the post-quantum ML-KEM secret (`ikm = u16 len || ss_classical || u16 len
|| ss_pq`). An adversary must recover **both** secrets to derive the key; a future CRQC that breaks
the classical leg alone still cannot open the envelope. The u16 length prefixes (SP 800-56C shape)
make the concatenation injective, so two distinct `(ss_classical, ss_pq)` pairs can never alias to
the same `ikm`.

### 8.2 Downgrade resistance / suite binding

`suite_id` is taken from the **recipient's own key**, cross-checked on open (`sid != suite_id` to
hard error), and bound into both the AEAD AAD (it sits in `header`) and the HKDF transcript (it is
`pre_auth[0]` *and* a standalone byte in the HKDF `info`). `flags` is bound the same way. A sender or
MITM cannot select a weaker suite or strip the authenticated-mode flag without either breaking the
GCM tag or deriving a different (useless) key. See sections 2.6–2.7.

### 8.3 Full-transcript binding

The HKDF `info` carries the entire `pre_auth` transcript — `suite_id`, `flags`, `recipient_key_id`,
`eph_pub`, `kem_ct`, `nonce` — so the derived key is unique to this exact handshake. Separately, the
whole `header` (which TLV-frames those same values plus `MAGIC` / `VERSION` / `sender_block`) is the
GCM AAD. Tampering with any negotiated value changes the key, fails the tag, or both. In
authenticated mode the sender's ML-DSA signature covers `pre_auth || sender_kid`, binding the signer
identity into the same transcript (SIGMA-style), so a signature can never be re-attributed to a
different sender (unknown-key-share / misbinding).

### 8.4 Anti-truncation, anti-reorder, anti-drop (streaming)

Each `PLST` chunk's 12-byte nonce is `base_nonce(7) || counter(4) || final(1)`, and the same
`counter || final` is **also** appended to that chunk's AAD (`header || ctr`). The receiver
recomputes the counter and final-flag from each blob's **position in the received stream**:

- a reordered, duplicated, or shifted chunk decrypts under the wrong nonce/AAD and fails the tag;
- dropping a middle chunk shifts every later index and fails them all;
- truncating the tail removes the only chunk that carried `final = 1`, and that flag is bound into
  the nonce and AAD, so the stream cannot be silently shortened.

This upgrades the integrity guarantee from "no bit-flips" (plain AEAD) to "no bit-flips **and** the
exact, complete, in-order sequence of chunks."

### 8.5 Exact-length framing (anti-trailing-data, anti-truncation, single-shot)

Every length field is bounds-checked (`_read_tlv`, the u32 ciphertext/blob lengths), and the
single-shot `decrypt()` enforces `off + clen == len(envelope)` exactly — no trailing bytes, no short
read. Key bundles are parsed with the same bounds-checked TLV reader, and `dual_verify` enforces that
its two length-framed legs consume the buffer exactly. Malformed, truncated, or padded inputs are
rejected before any cryptographic secret is used.

### 8.6 Authentication caveat (freshness)

Authenticated mode proves **sender identity and integrity**, not **freshness**: a stateless one-pass
open does not detect replay of a previously captured envelope. Callers needing replay resistance must
add an application-layer check (nonce/transcript dedup, or an in-plaintext challenge/timestamp). This
is documented on `decrypt_authenticated` and repeated here so implementers do not over-read the
guarantee.

### 8.7 Key commitment (non-committing AEAD)

AES-256-GCM is **not** a key-committing AEAD: a single ciphertext+tag can, in principle, be crafted to
decrypt validly under more than one key (the "invisible salamander" / partitioning-oracle class), so
GCM alone does not commit to the key or the context. The Shield supplies that key/context commitment
**at the KDF layer instead**: the AEAD key is bound to the full handshake transcript (`suite_id ‖
flags ‖ recipient_key_id ‖ eph_pub ‖ kem_ct ‖ nonce`) via the HKDF `info` (§2.6), so a given
ciphertext is tied to exactly one derived key and one negotiated context. This is the relevant defence
in **anonymous mode**, which carries no sender signature, and it pre-empts a partitioning-oracle
reading of the AEAD.

---

## 9. Magic-number summary

| Magic | Format | Defined in | Section |
|---|---|---|---|
| `PLSH` | single-shot envelope | `shield.py` (`MAGIC`) | 2 |
| `PLST` | streaming envelope | `shield.py` (`STREAM_MAGIC`) | 4 |
| `PLSK` | KEM / signing key bundle | `shield.py` (`KEY_MAGIC`) | 5 |
| `PLSW` | at-rest passphrase-wrapped private key (CLI) | `__main__.py` (`_WRAP_MAGIC`) | 5.3 |
| `PLHA` | SLH-DSA high-assurance key bundle | `highassurance.py` (`_HA_MAGIC`) | 6.1 |
| `PLDU` | dual ML-DSA + SLH-DSA signature | `highassurance.py` (`_DUAL_MAGIC`) | 6.2 |
| `X25O` | classical-only demo seal (NOT a Shield format) | `shield.py`, `encrypt_classical_only` | — |

The `X25O` prefix produced by `encrypt_classical_only()` is intentionally **not** a Shield envelope:
that function is a quantum-vulnerable demonstration of harvest-now / decrypt-later and is documented
only for contrast.

---

*Specification derived byte-for-byte from `polaris_shield/shield.py` and
`polaris_shield/highassurance.py`. This is a reference implementation and a project convention, not a
standardized protocol and not a FIPS-validated module — see [SECURITY.md](SECURITY.md) and
[THREAT_MODEL.md](THREAT_MODEL.md).*
