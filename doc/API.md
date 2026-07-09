# SnowlandSMX.jl API Reference

## Version

**0.1.0** -- BSD 3-Clause License

## Project Structure

```
src/smx/
  SM3/        SM3 cryptographic hash (GB/T 32905-2016)
  SM4/        SM4 block cipher (GM/T 0002-2012)
  ZUC/        ZUC stream cipher (GM/T 0001-2012)
  SM2/        SM2 elliptic curve public key (GM/T 0003-2012)
  SM9/        SM9 identity-based cryptography (GM/T 0044-2016)
  util/       Shared utilities (hex/bytes, random, buffer I/O)
  crypto/     CryptoHash: unified hash interface
```

## Dependencies

| Package | Version | Required |
|---------|---------|----------|
| Julia | >= 1.6 | Yes |
| CryptoGroups.jl | >= 0.6 | Yes (SM2/SM9) |
| Random | stdlib | Yes |
| OpenSSL.jl | >= 1.6 | No (benchmark only) |

---

## Module: SM3 -- Cryptographic Hash

**Standard:** GB/T 32905-2016

### Types

#### `SM3Context`

Streaming SM3 hash context.

```julia
mutable struct SM3Context
    iv::Vector{UInt32}       # current hash state (8 x UInt32)
    block::Vector{UInt8}     # buffered partial block
    length::Int              # total bytes accumulated
end
```

Constructors:

| Signature | Description |
|-----------|-------------|
| `SM3Context()` | Empty context |
| `SM3Context(data::Vector{UInt8})` | Pre-feed with byte data |
| `SM3Context(data::AbstractString)` | Pre-feed with string |

### Constants

| Name | Type | Value |
|------|------|-------|
| `IV` | `Vector{UInt32}` (8) | SM3 initial hash value |
| `T_j` | `Vector{UInt32}` (64) | Round constants |
| `hexdigest` | alias | = `sm3_hash` |

### One-Shot Hash Functions

#### `sm3_hash(data; hex_input=false) -> String`

Compute SM3 hash, returns 64-char hex string.

| Parameter | Type | Description |
|-----------|------|-------------|
| `data` | `AbstractString` or `Vector{UInt8}` | Input data |
| `hex_input` | `Bool` | If `true`, interpret `data` as hex string |

**Return:** 64-character lowercase hex string (32 bytes).

```julia
sm3_hash("abc")  # => "66c7f0f462eeedd9..."
```

> **Note:** This is the recommended one-shot API. Input is automatically UTF-8 encoded from strings.

---

#### `sm3_digest(data; hex_input=false) -> Vector{UInt8}`

Compute SM3 hash, returns raw 32-byte array.

| Parameter | Type | Description |
|-----------|------|-------------|
| `data` | `AbstractString` or `Vector{UInt8}` | Input data |
| `hex_input` | `Bool` | If `true`, interpret `data` as hex string |

**Return:** `Vector{UInt8}` of length 32.

```julia
sm3_digest("abc")  # => 32-byte Vector{UInt8}
```

---

#### `sm3_hexdigest(data; hex_input=false) -> String`

Alias for `sm3_hash`. Returns 64-char hex string.

---

#### `hash_msg(msg) -> String`

One-shot hash without hex input option.

| Parameter | Type | Description |
|-----------|------|-------------|
| `msg` | Any | Message to hash |

**Return:** 64-char hex string.

---

#### `digest(data; hex_input=false) -> Vector{UInt8}`

Low-level digest, returns raw bytes. Same as `sm3_digest`.

### Streaming Hash Functions

#### `update!(ctx::SM3Context, data)`

Feed data into the streaming context.

| Parameter | Type | Description |
|-----------|------|-------------|
| `ctx` | `SM3Context` | Hash context |
| `data` | `AbstractString` or `Vector{UInt8}` | Data to feed |

> **Note:** Does not copy `data` on each call -- partial block is buffered internally. Only calls compression function on full 64-byte blocks.

---

#### `digest!(ctx::SM3Context) -> Vector{UInt8}`

Finalize and return raw 32-byte digest. **Resets** the context after finalization.

---

#### `hexdigest!(ctx::SM3Context) -> String`

Finalize and return 64-char hex string. **Resets** the context after finalization.

### Key Derivation Functions

#### `sm3_kdf(z::AbstractString, klen::Integer) -> String`

SM3-based KDF. Returns hex string of `klen` bytes.

| Parameter | Type | Description |
|-----------|------|-------------|
| `z` | `AbstractString` | Shared secret as hex string |
| `klen` | `Integer` | Desired output length in bytes |

---

#### `sm3_kdf_bytes(z::AbstractString, klen::Integer) -> Vector{UInt8}`

Same as `sm3_kdf` but returns raw bytes.

---

#### `sm3_kdf_from_bytes(z_bytes::Vector{UInt8}, klen::Integer) -> Vector{UInt8}`

KDF from raw byte input. Used internally by SM2/SM9.

| Parameter | Type | Description |
|-----------|------|-------------|
| `z_bytes` | `Vector{UInt8}` | Shared secret as bytes |
| `klen` | `Integer` | Desired output length in bytes |

### Core Primitives

These are exported as building blocks:

| Function | Signature | Description |
|----------|-----------|-------------|
| `rotate_left` | `(a::UInt32, k::Integer) -> UInt32` | Left rotate by k bits |
| `P_0` | `(X::UInt32) -> UInt32` | Permutation P0 |
| `P_1` | `(X::UInt32) -> UInt32` | Permutation P1 |
| `FF_j` | `(X, Y, Z, j) -> UInt32` | Boolean function FF (j<16: XOR, j>=16: majority) |
| `GG_j` | `(X, Y, Z, j) -> UInt32` | Boolean function GG (j<16: XOR, j>=16: choice) |
| `CF` | `(V_i, B_i) -> Vector{UInt32}` | Compression function |
| `PUT_UINT32_BE` | `(n::UInt32) -> Vector{UInt8}` | UInt32 to 4-byte big-endian |

### Utility

#### `byte2hex(data::Vector{UInt8}) -> String`

Convert bytes to lowercase hex string.

---

## Module: SM4 -- Block Cipher

**Standard:** GM/T 0002-2012

### Constants

| Name | Type | Value |
|------|------|-------|
| `ENCRYPT` | `Int` | `0` |
| `DECRYPT` | `Int` | `1` |

### Types

#### `Sm4`

ECB/CBC block cipher context holding 32 expanded round keys.

```julia
mutable struct Sm4
    sk::Vector{UInt32}    # 32 round keys
    mode::Int             # ENCRYPT or DECRYPT
end
```

Constructor: `Sm4()`

---

#### `Sm4Ctr`

CTR-mode streaming context. **Recommended** for large data.

```julia
mutable struct Sm4Ctr
    sk::Vector{UInt32}      # 32 expanded round keys (ENCRYPT direction)
    ctr::Vector{UInt8}      # 16-byte counter block
    kstream::Vector{UInt8}  # 16-byte encrypted counter
    kpos::Int               # current byte offset in kstream (17 = needs refill)
end
```

Constructor: `Sm4Ctr(key::Vector{UInt8}, iv::Vector{UInt8})`

| Parameter | Type | Description |
|-----------|------|-------------|
| `key` | `Vector{UInt8}` | 16-byte key |
| `iv` | `Vector{UInt8}` | 16-byte initial counter |

---

#### `Sm4Cbc`

CBC-mode streaming context with PKCS7 padding.

```julia
mutable struct Sm4Cbc
    sk::Vector{UInt32}    # 32 round keys
    chain::Vector{UInt8}  # 16-byte chaining block
    buffer::Vector{UInt8} # 16-byte overflow buffer
    buf_len::Int          # bytes in buffer (0..15)
    mode::Int             # ENCRYPT or DECRYPT
end
```

Constructor: `Sm4Cbc(key::Vector{UInt8}, iv::Vector{UInt8}, mode::Int)`

| Parameter | Type | Description |
|-----------|------|-------------|
| `key` | `Vector{UInt8}` | 16-byte key |
| `iv` | `Vector{UInt8}` | 16-byte initialization vector |
| `mode` | `Int` | `ENCRYPT(0)` or `DECRYPT(1)` |

> **Error:** Throws if IV length != 16 or mode is invalid.

### Key Setup

#### `sm4_setkey!(sm4::Sm4, key::Vector{UInt8}, mode::Int)`

Set key and expand round keys.

| Parameter | Type | Description |
|-----------|------|-------------|
| `sm4` | `Sm4` | Cipher context |
| `key` | `Vector{UInt8}` | 16-byte key |
| `mode` | `Int` | `ENCRYPT(0)` or `DECRYPT(1)` |

### One-Shot ECB

#### `sm4_crypt_ecb(mode::Int, key::Vector{UInt8}, data::Vector{UInt8}) -> Vector{UInt8}`

SM4-ECB encryption/decryption. Creates a temporary `Sm4` context internally.

| Parameter | Type | Description |
|-----------|------|-------------|
| `mode` | `Int` | `ENCRYPT(0)` or `DECRYPT(1)` |
| `key` | `Vector{UInt8}` | 16-byte key |
| `data` | `Vector{UInt8}` | Input (must be multiple of 16 bytes) |

**Return:** Encrypted/decrypted `Vector{UInt8}` of same length.

> **Note:** No padding; input must be a multiple of 16 bytes.

---

#### `sm4_crypt_ecb!(sm4::Sm4, input_data::Vector{UInt8}) -> Vector{UInt8}`

In-place-friendly ECB. Uses pre-configured context (no key setup overhead on repeated calls).

| Parameter | Type | Description |
|-----------|------|-------------|
| `sm4` | `Sm4` | Pre-configured cipher context |
| `input_data` | `Vector{UInt8}` | Input (multiple of 16 bytes) |

### One-Shot CBC

#### `sm4_crypt_cbc(mode::Int, key::Vector{UInt8}, iv::Vector{UInt8}, data::Vector{UInt8}) -> Vector{UInt8}`

SM4-CBC encryption/decryption. Creates a temporary context.

| Parameter | Type | Description |
|-----------|------|-------------|
| `mode` | `Int` | `ENCRYPT(0)` or `DECRYPT(1)` |
| `key` | `Vector{UInt8}` | 16-byte key |
| `iv` | `Vector{UInt8}` | 16-byte initialization vector |
| `data` | `Vector{UInt8}` | Input (multiple of 16 bytes) |

---

#### `sm4_crypt_cbc!(sm4::Sm4, iv::Vector{UInt8}, input_data::Vector{UInt8}) -> Vector{UInt8}`

CBC with pre-configured context.

### Streaming CTR Mode (Recommended for Large Data)

#### `sm4_ctr_xor!(ctx::Sm4Ctr, input, output) -> Int`

CTR-mode XOR. Encrypts or decrypts `input` into `output`. No padding -- output length always equals input length.

| Parameter | Type | Description |
|-----------|------|-------------|
| `ctx` | `Sm4Ctr` | CTR context |
| `input` | `AbstractVector{UInt8}` | Plaintext or ciphertext |
| `output` | `AbstractVector{UInt8}` | Output buffer (must be >= length(input)) |

**Return:** Number of bytes processed (= `length(input)`).

> **Note:** CTR mode uses only the encrypt direction internally. Encryption and decryption are identical operations.

### Streaming CBC Mode

#### `sm4_cbc_encrypt_update!(ctx::Sm4Cbc, input, output) -> Int`

Feed plaintext into CBC encryption stream.

| Parameter | Type | Description |
|-----------|------|-------------|
| `ctx` | `Sm4Cbc` | CBC context (mode = ENCRYPT) |
| `input` | `AbstractVector{UInt8}` | Plaintext |
| `output` | `AbstractVector{UInt8}` | Output buffer |

**Return:** Number of bytes written (always a multiple of 16). Partial block is buffered internally.

---

#### `sm4_cbc_encrypt_final!(ctx::Sm4Cbc, output, offset=1) -> Int`

Finalize CBC encryption. Applies PKCS7 padding and writes final block(s).

| Parameter | Type | Description |
|-----------|------|-------------|
| `ctx` | `Sm4Cbc` | CBC context |
| `output` | `AbstractVector{UInt8}` | Output buffer |
| `offset` | `Int` | Write position (1-based, default=1) |

**Return:** Number of bytes written (16, always one block with padding).

> **Note:** Context should not be reused after `final!`.

---

#### `sm4_cbc_decrypt_update!(ctx::Sm4Cbc, input, output) -> Int`

Feed ciphertext into CBC decryption stream.

| Parameter | Type | Description |
|-----------|------|-------------|
| `ctx` | `Sm4Cbc` | CBC context (mode = DECRYPT) |
| `input` | `AbstractVector{UInt8}` | Ciphertext |
| `output` | `AbstractVector{UInt8}` | Output buffer |

**Return:** Number of bytes written (multiple of 16). Last block is always held back for PKCS7 validation in `final!`.

> **Note:** Output requires space for `max(0, floor((buf_len + len(input))/16) - 1) * 16` bytes. At least 2 full blocks must accumulate before any output.

---

#### `sm4_cbc_decrypt_final!(ctx::Sm4Cbc, output, offset=1) -> Int`

Finalize CBC decryption. Decrypts last block, removes PKCS7 padding.

| Parameter | Type | Description |
|-----------|------|-------------|
| `ctx` | `Sm4Cbc` | CBC context |
| `output` | `AbstractVector{UInt8}` | Output buffer |
| `offset` | `Int` | Write position (1-based) |

**Return:** Number of plaintext bytes written (<= 16).

> **Error:** Throws if remaining data != 16 bytes or padding is invalid.

---

## Module: ZUC -- Stream Cipher

**Standard:** GM/T 0001-2012

### Types

#### `ZUCContext`

Stream cipher context with ring-buffer LFSR for O(1) shift operations.

```julia
mutable struct ZUCContext
    lfsr_buf::Vector{UInt32}   # 16-element ring buffer
    lfsr_head::Int             # index (1-based) for LFSR[1]
    r::Vector{UInt32}          # R1, R2
    x::Vector{UInt32}          # X0, X1, X2, X3
end
```

Constructor: `ZUCContext(key::Vector{UInt8}, iv::Vector{UInt8})`

| Parameter | Type | Description |
|-----------|------|-------------|
| `key` | `Vector{UInt8}` | 16-byte key |
| `iv` | `Vector{UInt8}` | 16-byte IV |

### Functions

#### `zuc_encrypt(ctx::ZUCContext, input::Vector{UInt8}) -> Vector{UInt8}`

Encrypt or decrypt data. Since ZUC is a synchronous stream cipher, encryption and decryption are identical.

| Parameter | Type | Description |
|-----------|------|-------------|
| `ctx` | `ZUCContext` | Initialized context |
| `input` | `Vector{UInt8}` | Plaintext or ciphertext |

**Return:** `Vector{UInt8}` of same length.

```julia
ctx = ZUCContext(key, iv)
ct = zuc_encrypt(ctx, plaintext)

# Reset for decryption
ctx2 = ZUCContext(key, iv)
pt = zuc_encrypt(ctx2, ct)  # pt == plaintext
```

> **Note:** Each `ZUCContext` consumes keystream starting from its initialization. To decrypt, create a **new** context with the same key/IV. The context is **not** reusable after encryption; a ZUC context is one-shot.

---

#### `zuc_generate_keystream(ctx::ZUCContext, length::Integer) -> Vector{UInt32}`

Generate ZUC keystream of specified number of 32-bit words.

| Parameter | Type | Description |
|-----------|------|-------------|
| `ctx` | `ZUCContext` | Initialized context |
| `length` | `Integer` | Number of 32-bit words to generate |

**Return:** `Vector{UInt32}` of `length` keystream words.

> **Note:** Internal function. Use `zuc_encrypt` for normal encryption.

---

## Module: SM2 -- Elliptic Curve Public Key

**Standard:** GM/T 0003-2012

### Constants

| Name | Type | Description |
|------|------|-------------|
| `sm2_N` | `BigInt` | Curve order |
| `sm2_P` | `BigInt` | Field prime |
| `sm2_G` | `SM2Point` | Generator point |

### Types

#### `SM2KeyPair`

```julia
struct SM2KeyPair
    publicKey::Vector{UInt8}   # 64 bytes (x || y)
    privateKey::String         # 64-char hex string
end
```

> **Note:** `privateKey` is hex-encoded, ready to use directly with `sm2_sign`/`sm2_decrypt`. `publicKey` is 64 raw bytes.

### Key Generation

#### `sm2_generate_keypair() -> SM2KeyPair`

Generate an SM2 key pair using CSPRNG (`Random.RandomDevice`).

**Return:** `SM2KeyPair` with CSPRNG-generated private key and corresponding public key.

```julia
kp = sm2_generate_keypair()
# kp.privateKey  -> "a3f2..."  (64-char hex)
# kp.publicKey   -> 64-byte Vector{UInt8}
```

> **Security:** Private key `d` is generated in [1, N-1] using rejection sampling from `RandomDevice`.

---

### ZA Computation

#### `sm2_compute_za(id::AbstractString, pubkey::Vector{UInt8}) -> Vector{UInt8}`

Compute ZA = SM3(ENTL || ID || a || b || xG || yG || xA || yA), per GM/T 0003.2-2012 Section 5.5.

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | `AbstractString` | User's distinguishable identifier |
| `pubkey` | `Vector{UInt8}` | 64-byte public key (x || y) |

**Return:** 32-byte ZA digest.

> **Note:** Signature functions (`sm2_sign`, `sm2_verify`) automatically compute ZA when given `(id, pubkey)`. You only need this directly when implementing custom signing flows.

---

### Digital Signature

#### `sm2_sign(message, DA, id, pubkey; Hexstr=false) -> Vector{UInt8}`

SM2 signature with ZA (GM/T 0003.2-2012). Standard format.

| Parameter | Type | Description |
|-----------|------|-------------|
| `message` | `String` or `Vector{UInt8}` | Message to sign |
| `DA` | `AbstractString` | 64-char hex private key |
| `id` | `AbstractString` | User identifier |
| `pubkey` | `Vector{UInt8}` or `AbstractString` | Public key (64 bytes or 128-char hex) |
| `Hexstr` | `Bool` | If `true`, message is already hex |

**Return:** `Vector{UInt8}` (64 bytes: r || s, each 32 bytes).

```
Internal flow:
  1. ZA = sm3_compute_za(id, pubkey)
  2. H = sm3_digest(ZA || message)
  3. Sign H with private key DA
```

---

#### `sm2_sign(message, DA, K; Hexstr=false) -> Vector{UInt8}`

Legacy overload with explicit nonce `K` (for deterministic testing). Does **NOT** use ZA -- the message is hashed directly.

| Parameter | Type | Description |
|-----------|------|-------------|
| `message` | Any | Message to sign |
| `DA` | `AbstractString` | 64-char hex private key |
| `K` | `AbstractString` | 64-char hex random nonce |

> **Note:** Use the standard `(message, DA, id, pubkey)` overload for production.

---

#### `sm2_verify(Sign, message, id, pubkey_bytes; Hexstr=false) -> Bool`

SM2 signature verification with ZA.

| Parameter | Type | Description |
|-----------|------|-------------|
| `Sign` | `Vector{UInt8}` | 64-byte signature (r || s) |
| `message` | `String` or `Vector{UInt8}` | Original message |
| `id` | `AbstractString` | Signer's identifier |
| `pubkey_bytes` | `Vector{UInt8}` | Signer's 64-byte public key |
| `Hexstr` | `Bool` | If `true`, treat message as hex |

**Return:** `true` if signature is valid, `false` otherwise.

---

#### `sm2_verify(Sign, E, PA; Hexstr=false) -> Bool`

Legacy verification without ZA (verifies against raw hash/point).

| Parameter | Type | Description |
|-----------|------|-------------|
| `Sign` | `Vector{UInt8}` | 64-byte signature |
| `E` | Any | Message or pre-computed hash |
| `PA` | `AbstractString` or `Vector{UInt8}` | Public key |

---

### Encryption / Decryption

#### `sm2_encrypt(message, PA; format=:C1C3C2, Hexstr=false) -> Vector{UInt8}`

SM2 public key encryption.

| Parameter | Type | Description |
|-----------|------|-------------|
| `message` | `String` or `Vector{UInt8}` | Plaintext |
| `PA` | `AbstractString` or `Vector{UInt8}` | Recipient's public key |
| `format` | `Symbol` | `:C1C3C2` (default) or `:C1C2C3` |
| `Hexstr` | `Bool` | If `true`, message is hex |

**Return:** Ciphertext bytes:
- `:C1C3C2` (GMT 0009-2012, GmSSL-compatible): `C1(64B) || C3(32B) || C2(variable)`
- `:C1C2C3` (legacy): `C1(64B) || C2(variable) || C3(32B)`

> **Note:** `:C1C3C2` is the recommended and default format for interoperability with GmSSL.

---

#### `sm2_decrypt(C, DA; format=:C1C3C2) -> Union{Vector{UInt8}, Nothing}`

SM2 decryption.

| Parameter | Type | Description |
|-----------|------|-------------|
| `C` | `Vector{UInt8}` | Ciphertext |
| `DA` | `AbstractString` | 64-char hex private key |
| `format` | `Symbol` | `:C1C3C2` (default) or `:C1C2C3` |

**Return:** Plaintext bytes if C3 MAC verifies, `nothing` otherwise.

> **Security:** C3 verification (SM3-based MAC) is mandatory. Decryption fails if ciphertext is tampered with.

---

#### `sm2_get_hash(message; Hexstr=false) -> String`

SM3 hash utility for SM2 operations.

| Parameter | Type | Description |
|-----------|------|-------------|
| `message` | Any | Input |
| `Hexstr` | `Bool` | If `true`, input is hex |

---

## Module: SM9 -- Identity-Based Cryptography

**Standard:** GM/T 0044-2016

### Constants

| Name | Type | Description |
|------|------|-------------|
| `SM9_q` | `BigInt` | BN curve field prime |
| `SM9_N` | `BigInt` | BN curve order |
| `SM9_P1` | `(BigInt, BigInt)` | G1 generator coordinates |
| `SM9_t` | `BigInt` | BN curve parameter |
| `SM9_a` | `BigInt` | Curve a coefficient (= 0) |
| `SM9_b` | `BigInt` | Curve b coefficient (= 5) |
| `sm9_g1_generator` | `SM9G1Point` | G1 generator point |

> **Note:** All SM9 parameters are initialized via `__init__()` when the module loads. The G2 generator is computed at init time.

### Types

#### `SM9EncryptMasterKey`

```julia
struct SM9EncryptMasterKey
    ke::BigInt               # master private key
    P_pub_e::SM9G1Point      # [ke]P1 (in G1)
end
```

---

#### `SM9EncryptPrivateKey`

```julia
struct SM9EncryptPrivateKey
    de_B::G2Point            # user decrypt key in G2
    hid::UInt8               # key usage identifier
end
```

---

#### `SM9SignMasterKey`

```julia
struct SM9SignMasterKey
    ks::BigInt               # master private key
    P_pub_s::G2Point         # [ks]P2 (in G2)
end
```

---

#### `SM9SignPrivateKey`

```julia
struct SM9SignPrivateKey
    ds_A::SM9G1Point         # user signing key in G1
    hid::UInt8               # key usage identifier
end
```

---

#### `SM9EncryptCiphertext`

```julia
struct SM9EncryptCiphertext
    C1::Vector{UInt8}        # 64 bytes (G1 point)
    C3::Vector{UInt8}        # 32 bytes (MAC)
    C2::Vector{UInt8}        # variable (encrypted message)
end
```

### Master Key Generation

#### `sm9_master_key() -> SM9EncryptMasterKey`

Generate SM9 encryption master key pair.

**Return:** `SM9EncryptMasterKey` with CSPRNG-generated `ke` and corresponding `P_pub_e = [ke]P1`.

---

#### `sm9_sign_master_key() -> SM9SignMasterKey`

Generate SM9 signature master key pair.

**Return:** `SM9SignMasterKey` with CSPRNG-generated `ks` and corresponding `P_pub_s = [ks]P2`.

### User Key Extraction

#### `sm9_encrypt_private_key(master::SM9EncryptMasterKey, id; hid=0x03) -> SM9EncryptPrivateKey`

Extract user encryption private key: `de_B = [ke / (H1(ID||hid) + ke)] * P2`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `master` | `SM9EncryptMasterKey` | Encryption master key |
| `id` | `AbstractString` | User identifier |
| `hid` | `UInt8` | Key usage ID (default: `0x03` for encryption) |

**Return:** `SM9EncryptPrivateKey` (G2 point).

> **Error:** Throws if `t1 == 0` (re-generate master key).

---

#### `sm9_sign_private_key(master::SM9SignMasterKey, id; hid=0x01) -> SM9SignPrivateKey`

Extract user signing private key: `ds_A = [ks / (H1(ID||hid) + ks)] * P1`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `master` | `SM9SignMasterKey` | Signing master key |
| `id` | `AbstractString` | User identifier |
| `hid` | `UInt8` | Key usage ID (default: `0x01` for signing) |

**Return:** `SM9SignPrivateKey` (G1 point, as `SM9G1Point`).

### Encryption / Decryption

#### `sm9_encrypt(master_public, id, message; hid=0x03) -> Vector{UInt8}`

SM9 KEM-DEM encryption (GM/T 0044.4-2016).

| Parameter | Type | Description |
|-----------|------|-------------|
| `master_public` | `SM9EncryptMasterKey` | System master public key |
| `id` | `AbstractString` | Recipient identifier |
| `message` | `String` or `Vector{UInt8}` | Plaintext |
| `hid` | `UInt8` | Key usage ID (default: `0x03`) |

**Return:** Ciphertext in C1C3C2 format: `C1(64B) || C3(32B) || C2(variable)`.

```
Internal flow:
  1. Q_B = [H1(ID)]*P1 + Ppub-e
  2. r = random, C1 = [r]*Q_B
  3. g = e(Ppub-e, P2), w = g^r
  4. K = KDF(C1 || w || ID, mlen*8 + 256)
  5. C2 = M xor K1, C3 = SM3(C2 || K2)
```

---

#### `sm9_decrypt(de_B, id, ciphertext) -> Union{Vector{UInt8}, Nothing}`

SM9 KEM-DEM decryption.

| Parameter | Type | Description |
|-----------|------|-------------|
| `de_B` | `SM9EncryptPrivateKey` | User's decrypt key |
| `id` | `AbstractString` | User identifier |
| `ciphertext` | `Vector{UInt8}` | Ciphertext (C1C3C2 format) |

**Return:** Plaintext bytes if MAC verifies, `nothing` otherwise.

> **Security:** C3 verification ensures ciphertext integrity. Returns `nothing` on failure (tampered or malformed input).

### Digital Signature

#### `sm9_sign(master_public, Da, message) -> (BigInt, SM9G1Point)`

SM9 digital signature (GM/T 0044.2-2016).

| Parameter | Type | Description |
|-----------|------|-------------|
| `master_public` | `SM9SignMasterKey` | System master public key |
| `Da` | `SM9SignPrivateKey` | Signer's private key |
| `message` | `String` or `Vector{UInt8}` | Message to sign |

**Return:** `(h, S)` tuple -- `h` is a `BigInt`, `S` is an `SM9G1Point`.

```
Internal flow:
  1. g = e(P1, Ppub-s)
  2. r = random, w = g^r
  3. h = H2(M || w)
  4. l = (r - h) mod N
  5. S = [l] * ds_A
```

---

#### `sm9_verify(master_public, id, message, signature) -> Bool`

SM9 signature verification.

| Parameter | Type | Description |
|-----------|------|-------------|
| `master_public` | `SM9SignMasterKey` | System master public key |
| `id` | `AbstractString` | Signer's identifier |
| `message` | `String` or `Vector{UInt8}` | Original message |
| `signature` | `Tuple{BigInt, SM9G1Point}` | `(h, S)` from `sm9_sign` |

**Return:** `true` if valid, `false` otherwise.

> **Note:** Returns `false` if `h < 1` or `h >= N` (domain check).

### G1 Operations

#### `sm9_g1_hash(id; hid=0x03) -> SM9G1Point`

Hash an identifier to a G1 point: computes `[H1(ID||hid)] * P1`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | `AbstractString` | Identifier string |
| `hid` | `UInt8` | Key usage ID |

---

### Parameter Verification

#### `sm9_verify_params() -> Bool`

Verify SM9 BN curve parameters are correct.

Checks:
- `a == 0`, `b == 5`
- P1 is on the curve: `y^2 == x^3 + b`
- q and N match the BN formula: `q = 36t^4 + 36t^3 + 24t^2 + 6t + 1`, `N = 36t^4 + 36t^3 + 18t^2 + 6t + 1`

**Return:** `true` if all checks pass.

### Utilities

#### `generate_prime(length::Int; n=100) -> BigInt`

Generate a random prime of specified hex length using Miller-Rabin.

| Parameter | Type | Description |
|-----------|------|-------------|
| `length` | `Int` | Hex digit length |
| `n` | `Int` | Miller-Rabin iterations (default: 100) |

---

#### `is_probable_prime(number::BigInt, itor=10) -> Bool`

Miller-Rabin primality test.

| Parameter | Type | Description |
|-----------|------|-------------|
| `number` | `BigInt` | Number to test |
| `itor` | `Int` | Iterations (default: 10) |

---

## Module: CryptoHash -- Unified Hash Interface

Provides a factory pattern for hash algorithms (currently SM3 only).

### Functions

#### `new_hash(name, data=nothing) -> SM3HashCtx`

Create a hash context by algorithm name.

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | `AbstractString` | Hash algorithm (only `"sm3"` supported) |
| `data` | `Vector{UInt8}`, `AbstractString`, or `nothing` | Optional initial data |

**Return:** `SM3HashCtx` streaming context.

```julia
ctx = new_hash("sm3", "hello")
update!(ctx, " world")
hexdigest(ctx)  # => SM3 hash hex string
```

> **Note:** Only SM3 is built-in. For SHA algorithms, use Julia's stdlib `SHA`.

---

#### `digest_size_for(name::AbstractString) -> Int`

Get digest output size in bytes for a given hash algorithm.

| Algorithm | Size (bytes) |
|-----------|-------------|
| sm3 / sha256 | 32 |
| sha224 | 28 |
| sha384 | 48 |
| sha512 | 64 |
| sha3_256 | 32 |
| sha3_512 | 64 |
| md5 | 16 |
| sha1 | 20 |

---

#### `supported_hashes -> Set{String}`

Returns set of supported hash names: `Set(["sm3"])`.

#### `sm3_hashlib`

Alias for `SM3HashCtx`.

### Types

#### `SM3HashCtx`

```julia
mutable struct SM3HashCtx
    data::Vector{UInt8}
end
```

| Method | Signature | Return |
|--------|-----------|--------|
| Constructor | `SM3HashCtx()` | Empty context |
| Constructor | `SM3HashCtx(Vector{UInt8})` | Pre-loaded context |
| `update!` | `(ctx, data::Vector{UInt8})` | `nothing` |
| `update!` | `(ctx, data::AbstractString)` | `nothing` |
| `digest` | `(ctx)` | `Vector{UInt8}` (32 bytes) |
| `hexdigest` | `(ctx)` | `String` (64 chars) |

---

## Internal Utilities (`util.jl`)

Shared functions included inline in SM2, SM4, SM9, and ZUC modules. **Not exported** -- use through the public module APIs.

| Function | Signature | Description |
|----------|-----------|-------------|
| `_hex2bytes` | `(s::AbstractString) -> Vector{UInt8}` | Hex string to bytes |
| `_bytes2hex` | `(data::Vector{UInt8}) -> String` | Bytes to hex string |
| `_bigint_to_hex` | `(x::BigInt, len::Int) -> String` | BigInt to zero-padded hex |
| `_rand_bytes` | `(n::Int) -> Vector{UInt8}` | CSPRNG random bytes |
| `_rand_bigint` | `(n_bytes::Int) -> BigInt` | Random BigInt |
| `_put_u32_be!` | `(buf, off, n::UInt32)` | Write UInt32 big-endian |
| `_get_u32_be` | `(data, off=1) -> UInt32` | Read UInt32 big-endian |
