# SnowlandSMX.jl

Chinese Commercial Cryptography Suite in pure Julia.

## Overview

SnowlandSMX.jl implements the complete set of Chinese national cryptographic
standards (GM/T) as specified by the State Cryptography Administration of China.

**Version:** 0.1.0 | **License:** BSD 3-Clause | **Julia:** >= 1.6

## Project Structure

```
src/smx/
  SM3/        SM3 cryptographic hash (GB/T 32905-2016)
  SM4/        SM4 block cipher (GM/T 0002-2012)
  ZUC/        ZUC stream cipher (GM/T 0001-2012)
  SM2/        SM2 elliptic curve public key crypto (GM/T 0003-2012)
  SM9/        SM9 identity-based cryptography (GM/T 0044-2016)
  util/       Shared utilities (hex/bytes, CSPRNG, buffer I/O)
  crypto/     CryptoHash: unified hash interface
```

## Algorithms

| Algorithm | Standard   | Type                             | Status  |
|-----------|------------|----------------------------------|---------|
| SM2       | GM/T 0003  | Elliptic curve public key crypto | Stable  |
| SM3       | GB/T 32905 | Cryptographic hash (256-bit)     | Stable  |
| SM4       | GM/T 0002  | Block cipher (128-bit)           | Stable  |
| SM9       | GM/T 0044  | Identity-based cryptography      | Stable  |
| ZUC       | GM/T 0001  | Stream cipher                    | Stable  |

### SM2
- Key generation, signing, verification, encryption, decryption
- 256-bit prime field elliptic curve
- SM3 as the underlying hash and KDF
- `SM2KeyPair` with hex-encoded `privateKey` (ready to use with API)
- Two ciphertext formats: `:C1C3C2` (GmSSL-compatible, default) and `:C1C2C3` (legacy)

### SM3
- One-shot hashing (string, hex, byte array input)
- Streaming hashing via `SM3Context`
- Key derivation function (KDF) with both hex and byte input
- **Test vectors verified against GB/T 32905-2016 Appendix A**

### SM4
- ECB and CBC modes with pre-allocated output buffers
- **Streaming API:** CTR mode (`Sm4Ctr`) and CBC mode (`Sm4Cbc`) with PKCS7 padding
- 128-bit block size, 128-bit key
- In-place encryption via `Sm4` context (no allocations in hot path)
- **Test vector verified against GM/T 0002-2012 Appendix A**

### SM9
- BN curve parameters (256-bit)
- Master key generation, user key extraction
- G1 hash-to-point, parameter verification
- **KEM-DEM encryption/decryption** with SM3-based MAC (C1C3C2 format)
- **Digital signature/verification** with full pairing (Ate pairing on BN curve)
- Pure Julia implementation of all field extensions (Fq, Fq2, Fq12) and elliptic curve operations

### ZUC
- Stream cipher with 128-bit key and 128-bit IV
- Ring-buffer LFSR for O(1) shift operations
- Keystream generation and encryption/decryption

## Installation

```julia
using Pkg
Pkg.develop(path=".")
```

## Dependencies

- Julia >= 1.6
- [CryptoGroups.jl](https://github.com/dfinity/CryptoGroups.jl) >= 0.6 (EC point operations for SM2/SM9)
- [OpenSSL.jl](https://github.com/JuliaCrypto/OpenSSL.jl) (optional, for benchmark comparison)

## Quick Start

```julia
using SnowlandSMX

# === SM3 Hash ===
using SnowlandSMX.SM3
sm3_hash("abc")
# => "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"

# Streaming hash
ctx = SM3Context()
update!(ctx, "hello "); update!(ctx, "world")
hexdigest!(ctx)

# Byte input
sm3_digest("abc")  # => 32-byte Vector{UInt8}

# KDF (hex or bytes)
sm3_kdf_bytes("010203...", 32)
sm3_kdf_from_bytes(z_bytes, 32)

# === SM4 Block Cipher ===
using SnowlandSMX.SM4
key = rand(UInt8, 16)
ciphertext = sm4_crypt_ecb(ENCRYPT, key, plaintext)
decrypted  = sm4_crypt_ecb(DECRYPT, key, ciphertext)

# CBC mode
iv = zeros(UInt8, 16)
ciphertext = sm4_crypt_cbc(ENCRYPT, key, iv, plaintext)

# Streaming CTR mode (recommended for large data)
ctx = Sm4Ctr(key, iv)
out = Vector{UInt8}(undef, length(input))
sm4_ctr_xor!(ctx, input, out)

# Streaming CBC mode
ctx = Sm4Cbc(key, iv, ENCRYPT)
out = similar(input)
n = sm4_cbc_encrypt_update!(ctx, input, out)
rem = sm4_cbc_encrypt_final!(ctx, out, n)

# === SM2 ECC ===
using SnowlandSMX.SM2
kp = sm2_generate_keypair()
# kp.privateKey is a 64-char hex string (usable directly)
# kp.publicKey is 64 raw bytes

# Sign with ZA (user ID + public key)
sig = sm2_sign("hello", kp.privateKey, "1234567812345678", kp.publicKey)
sm2_verify(sig, "hello", "1234567812345678", kp.publicKey)  # => true

# Encrypt/decrypt (default C1C3C2 format, GmSSL-compatible)
ct = sm2_encrypt("secret data", kp.publicKey)
pt = sm2_decrypt(ct, kp.privateKey)

# === SM9 IBE ===
using SnowlandSMX.SM9

# Encrypt
master_key = sm9_master_key()
ct = sm9_encrypt(master_key, "alice@example.com", "secret message")
user_key = sm9_encrypt_private_key(master_key, "alice@example.com")
pt = sm9_decrypt(user_key, "alice@example.com", ct)

# Sign
sign_master = sm9_sign_master_key()
sign_key = sm9_sign_private_key(sign_master, "alice@example.com")
sig = sm9_sign(sign_master, sign_key, "message")
sm9_verify(sign_master, "alice@example.com", "message", sig)  # => true

# === ZUC Stream Cipher ===
using SnowlandSMX.ZUC
ctx = ZUCContext(key, iv)  # each 16 bytes
ciphertext = zuc_encrypt(ctx, plaintext)

# Reset context to decrypt
ctx2 = ZUCContext(key, iv)
plaintext = zuc_encrypt(ctx2, ciphertext)
```

## Testing

Run the full test suite (each module in its own process):

```bash
julia --project=. test/runtests.jl
```

Individual module tests:
```bash
julia --project=. -e "using SnowlandSMX.SM3, Test; include(\"test/sm3_test.jl\")"
julia --project=. -e "using SnowlandSMX.SM4; include(\"test/sm4_test.jl\")"
julia --project=. -e "using SnowlandSMX.ZUC; include(\"test/zuc_test.jl\")"
```

## Documentation

Full API reference: [doc/API.md](doc/API.md)

## Performance

All benchmarks measured on Windows 10 x64, Julia 1.12.6, CPU: i7-12700H.
Pure Julia vs OpenSSL 3.x EVP API comparison (where available).

### SM4 Block Cipher (ECB & CBC)

**ECB Encryption:**

| Size    | Julia (ms) | Julia (MB/s) | OpenSSL (ms) | OpenSSL (MB/s) | Ratio |
|---------|-----------|-------------|-------------|----------------|-------|
| 16 B    | 0.0005    | 32.0        | --          | --             | --    |
| 1 KB    | 0.012     | 84.7        | 0.008       | 130.5          | 1.5x  |
| 64 KB   | 0.748     | 85.6        | 0.488       | 131.3          | 1.5x  |
| 1 MB    | 12.68     | 78.9        | 9.17        | 109.0          | 1.4x  |

- **Key setup:** < 0.001 ms
- SM4 Julia is only **1.4-1.5x slower** than OpenSSL's hand-optimized assembly

### SM3 Hash (Pure Julia)

| Size  | One-shot (ms) | One-shot (MB/s) | Stream (ms) | Stream (MB/s) |
|-------|--------------|-----------------|-------------|---------------|
| 16 B  | 0.0004       | 40.0            | 0.0006      | 26.7          |
| 1 KB  | 0.012        | 81.3            | 0.014       | 73.9          |

- Steady-state throughput: **~80 MB/s**

### SM2 ECC Operations

| Operation | Pure Julia | OpenSSL EVP | Ratio  |
|-----------|-----------|-------------|--------|
| keygen    | 2.106 ms  | 0.413 ms    | 5.1x   |
| sign      | 2.166 ms  | 0.537 ms    | 4.0x   |
| verify    | 4.816 ms  | 0.363 ms    | 13.3x  |
| encrypt   | 5.448 ms  | 0.852 ms    | 6.4x   |
| decrypt   | 2.649 ms  | 0.558 ms    | 4.7x   |

### SM9 IBE Operations (Pure Julia only)

| Operation          | Latency  |
|--------------------|----------|
| Master key gen     | 4.04 ms  |
| User key extract   | 2.32 ms  |
| G1 hash-to-point   | 3.79 ms  |
| G1 scalar mult     | 3.70 ms  |
| Param verification | 6.9 us   |

### ZUC Stream Cipher (Pure Julia)

| Size  | Encrypt (ms) | Encrypt (MB/s) |
|-------|-------------|----------------|
| 1 KB  | 0.027       | 37.0           |
| 64 KB | 1.894       | 33.8           |
| 100 KB| 2.557       | 39.1           |

### Running Benchmarks

```bash
# Pure Julia only (always works):
julia --project=. demo/benchmark/run_benchmarks.jl

# Full comparison with OpenSSL:
julia --project=. demo/benchmark/sm4_benchmark.jl
julia --project=. demo/benchmark/sm2_benchmark.jl
julia --project=. demo/benchmark/sm9_benchmark.jl
```

## Demos

```bash
julia --project=. demo/sm2_demo.jl
julia --project=. demo/sm3_demo.jl
julia --project=. demo/sm4_demo.jl
julia --project=. demo/zuc_demo.jl
```

## Known Issues

- **Julia 1.12 GC Bug** (Julia 1.12.6, Windows):
  - **Trigger:** `using SnowlandSMX.SM3` (which loads all modules) + allocating
    >= 1000-byte arrays in SM3's `_pad` function.
  - **Symptom:** `EXCEPTION_ACCESS_VIOLATION` at `jl_gc_small_alloc_inner` /
    `gc_sweep_pool` -- the stock GC corrupts memory during allocation or sweep.
  - **Workaround:** The test runner and benchmark runner spawn each module in a
    separate Julia process. Production: load only one crypto module per process.
  - This is a **Julia runtime issue**, not a bug in this library.

## Standards

- GM/T 0001-2012: ZUC stream cipher
- GM/T 0002-2012: SM4 block cipher
- GM/T 0003-2012: SM2 elliptic curve public key cryptography
- GB/T 32905-2016: SM3 cryptographic hash algorithm
- GM/T 0044-2016: SM9 identity-based cryptography

## License

This project is licensed under the BSD 3-Clause License -- see the [LICENSE](LICENSE) file for details.
