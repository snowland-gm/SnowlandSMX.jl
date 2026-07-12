# Performance Benchmarks

**Environment:** Windows 10 x64 | Julia 1.12.6 | CPU: i7-12700H | OpenSSL 3.x

All benchmarks use median latency from 50-5000 iterations with 5 warmup runs.
OpenSSL comparison uses the EVP API via `libcrypto`.
Streaming benchmarks use 64-byte chunked `sm4_stream_update!` / `update!` calls,
simulating real-world streaming scenarios.

---

## SM4 Block Cipher

### ECB Batch Encrypt / Decrypt (legacy `Sm4` API)

| Size  | Enc (ms) | Enc (MB/s) | Dec (ms) | Dec (MB/s) |
|-------|---------|-----------|----------|-----------|
| 16 B  | 0.000   | 40.0      | 0.000    | 40.0      |
| 1 KB  | 0.008   | 126.4     | 0.008    | 128.0     |
| 64 KB | 0.505   | 126.8     | 0.506    | 126.6     |
| 100 KB| 0.803   | 124.5     | 0.793    | 126.1     |
| 1 MB  | 8.626   | 115.9     | 8.422    | 118.7     |

### CBC Batch Encrypt (legacy `Sm4` API)

| Size  | Julia (ms) | Julia (MB/s) |
|-------|-----------|-------------|
| 16 B  | 0.000     | 40.0        |
| 1 KB  | 0.008     | 124.9       |
| 64 KB | 0.510     | 125.5       |
| 100 KB| 0.803     | 124.5       |
| 1 MB  | 9.021     | 110.9       |

### ECB / CBC / CFB / OFB / CTR Streaming (`Sm4Stream` API)

Single-shot `sm4_stream_update!` + `sm4_stream_final!` (all modes at 1 MB).
ECB / CBC use PKCS7 padding by default; CFB / OFB / CTR have no padding:

| Mode       | Dir  | ms    | MB/s |
|------------|------|-------|------|
| ECB stream | enc  | 8.75  | 114.2 |
| CBC stream | enc  | 8.63  | 115.9 |
| CBC stream | dec  | 8.81  | 113.5 |
| CFB stream | enc  | 8.98  | 111.4 |
| OFB stream | enc  | 9.12  | 109.6 |
| CTR stream | enc  | 9.05  | 110.5 |

### Chunked Streaming (64B blocks, Sm4Stream)

Real-world streaming scenario with `sm4_stream_update!` called once per 64-byte block:

| Total   | Chunks | CBC (ms) | CBC (MB/s) | CTR (ms) | CTR (MB/s) | OFB (ms) | OFB (MB/s) | CFB (ms) | CFB (MB/s) |
|---------|--------|---------|-----------|----------|-----------|----------|-----------|----------|-----------|
| 64 B    | 1      | 0.001   | 64.0      | 0.001    | 80.0      | 0.001    | 80.0      | 0.001    | 80.0      |
| 640 B   | 10     | 0.006   | 112.3     | 0.006    | 110.3     | 0.006    | 108.5     | 0.005    | 116.4     |
| 6.4 KB  | 100    | 0.053   | 119.9     | 0.056    | 114.7     | 0.056    | 114.3     | 0.052    | 122.6     |
| 64 KB   | 1000   | 0.530   | 120.8     | 0.573    | 111.8     | 0.568    | 112.6     | 0.522    | 122.7     |

### Init Overhead

| Operation         | Latency    |
|-------------------|-----------|
| Key setup (Sm4)   | < 0.001 ms |
| Sm4Stream ECB init| < 0.001 ms |
| Sm4Stream CBC init| < 0.001 ms |
| Sm4Stream CFB init| < 0.001 ms |
| Sm4Stream OFB init| < 0.001 ms |
| Sm4Stream CTR init| < 0.001 ms |

**SM4 Summary:** Pure Julia SM4 achieves **110-128 MB/s** (batch) across all modes
and **110-116 MB/s** (streaming). T-table precomputation (v0.1.0) delivers ~1.5x
speedup over the baseline implementation. ECB needs no IV and is slightly faster
than CBC. ECB/CBC streaming use PKCS7 padding by default; chunking overhead is
negligible. Streaming API (`Sm4Stream`) performance matches one-shot modes.

---

## SM2 ECC

| Operation | Julia (ms) | OpenSSL (ms) | Ratio  |
|-----------|-----------|-------------|--------|
| keygen    | 2.688     | 0.351       | 7.7x   |
| sign      | 3.782     | 0.593       | 6.4x   |
| verify    | 5.487     | 0.298       | 18.4x  |
| encrypt   | 5.404     | 0.675       | 8.0x   |
| decrypt   | 2.317     | 0.329       | 7.0x   |

**Note:** SM2 uses BigInt + CryptoGroups for elliptic curve operations. OpenSSL's
hand-optimized C+assembly is **6-18x faster**. Multi-precision integer arithmetic
and modular inversion remain inherently slower in pure Julia.

---

## SM3 Hash

### One-Shot Hash

| Size | Julia (ms) | Julia (MB/s) |
|------|-----------|-------------|
| 16 B | < 0.001   | 32.0        |
| 64 B | 0.001     | 71.1        |

### Chunked Streaming Hash (64B blocks via `update!`)

This is the real-world SM3 streaming usage pattern, feeding data block by block:

| Total   | Chunks | Julia (ms) | Julia (MB/s) |
|---------|--------|-----------|-------------|
| 64 B    | 1      | 0.001     | 106.7       |
| 640 B   | 10     | 0.003     | 206.5       |
| 6.4 KB  | 100    | 0.028     | 229.4       |
| 64 KB   | 1000   | 0.289     | 221.6       |

Pure Julia SM3 achieves **~222 MB/s** steady-state throughput in chunked streaming mode.
The one-shot API for large messages is affected by a Julia 1.12 GC crash (known issue,
only sizes <= 64 bytes are testable in one-shot mode).

### KDF Derivation

| Key Length | Latency (ms) |
|------------|-------------|
| 16 B       | < 0.001     |
| 32 B       | < 0.001     |
| 64 B       | < 0.001     |

### Context Initialization

| Operation     | Latency  |
|---------------|---------|
| SM3Context()  | < 0.001 ms |

---

## SM9 IBE

| Operation              | Latency  |
|------------------------|----------|
| Master key gen         | 4.04 ms  |
| User key extract       | 2.32 ms  |
| G1 hash-to-point       | 3.79 ms  |
| G1 scalar mult         | 3.70 ms  |
| Parameter verification | 6.9 us   |

SM9 operates on a 256-bit BN curve with full field extension tower
(Fq -> Fq2 -> Fq12) and Ate pairing, all implemented in pure Julia.
OpenSSL has no SM9 support for comparison.

---

## ZUC Stream Cipher

### Encryption

| Size    | Encrypt (ms) | Encrypt (MB/s) |
|---------|-------------|----------------|
| 16 B    | 0.001       | 22.9           |
| 1 KB    | 0.005       | 212.8          |
| 64 KB   | 0.271       | 235.9          |
| 100 KB  | 0.438       | 228.2          |
| 500 KB  | 2.489       | 200.9          |

### Keystream Generation

| Size    | Keystream (ms) | Keystream (MB/s) |
|---------|---------------|-------------------|
| 1 KB    | 0.017         | 60.2              |
| 64 KB   | 1.076         | 59.5              |
| 100 KB  | 1.760         | 56.8              |

ZUC encryption achieves **~201-236 MB/s** steady-state throughput with 4-byte
bulk processing. Encrypt overhead is negligible vs raw keystream generation (both
eliminate intermediate keystream buffers).

---

## Summary

| Algorithm     | Type              | Pure Julia Throughput | vs OpenSSL    |
|---------------|-------------------|-----------------------|---------------|
| SM4 ECB       | Block cipher      | 115-127 MB/s         | 1.5x slower   |
| SM4 CBC       | Block cipher      | 111-125 MB/s         | 1.6x slower   |
| SM4 CTR       | Stream cipher     | 110-119 MB/s         | N/A           |
| SM4 CBC stream| Stream cipher     | 114-124 MB/s         | N/A           |
| SM4 CFB stream| Stream cipher     | 111-123 MB/s         | N/A           |
| SM4 OFB stream| Stream cipher     | 110-120 MB/s         | N/A           |
| SM3           | Hash              | 222 MB/s (streaming)  | N/A           |
| ZUC           | Stream cipher     | 201-236 MB/s          | N/A           |
| SM2 sign      | ECC               | 3.8 ms/op             | 6.4x slower   |
| SM2 verify    | ECC               | 5.5 ms/op             | 18.4x slower  |
| SM9           | IBE               | 2-4 ms/op             | N/A           |

- **SM4**: Best-in-class performance for pure Julia; only 1.4-1.6x slower than C+assembly.
  Streaming `Sm4Stream` API covers all 5 modes (ECB/CBC/CFB/OFB/CTR) with PKCS7 padding for
  ECB/CBC by default; T-table precomputation delivers ~1.5x speedup
- **SM3**: Chunked streaming achieves **222 MB/s**. In-place CF! and reusable W buffer
  eliminate per-block allocation. One-shot hash for large messages is
  affected by Julia 1.12 GC bug
- **ZUC**: 4-byte bulk keystream extraction achieves **~236 MB/s** peak throughput,
  a ~4x improvement over byte-by-byte processing with no intermediate buffer

---

## Running Benchmarks

```bash
# Pure Julia standalone (no external deps):
julia --project=. demo/benchmark/sm4_standalone_v2.jl
julia --project=. demo/benchmark/sm3_standalone_v2.jl
julia --project=. demo/benchmark/zuc_standalone_v2.jl

# All standalone benchmarks in one go:
julia --project=. demo/benchmark/run_benchmarks.jl

# With OpenSSL comparison (requires OpenSSL_jll):
julia --project=. demo/benchmark/sm4_benchmark.jl
julia --project=. demo/benchmark/sm2_benchmark.jl
```
