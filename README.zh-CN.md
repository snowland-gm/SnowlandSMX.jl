# SnowlandSMX.jl

纯 Julia 实现的中国商用密码算法套件。

## 概述

SnowlandSMX.jl 完整实现了中国国家密码管理局发布的商用密码算法标准（GM/T 系列）。

**版本:** 0.1.0 | **许可证:** BSD 3-Clause | **Julia:** >= 1.6

## 项目结构

```
src/smx/
  SM3/        SM3 密码杂凑算法（GB/T 32905-2016）
  SM4/        SM4 分组密码算法（GM/T 0002-2012）
  ZUC/        ZUC 祖冲之序列密码算法（GM/T 0001-2012）
  SM2/        SM2 椭圆曲线公钥密码算法（GM/T 0003-2012）
  SM9/        SM9 标识密码算法（GM/T 0044-2016）
  util/       共享工具（hex/bytes、CSPRNG、缓冲区读写）
  crypto/     CryptoHash：统一哈希接口
```

## 算法

| 算法 | 标准        | 类型                | 状态 |
|------|------------|---------------------|------|
| SM2  | GM/T 0003  | 椭圆曲线公钥密码算法   | 稳定 |
| SM3  | GB/T 32905 | 密码杂凑算法（256 位） | 稳定 |
| SM4  | GM/T 0002  | 分组密码算法（128 位） | 稳定 |
| SM9  | GM/T 0044  | 标识密码算法          | 稳定 |
| ZUC  | GM/T 0001  | 祖冲之序列密码算法     | 稳定 |

### SM2
- 密钥生成、签名、验签、加密、解密
- 256 位素域椭圆曲线
- SM3 作为底层哈希和 KDF
- `SM2KeyPair.privateKey` 为 hex 字符串，可直接用于 API
- 支持两种密文格式：`:C1C3C2`（GmSSL 兼容，默认）和 `:C1C2C3`（旧格式）

### SM3
- 一次性哈希（支持字符串、hex、字节数组输入）
- 流式哈希（通过 `SM3Context` 逐步更新）
- KDF 密钥派生（支持 hex 和字节输入）
- **测试向量已通过 GB/T 32905-2016 附录 A 验证**

### SM4
- ECB 和 CBC 模式，预分配输出缓冲区
- **流式 API：** CTR 模式（`Sm4Ctr`）和 CBC 模式（`Sm4Cbc`），支持 PKCS7 填充
- 128 位分组，128 位密钥
- 通过 `Sm4` 上下文实现无分配热路径加密
- **测试向量已通过 GM/T 0002-2012 附录 A 验证**

### SM9
- BN 曲线参数（256 位）
- 主密钥生成、用户密钥提取
- G1 哈希到点、参数验证
- **KEM-DEM 加密/解密**，带 SM3 MAC（C1C3C2 格式）
- **数字签名/验签**，完整双线性配对（Ate pairing on BN curve）
- 纯 Julia 实现全部域扩展（Fq、Fq2、Fq12）及椭圆曲线运算

### ZUC
- 128 位密钥 + 128 位 IV 流密码
- 环形缓冲区 LFSR（O(1) 移位操作）
- 密钥流生成和加解密

## 安装

```julia
using Pkg
Pkg.develop(path=".")
```

## 依赖

- Julia >= 1.10
- [CryptoGroups.jl](https://github.com/dfinity/CryptoGroups.jl) >= 0.6（SM2/SM9 椭圆曲线点运算）
- [OpenSSL.jl](https://github.com/JuliaCrypto/OpenSSL.jl)（可选，用于性能对比）

## 快速开始

```julia
using SnowlandSMX

# === SM3 哈希 ===
using SnowlandSMX.SM3
sm3_hash("abc")
# => "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"

# 流式哈希
ctx = SM3Context()
update!(ctx, "hello "); update!(ctx, "world")
hexdigest!(ctx)

# 字节输入
sm3_digest("abc")  # => 32 字节 Vector{UInt8}

# KDF
sm3_kdf_bytes("010203...", 32)
sm3_kdf_from_bytes(z_bytes, 32)

# === SM4 分组密码 ===
using SnowlandSMX.SM4
key = rand(UInt8, 16)
ciphertext = sm4_crypt_ecb(ENCRYPT, key, plaintext)
decrypted  = sm4_crypt_ecb(DECRYPT, key, ciphertext)

# CBC 模式
iv = zeros(UInt8, 16)
ciphertext = sm4_crypt_cbc(ENCRYPT, key, iv, plaintext)

# 流式 CTR 模式（推荐用于大数据）
ctx = Sm4Ctr(key, iv)
out = Vector{UInt8}(undef, length(input))
sm4_ctr_xor!(ctx, input, out)

# 流式 CBC 模式
ctx = Sm4Cbc(key, iv, ENCRYPT)
out = similar(input)
n = sm4_cbc_encrypt_update!(ctx, input, out)
rem = sm4_cbc_encrypt_final!(ctx, out, n)

# === SM2 椭圆曲线 ===
using SnowlandSMX.SM2
kp = sm2_generate_keypair()
# kp.privateKey 为 64 位 hex 字符串（可直接使用）
# kp.publicKey 为 64 字节原始数据

# 带 ZA（用户 ID + 公钥）签名
sig = sm2_sign("hello", kp.privateKey, "1234567812345678", kp.publicKey)
sm2_verify(sig, "hello", "1234567812345678", kp.publicKey)  # => true

# 加密/解密（默认 C1C3C2 格式，GmSSL 兼容）
ct = sm2_encrypt("secret data", kp.publicKey)
pt = sm2_decrypt(ct, kp.privateKey)

# === SM9 标识密码 ===
using SnowlandSMX.SM9

# 加密
master_key = sm9_master_key()
ct = sm9_encrypt(master_key, "alice@example.com", "secret message")
user_key = sm9_encrypt_private_key(master_key, "alice@example.com")
pt = sm9_decrypt(user_key, "alice@example.com", ct)

# 签名
sign_master = sm9_sign_master_key()
sign_key = sm9_sign_private_key(sign_master, "alice@example.com")
sig = sm9_sign(sign_master, sign_key, "message")
sm9_verify(sign_master, "alice@example.com", "message", sig)  # => true

# === ZUC 流密码 ===
using SnowlandSMX.ZUC
ctx = ZUCContext(key, iv)  # 各 16 字节
ciphertext = zuc_encrypt(ctx, plaintext)

# 重置上下文解密
ctx2 = ZUCContext(key, iv)
plaintext = zuc_encrypt(ctx2, ciphertext)
```

## 测试

运行完整测试套件（每个模块在独立进程中运行）：

```bash
julia --project=. test/runtests.jl
```

单独运行某模块测试：
```bash
julia --project=. -e "using SnowlandSMX.SM3, Test; include(\"test/sm3_test.jl\")"
julia --project=. -e "using SnowlandSMX.SM4; include(\"test/sm4_test.jl\")"
julia --project=. -e "using SnowlandSMX.ZUC; include(\"test/zuc_test.jl\")"
```

## 文档

完整 API 参考文档：[doc/API.md](doc/API.md)

## 性能对比

基于 Windows 10 x64, Julia 1.12.6, CPU: i7-12700H 实测。
纯 Julia 实现与 OpenSSL 3.x EVP API 对比。

### SM4 分组密码 (ECB & CBC)

**ECB 加密：**

| 大小   | Julia (ms) | Julia (MB/s) | OpenSSL (ms) | OpenSSL (MB/s) | 比值 |
|--------|-----------|-------------|-------------|----------------|------|
| 16 B   | 0.0005    | 32.0        | --          | --             | --   |
| 1 KB   | 0.012     | 84.7        | 0.008       | 130.5          | 1.5x |
| 64 KB  | 0.748     | 85.6        | 0.488       | 131.3          | 1.5x |
| 1 MB   | 12.68     | 78.9        | 9.17        | 109.0          | 1.4x |

- **密钥扩展开销：** < 0.001 ms
- SM4 纯 Julia 仅比 OpenSSL 手写汇编**慢 1.4-1.5 倍**

### SM3 哈希（纯 Julia）

| 大小  | 一次性 (ms) | 一次性 (MB/s) | 流式 (ms) | 流式 (MB/s) |
|-------|-----------|--------------|----------|-------------|
| 16 B  | 0.0004    | 40.0         | 0.0006   | 26.7        |
| 1 KB  | 0.012     | 81.3         | 0.014    | 73.9        |

- 稳态吞吐量：**约 80 MB/s**

### SM2 ECC 操作

| 操作   | 纯 Julia  | OpenSSL EVP | 比值  |
|--------|----------|-------------|-------|
| 密钥生成 | 2.106 ms | 0.413 ms    | 5.1x  |
| 签名   | 2.166 ms | 0.537 ms    | 4.0x  |
| 验签   | 4.816 ms | 0.363 ms    | 13.3x |
| 加密   | 5.448 ms | 0.852 ms    | 6.4x  |
| 解密   | 2.649 ms | 0.558 ms    | 4.7x  |

### SM9 IBE 操作（纯 Julia）

| 操作            | 延迟    |
|-----------------|---------|
| 主密钥生成       | 4.04 ms |
| 用户密钥提取     | 2.32 ms |
| G1 哈希到点      | 3.79 ms |
| G1 标量乘法      | 3.70 ms |
| 参数验证         | 6.9 us  |

### ZUC 流密码（纯 Julia）

| 大小    | 加密 (ms) | 加密 (MB/s) |
|---------|---------|------------|
| 1 KB    | 0.027   | 37.0       |
| 64 KB   | 1.894   | 33.8       |
| 100 KB  | 2.557   | 39.1       |

### 运行性能测试

```bash
# 纯 Julia（始终可用）：
julia --project=. demo/benchmark/run_benchmarks.jl

# 含 OpenSSL 完整对比：
julia --project=. demo/benchmark/sm4_benchmark.jl
julia --project=. demo/benchmark/sm2_benchmark.jl
julia --project=. demo/benchmark/sm9_benchmark.jl
```

## 示例

```bash
julia --project=. demo/sm2_demo.jl
julia --project=. demo/sm3_demo.jl
julia --project=. demo/sm4_demo.jl
julia --project=. demo/zuc_demo.jl
```

## 已知问题

- **Julia 1.12 GC Bug**（Julia 1.12.6, Windows）：
  - **触发条件：** `using SnowlandSMX.SM3`（同时加载全部模块）+ 在 SM3 的 `_pad`
    函数中分配 >= 1000 字节的数组。
  - **现象：** `EXCEPTION_ACCESS_VIOLATION` at `jl_gc_small_alloc_inner` /
    `gc_sweep_pool` -- 原生 GC 在分配或回收阶段破坏内存。
  - **规避方案：** 测试运行器和基准运行器分别在独立 Julia 进程中运行每个模块。
    生产环境：Julia 1.12 上每个进程只加载一个加解密模块。
  - 这是 **Julia 运行时的问题**，并非本库的 bug。

## 标准

- GM/T 0001-2012：ZUC 祖冲之序列密码算法
- GM/T 0002-2012：SM4 分组密码算法
- GM/T 0003-2012：SM2 椭圆曲线公钥密码算法
- GB/T 32905-2016：SM3 密码杂凑算法
- GM/T 0044-2016：SM9 标识密码算法

## 许可证

本项目基于 BSD 3-Clause License 发布 -- 详见 [LICENSE](LICENSE) 文件。
