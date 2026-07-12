# SnowlandSMX.jl API 参考文档

## 版本

**0.1.0** -- BSD 3-Clause License

## 项目结构

```
src/smx/
  SM3/        SM3 密码杂凑算法 (GB/T 32905-2016)
  SM4/        SM4 分组密码算法 (GM/T 0002-2012)
  ZUC/        ZUC 流密码算法 (GM/T 0001-2012)
  SM2/        SM2 椭圆曲线公钥密码算法 (GM/T 0003-2012)
  SM9/        SM9 标识密码算法 (GM/T 0044-2016)
  util/       共享工具函数（hex/bytes、随机数、缓冲区 I/O）
  crypto/     CryptoHash: 统一哈希接口
```

## 依赖

| 包 | 版本 | 必需 |
|---------|---------|----------|
| Julia | >= 1.6 | 是 |
| CryptoGroups.jl | >= 0.6 | 是 (SM2/SM9) |
| Random | stdlib | 是 |
| OpenSSL.jl | >= 1.6 | 否（仅用于性能测试） |

---

## 模块: SM3 -- 密码杂凑算法

**标准:** GB/T 32905-2016

### 类型

#### `SM3Context`

SM3 流式哈希上下文。

```julia
mutable struct SM3Context
    iv::Vector{UInt32}       # 当前哈希状态（8 个 UInt32）
    block::Vector{UInt8}     # 缓存的部分块
    length::Int              # 累计字节数
    w::Vector{UInt32}        # 可复用的 68-UInt32 消息扩展缓冲区
end
```

构造函数:

| 签名 | 描述 |
|-----------|-------------|
| `SM3Context()` | 空上下文 |
| `SM3Context(data::Vector{UInt8})` | 预填入字节数据 |
| `SM3Context(data::AbstractString)` | 预填入字符串 |

### 常量

| 名称 | 类型 | 值 |
|------|------|-------|
| `IV` | `Vector{UInt32}` (8) | SM3 初始哈希值 |
| `T_j` | `Vector{UInt32}` (64) | 轮常数 |
| `T_j_rot` | `Vector{UInt32}` (64) | 预计算的 rotate_left(T_j[j], j-1) |
| `hexdigest` | 别名 | = `sm3_hash` |

### 一次性哈希函数

#### `sm3_hash(data; hex_input=false) -> String`

计算 SM3 哈希，返回 64 字符十六进制字符串。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `data` | `AbstractString` 或 `Vector{UInt8}` | 输入数据 |
| `hex_input` | `Bool` | 为 `true` 时，将 `data` 解释为十六进制字符串 |

**返回:** 64 字符小写十六进制字符串（32 字节）。

```julia
sm3_hash("abc")  # => "66c7f0f462eeedd9..."
```

> **注意:** 这是推荐的一次性 API。字符串输入会自动编码为 UTF-8。

---

#### `sm3_digest(data; hex_input=false) -> Vector{UInt8}`

计算 SM3 哈希，返回原始 32 字节数组。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `data` | `AbstractString` 或 `Vector{UInt8}` | 输入数据 |
| `hex_input` | `Bool` | 为 `true` 时，将 `data` 解释为十六进制字符串 |

**返回:** 长度为 32 的 `Vector{UInt8}`。

```julia
sm3_digest("abc")  # => 32-byte Vector{UInt8}
```

---

#### `sm3_hexdigest(data; hex_input=false) -> String`

`sm3_hash` 的别名。返回 64 字符十六进制字符串。

---

#### `hash_msg(msg) -> String`

一次性哈希，不支持十六进制输入选项。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `msg` | 任意 | 待哈希的消息 |

**返回:** 64 字符十六进制字符串。

---

#### `digest(data; hex_input=false) -> Vector{UInt8}`

底层摘要函数，返回原始字节。等价于 `sm3_digest`。

### 流式哈希函数

#### `update!(ctx::SM3Context, data)`

向流式上下文中送入数据。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `ctx` | `SM3Context` | 哈希上下文 |
| `data` | `AbstractString` 或 `Vector{UInt8}` | 待送入的数据 |

> **注意:** 每次调用不复制 `data` -- 不足一完整块的数据在内部缓存。仅在累积满 64 字节块时才调用压缩函数。

---

#### `digest!(ctx::SM3Context) -> Vector{UInt8}`

完成哈希并返回原始 32 字节摘要。完成后**重置**上下文。

---

#### `hexdigest!(ctx::SM3Context) -> String`

完成哈希并返回 64 字符十六进制字符串。完成后**重置**上下文。

### 密钥派生函数

#### `sm3_kdf(z::AbstractString, klen::Integer) -> String`

基于 SM3 的 KDF。返回 `klen` 字节的十六进制字符串。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `z` | `AbstractString` | 共享秘密（十六进制字符串） |
| `klen` | `Integer` | 期望的输出字节长度 |

---

#### `sm3_kdf_bytes(z::AbstractString, klen::Integer) -> Vector{UInt8}`

同 `sm3_kdf`，但返回原始字节。

---

#### `sm3_kdf_from_bytes(z_bytes::Vector{UInt8}, klen::Integer) -> Vector{UInt8}`

从原始字节输入进行 KDF。由 SM2/SM9 内部使用。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `z_bytes` | `Vector{UInt8}` | 共享秘密（字节） |
| `klen` | `Integer` | 期望的输出字节长度 |

### 核心原语

以下原语作为构建块导出：

| 函数 | 签名 | 描述 |
|----------|-----------|-------------|
| `rotate_left` | `(a::UInt32, k::Integer) -> UInt32` | 循环左移 k 位 |
| `P_0` | `(X::UInt32) -> UInt32` | 置换 P0 |
| `P_1` | `(X::UInt32) -> UInt32` | 置换 P1 |
| `FF_j` | `(X, Y, Z, j) -> UInt32` | 布尔函数 FF（j<16: XOR, j>=16: majority） |
| `GG_j` | `(X, Y, Z, j) -> UInt32` | 布尔函数 GG（j<16: XOR, j>=16: choice） |
| `CF` | `(V_i, B_i) -> Vector{UInt32}` | 压缩函数（分配新 V） |
| `CF!` | `(V, block, off, W)` | 就地压缩函数（零分配，带可复用 W） |
| `PUT_UINT32_BE` | `(n::UInt32) -> Vector{UInt8}` | UInt32 转为 4 字节大端序 |

### 工具函数

#### `byte2hex(data::Vector{UInt8}) -> String`

字节转小写十六进制字符串。

---

## 模块: SM4 -- 分组密码算法

**标准:** GM/T 0002-2012

### 常量

| 名称 | 类型 | 值 |
|------|------|-------|
| `ENCRYPT` | `Int` | `0` |
| `DECRYPT` | `Int` | `1` |
| `SM4_MODE_ECB` | `Int` | `0` |
| `SM4_MODE_CBC` | `Int` | `1` |
| `SM4_MODE_CFB` | `Int` | `2` |
| `SM4_MODE_OFB` | `Int` | `3` |
| `SM4_MODE_CTR` | `Int` | `4` |
| `SM4_T0` | `Vector{UInt32}` (256) | 预计算 T-table（字节 0） |
| `SM4_T1` | `Vector{UInt32}` (256) | 预计算 T-table（字节 1） |
| `SM4_T2` | `Vector{UInt32}` (256) | 预计算 T-table（字节 2） |
| `SM4_T3` | `Vector{UInt32}` (256) | 预计算 T-table（字节 3） |

### 类型

#### `Sm4`

ECB/CBC 分组密码上下文，保存 32 个扩展轮密钥。

```julia
mutable struct Sm4
    sk::Vector{UInt32}    # 32 个轮密钥
    mode::Int             # ENCRYPT 或 DECRYPT
end
```

构造函数: `Sm4()`

---

#### `Sm4Stream`（推荐）

统一 SM4 流式加解密上下文。单一类型同时支持五种模式（ECB、CBC、CFB、OFB、CTR），通过构造时的 `mode` 参数选择算法。

```julia
mutable struct Sm4Stream
    sk::Vector{UInt32}      # 32 个扩展轮密钥
    mode::Int               # SM4_MODE_ECB .. SM4_MODE_CTR
    dir::Int                # ENCRYPT 或 DECRYPT
    # ... 内部状态随模式变化
end
```

构造函数: `Sm4Stream(key::Vector{UInt8}, iv::Vector{UInt8}, mode::Int, dir::Int=ENCRYPT)`

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `key` | `Vector{UInt8}` | 16 字节密钥 |
| `iv` | `Vector{UInt8}` | 16 字节初始向量（ECB 模式不使用） |
| `mode` | `Int` | `SM4_MODE_ECB/CBC/CFB/OFB/CTR` |
| `dir` | `Int` | `ENCRYPT(0)` 或 `DECRYPT(1)`（OFB/CTR 模式忽略） |

**模式总览:**

| 模式 | 填充 | dir 影响 | 输出粒度 | `final!` |
|------|------|----------|----------|----------|
| `SM4_MODE_ECB` | 无 | 是 | 16 字节块 | 部分数据报错 |
| `SM4_MODE_CBC` | PKCS7 | 是 | 字节级 | 填充/去填充 PKCS7 |
| `SM4_MODE_CFB` | 无 | 输入来源 | 16 字节块 | 无操作（返回 0） |
| `SM4_MODE_OFB` | 无 | 否 | 字节级 | 无操作（返回 0） |
| `SM4_MODE_CTR` | 无 | 否 | 字节级 | 无操作（返回 0） |

```julia
# CTR 模式（加解密相同）
ctx = Sm4Stream(key, iv, SM4_MODE_CTR)
sm4_stream_update!(ctx, input, output)

# CBC 加密（带 PKCS7 填充）
ctx = Sm4Stream(key, iv, SM4_MODE_CBC, ENCRYPT)
n = sm4_stream_update!(ctx, plaintext, output)
rem = sm4_stream_final!(ctx, output, n + 1)

# OFB 模式（流密码，加解密相同）
ctx = Sm4Stream(key, iv, SM4_MODE_OFB)
sm4_stream_update!(ctx, input, output)
```

> **注意:** `Sm4Stream` 是推荐的流式 API。OFB/CTR 模式下加解密为同一操作 -- 均与密钥流异或。CBC 模式下加密用 `ENCRYPT`，解密用 `DECRYPT`。

---

#### `Sm4Ctr`（旧版）

CTR 模式的旧版构造函数别名。**已过时** -- 推荐使用 `Sm4Stream(key, iv, SM4_MODE_CTR)`。

构造函数: `Sm4Ctr(key::Vector{UInt8}, iv::Vector{UInt8})`

等价于 `Sm4Stream(key, iv, SM4_MODE_CTR)`。

---

#### `Sm4Cbc`（旧版）

CBC 模式的旧版构造函数别名。**已过时** -- 推荐使用 `Sm4Stream(key, iv, SM4_MODE_CBC, mode)`。

构造函数: `Sm4Cbc(key::Vector{UInt8}, iv::Vector{UInt8}, mode::Int)`

等价于 `Sm4Stream(key, iv, SM4_MODE_CBC, mode)`。

### 密钥设置

#### `sm4_setkey!(sm4::Sm4, key::Vector{UInt8}, mode::Int)`

设置密钥并扩展轮密钥。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `sm4` | `Sm4` | 密码上下文 |
| `key` | `Vector{UInt8}` | 16 字节密钥 |
| `mode` | `Int` | `ENCRYPT(0)` 或 `DECRYPT(1)` |

### 一次性 ECB

#### `sm4_crypt_ecb(mode::Int, key::Vector{UInt8}, data::Vector{UInt8}) -> Vector{UInt8}`

SM4-ECB 加解密。内部创建临时 `Sm4` 上下文。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `mode` | `Int` | `ENCRYPT(0)` 或 `DECRYPT(1)` |
| `key` | `Vector{UInt8}` | 16 字节密钥 |
| `data` | `Vector{UInt8}` | 输入（必须为 16 字节的倍数） |

**返回:** 等长 `Vector{UInt8}` 加解密结果。

> **注意:** 无填充；输入必须为 16 字节的倍数。

---

#### `sm4_crypt_ecb!(sm4::Sm4, input_data::Vector{UInt8}) -> Vector{UInt8}`

使用预配置上下文的 ECB（重复调用无需重复设置密钥）。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `sm4` | `Sm4` | 预配置的密码上下文 |
| `input_data` | `Vector{UInt8}` | 输入（16 字节的倍数） |

### 一次性 CBC

#### `sm4_crypt_cbc(mode::Int, key::Vector{UInt8}, iv::Vector{UInt8}, data::Vector{UInt8}) -> Vector{UInt8}`

SM4-CBC 加解密。创建临时上下文。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `mode` | `Int` | `ENCRYPT(0)` 或 `DECRYPT(1)` |
| `key` | `Vector{UInt8}` | 16 字节密钥 |
| `iv` | `Vector{UInt8}` | 16 字节初始化向量 |
| `data` | `Vector{UInt8}` | 输入（16 字节的倍数） |

---

#### `sm4_crypt_cbc!(sm4::Sm4, iv::Vector{UInt8}, input_data::Vector{UInt8}) -> Vector{UInt8}`

使用预配置上下文的 CBC。

### 统一流式 API（推荐）

`Sm4Stream` 类型通过两个函数提供与模式无关的接口：

---

#### `sm4_stream_update!(ctx::Sm4Stream, input, output) -> Int`

向流中送入 `input` 数据。返回写入 `output` 的字节数。内部按 `ctx.mode` 分发。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `ctx` | `Sm4Stream` | 流式上下文 |
| `input` | `AbstractVector{UInt8}` | 明文或密文 |
| `output` | `AbstractVector{UInt8}` | 输出缓冲区（流式模式需 >= 输入长度，块模式需 >= floor(len/16)*16） |

**返回:** 写入 `output` 的字节数。

**各模式行为:**
- **ECB**: 处理完整 16 字节块，不足部分缓存。
- **CBC 加密**: 处理完整块，不足部分缓存。
- **CBC 解密**: 累积密文，输出除最后一块外的所有完整块。
- **CFB**: 按 16 字节块处理，不足部分缓存。
- **OFB**: 流密码，立即处理所有字节（无缓冲）。
- **CTR**: 流密码，立即处理所有字节（无缓冲）。

---

#### `sm4_stream_final!(ctx::Sm4Stream, output, offset=1) -> Int`

完成流式处理。返回从 `offset` 位置开始额外写入 `output` 的字节数。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `ctx` | `Sm4Stream` | 流式上下文 |
| `output` | `AbstractVector{UInt8}` | 输出缓冲区 |
| `offset` | `Int` | 写入起始位置（1 为起始，默认 1） |

**返回:** 额外写入的字节数。

**各模式行为:**
- **ECB**: 若存在不完整的块则报错（要求块对齐输入）。
- **CBC 加密**: 应用 PKCS7 填充，加密最后一块，返回 16。
- **CBC 解密**: 解密最后一块，去除 PKCS7 填充，返回明文长度。
- **CFB/OFB/CTR**: 无操作，始终返回 0。

> **注意:** `final!` 之后不应再复用该上下文。

```julia
# 示例: CBC 流式加密
ctx = Sm4Stream(key, iv, SM4_MODE_CBC, ENCRYPT)
out = zeros(UInt8, expected_size)
n = sm4_stream_update!(ctx, chunk1, out)
n += sm4_stream_update!(ctx, chunk2, view(out, n+1:end))
n += sm4_stream_final!(ctx, out, n + 1)
ciphertext = view(out, 1:n)  # 含 PKCS7 填充

# 示例: OFB 流式加密（无填充）
ctx = Sm4Stream(key, iv, SM4_MODE_OFB)
out = zeros(UInt8, length(data))
sm4_stream_update!(ctx, data, out)  # out == 密文
```

### 旧版流式函数（向后兼容）

以下旧版函数内部委托到 `Sm4Stream`。它们仍然被导出以保证向后兼容，但**新代码推荐使用 `Sm4Stream` + `sm4_stream_update!`/`sm4_stream_final!`**。

---

#### `sm4_ctr_xor!(ctx::Sm4Stream, input, output) -> Int`

旧版 CTR 模式异或。委托到 `sm4_stream_update!`。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `ctx` | `Sm4Stream` | CTR 上下文 (`SM4_MODE_CTR`) |
| `input` | `AbstractVector{UInt8}` | 明文或密文 |
| `output` | `AbstractVector{UInt8}` | 输出缓冲区 |

**返回:** 处理的字节数（= `length(input)`）。

> **注意:** CTR 模式内部仅使用加密方向。加解密为相同操作。

---

#### `sm4_cbc_encrypt_update!(ctx::Sm4Stream, input, output) -> Int`

旧版 CBC 加密更新。委托到 `sm4_stream_update!`。

---

#### `sm4_cbc_encrypt_final!(ctx::Sm4Stream, output, offset=1) -> Int`

旧版 CBC 加密完成。委托到 `sm4_stream_final!`。返回 16 字节（一个带填充的块）。

---

#### `sm4_cbc_decrypt_update!(ctx::Sm4Stream, input, output) -> Int`

旧版 CBC 解密更新。委托到 `sm4_stream_update!`。

> **注意:** 输出需留出 `max(0, floor((buf_len + len(input))/16) - 1) * 16` 字节空间。至少累积 2 个完整块后才有输出。

---

#### `sm4_cbc_decrypt_final!(ctx::Sm4Stream, output, offset=1) -> Int`

旧版 CBC 解密完成。委托到 `sm4_stream_final!`。返回明文字节数（<= 16）。

> **错误:** 若剩余数据不为 16 字节或填充无效时抛出异常。

---

## 模块: ZUC -- 流密码算法

**标准:** GM/T 0001-2012

### 类型

#### `ZUCContext`

流密码上下文，使用环形缓冲区 LFSR 实现 O(1) 移位操作。

```julia
mutable struct ZUCContext
    lfsr_buf::Vector{UInt32}   # 16 元素环形缓冲区
    lfsr_head::Int             # LFSR[1] 的索引（从 1 起）
    r::Vector{UInt32}          # R1, R2
    x::Vector{UInt32}          # X0, X1, X2, X3
end
```

构造函数: `ZUCContext(key::Vector{UInt8}, iv::Vector{UInt8})`

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `key` | `Vector{UInt8}` | 16 字节密钥 |
| `iv` | `Vector{UInt8}` | 16 字节初始向量 |

### 函数

#### `zuc_encrypt(ctx::ZUCContext, input::Vector{UInt8}) -> Vector{UInt8}`

加密或解密数据。由于 ZUC 是同步流密码，加解密操作相同。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `ctx` | `ZUCContext` | 已初始化的上下文 |
| `input` | `Vector{UInt8}` | 明文或密文 |

**返回:** 等长 `Vector{UInt8}`。

```julia
ctx = ZUCContext(key, iv)
ct = zuc_encrypt(ctx, plaintext)

# 重置以解密
ctx2 = ZUCContext(key, iv)
pt = zuc_encrypt(ctx2, ct)  # pt == plaintext
```

> **注意:** 每个 `ZUCContext` 从其初始化时刻开始消耗密钥流。解密时需创建一个**新的**上下文并使用相同的 key/IV。上下文**不可**在加密后复用；ZUC 上下文为一次性使用。

---

#### `zuc_generate_keystream(ctx::ZUCContext, length::Integer) -> Vector{UInt32}`

生成指定数量 32 位字的 ZUC 密钥流。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `ctx` | `ZUCContext` | 已初始化的上下文 |
| `length` | `Integer` | 要生成的 32 位字数 |

**返回:** 包含 `length` 个密钥流字的 `Vector{UInt32}`。

> **注意:** 内部函数。正常加解密请使用 `zuc_encrypt`。

---

## 模块: SM2 -- 椭圆曲线公钥密码算法

**标准:** GM/T 0003-2012

### 常量

| 名称 | 类型 | 描述 |
|------|------|-------------|
| `sm2_N` | `BigInt` | 曲线阶 |
| `sm2_P` | `BigInt` | 域素数 |
| `sm2_G` | `SM2Point` | 生成元 |

### 类型

#### `SM2KeyPair`

```julia
struct SM2KeyPair
    publicKey::Vector{UInt8}   # 64 字节 (x || y)
    privateKey::String         # 64 字符十六进制字符串
end
```

> **注意:** `privateKey` 为十六进制编码，可直接用于 `sm2_sign`/`sm2_decrypt`。`publicKey` 为 64 原始字节。

### 密钥生成

#### `sm2_generate_keypair() -> SM2KeyPair`

使用 CSPRNG (`Random.RandomDevice`) 生成 SM2 密钥对。

**返回:** 通过 CSPRNG 生成私钥及对应公钥的 `SM2KeyPair`。

```julia
kp = sm2_generate_keypair()
# kp.privateKey  -> "a3f2..."  (64 字符十六进制)
# kp.publicKey   -> 64 字节 Vector{UInt8}
```

> **安全性:** 私钥 `d` 在 [1, N-1] 范围内使用拒绝采样方式从 `RandomDevice` 生成。

---

### ZA 计算

#### `sm2_compute_za(id::AbstractString, pubkey::Vector{UInt8}) -> Vector{UInt8}`

计算 ZA = SM3(ENTL || ID || a || b || xG || yG || xA || yA)，依据 GM/T 0003.2-2012 第 5.5 节。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `id` | `AbstractString` | 用户的可辨别标识 |
| `pubkey` | `Vector{UInt8}` | 64 字节公钥 (x || y) |

**返回:** 32 字节 ZA 摘要。

> **注意:** 签名函数 (`sm2_sign`, `sm2_verify`) 在给定 `(id, pubkey)` 时会自动计算 ZA。仅当需要实现自定义签名流程时才需直接调用此函数。

---

### 数字签名

#### `sm2_sign(message, DA, id, pubkey; Hexstr=false) -> Vector{UInt8}`

带 ZA 的 SM2 签名 (GM/T 0003.2-2012)。标准格式。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `message` | `String` 或 `Vector{UInt8}` | 待签名消息 |
| `DA` | `AbstractString` | 64 字符十六进制私钥 |
| `id` | `AbstractString` | 用户标识 |
| `pubkey` | `Vector{UInt8}` 或 `AbstractString` | 公钥（64 字节或 128 字符十六进制） |
| `Hexstr` | `Bool` | 为 `true` 时，消息已是十六进制 |

**返回:** `Vector{UInt8}`（64 字节：r || s，各 32 字节）。

```
内部流程:
  1. ZA = sm3_compute_za(id, pubkey)
  2. H = sm3_digest(ZA || message)
  3. 使用私钥 DA 签名 H
```

---

#### `sm2_sign(message, DA, K; Hexstr=false) -> Vector{UInt8}`

带显式一次性随机数 `K` 的旧版重载（用于确定性测试）。**不**使用 ZA -- 消息直接哈希。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `message` | 任意 | 待签名消息 |
| `DA` | `AbstractString` | 64 字符十六进制私钥 |
| `K` | `AbstractString` | 64 字符十六进制随机数 |

> **注意:** 生产环境请使用标准重载 `(message, DA, id, pubkey)`。

---

#### `sm2_verify(Sign, message, id, pubkey_bytes; Hexstr=false) -> Bool`

带 ZA 的 SM2 签名验证。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `Sign` | `Vector{UInt8}` | 64 字节签名 (r || s) |
| `message` | `String` 或 `Vector{UInt8}` | 原始消息 |
| `id` | `AbstractString` | 签名者标识 |
| `pubkey_bytes` | `Vector{UInt8}` | 签名者 64 字节公钥 |
| `Hexstr` | `Bool` | 为 `true` 时，按十六进制处理消息 |

**返回:** 签名有效返回 `true`，否则返回 `false`。

---

#### `sm2_verify(Sign, E, PA; Hexstr=false) -> Bool`

旧版验证（不含 ZA），直接验证原始哈希/点。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `Sign` | `Vector{UInt8}` | 64 字节签名 |
| `E` | 任意 | 消息或预计算的哈希 |
| `PA` | `AbstractString` 或 `Vector{UInt8}` | 公钥 |

---

### 加密与解密

#### `sm2_encrypt(message, PA; format=:C1C3C2, Hexstr=false) -> Vector{UInt8}`

SM2 公钥加密。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `message` | `String` 或 `Vector{UInt8}` | 明文 |
| `PA` | `AbstractString` 或 `Vector{UInt8}` | 接收者公钥 |
| `format` | `Symbol` | `:C1C3C2`（默认）或 `:C1C2C3` |
| `Hexstr` | `Bool` | 为 `true` 时，消息为十六进制 |

**返回:** 密文字节:
- `:C1C3C2` (GMT 0009-2012，兼容 GmSSL): `C1(64B) || C3(32B) || C2(变长)`
- `:C1C2C3` (旧版): `C1(64B) || C2(变长) || C3(32B)`

> **注意:** `:C1C3C2` 为推荐和默认格式，用于与 GmSSL 互操作。

---

#### `sm2_decrypt(C, DA; format=:C1C3C2) -> Union{Vector{UInt8}, Nothing}`

SM2 解密。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `C` | `Vector{UInt8}` | 密文 |
| `DA` | `AbstractString` | 64 字符十六进制私钥 |
| `format` | `Symbol` | `:C1C3C2`（默认）或 `:C1C2C3` |

**返回:** C3 MAC 校验通过返回明文字节，否则返回 `nothing`。

> **安全性:** C3 校验（基于 SM3 的 MAC）为强制性的。密文被篡改时解密失败。

---

#### `sm2_get_hash(message; Hexstr=false) -> String`

用于 SM2 操作的 SM3 哈希工具。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `message` | 任意 | 输入 |
| `Hexstr` | `Bool` | 为 `true` 时，输入为十六进制 |

---

## 模块: SM9 -- 标识密码算法

**标准:** GM/T 0044-2016

### 常量

| 名称 | 类型 | 描述 |
|------|------|-------------|
| `SM9_q` | `BigInt` | BN 曲线域素数 |
| `SM9_N` | `BigInt` | BN 曲线阶 |
| `SM9_P1` | `(BigInt, BigInt)` | G1 生成元坐标 |
| `SM9_t` | `BigInt` | BN 曲线参数 |
| `SM9_a` | `BigInt` | 曲线 a 系数 (= 0) |
| `SM9_b` | `BigInt` | 曲线 b 系数 (= 5) |
| `sm9_g1_generator` | `SM9G1Point` | G1 生成元点 |

> **注意:** 所有 SM9 参数通过模块加载时的 `__init__()` 初始化。G2 生成元在初始化时计算。

### 类型

#### `SM9EncryptMasterKey`

```julia
struct SM9EncryptMasterKey
    ke::BigInt               # 主私钥
    P_pub_e::SM9G1Point      # [ke]P1（在 G1 中）
end
```

---

#### `SM9EncryptPrivateKey`

```julia
struct SM9EncryptPrivateKey
    de_B::G2Point            # 用户解密密钥（在 G2 中）
    hid::UInt8               # 密钥用途标识
end
```

---

#### `SM9SignMasterKey`

```julia
struct SM9SignMasterKey
    ks::BigInt               # 主私钥
    P_pub_s::G2Point         # [ks]P2（在 G2 中）
end
```

---

#### `SM9SignPrivateKey`

```julia
struct SM9SignPrivateKey
    ds_A::SM9G1Point         # 用户签名密钥（在 G1 中）
    hid::UInt8               # 密钥用途标识
end
```

---

#### `SM9EncryptCiphertext`

```julia
struct SM9EncryptCiphertext
    C1::Vector{UInt8}        # 64 字节（G1 点）
    C3::Vector{UInt8}        # 32 字节（MAC）
    C2::Vector{UInt8}        # 变长（加密消息）
end
```

### 主密钥生成

#### `sm9_master_key() -> SM9EncryptMasterKey`

生成 SM9 加密主密钥对。

**返回:** 包含 CSPRNG 生成的 `ke` 和对应 `P_pub_e = [ke]P1` 的 `SM9EncryptMasterKey`。

---

#### `sm9_sign_master_key() -> SM9SignMasterKey`

生成 SM9 签名主密钥对。

**返回:** 包含 CSPRNG 生成的 `ks` 和对应 `P_pub_s = [ks]P2` 的 `SM9SignMasterKey`。

### 用户密钥提取

#### `sm9_encrypt_private_key(master::SM9EncryptMasterKey, id; hid=0x03) -> SM9EncryptPrivateKey`

提取用户加密私钥: `de_B = [ke / (H1(ID||hid) + ke)] * P2`。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `master` | `SM9EncryptMasterKey` | 加密主密钥 |
| `id` | `AbstractString` | 用户标识 |
| `hid` | `UInt8` | 密钥用途标识（默认 `0x03` 用于加密） |

**返回:** `SM9EncryptPrivateKey`（G2 点）。

> **错误:** 若 `t1 == 0` 时抛出异常（需重新生成主密钥）。

---

#### `sm9_sign_private_key(master::SM9SignMasterKey, id; hid=0x01) -> SM9SignPrivateKey`

提取用户签名私钥: `ds_A = [ks / (H1(ID||hid) + ks)] * P1`。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `master` | `SM9SignMasterKey` | 签名主密钥 |
| `id` | `AbstractString` | 用户标识 |
| `hid` | `UInt8` | 密钥用途标识（默认 `0x01` 用于签名） |

**返回:** `SM9SignPrivateKey`（G1 点，即 `SM9G1Point`）。

### 加密与解密

#### `sm9_encrypt(master_public, id, message; hid=0x03) -> Vector{UInt8}`

SM9 KEM-DEM 加密 (GM/T 0044.4-2016)。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `master_public` | `SM9EncryptMasterKey` | 系统主公钥 |
| `id` | `AbstractString` | 接收者标识 |
| `message` | `String` 或 `Vector{UInt8}` | 明文 |
| `hid` | `UInt8` | 密钥用途标识 |

**返回:** C1C3C2 格式密文: `C1(64B) || C3(32B) || C2(变长)`。

```
内部流程:
  1. Q_B = [H1(ID)]*P1 + Ppub-e
  2. r = random, C1 = [r]*Q_B
  3. g = e(Ppub-e, P2), w = g^r
  4. K = KDF(C1 || w || ID, mlen*8 + 256)
  5. C2 = M xor K1, C3 = SM3(C2 || K2)
```

---

#### `sm9_decrypt(de_B, id, ciphertext) -> Union{Vector{UInt8}, Nothing}`

SM9 KEM-DEM 解密。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `de_B` | `SM9EncryptPrivateKey` | 用户解密密钥 |
| `id` | `AbstractString` | 用户标识 |
| `ciphertext` | `Vector{UInt8}` | 密文（C1C3C2 格式） |

**返回:** MAC 校验通过返回明文字节，否则返回 `nothing`。

> **安全性:** C3 校验保证密文完整性。失败（篡改或格式错误输入）返回 `nothing`。

### 数字签名

#### `sm9_sign(master_public, Da, message) -> (BigInt, SM9G1Point)`

SM9 数字签名 (GM/T 0044.2-2016)。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `master_public` | `SM9SignMasterKey` | 系统主公钥 |
| `Da` | `SM9SignPrivateKey` | 签名者私钥 |
| `message` | `String` 或 `Vector{UInt8}` | 待签名消息 |

**返回:** `(h, S)` 元组 -- `h` 为 `BigInt`，`S` 为 `SM9G1Point`。

```
内部流程:
  1. g = e(P1, Ppub-s)
  2. r = random, w = g^r
  3. h = H2(M || w)
  4. l = (r - h) mod N
  5. S = [l] * ds_A
```

---

#### `sm9_verify(master_public, id, message, signature) -> Bool`

SM9 签名验证。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `master_public` | `SM9SignMasterKey` | 系统主公钥 |
| `id` | `AbstractString` | 签名者标识 |
| `message` | `String` 或 `Vector{UInt8}` | 原始消息 |
| `signature` | `Tuple{BigInt, SM9G1Point}` | 来自 `sm9_sign` 的 `(h, S)` |

**返回:** 有效返回 `true`，否则返回 `false`。

> **注意:** 若 `h < 1` 或 `h >= N`（域检查失败）返回 `false`。

### G1 运算

#### `sm9_g1_hash(id; hid=0x03) -> SM9G1Point`

将标识符哈希到 G1 点: 计算 `[H1(ID||hid)] * P1`。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `id` | `AbstractString` | 标识符字符串 |
| `hid` | `UInt8` | 密钥用途标识 |

---

### 参数验证

#### `sm9_verify_params() -> Bool`

验证 SM9 BN 曲线参数是否正确。

检查项:
- `a == 0`, `b == 5`
- P1 在曲线上: `y^2 == x^3 + b`
- q 和 N 符合 BN 公式

**返回:** 所有检查通过返回 `true`。

### 工具函数

#### `generate_prime(length::Int; n=100) -> BigInt`

使用 Miller-Rabin 生成指定十六进制长度的随机素数。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `length` | `Int` | 十六进制位数 |
| `n` | `Int` | Miller-Rabin 迭代次数（默认: 100） |

---

#### `is_probable_prime(number::BigInt, itor=10) -> Bool`

Miller-Rabin 素性测试。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `number` | `BigInt` | 待测试的数 |
| `itor` | `Int` | 迭代次数（默认: 10） |

---

## 模块: CryptoHash -- 统一哈希接口

提供哈希算法的工厂模式接口（目前仅支持 SM3）。

### 函数

#### `new_hash(name, data=nothing) -> SM3HashCtx`

按算法名创建哈希上下文。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `name` | `AbstractString` | 哈希算法（仅支持 `"sm3"`） |
| `data` | `Vector{UInt8}`、`AbstractString` 或 `nothing` | 可选初始数据 |

**返回:** `SM3HashCtx` 流式上下文。

```julia
ctx = new_hash("sm3", "hello")
update!(ctx, " world")
hexdigest(ctx)  # => SM3 哈希十六进制字符串
```

> **注意:** 仅内置 SM3。SHA 算法请使用 Julia 标准库 `SHA`。

---

#### `digest_size_for(name::AbstractString) -> Int`

获取指定哈希算法的摘要输出字节数。

| 算法 | 大小（字节） |
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

返回支持的哈希名称集合: `Set(["sm3"])`。

#### `sm3_hashlib`

`SM3HashCtx` 的别名。

### 类型

#### `SM3HashCtx`

```julia
mutable struct SM3HashCtx
    data::Vector{UInt8}
end
```

| 方法 | 签名 | 返回 |
|--------|-----------|--------|
| 构造函数 | `SM3HashCtx()` | 空上下文 |
| 构造函数 | `SM3HashCtx(Vector{UInt8})` | 预加载数据的上下文 |
| `update!` | `(ctx, data::Vector{UInt8})` | `nothing` |
| `update!` | `(ctx, data::AbstractString)` | `nothing` |
| `digest` | `(ctx)` | `Vector{UInt8}` (32 字节) |
| `hexdigest` | `(ctx)` | `String` (64 字符) |

---

## 内部工具函数 (`util.jl`)

内嵌在 SM2、SM4、SM9 和 ZUC 模块中的共享函数。**非导出** -- 通过公共模块 API 使用。

| 函数 | 签名 | 描述 |
|----------|-----------|-------------|
| `_hex2bytes` | `(s::AbstractString) -> Vector{UInt8}` | 十六进制字符串转字节 |
| `_bytes2hex` | `(data::Vector{UInt8}) -> String` | 字节转十六进制字符串 |
| `_bigint_to_hex` | `(x::BigInt, len::Int) -> String` | BigInt 转定长十六进制 |
| `_rand_bytes` | `(n::Int) -> Vector{UInt8}` | CSPRNG 随机字节 |
| `_rand_bigint` | `(n_bytes::Int) -> BigInt` | 随机 BigInt |
| `_bytes_to_bigint` | `(b::Vector{UInt8}) -> BigInt` | 大端序字节转 BigInt（无 hex 中转） |
| `_put_u32_be!` | `(buf, off, n::UInt32)` | 写入 UInt32 大端序 |
| `_get_u32_be` | `(data, off=1) -> UInt32` | 读取 UInt32 大端序 |
