# =============================================================================
# SM4 Streaming API - Unified Sm4Stream Object
#
# Design: A single Sm4Stream type handles all streaming modes.
# The mode parameter selects the algorithm at construction time.
# Unified update! / final! interface dispatches internally.
#
# Supported modes:
#   SM4_MODE_ECB - Electronic Codebook (PKCS7 padding by default; use SM4_PADDING_NONE for raw)
#   SM4_MODE_CBC - Cipher Block Chaining (PKCS7 padding)
#   SM4_MODE_CFB - Cipher Feedback (stream, no padding)
#   SM4_MODE_OFB - Output Feedback (stream, no padding)
#   SM4_MODE_CTR - Counter mode (stream, no padding)
#
# Usage:
#   # ECB encrypt (PKCS7 padding by default, handles arbitrary input length)
#   ctx = Sm4Stream(key, iv, SM4_MODE_ECB, ENCRYPT)
#   n = sm4_stream_update!(ctx, input, output)
#   rem = sm4_stream_final!(ctx, output, n + 1)
#   total_out = view(output, 1:n + rem)
#
#   # CBC encrypt
#   ctx = Sm4Stream(key, iv, SM4_MODE_CBC, ENCRYPT)
#   n = sm4_stream_update!(ctx, input, output)
#   rem = sm4_stream_final!(ctx, output, n + 1)
#   total_out = view(output, 1:n + rem)
#
#   # CFB mode (stream cipher, encrypt and decrypt are identical ops)
#   ctx = Sm4Stream(key, iv, SM4_MODE_CFB, ENCRYPT)
#   sm4_stream_update!(ctx, input, output)
#
#   # OFB mode (stream cipher, encrypt and decrypt are identical)
#   ctx = Sm4Stream(key, iv, SM4_MODE_OFB)
#   sm4_stream_update!(ctx, input, output)
#
#   # CTR mode (encrypt and decrypt are identical)
#   ctx = Sm4Stream(key, iv, SM4_MODE_CTR)
#   sm4_stream_update!(ctx, input, output)
# =============================================================================

# -----------------------------------------------------------------------------
# Mode Constants
# -----------------------------------------------------------------------------

const SM4_MODE_ECB = 0
const SM4_MODE_CBC = 1
const SM4_MODE_CFB = 2
const SM4_MODE_OFB = 3
const SM4_MODE_CTR = 4

# -----------------------------------------------------------------------------
# Padding Constants
# -----------------------------------------------------------------------------

const SM4_PADDING_NONE  = 0
const SM4_PADDING_PKCS7 = 1

# -----------------------------------------------------------------------------
# Standalone Block Encrypt Helpers
# -----------------------------------------------------------------------------

@inline function _sm4_encrypt_block!(sk::Vector{UInt32}, input::AbstractVector{UInt8},
                                      in_off::Int, output::AbstractVector{UInt8},
                                      out_off::Int)
    x1 = _get_u32_be(input, in_off)
    x2 = _get_u32_be(input, in_off + 4)
    x3 = _get_u32_be(input, in_off + 8)
    x4 = _get_u32_be(input, in_off + 12)

    y1, y2, y3, y4 = _sm4_round_u32(sk, x1, x2, x3, x4)

    _put_u32_be!(output, out_off,      y4)
    _put_u32_be!(output, out_off + 4,  y3)
    _put_u32_be!(output, out_off + 8,  y2)
    _put_u32_be!(output, out_off + 12, y1)
end

"""
    _sm4_encrypt_block_u32!(sk, input, in_off, output, out_off)

Same as `_sm4_encrypt_block!` but operates on `Vector{UInt32}` directly.
Offsets are word indices (1-based), reading/writing 4 consecutive UInt32 words.
"""
@inline function _sm4_encrypt_block_u32!(sk::Vector{UInt32},
                                         input::AbstractVector{UInt32}, in_off::Int,
                                         output::AbstractVector{UInt32}, out_off::Int)
    @inbounds begin
        x1 = input[in_off]
        x2 = input[in_off + 1]
        x3 = input[in_off + 2]
        x4 = input[in_off + 3]
    end

    y1, y2, y3, y4 = _sm4_round_u32(sk, x1, x2, x3, x4)

    @inbounds begin
        output[out_off]     = y4
        output[out_off + 1] = y3
        output[out_off + 2] = y2
        output[out_off + 3] = y1
    end
end

# -----------------------------------------------------------------------------
# UInt8 <-> UInt32 conversion helpers (reusable)
#
# Performance: Uses unsafe_load/unsafe_store! on Ptr{UInt32} to read/write
# 4 bytes per instruction, then ntoh/hton for big-endian conversion.
# ntoh/hton resolve to bswap on little-endian (all modern CPUs), identity on BE.
# This replaces 7 shift/or instructions per word with 1 bswap + 1 load/store.
#
# Pointer-based approach chosen over reinterpret() because reinterpret requires
# the entire array length to be divisible by 4, which fails on SubArray views
# (e.g. view(buf, offset:end) where (end-offset+1) % 4 != 0).
# unsafe_load/store only touches the 16 bytes we need, no length constraint.
# -----------------------------------------------------------------------------

"""
Read 4 consecutive big-endian UInt32 words (16 bytes) from `src[byte_off]`
into `dst[1:4]`.  Caller guarantees bounds.
"""
@inline function _load_u32x4_be!(dst::Vector{UInt32},
                                  src::AbstractVector{UInt8},
                                  byte_off::Int)
    GC.@preserve src begin
        p = convert(Ptr{UInt32}, pointer(src, byte_off))
        dst[1] = ntoh(unsafe_load(p))
        dst[2] = ntoh(unsafe_load(p, 2))
        dst[3] = ntoh(unsafe_load(p, 3))
        dst[4] = ntoh(unsafe_load(p, 4))
    end
end

"""
Write 4 UInt32 words from `src` as 16 big-endian bytes into `dst[byte_off]`.
"""
@inline function _store_u32x4_be!(dst::AbstractVector{UInt8},
                                   byte_off::Int,
                                   src::Vector{UInt32})
    GC.@preserve dst begin
        p = convert(Ptr{UInt32}, pointer(dst, byte_off))
        unsafe_store!(p, hton(src[1]))
        unsafe_store!(p, hton(src[2]), 2)
        unsafe_store!(p, hton(src[3]), 3)
        unsafe_store!(p, hton(src[4]), 4)
    end
end

@inline function _sm4_set_encrypt_key!(sk::Vector{UInt32}, key::Vector{UInt8})
    MK1 = _get_u32_be(key, 1)
    MK2 = _get_u32_be(key, 5)
    MK3 = _get_u32_be(key, 9)
    MK4 = _get_u32_be(key, 13)

    k = Vector{UInt32}(undef, 36)
    @inbounds begin
        k[1] = MK1 ⊻ FK[1]
        k[2] = MK2 ⊻ FK[2]
        k[3] = MK3 ⊻ FK[3]
        k[4] = MK4 ⊻ FK[4]
    end

    item = k[2] ⊻ k[3]
    @inbounds for i in 0:31
        item = item ⊻ k[i + 4]
        k[i + 5] = k[i + 1] ⊻ _sm4_calci_rk(item ⊻ CK[i + 1])
        item = item ⊻ k[i + 2]
    end

    @inbounds for i in 1:32
        sk[i] = k[i + 4]
    end
    return nothing
end

"""
    _sm4_set_encrypt_key_u32!(sk::Vector{UInt32}, key::AbstractVector{UInt32})

Same as `_sm4_set_encrypt_key!` but takes a 4-word UInt32 key directly,
skipping big-endian byte conversion.
"""
@inline function _sm4_set_encrypt_key_u32!(sk::Vector{UInt32},
                                           key::AbstractVector{UInt32})
    k = Vector{UInt32}(undef, 36)
    @inbounds begin
        k[1] = key[1] ⊻ FK[1]
        k[2] = key[2] ⊻ FK[2]
        k[3] = key[3] ⊻ FK[3]
        k[4] = key[4] ⊻ FK[4]
    end

    item = k[2] ⊻ k[3]
    @inbounds for i in 0:31
        item = item ⊻ k[i + 4]
        k[i + 5] = k[i + 1] ⊻ _sm4_calci_rk(item ⊻ CK[i + 1])
        item = item ⊻ k[i + 2]
    end

    @inbounds for i in 1:32
        sk[i] = k[i + 4]
    end
    return nothing
end

# =============================================================================
# Sm4Stream - Unified Streaming Cipher Context
# =============================================================================

"""
    Sm4Stream

Unified SM4 streaming cipher context.  A single type handles ECB, CBC, CFB,
OFB, and CTR modes; the mode is selected at construction time.

# Construction

    Sm4Stream(key::Vector{UInt8}, iv::Vector{UInt8}, mode::Int, dir::Int=ENCRYPT,
              padding::Int=SM4_PADDING_PKCS7)

- `mode`: `SM4_MODE_ECB`, `SM4_MODE_CBC`, `SM4_MODE_CFB`, `SM4_MODE_OFB`, `SM4_MODE_CTR`
- `dir`: `ENCRYPT` or `DECRYPT` (ignored for OFB/CTR)
- `padding`: `SM4_PADDING_PKCS7` (default) or `SM4_PADDING_NONE`
  (effective for ECB mode; CBC always uses PKCS7; CFB/OFB/CTR ignore this field)

# Unified Interface

    sm4_stream_update!(ctx::Sm4Stream, input, output) -> Int
    sm4_stream_final!(ctx::Sm4Stream, output, offset=1) -> Int

# Mode Summary

| Mode | Padding      | dir affects | Output Granularity | final!                 |
|------|--------------|-------------|--------------------|------------------------|
| ECB  | PKCS7 / None | Yes         | 16-byte blocks     | pad/strip or error     |
| CBC  | PKCS7        | Yes         | byte-level         | pad/add or strip/check |
| CFB  | None         | Input src   | 16-byte blocks     | no-op (returns 0)      |
| OFB  | None         | No          | byte-level         | no-op (returns 0)      |
| CTR  | None         | No          | byte-level         | no-op (returns 0)      |
"""
mutable struct Sm4Stream
    sk::Vector{UInt32}
    mode::Int
    dir::Int
    padding::Int

    # CTR/OFB state (feedback register / counter)
    ctr::Vector{UInt8}
    kstream::Vector{UInt8}
    kpos::Int

    # CBC/CFB state (chain / feedback register)
    chain::Vector{UInt8}
    buffer::Vector{UInt8}
    buf_len::Int

    function Sm4Stream(key::Vector{UInt8}, iv::Vector{UInt8},
                       mode::Int, dir::Int=ENCRYPT, padding::Int=SM4_PADDING_PKCS7)
        length(key) == 16 || error("Key must be 16 bytes, got $(length(key))")

        ctx = new(zeros(UInt32, 32), mode, dir, padding,
                  zeros(UInt8, 16), zeros(UInt8, 16), 17,
                  zeros(UInt8, 16), zeros(UInt8, 16), 0)

        # ECB -- no IV needed, accept any iv (ignored)
        if mode == SM4_MODE_ECB
            if dir == ENCRYPT
                _sm4_set_encrypt_key!(ctx.sk, key)
            elseif dir == DECRYPT
                _sm4_set_encrypt_key!(ctx.sk, key)
                reverse!(ctx.sk)
            else
                error("ECB: invalid direction $dir, expected ENCRYPT(0) or DECRYPT(1)")
            end

        # CBC
        elseif mode == SM4_MODE_CBC
            length(iv) == 16 || error("CBC IV must be 16 bytes, got $(length(iv))")
            if dir == ENCRYPT
                _sm4_set_encrypt_key!(ctx.sk, key)
            elseif dir == DECRYPT
                _sm4_set_encrypt_key!(ctx.sk, key)
                reverse!(ctx.sk)
            else
                error("CBC: invalid direction $dir, expected ENCRYPT(0) or DECRYPT(1)")
            end
            copyto!(ctx.chain, iv)

        # CFB -- both encrypt and decrypt use ENCRYPT key schedule
        elseif mode == SM4_MODE_CFB
            length(iv) == 16 || error("CFB IV must be 16 bytes, got $(length(iv))")
            _sm4_set_encrypt_key!(ctx.sk, key)
            copyto!(ctx.chain, iv)

        # OFB -- both encrypt and decrypt use the same keystream
        elseif mode == SM4_MODE_OFB
            length(iv) == 16 || error("OFB IV must be 16 bytes, got $(length(iv))")
            _sm4_set_encrypt_key!(ctx.sk, key)
            copyto!(ctx.ctr, iv)

        # CTR
        elseif mode == SM4_MODE_CTR
            length(iv) == 16 || error("CTR IV must be 16 bytes, got $(length(iv))")
            _sm4_set_encrypt_key!(ctx.sk, key)
            copyto!(ctx.ctr, iv)

        else
            error("Invalid mode: $mode, expected SM4_MODE_ECB..SM4_MODE_CTR (0..4)")
        end

        return ctx
    end
end

# =============================================================================
# Unified Public Interface
# =============================================================================

"""
    sm4_stream_update!(ctx::Sm4Stream, input, output) -> Int

Feed `input` into the stream.  Returns the number of bytes written to `output`.
Dispatches internally based on `ctx.mode`.

- ECB: processes full 16-byte blocks; partial bytes are buffered.
- CBC encrypt: processes full blocks; partial bytes are buffered.
- CBC decrypt: accumulates ciphertext; outputs all complete blocks except the last.
- CFB: processes in 16-byte blocks; partial bytes are buffered.
- OFB: stream cipher, processes all bytes immediately (no buffering).
- CTR: stream cipher, processes all bytes immediately (no buffering).
"""
function sm4_stream_update!(ctx::Sm4Stream,
                            input::AbstractVector{UInt8},
                            output::AbstractVector{UInt8})
    if ctx.mode == SM4_MODE_ECB
        return _sm4_ecb_update!(ctx, input, output)
    elseif ctx.mode == SM4_MODE_CBC && ctx.dir == ENCRYPT
        return _sm4_cbc_encrypt_update!(ctx, input, output)
    elseif ctx.mode == SM4_MODE_CBC && ctx.dir == DECRYPT
        return _sm4_cbc_decrypt_update!(ctx, input, output)
    elseif ctx.mode == SM4_MODE_CFB
        return _sm4_cfb_update!(ctx, input, output)
    elseif ctx.mode == SM4_MODE_OFB
        return _sm4_ofb_update!(ctx, input, output)
    elseif ctx.mode == SM4_MODE_CTR
        return _sm4_ctr_update!(ctx, input, output)
    else
        error("Sm4Stream: unknown mode=$(ctx.mode) dir=$(ctx.dir)")
    end
end

"""
    sm4_stream_final!(ctx::Sm4Stream, output, offset=1) -> Int

Finalize the stream.  Returns the number of additional bytes written to `output`
starting at `offset`.

- ECB encrypt: applies PKCS7 padding (or errors if SM4_PADDING_NONE and partial block remains).
- ECB decrypt: decrypts the last block and strips PKCS7 padding (or errors if SM4_PADDING_NONE).
- CBC encrypt: applies PKCS7 padding, encrypts the last block, returns 16.
- CBC decrypt: decrypts the last block, strips PKCS7 padding, returns plaintext length.
- CFB/OFB/CTR: no-op, always returns 0.
"""
function sm4_stream_final!(ctx::Sm4Stream,
                           output::AbstractVector{UInt8},
                           offset::Int=1)
    if ctx.mode == SM4_MODE_ECB
        return _sm4_ecb_final!(ctx, output, offset)
    elseif ctx.mode == SM4_MODE_CBC && ctx.dir == ENCRYPT
        return _sm4_cbc_encrypt_final!(ctx, output, offset)
    elseif ctx.mode == SM4_MODE_CBC && ctx.dir == DECRYPT
        return _sm4_cbc_decrypt_final!(ctx, output, offset)
    elseif ctx.mode in (SM4_MODE_CFB, SM4_MODE_OFB, SM4_MODE_CTR)
        return 0
    else
        error("Sm4Stream: unknown mode=$(ctx.mode) dir=$(ctx.dir)")
    end
end

# =============================================================================
# ECB Mode
# =============================================================================

"""
ECB update: process complete 16-byte blocks, buffer partial bytes.
No chaining -- each block is encrypted/decrypted independently.

When `padding == SM4_PADDING_PKCS7` and `dir == DECRYPT`, keeps the last
block buffered for padding stripping in `final!`.
"""
function _sm4_ecb_update!(ctx::Sm4Stream, input::AbstractVector{UInt8},
                           output::AbstractVector{UInt8})
    # PKCS7 decrypt: hold back last block for padding stripping
    if ctx.padding == SM4_PADDING_PKCS7 && ctx.dir == DECRYPT
        return _sm4_ecb_decrypt_update!(ctx, input, output)
    end

    n_in = length(input)
    total_len = ctx.buf_len + n_in

    # Build combined UInt8 buffer (cache + new input)
    combined = Vector{UInt8}(undef, total_len)
    if ctx.buf_len > 0
        @inbounds copyto!(combined, 1, ctx.buffer, 1, ctx.buf_len)
    end
    @inbounds copyto!(combined, ctx.buf_len + 1, input, 1, n_in)

    # Calculate full 16-byte blocks; process per-block with UInt32 conversion
    n_blocks = total_len >> 4
    blk_u32 = Vector{UInt32}(undef, 4)
    out_u32 = Vector{UInt32}(undef, 4)

    @inbounds for b in 0:n_blocks-1
        byte_off = (b << 4) + 1
        _load_u32x4_be!(blk_u32, combined, byte_off)
        _sm4_encrypt_block_u32!(ctx.sk, blk_u32, 1, out_u32, 1)
        _store_u32x4_be!(output, byte_off, out_u32)
    end

    # Buffer remaining bytes (< 16) as UInt8
    out_bytes = n_blocks << 4
    remaining = total_len - out_bytes
    if remaining > 0
        @inbounds copyto!(ctx.buffer, 1, combined, out_bytes + 1, remaining)
        ctx.buf_len = remaining
    else
        ctx.buf_len = 0
    end

    return out_bytes
end

"""
ECB decrypt update for PKCS7 mode: accumulate ciphertext, output all but
the last block (the last block is held for padding stripping in `final!`).
"""
function _sm4_ecb_decrypt_update!(ctx::Sm4Stream, input::AbstractVector{UInt8},
                                   output::AbstractVector{UInt8})
    n_in = length(input)

    # Accumulate ciphertext in buffer (UInt8)
    if ctx.buf_len + n_in > length(ctx.buffer)
        resize!(ctx.buffer, max(length(ctx.buffer) * 2, ctx.buf_len + n_in + 32))
    end
    @inbounds copyto!(ctx.buffer, ctx.buf_len + 1, input, 1, n_in)
    ctx.buf_len += n_in

    # Need at least 2 blocks to output any (keep last block for padding stripping)
    blocks_total = ctx.buf_len >> 4
    if blocks_total < 2
        return 0
    end

    blocks_out = blocks_total - 1
    blk_u32 = Vector{UInt32}(undef, 4)
    out_u32 = Vector{UInt32}(undef, 4)

    @inbounds for b in 0:blocks_out-1
        byte_off = (b << 4) + 1
        _load_u32x4_be!(blk_u32, ctx.buffer, byte_off)
        _sm4_encrypt_block_u32!(ctx.sk, blk_u32, 1, out_u32, 1)
        _store_u32x4_be!(output, byte_off, out_u32)
    end

    # Shift remaining bytes (the last block) to front
    consumed = blocks_out << 4
    remaining = ctx.buf_len - consumed
    @inbounds for i in 1:remaining
        ctx.buffer[i] = ctx.buffer[consumed + i]
    end
    ctx.buf_len = remaining

    return consumed
end

function _sm4_ecb_final!(ctx::Sm4Stream, output::AbstractVector{UInt8}, offset::Int)
    if ctx.padding == SM4_PADDING_NONE
        ctx.buf_len == 0 || error(
            "ECB finalize: $(ctx.buf_len) unprocessed bytes remain; use SM4_PADDING_PKCS7 for automatic padding")
        return 0
    elseif ctx.padding == SM4_PADDING_PKCS7
        if ctx.dir == ENCRYPT
            return _sm4_ecb_encrypt_final!(ctx, output, offset)
        else
            return _sm4_ecb_decrypt_final!(ctx, output, offset)
        end
    else
        error("ECB finalize: unknown padding mode $(ctx.padding)")
    end
end

"""
ECB encrypt finalize for PKCS7 mode: pad remaining plaintext with PKCS7,
encrypt the padded block, and write 16 bytes of ciphertext.
"""
function _sm4_ecb_encrypt_final!(ctx::Sm4Stream, output::AbstractVector{UInt8},
                                  offset::Int)
    pad_val = UInt8(16 - ctx.buf_len)
    @inbounds for i in (ctx.buf_len + 1):16
        ctx.buffer[i] = pad_val
    end
    _sm4_encrypt_block!(ctx.sk, ctx.buffer, 1, output, offset)
    ctx.buf_len = 0
    return 16
end

"""
ECB decrypt finalize for PKCS7 mode: decrypt the last buffered ciphertext block
and strip PKCS7 padding, returning the plaintext byte count.
"""
function _sm4_ecb_decrypt_final!(ctx::Sm4Stream, output::AbstractVector{UInt8},
                                  offset::Int)
    ctx.buf_len == 16 || error(
        "ECB decrypt finalize: expected 16 buffered bytes, got $(ctx.buf_len)")

    # Decrypt the last block
    _sm4_encrypt_block!(ctx.sk, ctx.buffer, 1, output, offset)

    # Remove PKCS7 padding
    pad_len = output[offset + 15]
    if pad_len < 1 || pad_len > 16
        error("ECB decrypt finalize: invalid PKCS7 padding value $pad_len")
    end
    @inbounds for k in 1:pad_len
        if output[offset + 16 - k] != pad_len
            error("ECB decrypt finalize: PKCS7 padding mismatch at position $k")
        end
    end

    ctx.buf_len = 0
    return 16 - Int(pad_len)
end

# =============================================================================
# CFB Mode (Cipher Feedback, 128-bit)
#
# Encrypt: C_i = E_k(C_{i-1}) XOR P_i,  C_0 = IV
# Decrypt: P_i = E_k(C_{i-1}) XOR C_i
# Both use the encrypt direction of the cipher.
# Processes input in 16-byte blocks; partial bytes are buffered.
# =============================================================================

function _sm4_cfb_update!(ctx::Sm4Stream, input::AbstractVector{UInt8},
                           output::AbstractVector{UInt8})
    n_in = length(input)

    # Accumulate input in buffer (UInt8)
    if ctx.buf_len + n_in > length(ctx.buffer)
        resize!(ctx.buffer,
                max(length(ctx.buffer) * 2, ctx.buf_len + n_in + 16))
    end
    @inbounds copyto!(ctx.buffer, ctx.buf_len + 1, input, 1, n_in)
    ctx.buf_len += n_in

    blocks = ctx.buf_len >> 4
    blocks == 0 && return 0

    # Convert chain to UInt32 once, reuse per block
    chain_u32 = Vector{UInt32}(undef, 4)
    _load_u32x4_be!(chain_u32, ctx.chain, 1)

    ks_u32 = Vector{UInt32}(undef, 4)
    blk_u32 = Vector{UInt32}(undef, 4)

    @inbounds for b in 0:blocks-1
        ioff = (b << 4) + 1
        ooff = (b << 4) + 1

        # Encrypt chain (UInt32 path)
        _sm4_encrypt_block_u32!(ctx.sk, chain_u32, 1, ks_u32, 1)

        # XOR keystream with input block, write output
        _load_u32x4_be!(blk_u32, ctx.buffer, ioff)
        blk_u32[1] ⊻= ks_u32[1]
        blk_u32[2] ⊻= ks_u32[2]
        blk_u32[3] ⊻= ks_u32[3]
        blk_u32[4] ⊻= ks_u32[4]
        _store_u32x4_be!(output, ooff, blk_u32)

        # Update chain for next block
        if ctx.dir == ENCRYPT
            _load_u32x4_be!(chain_u32, output, ooff)
        else
            _load_u32x4_be!(chain_u32, ctx.buffer, ioff)
        end
    end

    # Write chain back to bytes
    _store_u32x4_be!(ctx.chain, 1, chain_u32)

    # Shift remaining bytes to front (buffer stays UInt8)
    consumed = blocks << 4
    remaining = ctx.buf_len - consumed
    @inbounds for i in 1:remaining
        ctx.buffer[i] = ctx.buffer[consumed + i]
    end
    ctx.buf_len = remaining

    return consumed
end

# =============================================================================
# OFB Mode (Output Feedback, 128-bit)
#
# O_i = E(O_{i-1}),  where O_0 = IV
# C_i = P_i XOR O_i
# Encrypt and decrypt are identical (XOR with keystream).
# =============================================================================

function _sm4_ofb_update!(ctx::Sm4Stream, input::AbstractVector{UInt8},
                           output::AbstractVector{UInt8})
    n = length(input)
    ctr_u32 = Vector{UInt32}(undef, 4)
    ks_u32  = Vector{UInt32}(undef, 4)

    @inbounds for i in 1:n
        if ctx.kpos >= 17
            # Convert ctr → UInt32, encrypt, write back to both ctr & kstream
            _load_u32x4_be!(ctr_u32, ctx.ctr, 1)
            _sm4_encrypt_block_u32!(ctx.sk, ctr_u32, 1, ks_u32, 1)
            _store_u32x4_be!(ctx.kstream, 1, ks_u32)
            _store_u32x4_be!(ctx.ctr, 1, ks_u32)
            ctx.kpos = 1
        end
        output[i] = input[i] ⊻ ctx.kstream[ctx.kpos]
        ctx.kpos += 1
    end
    return n
end

# =============================================================================
# CTR Mode
# =============================================================================

function _sm4_ctr_update!(ctx::Sm4Stream, input::AbstractVector{UInt8},
                           output::AbstractVector{UInt8})
    n = length(input)
    ctr_u32 = Vector{UInt32}(undef, 4)
    ks_u32  = Vector{UInt32}(undef, 4)

    @inbounds for i in 1:n
        if ctx.kpos >= 17
            _load_u32x4_be!(ctr_u32, ctx.ctr, 1)
            _sm4_encrypt_block_u32!(ctx.sk, ctr_u32, 1, ks_u32, 1)
            _store_u32x4_be!(ctx.kstream, 1, ks_u32)
            ctx.kpos = 1
            # Increment counter (big-endian)
            for j in 16:-1:1
                ctx.ctr[j] += 0x01
                ctx.ctr[j] != 0x00 && break
            end
        end
        output[i] = input[i] ⊻ ctx.kstream[ctx.kpos]
        ctx.kpos += 1
    end
    return n
end

# =============================================================================
# CBC Mode Internals - Encrypt
# =============================================================================

function _sm4_cbc_encrypt_update!(ctx::Sm4Stream, input::AbstractVector{UInt8},
                                   output::AbstractVector{UInt8})
    n_in = length(input)
    total_len = ctx.buf_len + n_in

    # Build combined UInt8 buffer (cache + new input)
    combined = Vector{UInt8}(undef, total_len)
    if ctx.buf_len > 0
        @inbounds copyto!(combined, 1, ctx.buffer, 1, ctx.buf_len)
    end
    @inbounds copyto!(combined, ctx.buf_len + 1, input, 1, n_in)

    # Calculate full 16-byte blocks
    n_blocks = total_len >> 4
    if n_blocks == 0
        ctx.buf_len = total_len
        @inbounds copyto!(ctx.buffer, 1, combined, 1, total_len)
        return 0
    end

    # Load chain as UInt32
    chain_u32 = Vector{UInt32}(undef, 4)
    _load_u32x4_be!(chain_u32, ctx.chain, 1)

    blk_u32 = Vector{UInt32}(undef, 4)

    @inbounds for b in 0:n_blocks-1
        byte_off = (b << 4) + 1

        # Load plaintext block, XOR with chain
        _load_u32x4_be!(blk_u32, combined, byte_off)
        blk_u32[1] ⊻= chain_u32[1]
        blk_u32[2] ⊻= chain_u32[2]
        blk_u32[3] ⊻= chain_u32[3]
        blk_u32[4] ⊻= chain_u32[4]

        # Encrypt; ciphertext becomes next chain (write directly into chain_u32)
        _sm4_encrypt_block_u32!(ctx.sk, blk_u32, 1, chain_u32, 1)

        # Write ciphertext to output
        _store_u32x4_be!(output, byte_off, chain_u32)
    end

    # Write chain back to bytes
    _store_u32x4_be!(ctx.chain, 1, chain_u32)

    # Buffer remaining bytes (< 16) as UInt8
    out_bytes = n_blocks << 4
    remaining = total_len - out_bytes
    if remaining > 0
        @inbounds copyto!(ctx.buffer, 1, combined, out_bytes + 1, remaining)
        ctx.buf_len = remaining
    else
        ctx.buf_len = 0
    end

    return out_bytes
end

function _sm4_cbc_encrypt_final!(ctx::Sm4Stream, output::AbstractVector{UInt8},
                                  offset::Int)
    pad_val = UInt8(16 - ctx.buf_len)
    @inbounds for i in (ctx.buf_len + 1):16
        ctx.buffer[i] = pad_val
    end

    @inbounds for j in 1:16
        ctx.buffer[j] ⊻= ctx.chain[j]
    end
    _sm4_encrypt_block!(ctx.sk, ctx.buffer, 1, output, offset)
    return 16
end

# =============================================================================
# CBC Mode Internals - Decrypt
# =============================================================================

function _sm4_cbc_decrypt_update!(ctx::Sm4Stream, input::AbstractVector{UInt8},
                                   output::AbstractVector{UInt8})
    n_in = length(input)

    # Accumulate ciphertext in buffer (UInt8)
    if ctx.buf_len + n_in > length(ctx.buffer)
        resize!(ctx.buffer, max(length(ctx.buffer) * 2, ctx.buf_len + n_in + 32))
    end
    @inbounds copyto!(ctx.buffer, ctx.buf_len + 1, input, 1, n_in)
    ctx.buf_len += n_in

    blocks_total = ctx.buf_len >> 4
    if blocks_total < 2
        return 0
    end

    blocks_out = blocks_total - 1

    # Load chain as UInt32
    chain_u32 = Vector{UInt32}(undef, 4)
    _load_u32x4_be!(chain_u32, ctx.chain, 1)

    blk_u32 = Vector{UInt32}(undef, 4)
    dec_u32 = Vector{UInt32}(undef, 4)

    for b in 0:blocks_out-1
        ioff = (b << 4) + 1
        ooff = (b << 4) + 1

        # Load ciphertext block as UInt32
        _load_u32x4_be!(blk_u32, ctx.buffer, ioff)

        # Decrypt (reversed key schedule)
        _sm4_encrypt_block_u32!(ctx.sk, blk_u32, 1, dec_u32, 1)

        # XOR with chain and write plaintext
        dec_u32[1] ⊻= chain_u32[1]
        dec_u32[2] ⊻= chain_u32[2]
        dec_u32[3] ⊻= chain_u32[3]
        dec_u32[4] ⊻= chain_u32[4]
        _store_u32x4_be!(output, ooff, dec_u32)

        # New chain = current ciphertext block
        chain_u32[1] = blk_u32[1]
        chain_u32[2] = blk_u32[2]
        chain_u32[3] = blk_u32[3]
        chain_u32[4] = blk_u32[4]
    end

    # Write chain back to bytes
    _store_u32x4_be!(ctx.chain, 1, chain_u32)

    # Shift remaining bytes in buffer
    consumed = blocks_out << 4
    remaining = ctx.buf_len - consumed
    @inbounds for i in 1:remaining
        ctx.buffer[i] = ctx.buffer[consumed + i]
    end
    ctx.buf_len = remaining

    return consumed
end

function _sm4_cbc_decrypt_final!(ctx::Sm4Stream, output::AbstractVector{UInt8},
                                  offset::Int)
    ctx.buf_len == 16 || error(
        "CBC decrypt finalize: expected 16 buffered bytes, got $(ctx.buf_len)")

    tmp = Vector{UInt8}(undef, 16)
    _sm4_encrypt_block!(ctx.sk, ctx.buffer, 1, tmp, 1)
    @inbounds for j in 1:16
        output[offset + j - 1] = ctx.chain[j] ⊻ tmp[j]
    end

    # Remove PKCS7 padding
    pad_len = output[offset + 15]
    if pad_len < 1 || pad_len > 16
        error("CBC decrypt finalize: invalid PKCS7 padding value $pad_len")
    end
    @inbounds for k in 1:pad_len
        if output[offset + 16 - k] != pad_len
            error("CBC decrypt finalize: PKCS7 padding mismatch at position $k")
        end
    end

    ctx.buf_len = 0
    return 16 - Int(pad_len)
end

# =============================================================================
# Backward Compatibility: Legacy Constructors & Function Wrappers
# =============================================================================

"""
    Sm4Ctr(key::Vector{UInt8}, iv::Vector{UInt8}) -> Sm4Stream

Legacy constructor for CTR mode.  Equivalent to `Sm4Stream(key, iv, SM4_MODE_CTR)`.
Kept for backward compatibility; prefer `Sm4Stream` directly.
"""
Sm4Ctr(key::Vector{UInt8}, iv::Vector{UInt8}) = Sm4Stream(key, iv, SM4_MODE_CTR)

"""
    Sm4Cbc(key::Vector{UInt8}, iv::Vector{UInt8}, mode::Int) -> Sm4Stream

Legacy constructor for CBC mode.  Equivalent to `Sm4Stream(key, iv, SM4_MODE_CBC, mode)`.
Kept for backward compatibility; prefer `Sm4Stream` directly.
"""
Sm4Cbc(key::Vector{UInt8}, iv::Vector{UInt8}, mode::Int) = Sm4Stream(key, iv, SM4_MODE_CBC, mode)

# Legacy wrapper functions — delegate to unified API
function sm4_ctr_xor!(ctx::Sm4Stream, input::AbstractVector{UInt8},
                       output::AbstractVector{UInt8})
    ctx.mode == SM4_MODE_CTR || error("sm4_ctr_xor! requires SM4_MODE_CTR, got mode=$(ctx.mode)")
    return sm4_stream_update!(ctx, input, output)
end

function sm4_cbc_encrypt_update!(ctx::Sm4Stream, input::AbstractVector{UInt8},
                                  output::AbstractVector{UInt8})
    ctx.mode == SM4_MODE_CBC && ctx.dir == ENCRYPT ||
        error("sm4_cbc_encrypt_update! requires SM4_MODE_CBC + ENCRYPT")
    return sm4_stream_update!(ctx, input, output)
end

function sm4_cbc_encrypt_final!(ctx::Sm4Stream, output::AbstractVector{UInt8},
                                 offset::Int=1)
    ctx.mode == SM4_MODE_CBC && ctx.dir == ENCRYPT ||
        error("sm4_cbc_encrypt_final! requires SM4_MODE_CBC + ENCRYPT")
    return sm4_stream_final!(ctx, output, offset)
end

function sm4_cbc_decrypt_update!(ctx::Sm4Stream, input::AbstractVector{UInt8},
                                  output::AbstractVector{UInt8})
    ctx.mode == SM4_MODE_CBC && ctx.dir == DECRYPT ||
        error("sm4_cbc_decrypt_update! requires SM4_MODE_CBC + DECRYPT")
    return sm4_stream_update!(ctx, input, output)
end

function sm4_cbc_decrypt_final!(ctx::Sm4Stream, output::AbstractVector{UInt8},
                                 offset::Int=1)
    ctx.mode == SM4_MODE_CBC && ctx.dir == DECRYPT ||
        error("sm4_cbc_decrypt_final! requires SM4_MODE_CBC + DECRYPT")
    return sm4_stream_final!(ctx, output, offset)
end
