module SM4

# =============================================================================
# SM4 - Block Cipher  (GM/T 0002-2012)
#
# Performance optimizations:
#   1. sm4_one_round uses scalar variables (zero per-round allocations)
#   2. sm4_tau does inline S-box lookup on UInt32 bytes (no arrays)
#   3. put_u32_be! writes directly into output buffer (no temp arrays)
#   4. @inbounds on all hot loops
#   5. Removed dead code in sm4_setkey!
# =============================================================================

export Sm4, sm4_crypt_ecb, sm4_crypt_cbc,
       ENCRYPT, DECRYPT,
       Sm4Ctr, Sm4Cbc, sm4_ctr_xor!, sm4_cbc_encrypt_update!,
       sm4_cbc_encrypt_final!, sm4_cbc_decrypt_update!,
       sm4_cbc_decrypt_final!

# =============================================================================
# Constants
# =============================================================================

const SboxTable = UInt8[
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
]

const FK = UInt32[0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]

const CK = UInt32[
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
]

const ENCRYPT = 0
const DECRYPT = 1

# =============================================================================
# Inline helpers
# =============================================================================

@inline function _get_u32_be(data::AbstractVector{UInt8}, off::Int)
    @inbounds return (UInt32(data[off])     << 24) |
                     (UInt32(data[off + 1]) << 16) |
                     (UInt32(data[off + 2]) << 8)  |
                      UInt32(data[off + 3])
end

@inline function _put_u32_be!(buf::AbstractVector{UInt8}, off::Int, n::UInt32)
    @inbounds begin
        buf[off]     = n >> 24
        buf[off + 1] = (n >> 16) & 0xff
        buf[off + 2] = (n >> 8) & 0xff
        buf[off + 3] = n & 0xff
    end
end

@inline function _rotl(x::UInt32, n::Integer)::UInt32
    return (x << n) | (x >> (32 - n))
end

# =============================================================================
# S-box: inline byte-level lookup on UInt32 (zero allocation)
# =============================================================================

@inline function _sm4_tau(ka::UInt32)::UInt32
    @inbounds return (UInt32(SboxTable[(ka >> 24) + 1]) << 24) |
                     (UInt32(SboxTable[((ka >> 16) & 0xff) + 1]) << 16) |
                     (UInt32(SboxTable[((ka >> 8)  & 0xff) + 1]) << 8)  |
                      UInt32(SboxTable[( ka        & 0xff) + 1])
end

# =============================================================================
# SM4 Core Functions
# =============================================================================

@inline function _sm4_calci_rk(ka::UInt32)::UInt32
    bb = _sm4_tau(ka)
    return bb ⊻ _rotl(bb, 13) ⊻ _rotl(bb, 23)
end

@inline function _sm4_lt(ka::UInt32)::UInt32
    bb = _sm4_tau(ka)
    return bb ⊻ _rotl(bb, 2) ⊻ _rotl(bb, 10) ⊻ _rotl(bb, 18) ⊻ _rotl(bb, 24)
end

@inline function _sm4_f(x0::UInt32, x1::UInt32, x2::UInt32, x3::UInt32, rk::UInt32)::UInt32
    return x0 ⊻ _sm4_lt(x1 ⊻ x2 ⊻ x3 ⊻ rk)
end

# =============================================================================
# Sm4 Cipher Context
# =============================================================================

"""
    Sm4

SM4 block cipher context holding 32 expanded round keys.
"""
mutable struct Sm4
    sk::Vector{UInt32}
    mode::Int

    function Sm4()
        return new(zeros(UInt32, 32), ENCRYPT)
    end
end

"""
    sm4_setkey!(sm4::Sm4, key::Vector{UInt8}, mode::Int)

Set the key and expand round keys.
"""
function sm4_setkey!(sm4::Sm4, key::Vector{UInt8}, mode::Int)
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
        sm4.sk[i] = k[i + 4]
    end
    sm4.mode = mode

    if mode == DECRYPT
        reverse!(sm4.sk)
    end
end

"""
    sm4_one_round(sm4::Sm4, input::Vector{UInt8}, in_off::Int,
                  output::Vector{UInt8}, out_off::Int)

Process one 16-byte block. Uses scalar variables for zero allocation in the
inner loop.
"""
function sm4_one_round(sm4::Sm4, input::Vector{UInt8}, in_off::Int,
                        output::Vector{UInt8}, out_off::Int)
    x1 = _get_u32_be(input, in_off)
    x2 = _get_u32_be(input, in_off + 4)
    x3 = _get_u32_be(input, in_off + 8)
    x4 = _get_u32_be(input, in_off + 12)

    sk = sm4.sk
    @inbounds for rk in sk
        tmp = _sm4_f(x1, x2, x3, x4, rk)
        x1, x2, x3, x4 = x2, x3, x4, tmp
    end

    # Output in reverse: x4, x3, x2, x1
    _put_u32_be!(output, out_off,      x4)
    _put_u32_be!(output, out_off + 4,  x3)
    _put_u32_be!(output, out_off + 8,  x2)
    _put_u32_be!(output, out_off + 12, x1)
end

# =============================================================================
# ECB Mode
# =============================================================================

"""
    sm4_crypt_ecb!(sm4::Sm4, input_data::Vector{UInt8}) -> Vector{UInt8}

SM4-ECB mode encryption/decryption.  Pre-allocates output buffer.
"""
function sm4_crypt_ecb!(sm4::Sm4, input_data::Vector{UInt8})
    n = length(input_data)
    output_data = Vector{UInt8}(undef, n)
    @inbounds for i in 0:16:n-1
        sm4_one_round(sm4, input_data, i + 1, output_data, i + 1)
    end
    return output_data
end

# =============================================================================
# CBC Mode
# =============================================================================

"""
    sm4_crypt_cbc!(sm4::Sm4, iv::Vector{UInt8}, input_data::Vector{UInt8}) -> Vector{UInt8}

SM4-CBC mode encryption/decryption.
"""
function sm4_crypt_cbc!(sm4::Sm4, iv::Vector{UInt8}, input_data::Vector{UInt8})
    n = length(input_data)
    n_blocks = n >> 4
    output_data = Vector{UInt8}(undef, n)

    if sm4.mode == ENCRYPT
        prev = copy(iv)
        xored = Vector{UInt8}(undef, 16)
        @inbounds for b in 0:n_blocks-1
            off = b << 4
            for j in 1:16
                xored[j] = prev[j] ⊻ input_data[off + j]
            end
            sm4_one_round(sm4, xored, 1, output_data, off + 1)
            for j in 1:16
                prev[j] = output_data[off + j]
            end
        end
    else  # DECRYPT
        prev = copy(iv)
        block = Vector{UInt8}(undef, 16)
        @inbounds for b in 0:n_blocks-1
            off = b << 4
            sm4_one_round(sm4, input_data, off + 1, block, 1)
            for j in 1:16
                output_data[off + j] = prev[j] ⊻ block[j]
            end
            for j in 1:16
                prev[j] = input_data[off + j]
            end
        end
    end

    return output_data
end

# =============================================================================
# Convenience Functions
# =============================================================================

function sm4_crypt_ecb(mode::Int, key::Vector{UInt8}, data::Vector{UInt8})
    sm4 = Sm4()
    sm4_setkey!(sm4, key, mode)
    return sm4_crypt_ecb!(sm4, data)
end

function sm4_crypt_cbc(mode::Int, key::Vector{UInt8}, iv::Vector{UInt8}, data::Vector{UInt8})
    sm4 = Sm4()
    sm4_setkey!(sm4, key, mode)
    return sm4_crypt_cbc!(sm4, iv, data)
end

# =============================================================================
# SM4 Streaming API
#
# Motivation: sm4_crypt_ecb! and sm4_crypt_cbc! allocate a full output
# buffer (Vector{UInt8}(undef, n)) and copy IV/chain state.  For large
# data (e.g. 100+ MB) this causes GC pressure and frequent major collections.
#
# The streaming API solves this:
#   1. CTR mode - no buffering, output length = input length, no padding.
#   2. CBC mode - 16-byte internal buffer, PKCS7 padding on finalize.
#      User provides pre-allocated output; only internal scratch is
#      allocated once at construction time.
#
# Usage:
#   # CTR (simplest, recommended for large streams)
#   ctx = Sm4Ctr(key, iv)
#   out = Vector{UInt8}(undef, 4096)
#   for chunk in reader
#       sm4_ctr_xor!(ctx, chunk, out)
#       write(writer, view(out, 1:length(chunk)))
#   end
#
#   # CBC encrypt (streaming)
#   ctx = Sm4Cbc(key, iv, ENCRYPT)
#   out = similar(input)
#   n = sm4_cbc_encrypt_update!(ctx, input, out)
#   rem = sm4_cbc_encrypt_final!(ctx, out, n)
#   total_out = view(out, 1:n + rem)
#
#   # CBC decrypt (streaming)
#   ctx = Sm4Cbc(key, iv, DECRYPT)
#   out = similar(input)
#   n = sm4_cbc_decrypt_update!(ctx, input, out)
#   rem = sm4_cbc_decrypt_final!(ctx, out, n)
#   total_out = view(out, 1:n + rem)
# =============================================================================

# -----------------------------------------------------------------------------
# Standalone block encrypt (operates on plain sk::Vector{UInt32})
# -----------------------------------------------------------------------------
@inline function _sm4_encrypt_block!(sk::Vector{UInt32}, input::AbstractVector{UInt8},
                                      in_off::Int, output::AbstractVector{UInt8},
                                      out_off::Int)
    x1 = _get_u32_be(input, in_off)
    x2 = _get_u32_be(input, in_off + 4)
    x3 = _get_u32_be(input, in_off + 8)
    x4 = _get_u32_be(input, in_off + 12)

    @inbounds for rk in sk
        tmp = _sm4_f(x1, x2, x3, x4, rk)
        x1, x2, x3, x4 = x2, x3, x4, tmp
    end

    _put_u32_be!(output, out_off,      x4)
    _put_u32_be!(output, out_off + 4,  x3)
    _put_u32_be!(output, out_off + 8,  x2)
    _put_u32_be!(output, out_off + 12, x1)
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

# =============================================================================
# CTR Mode - most efficient streaming mode
# =============================================================================

"""
    Sm4Ctr

CTR-mode streaming context.  Pre-allocates all internal buffers once.
CTR uses only the encrypt direction; encryption and decryption are
identical (XOR with keystream).

# Fields
- `sk::Vector{UInt32}`: 32 expanded round keys (ENCRYPT direction)
- `ctr::Vector{UInt8}`: 16-byte counter block
- `kstream::Vector{UInt8}`: 16-byte encrypted counter (keystream chunk)
- `kpos::Int`: current byte offset within kstream (1-based, 17 = need new block)
"""
mutable struct Sm4Ctr
    sk::Vector{UInt32}
    ctr::Vector{UInt8}
    kstream::Vector{UInt8}
    kpos::Int

    function Sm4Ctr(key::Vector{UInt8}, iv::Vector{UInt8})
        length(iv) == 16 || error("IV must be 16 bytes, got $(length(iv))")
        ctx = new(zeros(UInt32, 32), zeros(UInt8, 16), zeros(UInt8, 16), 17)
        _sm4_set_encrypt_key!(ctx.sk, key)
        copyto!(ctx.ctr, iv)
        return ctx
    end
end

"""
    sm4_ctr_xor!(ctx::Sm4Ctr, input::Vector{UInt8}, output::Vector{UInt8})

CTR-mode XOR.  Encrypts or decrypts `input` into `output`.
`output` must be at least `length(input)` bytes.
Returns number of bytes processed (= length(input)).

No padding needed — output length always equals input length.
"""
function sm4_ctr_xor!(ctx::Sm4Ctr, input::AbstractVector{UInt8}, output::AbstractVector{UInt8})
    n = length(input)
    @inbounds for i in 1:n
        if ctx.kpos >= 17
            _sm4_encrypt_block!(ctx.sk, ctx.ctr, 1, ctx.kstream, 1)
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
# CBC Mode - streaming with PKCS7 padding
# =============================================================================

"""
    Sm4Cbc

CBC-mode streaming context.  Maintains chain state and a 16-byte
overflow buffer for partial blocks.

# Fields
- `sk::Vector{UInt32}`: 32 expanded round keys
- `chain::Vector{UInt8}`: 16-byte chaining block (IV updated to last CT)
- `buffer::Vector{UInt8}`: 16-byte overflow buffer
- `buf_len::Int`: bytes accumulated in buffer (0..15)
- `mode::Int`: ENCRYPT or DECRYPT
"""
mutable struct Sm4Cbc
    sk::Vector{UInt32}
    chain::Vector{UInt8}
    buffer::Vector{UInt8}
    buf_len::Int
    mode::Int

    function Sm4Cbc(key::Vector{UInt8}, iv::Vector{UInt8}, mode::Int)
        length(iv) == 16 || error("IV must be 16 bytes, got $(length(iv))")
        ctx = new(zeros(UInt32, 32), zeros(UInt8, 16),
                  zeros(UInt8, 16), 0, mode)
        if mode == ENCRYPT
            _sm4_set_encrypt_key!(ctx.sk, key)
        elseif mode == DECRYPT
            _sm4_set_encrypt_key!(ctx.sk, key)
            reverse!(ctx.sk)  # decrypt = encrypt with reversed round keys
        else
            error("Invalid mode: $mode, expected ENCRYPT(0) or DECRYPT(1)")
        end
        copyto!(ctx.chain, iv)
        return ctx
    end
end

# -----------------------------------------------------------------------------
# CBC Encrypt streaming
# -----------------------------------------------------------------------------

"""
    sm4_cbc_encrypt_update!(ctx::Sm4Cbc, input::Vector{UInt8}, output::Vector{UInt8}) -> Int

Feed `input` into the CBC encrypt stream.  Returns the number of bytes
written to `output` (always a multiple of 16).  Any partial block
(< 16 bytes) is buffered internally.

`output` must have space for `floor((ctx.buf_len + length(input)) / 16) * 16` bytes.
"""
function sm4_cbc_encrypt_update!(ctx::Sm4Cbc, input::AbstractVector{UInt8},
                                  output::AbstractVector{UInt8})
    n_in = length(input)
    out_off = 1

    # If we have buffered bytes from a previous call, try to fill a block
    if ctx.buf_len > 0
        needed = 16 - ctx.buf_len
        take = min(needed, n_in)
        @inbounds for i in 1:take
            ctx.buffer[ctx.buf_len + i] = input[i]
        end
        ctx.buf_len += take

        if ctx.buf_len == 16
            # Full block: XOR with chain, encrypt, update chain
            @inbounds for j in 1:16
                ctx.buffer[j] ⊻= ctx.chain[j]
            end
            _sm4_encrypt_block!(ctx.sk, ctx.buffer, 1, output, out_off)
            @inbounds copyto!(ctx.chain, 1, output, out_off, 16)
            out_off += 16
            ctx.buf_len = 0
        end
        # Process remaining input aligned from position take+1
        pos = take + 1
    else
        pos = 1
    end

    # Process full blocks
    n_full = (n_in - pos + 1) >> 4
    @inbounds for b in 0:n_full-1
        ioff = pos + (b << 4)
        ooff = out_off + (b << 4)
        # XOR with chain
        for j in 1:16
            output[ooff + j - 1] = ctx.chain[j] ⊻ input[ioff + j - 1]
        end
        _sm4_encrypt_block!(ctx.sk, output, ooff, output, ooff)
        copyto!(ctx.chain, 1, output, ooff, 16)
    end
    out_off += n_full << 4

    # Buffer remaining bytes
    remaining = n_in - pos - (n_full << 4) + 1
    if remaining > 0
        start = pos + (n_full << 4)
        @inbounds for i in 1:remaining
            ctx.buffer[i] = input[start + i - 1]
        end
        ctx.buf_len = remaining
    end

    return out_off - 1
end

"""
    sm4_cbc_encrypt_final!(ctx::Sm4Cbc, output::Vector{UInt8}, offset::Int) -> Int

Finalize CBC encryption.  Applies PKCS7 padding, encrypts the final
block(s), and writes to `output` starting at position `offset`.
Returns the number of bytes written (16 or possibly 32).

After calling finalize, the context should not be reused.
"""
function sm4_cbc_encrypt_final!(ctx::Sm4Cbc, output::AbstractVector{UInt8},
                                 offset::Int=1)
    pad_val = UInt8(16 - ctx.buf_len)
    @inbounds for i in (ctx.buf_len + 1):16
        ctx.buffer[i] = pad_val
    end

    # XOR last block with chain, encrypt
    @inbounds for j in 1:16
        ctx.buffer[j] ⊻= ctx.chain[j]
    end
    _sm4_encrypt_block!(ctx.sk, ctx.buffer, 1, output, offset)
    return 16
end

# -----------------------------------------------------------------------------
# CBC Decrypt streaming
# -----------------------------------------------------------------------------

"""
    sm4_cbc_decrypt_update!(ctx::Sm4Cbc, input::AbstractVector{UInt8},
                            output::AbstractVector{UInt8}) -> Int

Feed ciphertext into the CBC decrypt stream.  Returns bytes written to
`output`.  At least 2 full blocks (32 bytes) must be accumulated before
any output is produced, because the last block is always held back for
PKCS7 padding removal in `final!`.

`output` must have space for `max(0, floor((ctx.buf_len + length(input)) / 16) - 1) * 16` bytes.
"""
function sm4_cbc_decrypt_update!(ctx::Sm4Cbc, input::AbstractVector{UInt8},
                                  output::AbstractVector{UInt8})
    n_in = length(input)

    # Ensure buffer capacity (buf_len can grow beyond 16; resize rarely)
    if ctx.buf_len + n_in > length(ctx.buffer)
        resize!(ctx.buffer, max(length(ctx.buffer) * 2, ctx.buf_len + n_in + 32))
    end

    # Append input to buffer
    @inbounds for i in 1:n_in
        ctx.buffer[ctx.buf_len + i] = input[i]
    end
    ctx.buf_len += n_in

    # Output all complete blocks except the last one
    blocks_total = ctx.buf_len >> 4
    if blocks_total < 2
        return 0
    end

    blocks_out = blocks_total - 1
    tmp = Vector{UInt8}(undef, 16)
    for b in 0:blocks_out-1
        ioff = (b << 4) + 1
        ooff = (b << 4) + 1
        _sm4_encrypt_block!(ctx.sk, ctx.buffer, ioff, tmp, 1)
        @inbounds for j in 1:16
            output[ooff + j - 1] = ctx.chain[j] ⊻ tmp[j]
        end
        copyto!(ctx.chain, 1, ctx.buffer, ioff, 16)
    end

    # Shift remaining data (last block + any partial) to front of buffer
    consumed = blocks_out << 4
    remaining = ctx.buf_len - consumed
    @inbounds for i in 1:remaining
        ctx.buffer[i] = ctx.buffer[consumed + i]
    end
    ctx.buf_len = remaining

    return blocks_out << 4
end

"""
    sm4_cbc_decrypt_final!(ctx::Sm4Cbc, output::AbstractVector{UInt8},
                           offset::Int=1) -> Int

Finalize CBC decryption.  Decrypts the last buffered block, removes
PKCS7 padding, and writes plaintext to `output` starting at `offset`.
Returns the number of plaintext bytes written.

Errors on invalid padding.
"""
function sm4_cbc_decrypt_final!(ctx::Sm4Cbc, output::AbstractVector{UInt8},
                                 offset::Int=1)
    # Must have exactly one block remaining
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

end # module SM4
