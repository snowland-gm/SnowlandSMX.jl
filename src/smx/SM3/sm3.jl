module SM3

export SM3Context, sm3_hash, sm3_digest, sm3_hexdigest, byte2hex,
       digest, hash_msg, hexdigest,
       update!, digest!, hexdigest!,
       CF, rotate_left, P_0, P_1, FF_j, GG_j, PUT_UINT32_BE,
       sm3_kdf, sm3_kdf_bytes, sm3_kdf_from_bytes

# =============================================================================
# SM3 Constants (GM/T 0004-2012 / GB/T 32905-2016)
# =============================================================================

const IV = UInt32[0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
                  0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e]

const T_j = vcat(fill(UInt32(0x79cc4519), 16), fill(UInt32(0x7a879d8a), 48))

# =============================================================================
# Core SM3 Functions
# =============================================================================

function rotate_left(a::UInt32, k::Integer)
    k = k % UInt32(32)
    if k == 0
        return a
    end
    return (a << k) | (a >> (32 - k))
end

function P_0(X::UInt32)
    return X ⊻ rotate_left(X, 9) ⊻ rotate_left(X, 17)
end

function P_1(X::UInt32)
    return X ⊻ rotate_left(X, 15) ⊻ rotate_left(X, 23)
end

function FF_j(X::UInt32, Y::UInt32, Z::UInt32, j::Integer)
    if j < 16
        return X ⊻ Y ⊻ Z
    else
        return (X & Y) | (X & Z) | (Y & Z)
    end
end

function GG_j(X::UInt32, Y::UInt32, Z::UInt32, j::Integer)
    if j < 16
        return X ⊻ Y ⊻ Z
    else
        return (X & Y) | ((~X) & Z)
    end
end

function PUT_UINT32_BE(n::UInt32)
    return UInt8[n >> 24, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]
end

# =============================================================================
# Message Expansion (inlined for performance)
# =============================================================================

@inline function _msg_expand(block::Vector{UInt8})
    W = Vector{UInt32}(undef, 68)
    @inbounds for i in 0:15
        off = i * 4
        W[i + 1] = UInt32(block[off + 1]) << 24 |
                   UInt32(block[off + 2]) << 16 |
                   UInt32(block[off + 3]) << 8  |
                   UInt32(block[off + 4])
    end
    @inbounds for i in 16:67
        W[i + 1] = P_1(W[i - 16 + 1] ⊻ W[i - 9 + 1] ⊻
                        rotate_left(W[i - 3 + 1], 15)) ⊻
                    rotate_left(W[i - 13 + 1], 7) ⊻ W[i - 6 + 1]
    end
    return W
end

# =============================================================================
# SM3 Compression Function
# =============================================================================

function CF(V_i::Vector{UInt32}, B_i::Vector{UInt8})
    W = _msg_expand(B_i)

    A = V_i[1]; B = V_i[2]; C = V_i[3]; D = V_i[4]
    E = V_i[5]; F = V_i[6]; G = V_i[7]; H = V_i[8]

    @inbounds for j in 0:63
        SS1 = rotate_left(rotate_left(A, 12) + E + rotate_left(T_j[j + 1], j), 7)
        SS2 = SS1 ⊻ rotate_left(A, 12)
        TT1 = FF_j(A, B, C, j) + D + SS2 + (W[j + 1] ⊻ W[j + 4 + 1])
        TT2 = GG_j(E, F, G, j) + H + SS1 + W[j + 1]

        D = C
        C = rotate_left(B, 9)
        B = A
        A = TT1
        H = G
        G = rotate_left(F, 19)
        F = E
        E = P_0(TT2)
    end

    return UInt32[A ⊻ V_i[1], B ⊻ V_i[2], C ⊻ V_i[3], D ⊻ V_i[4],
                  E ⊻ V_i[5], F ⊻ V_i[6], G ⊻ V_i[7], H ⊻ V_i[8]]
end

# =============================================================================
# Helper: write UInt32 into buffer at offset (big-endian)
# =============================================================================

@inline function _put_u32_be!(buf::Vector{UInt8}, off::Int, n::UInt32)
    @inbounds begin
        buf[off]     = n >> 24
        buf[off + 1] = (n >> 16) & 0xff
        buf[off + 2] = (n >> 8) & 0xff
        buf[off + 3] = n & 0xff
    end
end

function _v_to_bytes(V::Vector{UInt32})
    result = Vector{UInt8}(undef, 32)
    for i in 1:8
        _put_u32_be!(result, (i - 1) * 4 + 1, V[i])
    end
    return result
end

# =============================================================================
# Utility Functions
# =============================================================================

function str2bytes(msg::AbstractString)
    return Vector{UInt8}(msg)
end

str2bytes(msg::Vector{UInt8}) = copy(msg)

function hex2byte(hex_str::AbstractString)
    s = strip(hex_str)
    if length(s) % 2 != 0
        s = '0' * s
    end
    return hex2bytes(s)
end

const _SM3_HEX_DIGITS = UInt8[0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
                               0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66]
function byte2hex(data::Vector{UInt8})
    n = length(data)
    buf = Vector{UInt8}(undef, n * 2)
    @inbounds for i in 1:n
        b = data[i]
        buf[2*i - 1] = _SM3_HEX_DIGITS[(b >> 4) + 1]
        buf[2*i]     = _SM3_HEX_DIGITS[(b & 0x0f) + 1]
    end
    return String(buf)
end

# =============================================================================
# Padding
# =============================================================================

function _pad(msg::Vector{UInt8})
    l = length(msg)
    bit_len = UInt64(l * 8)

    # Calculate zero-byte count k such that (l + 1 + k) % 64 == 56
    k = (56 - 1 - l) % Int64
    if k < 0
        k += 64
    end

    padded = Vector{UInt8}(undef, l + 1 + k + 8)
    @inbounds begin
        for i in 1:l
            padded[i] = msg[i]
        end
        padded[l + 1] = 0x80
        for i in 1:k
            padded[l + 1 + i] = 0x00
        end
        off = l + 1 + k
        for i in 0:7
            padded[off + i + 1] = UInt8((bit_len >> (56 - i * 8)) & 0xff)
        end
    end
    return padded
end

# =============================================================================
# One-shot SM3 Hash
# =============================================================================

function _digest_bytes(msg::Vector{UInt8})
    padded = _pad(msg)
    V = copy(IV)
    for i in 1:64:length(padded)
        V = CF(V, padded[i:i+63])
    end
    return _v_to_bytes(V)
end

function digest(data; hex_input::Bool=false)
    if hex_input
        msg = hex2byte(data)
    elseif data isa Vector{UInt8}
        msg = copy(data)
    else
        msg = str2bytes(data)
    end
    return _digest_bytes(msg)
end

function hash_msg(msg)
    return byte2hex(digest(msg, hex_input=false))
end

function sm3_hash(data; hex_input::Bool=false)
    return byte2hex(digest(data, hex_input=hex_input))
end

const hexdigest = sm3_hash

function sm3_digest(data; hex_input::Bool=false)
    return digest(data, hex_input=hex_input)
end

function sm3_hexdigest(data; hex_input::Bool=false)
    return sm3_hash(data, hex_input=hex_input)
end

# =============================================================================
# SM3 Streaming Context
# =============================================================================

mutable struct SM3Context
    iv::Vector{UInt32}
    block::Vector{UInt8}
    length::Int

    function SM3Context()
        return new(copy(IV), UInt8[], 0)
    end

    function SM3Context(data::Vector{UInt8})
        ctx = new(copy(IV), UInt8[], 0)
        if !isempty(data)
            update!(ctx, data)
        end
        return ctx
    end

    function SM3Context(data::AbstractString)
        ctx = new(copy(IV), UInt8[], 0)
        if !isempty(data)
            update!(ctx, data)
        end
        return ctx
    end
end

function update!(ctx::SM3Context, data::AbstractString)
    _update_bytes!(ctx, Vector{UInt8}(data))
end

function update!(ctx::SM3Context, data::Vector{UInt8})
    _update_bytes!(ctx, data)
end

function _update_bytes!(ctx::SM3Context, data::Vector{UInt8})
    ctx.length += length(data)
    append!(ctx.block, data)
    len_block = length(ctx.block)

    n_blocks = div(len_block, 64)
    idx = n_blocks * 64
    for i in 1:64:idx
        ctx.iv = CF(ctx.iv, ctx.block[i:i+63])
    end
    if idx + 1 <= len_block
        ctx.block = ctx.block[idx+1:end]
    else
        ctx.block = UInt8[]
    end
end

function digest!(ctx::SM3Context)
    padded = _pad_msg_for_context(ctx)
    len_block = length(padded)
    for i in 1:64:len_block
        ctx.iv = CF(ctx.iv, padded[i:i+63])
    end

    result = _v_to_bytes(ctx.iv)

    # Reset context
    ctx.iv = copy(IV)
    ctx.block = UInt8[]
    ctx.length = 0

    return result
end

function _pad_msg_for_context(ctx::SM3Context)
    l = ctx.length
    bit_len = UInt64(l * 8)
    blen = length(ctx.block)

    k = (56 - 1 - blen) % Int64
    if k < 0
        k += 64
    end

    padded = Vector{UInt8}(undef, blen + 1 + k + 8)
    @inbounds begin
        for i in 1:blen
            padded[i] = ctx.block[i]
        end
        padded[blen + 1] = 0x80
        for i in 1:k
            padded[blen + 1 + i] = 0x00
        end
        off = blen + 1 + k
        for i in 0:7
            padded[off + i + 1] = UInt8((bit_len >> (56 - i * 8)) & 0xff)
        end
    end
    return padded
end

function hexdigest!(ctx::SM3Context)
    return byte2hex(digest!(ctx))
end

# =============================================================================
# SM3 KDF
# =============================================================================

function sm3_kdf(z::AbstractString, klen::Integer)
    z_bytes = hex2byte(z)
    rcnt = ceil(Int, klen / 32)
    result = Vector{UInt8}(undef, rcnt * 32)
    for ct in 1:rcnt
        ct_bytes = UInt8[UInt32(ct) >> 24, (UInt32(ct) >> 16) & 0xff,
                         (UInt32(ct) >> 8) & 0xff,  UInt32(ct) & 0xff]
        msg = vcat(z_bytes, ct_bytes)
        dgst = _digest_bytes(msg)
        o = (ct - 1) * 32
        @inbounds for j in 1:32
            result[o + j] = dgst[j]
        end
    end
    return byte2hex(result[1:klen])
end

function sm3_kdf_bytes(z::AbstractString, klen::Integer)
    z_bytes = hex2byte(z)
    rcnt = ceil(Int, klen / 32)
    result = Vector{UInt8}(undef, rcnt * 32)
    for ct in 1:rcnt
        ct_bytes = UInt8[UInt32(ct) >> 24, (UInt32(ct) >> 16) & 0xff,
                         (UInt32(ct) >> 8) & 0xff,  UInt32(ct) & 0xff]
        msg = vcat(z_bytes, ct_bytes)
        dgst = _digest_bytes(msg)
        o = (ct - 1) * 32
        @inbounds for j in 1:32
            result[o + j] = dgst[j]
        end
    end
    return result[1:klen]
end

"""
    sm3_kdf_from_bytes(z_bytes::Vector{UInt8}, klen::Integer) -> Vector{UInt8}

SM3-based KDF taking raw bytes as input.
"""
function sm3_kdf_from_bytes(z_bytes::Vector{UInt8}, klen::Integer)
    rcnt = ceil(Int, klen / 32)
    result = Vector{UInt8}(undef, rcnt * 32)
    for ct in 1:rcnt
        ct_bytes = UInt8[UInt8(ct >> 24), UInt8((ct >> 16) & 0xff),
                         UInt8((ct >> 8) & 0xff),  UInt8(ct & 0xff)]
        msg = vcat(z_bytes, ct_bytes)
        dgst = _digest_bytes(msg)
        o = (ct - 1) * 32
        @inbounds for j in 1:32
            result[o + j] = dgst[j]
        end
    end
    return result[1:klen]
end

end # module SM3
