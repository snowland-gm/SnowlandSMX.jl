# =============================================================================
# smx/util/util.jl -- Shared utility functions for SMx modules
#
# Provides hex/byte conversion, BigInt formatting, and buffer I/O helpers
# used by SM2, SM4, SM9, and ZUC.
# =============================================================================

"""
    _hex2bytes(s::AbstractString) -> Vector{UInt8}

Parse a hex string to bytes. Handles odd-length strings by prepending '0'.
"""
function _hex2bytes(s::AbstractString)
    s_stripped = strip(s)
    if length(s_stripped) % 2 != 0
        s_stripped = "0" * s_stripped
    end
    n = length(s_stripped) >> 1
    result = Vector{UInt8}(undef, n)
    @inbounds for i in 1:n
        result[i] = parse(UInt8, s_stripped[2*i-1:2*i], base=16)
    end
    return result
end

"""
    _bytes2hex(data::Vector{UInt8}) -> String

Convert bytes to a lowercase hex string.
"""
const _HEX_DIGITS = UInt8[0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
                           0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66]
function _bytes2hex(data::Vector{UInt8})
    n = length(data)
    buf = Vector{UInt8}(undef, n * 2)
    @inbounds for i in 1:n
        b = data[i]
        buf[2*i - 1] = _HEX_DIGITS[(b >> 4) + 1]
        buf[2*i]     = _HEX_DIGITS[(b & 0x0f) + 1]
    end
    return String(buf)
end

"""
    _bigint_to_hex(x::BigInt, len::Int) -> String

Convert a BigInt to a zero-padded lowercase hex string of specified length.
"""
function _bigint_to_hex(x::BigInt, len::Int)
    return string(x, base=16, pad=len)
end

"""
    _rand_bytes(n::Int) -> Vector{UInt8}

Generate n bytes of cryptographically secure random data.
Uses RandomDevice when available, falls back to default RNG.
"""
function _rand_bytes(n::Int)
    try
        return rand(Random.RandomDevice(), UInt8, n)
    catch
        return rand(UInt8, n)
    end
end

"""
    _rand_bigint(n_bytes::Int) -> BigInt

Generate a random BigInt from n_bytes of secure random data.
"""
function _rand_bigint(n_bytes::Int)
    return parse(BigInt, _bytes2hex(_rand_bytes(n_bytes)), base=16)
end

"""
    _put_u32_be!(buf::Vector{UInt8}, off::Int, n::UInt32)

Write a UInt32 into buf at offset (1-based) in big-endian order.
"""
@inline function _put_u32_be!(buf::Vector{UInt8}, off::Int, n::UInt32)
    @inbounds begin
        buf[off]     = n >> 24
        buf[off + 1] = (n >> 16) & 0xff
        buf[off + 2] = (n >> 8) & 0xff
        buf[off + 3] = n & 0xff
    end
end

"""
    _get_u32_be(data::Vector{UInt8}, off::Int=1) -> UInt32

Read a UInt32 from data at offset (1-based) in big-endian order.
"""
@inline function _get_u32_be(data::Vector{UInt8}, off::Int=1)
    @inbounds return (UInt32(data[off])     << 24) |
                     (UInt32(data[off + 1]) << 16) |
                     (UInt32(data[off + 2]) << 8)  |
                      UInt32(data[off + 3])
end
