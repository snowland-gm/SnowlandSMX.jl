module SM4

# =============================================================================
# SM4 - Block Cipher  (GM/T 0002-2012)
#
# Performance optimizations:
#   1. _sm4_round_u32 is the pure-UInt32 core (zero allocation, scalar registers)
#   2. All block-level ops use UInt32 paths: _load_u32x4_be! / _encrypt_block_u32! / _store_u32x4_be!
#   3. sm4_tau does inline S-box lookup on UInt32 bytes (no arrays)
#   4. put_u32_be! writes directly into output buffer (no temp arrays)
#   5. @inbounds on all hot loops
# =============================================================================

export Sm4, sm4_crypt_ecb, sm4_crypt_cbc,
       ENCRYPT, DECRYPT,
       SM4_MODE_ECB, SM4_MODE_CBC, SM4_MODE_CFB, SM4_MODE_OFB, SM4_MODE_CTR,
       SM4_PADDING_NONE, SM4_PADDING_PKCS7,
       Sm4Stream, sm4_stream_update!, sm4_stream_final!,
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

@inline _rotl(x::UInt32, n::Integer)::UInt32 = Base.bitrotate(x, n)

# =============================================================================
# Precomputed T-tables for SM4 round function
#
# Tj[x] = L(Sbox[x] at byte position j), where L is the linear transform
# b ^ (b<<<2) ^ (b<<<10) ^ (b<<<18) ^ (b<<<24).
#
# This replaces 4 S-box lookups + 4 rotl + 4 XOR per round with
# 4 T-table lookups + 3 XOR, saving ~128 rotl + 128 XOR per 16-byte block.
# =============================================================================

@inline function _sm4_make_L(b::UInt32)::UInt32
    return b ⊻ Base.bitrotate(b, 2) ⊻ Base.bitrotate(b, 10) ⊻
           Base.bitrotate(b, 18) ⊻ Base.bitrotate(b, 24)
end

const SM4_T0 = UInt32[_sm4_make_L(UInt32(SboxTable[i]) << 24) for i in 1:256]
const SM4_T1 = UInt32[_sm4_make_L(UInt32(SboxTable[i]) << 16) for i in 1:256]
const SM4_T2 = UInt32[_sm4_make_L(UInt32(SboxTable[i]) << 8)  for i in 1:256]
const SM4_T3 = UInt32[_sm4_make_L(UInt32(SboxTable[i]))        for i in 1:256]

# =============================================================================
# S-box: inline byte-level lookup on UInt32 (zero allocation).
# With T-tables: SM4_T0..T3 combine S-box + linear transform.
# _sm4_tau is kept for key expansion where L differs (rotl 13,23 vs 2,10,18,24).

@inline function _sm4_tau(ka::UInt32)::UInt32
    @inbounds return (UInt32(SboxTable[(ka >> 24) + 1]) << 24) |
                     (UInt32(SboxTable[((ka >> 16) & 0xff) + 1]) << 16) |
                     (UInt32(SboxTable[((ka >> 8)  & 0xff) + 1]) << 8)  |
                      UInt32(SboxTable[( ka        & 0xff) + 1])
end

# Core L-transform for encryption (using precomputed T-tables)
# L(tau(x)) = T0[x_byte0] ^ T1[x_byte1] ^ T2[x_byte2] ^ T3[x_byte3]
@inline function _sm4_lt(ka::UInt32)::UInt32
    @inbounds return SM4_T0[(ka >> 24) + 1] ⊻
                     SM4_T1[((ka >> 16) & 0xff) + 1] ⊻
                     SM4_T2[((ka >> 8)  & 0xff) + 1] ⊻
                     SM4_T3[(ka & 0xff) + 1]
end

# =============================================================================
# SM4 Core Functions
# =============================================================================

@inline function _sm4_calci_rk(ka::UInt32)::UInt32
    bb = _sm4_tau(ka)
    return bb ⊻ _rotl(bb, 13) ⊻ _rotl(bb, 23)
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

    copyto!(sm4.sk, 1, k, 5, 32)
    sm4.mode = mode

    if mode == DECRYPT
        reverse!(sm4.sk)
    end
end

"""
    _sm4_round_u32(sk::Vector{UInt32}, x1::UInt32, x2::UInt32,
                   x3::UInt32, x4::UInt32) -> NTuple{4, UInt32}

Pure-UInt32 SM4 core: runs 32 rounds in scalar registers.
Returns the 4-word final state (x1, x2, x3, x4).
Caller packs in reverse for SM4 output order (x4, x3, x2, x1).
"""
@inline function _sm4_round_u32(sk::Vector{UInt32}, x1::UInt32, x2::UInt32,
                                 x3::UInt32, x4::UInt32)
    @inbounds for rk in sk
        tmp = _sm4_f(x1, x2, x3, x4, rk)
        x1, x2, x3, x4 = x2, x3, x4, tmp
    end
    return (x1, x2, x3, x4)
end

# =============================================================================
# Streaming API (Sm4Stream, helpers) - included inline for visibility
# =============================================================================
include("sm4_stream.jl")

# =============================================================================
# ECB Mode (UInt32 path: load → encrypt → store)
# =============================================================================

"""
    sm4_crypt_ecb!(sm4::Sm4, input_data::Vector{UInt8}) -> Vector{UInt8}

SM4-ECB mode encryption/decryption.  Pre-allocates output buffer.
Uses the UInt32 native path: load 4 words, encrypt, store 4 words.
"""
function sm4_crypt_ecb!(sm4::Sm4, input_data::Vector{UInt8})
    n = length(input_data)
    output_data = Vector{UInt8}(undef, n)
    n_blocks = n >> 4
    blk_u32 = Vector{UInt32}(undef, 4)
    out_u32 = Vector{UInt32}(undef, 4)
    @inbounds for b in 0:n_blocks-1
        byte_off = (b << 4) + 1
        _load_u32x4_be!(blk_u32, input_data, byte_off)
        _sm4_encrypt_block_u32!(sm4.sk, blk_u32, 1, out_u32, 1)
        _store_u32x4_be!(output_data, byte_off, out_u32)
    end
    return output_data
end

# =============================================================================
# CBC Mode (UInt32 path: load → XOR in UInt32 → encrypt → store)
# =============================================================================

"""
    sm4_crypt_cbc!(sm4::Sm4, iv::Vector{UInt8}, input_data::Vector{UInt8}) -> Vector{UInt8}

SM4-CBC mode encryption/decryption.
Uses the UInt32 native path: load chain+block as UInt32, XOR/encrypt/store.
"""
function sm4_crypt_cbc!(sm4::Sm4, iv::Vector{UInt8}, input_data::Vector{UInt8})
    n = length(input_data)
    n_blocks = n >> 4
    output_data = Vector{UInt8}(undef, n)

    chain_u32 = Vector{UInt32}(undef, 4)
    _load_u32x4_be!(chain_u32, iv, 1)
    blk_u32 = Vector{UInt32}(undef, 4)
    dec_u32 = Vector{UInt32}(undef, 4)

    if sm4.mode == ENCRYPT
        @inbounds for b in 0:n_blocks-1
            byte_off = (b << 4) + 1

            # Load plaintext block, XOR with chain in UInt32
            _load_u32x4_be!(blk_u32, input_data, byte_off)
            blk_u32[1] ⊻= chain_u32[1]
            blk_u32[2] ⊻= chain_u32[2]
            blk_u32[3] ⊻= chain_u32[3]
            blk_u32[4] ⊻= chain_u32[4]

            # Encrypt; ciphertext becomes next chain (write directly into chain_u32)
            _sm4_encrypt_block_u32!(sm4.sk, blk_u32, 1, chain_u32, 1)

            # Write ciphertext
            _store_u32x4_be!(output_data, byte_off, chain_u32)
        end
    else  # DECRYPT
        @inbounds for b in 0:n_blocks-1
            byte_off = (b << 4) + 1

            # Load ciphertext block
            _load_u32x4_be!(blk_u32, input_data, byte_off)

            # Decrypt (reversed key schedule)
            _sm4_encrypt_block_u32!(sm4.sk, blk_u32, 1, dec_u32, 1)

            # XOR with chain and write plaintext
            dec_u32[1] ⊻= chain_u32[1]
            dec_u32[2] ⊻= chain_u32[2]
            dec_u32[3] ⊻= chain_u32[3]
            dec_u32[4] ⊻= chain_u32[4]
            _store_u32x4_be!(output_data, byte_off, dec_u32)

            # New chain = current ciphertext block
            chain_u32[1] = blk_u32[1]
            chain_u32[2] = blk_u32[2]
            chain_u32[3] = blk_u32[3]
            chain_u32[4] = blk_u32[4]
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

end # module SM4
