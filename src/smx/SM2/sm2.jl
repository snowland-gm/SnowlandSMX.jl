module SM2

# =============================================================================
# SM2 - Elliptic Curve Public Key Cryptography  (GM/T 0003-2012)
#
# Optimizations:
#   1. Point-to-bytes serialization (no hex intermediate)
#   2. Encrypt/decrypt fully byte-based (no hex string conversions)
#   3. CSPRNG via RandomDevice for all key/random material
#   4. sm2_compute_za for ZA prefix in standard-compliant signing
#   5. Shared utilities from crypto/util.jl
# =============================================================================

export sm2_sign, sm2_verify, sm2_encrypt, sm2_decrypt,
       sm2_generate_keypair, sm2_get_hash, sm2_compute_za,
       sm2_N, sm2_P, sm2_G

using Random
using CryptoGroups
import CryptoGroups: octet, concretize_type
import CryptoGroups.Utils: octet2int
import CryptoGroups.Curves: gx, gy, ECPoint
import CryptoGroups.Specs

using ..SM3: sm3_hash, sm3_digest, sm3_kdf_from_bytes

include("../util/util.jl")

# =============================================================================
# SM2 Elliptic Curve Parameters (256-bit prime field)
# =============================================================================

const sm2_N_hex = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"
const sm2_P_hex = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"
const sm2_Gx_hex = "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7"
const sm2_Gy_hex = "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"
const sm2_a_hex = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"
const sm2_b_hex = "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"

const sm2_N = parse(BigInt, sm2_N_hex, base=16)
const sm2_P = parse(BigInt, sm2_P_hex, base=16)
const sm2_a = parse(BigInt, sm2_a_hex, base=16)
const sm2_b = parse(BigInt, sm2_b_hex, base=16)
const sm2_Gx = parse(BigInt, sm2_Gx_hex, base=16)
const sm2_Gy = parse(BigInt, sm2_Gy_hex, base=16)

const _sm2_spec = Specs.ECP(sm2_P, sm2_N, sm2_a, sm2_b, 1, sm2_Gx, sm2_Gy)
const SM2Point = concretize_type(ECPoint, _sm2_spec)
const sm2_G = let gen = Specs.generator(_sm2_spec)
    SM2Point(gen[1], gen[2])
end

const COORD_BYTES = 32
const POINT_BYTES  = 64
const HEX_LEN      = 64

# Precomputed byte representations of SM2 curve constants (avoids repeated
# BigInt→hex→bytes conversion in sm2_compute_za on every sign/verify call).
const _sm2_a_bytes  = _hex2bytes(sm2_a_hex)
const _sm2_b_bytes  = _hex2bytes(sm2_b_hex)
const _sm2_Gx_bytes = _hex2bytes(sm2_Gx_hex)
const _sm2_Gy_bytes = _hex2bytes(sm2_Gy_hex)

# =============================================================================
# Secure Random BigInt
# =============================================================================

function _sm2_rand_bigint()
    while true
        d_bytes = _rand_bytes(32)
        d = _bytes_to_bigint(d_bytes)
        if 0 < d < sm2_N
            return d
        end
    end
end

function _sm2_rand_hex(n::Int)
    return _bytes2hex(_rand_bytes(n >> 1))
end

# =============================================================================
# Point Serialization (bytes-based, no hex)
# =============================================================================

function _point_to_bytes(P::SM2Point)
    result = Vector{UInt8}(undef, POINT_BYTES)
    x_bytes = octet(gx(P))
    y_bytes = octet(gy(P))
    @inbounds for i in 1:COORD_BYTES
        result[i] = x_bytes[i]
        result[i + COORD_BYTES] = y_bytes[i]
    end
    return result
end

function _point_from_bytes(b::Vector{UInt8})
    return SM2Point(vcat(0x04, b))
end

function _point_x(P::SM2Point)
    return octet2int(octet(gx(P)))
end

function _point_to_hex(P::SM2Point)
    x_int = octet2int(octet(gx(P)))
    y_int = octet2int(octet(gy(P)))
    return _bigint_to_hex(x_int, HEX_LEN) * _bigint_to_hex(y_int, HEX_LEN)
end

function _point_from_hex(h::AbstractString)
    return SM2Point(_hex2bytes("04" * h))
end

# =============================================================================
# SM2 ZA Computation (GM/T 0003.2-2012, Section 5.5)
# =============================================================================

"""
    sm2_compute_za(id::AbstractString, pubkey::Vector{UInt8}) -> Vector{UInt8}

Compute ZA = SM3(ENTL || ID || a || b || xG || yG || xA || yA).

- id: user's distinguishable identifier (e.g. "1234567812345678")
- pubkey: user's public key as 64 bytes (x || y)

Returns 32-byte ZA digest.
"""
function sm2_compute_za(id::AbstractString, pubkey::Vector{UInt8})
    id_bytes = Vector{UInt8}(id)
    entl = UInt16(length(id_bytes) * 8)

    # Preallocated buffer: 2 (ENTL) + |id| + 4*32 (a,b,xG,yG) + 64 (pubkey)
    za_input = Vector{UInt8}(undef, 2 + length(id_bytes) + 4 * COORD_BYTES + POINT_BYTES)
    off = 1
    za_input[off] = (entl >> 8) & 0xff; off += 1
    za_input[off] = entl & 0xff;        off += 1
    copyto!(za_input, off, id_bytes, 1, length(id_bytes)); off += length(id_bytes)
    copyto!(za_input, off, _sm2_a_bytes,  1, COORD_BYTES); off += COORD_BYTES
    copyto!(za_input, off, _sm2_b_bytes,  1, COORD_BYTES); off += COORD_BYTES
    copyto!(za_input, off, _sm2_Gx_bytes, 1, COORD_BYTES); off += COORD_BYTES
    copyto!(za_input, off, _sm2_Gy_bytes, 1, COORD_BYTES); off += COORD_BYTES
    copyto!(za_input, off, pubkey,        1, POINT_BYTES)

    return sm3_digest(za_input)
end

# =============================================================================
# SM2 Hash Utility
# =============================================================================

function sm2_get_hash(message; Hexstr::Bool=false)
    return sm3_hash(message, hex_input=Hexstr)
end

# =============================================================================
# SM2 Digital Signature (GM/T 0003.2-2012)
# =============================================================================

"""
    sm2_sign(message, DA, id, pubkey; Hexstr=false)
    sm2_sign(message, DA, K; Hexstr=false)

SM2 digital signature with ZA prefix support.

# Arguments
- `message`: the message to sign (String or Vector{UInt8})
- `DA`: private key as hex string (64 chars)
- `id` / `pubkey`: user ID and public key for ZA computation,
   OR `K`: random nonce hex string for deterministic testing
- `Hexstr`: if true, message is already a hex string

# Returns
Signature bytes (r || s, 64 bytes).
"""
function sm2_sign(message, DA::AbstractString, id::AbstractString,
                  pubkey::Union{Vector{UInt8}, AbstractString};
                  Hexstr::Bool=false)
    # Compute ZA
    if pubkey isa AbstractString
        pk_bytes = _hex2bytes(pubkey)
    else
        pk_bytes = pubkey
    end
    za = sm2_compute_za(id, pk_bytes)

    # Hash: ZA || message → SM3
    if Hexstr
        msg_bytes = _hex2bytes(message)
    elseif message isa AbstractString
        msg_bytes = Vector{UInt8}(message)
    elseif message isa Vector{UInt8}
        msg_bytes = message
    else
        msg_bytes = Vector{UInt8}(string(message))
    end
    m_hash = sm3_digest(vcat(za, msg_bytes))

    return _sm2_sign_impl(m_hash, DA)
end

# Legacy overload with explicit K (for testing with fixed nonce)
function sm2_sign(message, DA::AbstractString, K::AbstractString;
                  Hexstr::Bool=false)
    if Hexstr
        e = parse(BigInt, message, base=16)
    else
        if message isa AbstractString
            msg_bytes = Vector{UInt8}(message)
        elseif message isa Vector{UInt8}
            msg_bytes = message
        else
            msg_bytes = Vector{UInt8}(string(message))
        end
        e = _bytes_to_bigint(msg_bytes)
    end
    return _sm2_sign_impl_e(e, DA, K)
end

function _sm2_sign_impl(m_hash::Vector{UInt8}, DA::AbstractString)
    e = _bytes_to_bigint(m_hash)
    d = parse(BigInt, DA, base=16)
    return _sm2_sign_impl_e(e, d)
end

function _sm2_sign_impl_e(e::BigInt, DA::Union{AbstractString, BigInt})
    d = DA isa AbstractString ? parse(BigInt, DA, base=16) : DA

    while true
        k = _sm2_rand_bigint()
        P1 = k * sm2_G
        x = _point_x(P1)
        R = (e + x) % sm2_N

        if R == 0 || R + k == sm2_N
            continue
        end

        d_1 = powermod(d + 1, sm2_N - 2, sm2_N)
        S = (d_1 * (k + R) - R) % sm2_N
        if S == 0
            continue
        end

        # Write R || S directly as bytes (skip hex string construction)
        result = Vector{UInt8}(undef, POINT_BYTES)
        v = R
        @inbounds for i in COORD_BYTES:-1:1
            result[i] = UInt8(v & 0xff)
            v >>= 8
        end
        v = S
        @inbounds for i in COORD_BYTES:-1:1
            result[COORD_BYTES + i] = UInt8(v & 0xff)
            v >>= 8
        end
        return result
    end
end

function _sm2_sign_impl_e(e::BigInt, DA::AbstractString, K::AbstractString)
    d = parse(BigInt, DA, base=16)
    k = parse(BigInt, K, base=16)

    P1 = k * sm2_G
    x = _point_x(P1)
    R = (e + x) % sm2_N

    if R == 0 || R + k == sm2_N
        return UInt8[]
    end

    d_1 = powermod(d + 1, sm2_N - 2, sm2_N)
    S = (d_1 * (k + R) - R) % sm2_N
    if S == 0
        return UInt8[]
    end

    # Write R || S directly as bytes (skip hex string construction)
    result = Vector{UInt8}(undef, POINT_BYTES)
    v = R
    @inbounds for i in COORD_BYTES:-1:1
        result[i] = UInt8(v & 0xff)
        v >>= 8
    end
    v = S
    @inbounds for i in COORD_BYTES:-1:1
        result[COORD_BYTES + i] = UInt8(v & 0xff)
        v >>= 8
    end
    return result
end

# =============================================================================
# SM2 Signature Verification
# =============================================================================

function sm2_verify(Sign::Vector{UInt8}, message, id::AbstractString,
                    pubkey_bytes::Vector{UInt8}; Hexstr::Bool=false)
    za = sm2_compute_za(id, pubkey_bytes)

    if Hexstr
        msg_bytes = _hex2bytes(message)
    elseif message isa AbstractString
        msg_bytes = Vector{UInt8}(message)
    elseif message isa Vector{UInt8}
        msg_bytes = message
    else
        msg_bytes = Vector{UInt8}(string(message))
    end
    m_hash = sm3_digest(vcat(za, msg_bytes))

    return _sm2_verify_impl(Sign, m_hash, pubkey_bytes)
end

function sm2_verify(Sign::Vector{UInt8}, E, PA; Hexstr::Bool=false)
    r = _bytes_to_bigint(Sign[1:COORD_BYTES])
    s = _bytes_to_bigint(Sign[COORD_BYTES + 1:POINT_BYTES])

    if Hexstr
        e = parse(BigInt, E, base=16)
    else
        if E isa AbstractString
            E_bytes = Vector{UInt8}(E)
        elseif E isa Vector{UInt8}
            E_bytes = E
        else
            E_bytes = Vector{UInt8}(string(E))
        end
        e = _bytes_to_bigint(E_bytes)
    end

    return _sm2_verify_core(r, s, e, PA)
end

function _sm2_verify_impl(Sign::Vector{UInt8}, m_hash::Vector{UInt8},
                           PA::Vector{UInt8})
    r = _bytes_to_bigint(Sign[1:COORD_BYTES])
    s = _bytes_to_bigint(Sign[COORD_BYTES + 1:POINT_BYTES])
    e = _bytes_to_bigint(m_hash)
    return _sm2_verify_core(r, s, e, PA)
end

function _sm2_verify_core(r::BigInt, s::BigInt, e::BigInt, PA::Union{Vector{UInt8}, AbstractString})
    PA_point = if PA isa Vector{UInt8}
        _point_from_bytes(PA)
    elseif PA isa AbstractString
        _point_from_hex(PA)
    else
        error("PA must be a string or bytes")
    end

    t = (r + s) % sm2_N
    if t == 0
        return false
    end

    P1 = s * sm2_G
    P2 = t * PA_point
    P_result = P1 + P2

    x = _point_x(P_result)
    return r == ((e + x) % sm2_N)
end

# =============================================================================
# SM2 Public Key Encryption (byte-based, no hex conversions)
# =============================================================================

"""
    sm2_encrypt(message, PA; format=:C1C3C2, Hexstr=false) -> Vector{UInt8}

SM2 public key encryption.  Fully byte-based (no hex intermediate).

# Arguments
- `message`: plaintext string or Vector{UInt8}
- `PA`: recipient's public key as hex string or 64 bytes (x || y)

# Keyword Arguments
- `format::Symbol`: ciphertext layout, `:C1C3C2` (default, GMT 0009-2012 standard
  and GmSSL-compatible) or `:C1C2C3` (legacy format).
- `Hexstr::Bool=false`: if true, message is already a hex string.

# Returns
Ciphertext bytes:
- `:C1C3C2` → C1 (64 bytes) || C3 (32 bytes) || C2 (variable)
- `:C1C2C3` → C1 (64 bytes) || C2 (variable) || C3 (32 bytes)
"""
function sm2_encrypt(message, PA; format::Symbol=:C1C3C2, Hexstr::Bool=false)
    # Normalize message to bytes
    if Hexstr
        msg = _hex2bytes(message)
    elseif message isa AbstractString
        msg = Vector{UInt8}(message)
    elseif message isa Vector{UInt8}
        msg = message
    else
        msg = Vector{UInt8}(string(message))
    end

    # Normalize public key
    if PA isa Vector{UInt8}
        PA_point = _point_from_bytes(PA)
    elseif PA isa AbstractString
        PA_point = _point_from_hex(PA)
    else
        error("PA must be a string or bytes")
    end

    ml = length(msg)

    # Generate random k
    k = _sm2_rand_bigint()

    # C1 = k * G  (64 bytes)
    C1_point = k * sm2_G
    C1 = _point_to_bytes(C1_point)

    # (x2, y2) = k * PA  (64 bytes)
    xy_point = k * PA_point
    xy_bytes = _point_to_bytes(xy_point)

    # t = KDF(x2 || y2, klen)
    t_bytes = sm3_kdf_from_bytes(xy_bytes, ml)
    if all(iszero, t_bytes)
        return UInt8[]
    end

    # C2 = M xor t
    C2 = Vector{UInt8}(undef, ml)
    @inbounds for i in 1:ml
        C2[i] = msg[i] ⊻ t_bytes[i]
    end

    # C3 = SM3(x2 || M || y2)
    c3_input = Vector{UInt8}(undef, COORD_BYTES + ml + COORD_BYTES)
    copyto!(c3_input, 1, xy_bytes, 1, COORD_BYTES)
    copyto!(c3_input, COORD_BYTES + 1, msg, 1, ml)
    copyto!(c3_input, COORD_BYTES + ml + 1, xy_bytes, COORD_BYTES + 1, COORD_BYTES)
    C3 = sm3_digest(c3_input)

    # Assemble ciphertext: C1 || C3 || C2 (or C1 || C2 || C3)
    total_len = POINT_BYTES + 32 + ml
    result = Vector{UInt8}(undef, total_len)
    copyto!(result, 1, C1, 1, POINT_BYTES)
    if format == :C1C3C2
        copyto!(result, POINT_BYTES + 1, C3, 1, 32)
        copyto!(result, POINT_BYTES + 33, C2, 1, ml)
    elseif format == :C1C2C3
        copyto!(result, POINT_BYTES + 1, C2, 1, ml)
        copyto!(result, POINT_BYTES + ml + 1, C3, 1, 32)
    else
        error("Unknown ciphertext format: $format. Use :C1C3C2 or :C1C2C3")
    end
    return result
end

# =============================================================================
# SM2 Decryption (byte-based)
# =============================================================================

"""
    sm2_decrypt(C::Vector{UInt8}, DA::AbstractString; format=:C1C3C2) -> Vector{UInt8} | Nothing

SM2 decryption.  Fully byte-based.

# Arguments
- `C`: ciphertext bytes
- `DA`: private key as hex string (64 chars)

# Keyword Arguments
- `format::Symbol`: ciphertext layout, `:C1C3C2` (default, GMT 0009-2012 standard
  and GmSSL-compatible) or `:C1C2C3` (legacy format).

# Returns
Plaintext bytes, or `nothing` if C3 verification fails.

# Examples
```julia
# Standard C1C3C2 (default, GmSSL-compatible)
ct = sm2_encrypt("hello", pubkey)                       # outputs C1C3C2
pt = sm2_decrypt(ct, privkey)                           # parses C1C3C2

# Legacy C1C2C3
ct = sm2_encrypt("hello", pubkey, format=:C1C2C3)       # outputs C1C2C3
pt = sm2_decrypt(ct, privkey, format=:C1C2C3)           # parses C1C2C3
```
"""
function sm2_decrypt(C::Vector{UInt8}, DA::AbstractString; format::Symbol=:C1C3C2)
    # Parse C1 (64 bytes), C2, C3 (32 bytes) based on format
    if format == :C1C3C2
        C1 = C[1:POINT_BYTES]
        C3 = C[POINT_BYTES + 1:POINT_BYTES + 32]
        C2 = C[POINT_BYTES + 33:end]
    elseif format == :C1C2C3
        C1 = C[1:POINT_BYTES]
        C2_len = length(C) - POINT_BYTES - 32
        C2 = C[POINT_BYTES + 1:POINT_BYTES + C2_len]
        C3 = C[POINT_BYTES + C2_len + 1:end]
    else
        error("Unknown ciphertext format: $format. Use :C1C3C2 or :C1C2C3")
    end
    cl = length(C2)

    # (x2, y2) = d * C1
    C1_point = _point_from_bytes(C1)
    d = parse(BigInt, DA, base=16)
    xy_point = d * C1_point
    xy_bytes = _point_to_bytes(xy_point)

    # t = KDF(x2 || y2, klen)
    t_bytes = sm3_kdf_from_bytes(xy_bytes, cl)
    if all(iszero, t_bytes)
        return nothing
    end

    # M = C2 xor t
    M = Vector{UInt8}(undef, cl)
    @inbounds for i in 1:cl
        M[i] = C2[i] ⊻ t_bytes[i]
    end

    # Verify: u = SM3(x2 || M || y2) ?= C3
    c3_input = Vector{UInt8}(undef, COORD_BYTES + cl + COORD_BYTES)
    copyto!(c3_input, 1, xy_bytes, 1, COORD_BYTES)
    copyto!(c3_input, COORD_BYTES + 1, M, 1, cl)
    copyto!(c3_input, COORD_BYTES + cl + 1, xy_bytes, COORD_BYTES + 1, COORD_BYTES)
    u = sm3_digest(c3_input)

    if u == C3
        return M
    else
        return nothing
    end
end

# =============================================================================
# Key Generation
# =============================================================================

"""
    SM2KeyPair

SM2 key pair.  publicKey is 64 raw bytes (x || y).
privateKey is a 64-char hex string (usable directly with sm2_sign/decrypt).
"""
struct SM2KeyPair
    publicKey::Vector{UInt8}
    privateKey::String
end

"""
    sm2_generate_keypair() -> SM2KeyPair

Generate an SM2 key pair using CSPRNG.
"""
function sm2_generate_keypair()
    d = _sm2_rand_bigint()
    PA_point = d * sm2_G
    PA_bytes = _point_to_bytes(PA_point)
    d_hex = _bigint_to_hex(d, HEX_LEN)
    return SM2KeyPair(PA_bytes, d_hex)
end

end # module SM2
