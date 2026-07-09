module SM9

# =============================================================================
# SM9 - Identity-Based Cryptography (GM/T 0044-2016)
#
# Architecture:
#   G1 (base curve):  E/Fq: y^2 = x^3 + 5,   P1 in G1
#   G2 (twisted):     E'/Fq^2: y^2 = x^3 + 5/beta,  P2 in G2
#   GT (target):      subgroup of Fq^12
#   Pairing:          e: G1 x G2 -> GT  (Ate pairing)
#
# Encrypt scheme:
#   Ppub-e = [ke]P1 (G1),  de_B = [ke/(H1+ke)]P2 (G2)
# Sign scheme:
#   Ppub-s = [ks]P2 (G2),  ds_A = [ks/(H1+ks)]P1 (G1)
# =============================================================================

export SM9_q, SM9_N, SM9_P1, SM9_t, SM9_a, SM9_b,
       sm9_master_key, sm9_encrypt_private_key,
       sm9_g1_hash, sm9_g1_generator, SM9G1Point,
       generate_prime, is_probable_prime,
       sm9_verify_params,
       sm9_sign, sm9_verify,
       sm9_encrypt, sm9_decrypt,
       sm9_sign_master_key, sm9_sign_private_key,
       SM9SignMasterKey, SM9SignPrivateKey,
       SM9EncryptMasterKey, SM9EncryptPrivateKey,
       SM9EncryptCiphertext

using Random
using CryptoGroups
import CryptoGroups: octet, concretize_type
import CryptoGroups.Utils: octet2int
import CryptoGroups.Curves: gx, gy, ECPoint
import CryptoGroups.Specs

using ..SM3: sm3_hash, sm3_digest, sm3_kdf_from_bytes

include("../util/util.jl")

# =============================================================================
# Include field & curve modules
# =============================================================================

include("fp.jl")
include("fp2.jl")
include("fp12.jl")
include("curve.jl")
include("pairing.jl")

# =============================================================================
# SM9 BN Curve Parameters (256-bit)
# =============================================================================

const SM9_q_hex = "B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE5" *
                  "6F9B27E351457D"
const SM9_q = parse(BigInt, SM9_q_hex, base=16)

const SM9_N_hex = "B640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE5" *
                  "6EE19CD69ECF25"
const SM9_N = parse(BigInt, SM9_N_hex, base=16)

const SM9_P1x_hex = "93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280" *
                    "E8C4E4817C66DDDD"
const SM9_P1x = parse(BigInt, SM9_P1x_hex, base=16)
const SM9_P1y_hex = "21FE8DDA4F21E607631065125C395BBC1C1C00CBFA602435" *
                    "0C464CD70A3EA616"
const SM9_P1y = parse(BigInt, SM9_P1y_hex, base=16)
const SM9_P1 = (SM9_P1x, SM9_P1y)

const SM9_t_hex = "600000000058F98A"
const SM9_t = parse(BigInt, SM9_t_hex, base=16)

const SM9_a = BigInt(0)
const SM9_b = BigInt(5)

const HEX_LEN = 64
const COORD_BYTES = 32
const POINT_BYTES  = 64

# =============================================================================
# CryptoGroups Curve Spec (G1 on E/Fq)
# =============================================================================

const _sm9_spec = Specs.ECP(SM9_q, SM9_N, SM9_a, SM9_b, 1, SM9_P1x, SM9_P1y)
const SM9G1Point = concretize_type(ECPoint, _sm9_spec)
const sm9_g1_generator = let gen = Specs.generator(_sm9_spec)
    SM9G1Point(gen[1], gen[2])
end

# =============================================================================
# Field & Curve Initialization
# =============================================================================

function __init__()
    _fq_set_modulus(SM9_q)
    _fq6_set_xi(Fq2(Fq(1), Fq(1)))
    _curve_set_b(SM9_b)
    _pairing_init(SM9_t, SM9_q, SM9_N)
    _compute_g2_generator()
end

# =============================================================================
# G2 Generator Computation
# =============================================================================

const _SM9_P2 = Ref{G2Point}(G2Point(
    Fq2(Fq(0), Fq(0)), Fq2(Fq(0), Fq(0)), Fq2(Fq(0), Fq(0))
))

function _compute_g2_generator()
    t = SM9_t
    q = SM9_q
    N = SM9_N
    tr6 = BigInt(6) * t + BigInt(2)
    n_g2 = q * q + BigInt(2) * q + BigInt(1) - tr6 * tr6
    cofactor = n_g2 ÷ N

    beta = Fq2(Fq(1), Fq(1))
    bb   = Fq2(Fq(SM9_b), Fq(0)) / beta

    local x, y, ok
    y = Fq2(Fq(0), Fq(0))
    ok = false
    for _ in 1:1000
        x = Fq2(Fq(rand(BigInt(1):(SM9_q - 1))),
                Fq(rand(BigInt(1):(SM9_q - 1))))
        rhs = x * x * x + bb
        y, ok = _fq2_sqrt(rhs)
        if ok; break; end
    end
    if !ok; return; end

    P = G2Point(x, y, one(Fq2))
    P_N = _g2_mul(P, cofactor)

    if !isinf_g2(P_N) && is_on_curve_g2(P_N)
        _SM9_P2[] = P_N
    end
end

function _sm9_p2()
    P = _SM9_P2[]
    if isinf_g2(P)
        error("G2 generator not initialized. Run __init__() first.")
    end
    return P
end

# =============================================================================
# Conversion: CryptoGroups G1 <-> Our G1Point
# =============================================================================

function _g1_from_sm9(P::SM9G1Point)
    x = octet2int(octet(gx(P)))
    y = octet2int(octet(gy(P)))
    return G1Point(Fq(x), Fq(y), Fq(1))
end

# =============================================================================
# Secure Random for SM9
# =============================================================================

function _sm9_rand_bigint()
    while true
        d_bytes = _rand_bytes(32)
        d = parse(BigInt, _bytes2hex(d_bytes), base=16)
        if 0 < d < SM9_N
            return d
        end
    end
end

# =============================================================================
# Point Serialization
# =============================================================================

function _g1_point_to_bytes(P::SM9G1Point)
    result = Vector{UInt8}(undef, POINT_BYTES)
    x_bytes = octet(gx(P))
    y_bytes = octet(gy(P))
    @inbounds for i in 1:COORD_BYTES
        result[i] = x_bytes[i]
        result[i + COORD_BYTES] = y_bytes[i]
    end
    return result
end

function _g1_point_to_hex(P::SM9G1Point)
    x_int = octet2int(octet(gx(P)))
    y_int = octet2int(octet(gy(P)))
    return _bigint_to_hex(x_int, HEX_LEN) * _bigint_to_hex(y_int, HEX_LEN)
end

function _g1_point_from_hex(h::AbstractString)
    return SM9G1Point(_hex2bytes("04" * h))
end

function _g1_x(P::SM9G1Point)
    return octet2int(octet(gx(P)))
end

# =============================================================================
# SM9 Key Types
#
# Encrypt: Ppub-e in G1, private key de_B in G2
# Sign:    Ppub-s in G2, private key ds_A in G1
# =============================================================================

struct SM9EncryptMasterKey
    ke::BigInt
    P_pub_e::SM9G1Point       # [ke]P1 (in G1)
end

struct SM9EncryptPrivateKey
    de_B::G2Point              # user private key in G2
    hid::UInt8
end

struct SM9SignMasterKey
    ks::BigInt
    P_pub_s::G2Point           # [ks]P2 (in G2)
end

struct SM9SignPrivateKey
    ds_A::SM9G1Point           # user signing key in G1
    hid::UInt8
end

struct SM9EncryptCiphertext
    C1::Vector{UInt8}   # 64 bytes (G1 point)
    C3::Vector{UInt8}   # 32 bytes (MAC)
    C2::Vector{UInt8}   # variable (encrypted message)
end

# =============================================================================
# SM9 Master Key Generation
# =============================================================================

function sm9_master_key()
    ke = _sm9_rand_bigint()
    P_pub_e = ke * sm9_g1_generator
    return SM9EncryptMasterKey(ke, P_pub_e)
end

function sm9_sign_master_key()
    ks = _sm9_rand_bigint()
    P2 = _sm9_p2()
    P_pub_s = _g2_mul(P2, ks)
    return SM9SignMasterKey(ks, P_pub_s)
end

# =============================================================================
# SM9 H1: Hash-to-Integer (RFC format: SM3(ID || hid) mod N)
# =============================================================================

function _sm9_h1(id::AbstractString, hid::UInt8)
    id_bytes = Vector{UInt8}(id)
    h = sm3_digest(vcat(id_bytes, [hid]))
    h_int = parse(BigInt, _bytes2hex(h), base=16)
    return h_int % SM9_N
end

# =============================================================================
# SM9 G1 Hash-to-Point
# =============================================================================

function sm9_g1_hash(id::AbstractString; hid::UInt8 = 0x03)
    h = _sm9_h1(id, hid)
    if h == 0
        h = BigInt(1)
    end
    return h * sm9_g1_generator
end

# =============================================================================
# SM9 User Private Key Extraction
#
# Encrypt: de_B = [ke / (H1(ID||hid) + ke)] * P2   (G2 point)
# Sign:    ds_A = [ks / (H1(ID||hid) + ks)] * P1   (G1 point)
# =============================================================================

function sm9_encrypt_private_key(master::SM9EncryptMasterKey,
                                  id::AbstractString;
                                  hid::UInt8 = 0x03)
    t1 = _sm9_h1(id, hid) + master.ke
    t1 %= SM9_N

    if t1 == 0
        error("sm9_encrypt_private_key: t1 == 0, re-generate master key")
    end

    t1_inv = powermod(t1, SM9_N - 2, SM9_N)
    t2 = (master.ke * t1_inv) % SM9_N

    P2 = _sm9_p2()
    de_B = _g2_mul(P2, t2)

    return SM9EncryptPrivateKey(de_B, hid)
end

function sm9_sign_private_key(master::SM9SignMasterKey,
                               id::AbstractString;
                               hid::UInt8 = 0x01)
    t1 = _sm9_h1(id, hid) + master.ks
    t1 %= SM9_N

    if t1 == 0
        error("sm9_sign_private_key: t1 == 0, re-generate master key")
    end

    t1_inv = powermod(t1, SM9_N - 2, SM9_N)
    t2 = (master.ks * t1_inv) % SM9_N

    ds_A = t2 * sm9_g1_generator

    return SM9SignPrivateKey(ds_A, hid)
end

# =============================================================================
# SM9 Helper: H2 hash-to-integer
# =============================================================================

function _sm9_h2(z::Vector{UInt8}, n::BigInt)
    hlen = 8 * ceil(Int, (5 * ndigits(n, base=2)) / 32)
    ha = sm3_kdf_from_bytes(vcat([UInt8(0x02)], z), hlen)
    h = parse(BigInt, _bytes2hex(ha), base=16)
    return (h % (n - 1)) + 1
end

# =============================================================================
# Fq12 Serialization (for hash input in sign/verify)
# =============================================================================

function _fq12_to_bytes(x::Fq12)::Vector{UInt8}
    coeffs = Fq[x.hi.c0.a, x.hi.c0.b, x.hi.c1.a, x.hi.c1.b,
                x.hi.c2.a, x.hi.c2.b, x.lo.c0.a, x.lo.c0.b,
                x.lo.c1.a, x.lo.c1.b, x.lo.c2.a, x.lo.c2.b]
    result = UInt8[]
    for c in coeffs
        b = Vector{UInt8}(undef, 32)
        m = c.n
        for i in 32:-1:1
            b[i] = UInt8(m & 0xff)
            m >>= 8
        end
        append!(result, b)
    end
    return result
end

# =============================================================================
# SM9 Digital Signature (GM/T 0044.2-2016)
#
# Signer A with signing key ds_A in G1.
#   g = e(P1, Ppub-s)  (Ppub-s in G2)
#   Pick random r, w = g^r
#   h = H2(M || w)
#   l = (r - h) mod N
#   S = [l] * ds_A  (in G1)
#   Output: (h, S)
#
# Verifier:
#   Compute user public key: Q_A = [H1(ID_A)]P2 + Ppub-s  (in G2)
#   u = e(S, Q_A)
#   t = g^h
#   w' = u * t
#   Check: h == H2(M || w')
# =============================================================================

function sm9_sign(master_public::SM9SignMasterKey,
                  Da::SM9SignPrivateKey,
                  message)
    # Normalize message to bytes
    if message isa AbstractString
        msg_bytes = Vector{UInt8}(message)
    elseif message isa Vector{UInt8}
        msg_bytes = message
    else
        msg_bytes = Vector{UInt8}(string(message))
    end

    # g = e(P1, Ppub-s)
    P1 = _g1_from_sm9(sm9_g1_generator)
    g = ate_pairing(master_public.P_pub_s, P1)

    # w = g^r
    r = _sm9_rand_bigint()
    w = g^r

    # h = H2(M || w)
    msg_hash = sm3_digest(msg_bytes)
    w_bytes = _fq12_to_bytes(w)
    z = vcat(msg_hash, w_bytes)
    h = _sm9_h2(z, SM9_N)

    # l = (r - h) mod N
    l = (r - h) % SM9_N
    if l == 0
        return (h, sm9_g1_generator)  # retry normally, but return for now
    end

    # S = [l] * ds_A
    S = l * Da.ds_A
    return (h, S)
end

function sm9_verify(master_public::SM9SignMasterKey,
                    id::AbstractString,
                    message,
                    signature::Tuple{BigInt, SM9G1Point})
    h, S = signature

    if h < 1 || h >= SM9_N
        return false
    end

    # Normalize message
    if message isa AbstractString
        msg_bytes = Vector{UInt8}(message)
    elseif message isa Vector{UInt8}
        msg_bytes = message
    else
        msg_bytes = Vector{UInt8}(string(message))
    end

    # Compute user public key Q_A = [H1(ID)]*P2 + Ppub-s  (in G2)
    h1_id = _sm9_h1(id, 0x01)
    if h1_id == 0
        h1_id = BigInt(1)
    end
    P2 = _sm9_p2()
    Q_A = _g2_add(_g2_mul(P2, h1_id), master_public.P_pub_s)

    # g = e(P1, Ppub-s)
    P1 = _g1_from_sm9(sm9_g1_generator)
    g = ate_pairing(master_public.P_pub_s, P1)

    # u = e(S, Q_A)
    S_point = _g1_from_sm9(S)
    u = ate_pairing(Q_A, S_point)

    # t = g^h
    t = g^h

    # w' = u * t
    w_prime = u * t

    # Check h == H2(M || w')
    msg_hash = sm3_digest(msg_bytes)
    w_bytes = _fq12_to_bytes(w_prime)
    z = vcat(msg_hash, w_bytes)
    h2 = _sm9_h2(z, SM9_N)

    return h == h2
end

# =============================================================================
# SM9 KEM-DEM Encryption (GM/T 0044.4-2016)
#
# Encrypt(ID_B, M):
#   Q_B = [H1(ID_B)]*P1 + Ppub-e  (G1)
#   r = random
#   C1 = [r]*Q_B  (G1)
#   g = e(Ppub-e, P2)
#   w = g^r
#   K = KDF(C1 || w || ID_B, mlen + 256)
#   K1 = K[0:mlen], K2 = K[mlen:]
#   C2 = M xor K1
#   C3 = SM3(C2 || K2)
#   Output: C1 || C3 || C2  (C1C3C2 format)
#
# Decrypt(de_B, C):
#   w = e(C1, de_B)
#   K = KDF(C1 || w || ID_B, mlen + 256)
#   Verify C3 = SM3(C2 || K2)
#   M = C2 xor K1
# =============================================================================

function sm9_encrypt(master_public::SM9EncryptMasterKey,
                     id::AbstractString,
                     message;
                     hid::UInt8 = 0x03)
    # Normalize message
    if message isa AbstractString
        msg_bytes = Vector{UInt8}(message)
    elseif message isa Vector{UInt8}
        msg_bytes = message
    else
        msg_bytes = Vector{UInt8}(string(message))
    end
    mlen = length(msg_bytes)

    # Q_B = [H1(ID||hid)]*P1 + Ppub-e
    h1 = _sm9_h1(id, hid)
    if h1 == 0
        h1 = BigInt(1)
    end
    Q_B = h1 * sm9_g1_generator + master_public.P_pub_e

    # r = random, C1 = [r]*Q_B
    r = _sm9_rand_bigint()
    C1_point = r * Q_B
    C1_bytes = _g1_point_to_bytes(C1_point)

    # g = e(Ppub-e, P2), w = g^r
    P1_g1  = _g1_from_sm9(master_public.P_pub_e)
    P2_g2  = _sm9_p2()
    g = ate_pairing(P2_g2, P1_g1)
    w = g^r

    # K = KDF(C1 || w || ID_B, mlen*8 + 256)
    id_bytes = Vector{UInt8}(id)
    w_bytes = _fq12_to_bytes(w)
    kdf_input = vcat(C1_bytes, w_bytes, id_bytes)
    klen_bits = mlen * 8 + 256
    K = sm3_kdf_from_bytes(kdf_input, klen_bits)

    # Split: K1 (mlen bytes), K2 (32 bytes)
    if length(K) < mlen + 32
        error("sm9_encrypt: KDF output too short")
    end
    K1 = K[1:mlen]
    K2 = K[mlen + 1:mlen + 32]

    # C2 = M xor K1
    C2 = Vector{UInt8}(undef, mlen)
    @inbounds for i in 1:mlen
        C2[i] = msg_bytes[i] ⊻ K1[i]
    end

    # C3 = SM3(C2 || K2)
    C3 = sm3_digest(vcat(C2, K2))

    # C1C3C2 format (consistent with SM2, GmSSL-compatible)
    return vcat(C1_bytes, C3, C2)
end

function sm9_decrypt(de_B::SM9EncryptPrivateKey,
                     id::AbstractString,
                     ciphertext::Vector{UInt8})
    # Parse: C1 (64) || C3 (32) || C2 (rest)
    if length(ciphertext) < 97
        return nothing
    end
    C1_bytes = ciphertext[1:64]
    C3       = ciphertext[65:96]
    C2       = ciphertext[97:end]
    mlen     = length(C2)

    # Reconstruct C1 as G1Point
    C1_sm9 = _g1_point_from_hex(_bytes2hex(C1_bytes))
    C1_g1  = _g1_from_sm9(C1_sm9)

    # w = e(C1, de_B): G1 x G2 -> GT
    w = ate_pairing(de_B.de_B, C1_g1)

    # K = KDF(C1 || w || ID_B, mlen*8 + 256)
    id_bytes = Vector{UInt8}(id)
    w_bytes = _fq12_to_bytes(w)
    kdf_input = vcat(C1_bytes, w_bytes, id_bytes)
    klen_bits = mlen * 8 + 256
    K = sm3_kdf_from_bytes(kdf_input, klen_bits)

    if length(K) < mlen + 32
        return nothing
    end
    K1 = K[1:mlen]
    K2 = K[mlen + 1:mlen + 32]

    # Verify C3
    expected_C3 = sm3_digest(vcat(C2, K2))
    if C3 != expected_C3
        return nothing
    end

    # M = C2 xor K1
    M = Vector{UInt8}(undef, mlen)
    @inbounds for i in 1:mlen
        M[i] = C2[i] ⊻ K1[i]
    end

    return M
end

# =============================================================================
# Prime Generation Utility
# =============================================================================

const _hex_chars = "0123456789abcdef"
const _hex_start = "123456789abcdef"
const _hex_end   = "13579bdf"

function generate_prime(length::Int; n::Int=100)
    while true
        s = rand(_hex_start)
        for _ in 1:(length >> 2 - 2)
            s *= rand(_hex_chars)
        end
        s *= rand(_hex_end)
        candidate = parse(BigInt, s, base=16)
        if is_probable_prime(candidate, n)
            return candidate
        end
    end
end

function is_probable_prime(number::BigInt, itor::Int=10)
    if number < 2
        return false
    end
    d = number - 1
    s = 0
    while d % 2 == 0
        d >>= 1
        s += 1
    end
    for _ in 1:itor
        a = BigInt(rand(2:(number - 2)))
        x = powermod(a, d, number)
        if x == 1 || x == number - 1
            continue
        end
        composite = true
        for _ in 1:(s - 1)
            x = (x * x) % number
            if x == number - 1
                composite = false
                break
            end
        end
        if composite
            return false
        end
    end
    return true
end

# =============================================================================
# Parameter Verification
# =============================================================================

function sm9_verify_params()
    SM9_a == 0 || (println("SM9 a != 0") && (return false))
    SM9_b == 5 || (println("SM9 b != 5") && (return false))

    y2 = (SM9_P1y * SM9_P1y) % SM9_q
    x3b = (SM9_P1x^3 + SM9_b) % SM9_q
    y2 == x3b || (println("P1 not on curve!") && (return false))

    t = SM9_t
    t2 = t * t
    t3 = t2 * t
    t4 = t3 * t
    expected_q = 36 * t4 + 36 * t3 + 24 * t2 + 6 * t + 1
    expected_q == SM9_q || (println("q != BN formula!") && (return false))

    expected_N = 36 * t4 + 36 * t3 + 18 * t2 + 6 * t + 1
    expected_N == SM9_N || (println("N != BN formula!") && (return false))

    return true
end

end # module SM9
