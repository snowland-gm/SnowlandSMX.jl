# =============================================================================
# SM2 Performance Benchmark: Pure Julia vs OpenSSL (libcrypto EVP SM2)
#
# Usage:
#   julia --project=. demo/benchmark/sm2_benchmark.jl
#
# Requires: OpenSSL.jl (provides OpenSSL_jll with libcrypto)
# If OpenSSL is unavailable, only pure Julia results are shown.
# =============================================================================

using Random
using Printf
using Libdl
Random.seed!(42)

# ============================================================================
# Load pure Julia SM2 (SM3 must be loaded first as SM2 depends on ..SM3)
# ============================================================================
sm3_path = joinpath(@__DIR__, "..", "..", "src", "smx", "SM3", "sm3.jl")
sm2_path = joinpath(@__DIR__, "..", "..", "src", "smx", "SM2", "sm2.jl")
include(sm3_path)
include(sm2_path)
using .SM2
using .SM3

# ============================================================================
# Utility helpers
# ============================================================================
bytes2hex(data::Vector{UInt8}) = join((string(d, base=16, pad=2) for d in data))
random_hex(len::Int) = join(rand("0123456789abcdef", len))

const TEST_MESSAGE = "Hello, SM2 Performance Benchmark! (32 bytes)"

# ============================================================================
# Benchmark helper
# ============================================================================
function run_bench(name::String, f::Function, n::Int=100; warmup::Int=5)
    for _ in 1:warmup
        f()
    end
    GC.gc()
    ts = Vector{Float64}(undef, n)
    for i in 1:n
        ts[i] = @elapsed f()
    end
    sort!(ts)
    med_idx = n % 2 == 0 ? n >> 1 : (n + 1) >> 1
    med = n % 2 == 0 ? (ts[med_idx] + ts[med_idx+1]) / 2 : ts[med_idx]
    avg = sum(ts) / n
    return (name=name, min=ts[1], median=med, mean=avg, n=n)
end

function print_bench_result(r, indent::String="  ")
    ms_min = r.min * 1000
    ms_med = r.median * 1000
    ms_mean = r.mean * 1000
    println("$(indent)$(rpad(r.name, 12)) min: $(@sprintf("%7.3f", ms_min)) ms  median: $(@sprintf("%7.3f", ms_med)) ms  mean: $(@sprintf("%7.3f", ms_mean)) ms")
end

# ============================================================================
# OpenSSL Detection - use dlsym function pointers for Julia 1.12+ compat
# ============================================================================
const OPENSSL_AVAILABLE = Ref{Bool}(false)
const SM2_ID_BYTES = Vector{UInt8}(codeunits("1234567812345678"))

# Function pointer storage (use raw pointers in ccall to avoid compile-time lib)
const _F = Dict{Symbol,Ptr{Cvoid}}()

# Try to import OpenSSL_jll at top level
const _has_openssl_jll = try
    using OpenSSL_jll
    true
catch
    false
end

function _try_load_openssl()
    if !_has_openssl_jll
        return nothing, "OpenSSL_jll not available"
    end
    local lib::Ptr{Cvoid}
    try
        lib = Libdl.dlopen(OpenSSL_jll.libcrypto)
    catch
        try
            lib = Libdl.dlopen("libcrypto")
        catch
            return nothing, "libcrypto not found"
        end
    end

    # Probe SM2 support
    nid = ccall(Libdl.dlsym(lib, :OBJ_sn2nid), Cint, (Cstring,), "SM2")
    if nid <= 0
        Libdl.dlclose(lib)
        return nothing, "libcrypto lacks SM2 support"
    end

    # Resolve all EVP function pointers
    syms = Symbol[
        :EVP_PKEY_Q_keygen,
        :EVP_MD_CTX_new, :EVP_MD_CTX_free,
        :EVP_MD_fetch, :EVP_MD_free,
        :EVP_DigestSignInit, :EVP_DigestSign,
        :EVP_DigestVerifyInit, :EVP_DigestVerify,
        :EVP_PKEY_CTX_set1_id,
        :EVP_PKEY_CTX_new_from_pkey, :EVP_PKEY_CTX_free,
        :EVP_PKEY_encrypt_init, :EVP_PKEY_encrypt,
        :EVP_PKEY_decrypt_init, :EVP_PKEY_decrypt,
        :EVP_PKEY_free,
    ]
    for sym in syms
        try
            _F[sym] = Libdl.dlsym(lib, sym)
        catch
            Libdl.dlclose(lib)
            return nothing, "symbol $sym not found"
        end
    end

    return lib, ""
end

function init_openssl()
    lib, err = _try_load_openssl()
    if lib === nothing
        if !isempty(err)
            @warn "OpenSSL: $err. Only pure Julia benchmarks will run."
        end
        OPENSSL_AVAILABLE[] = false
        return
    end
    OPENSSL_AVAILABLE[] = true
    println("[OpenSSL] libcrypto loaded with SM2 support (OpenSSL 3.x)")
end

# ============================================================================
# OpenSSL SM2 Operations
#   Each function uses direct ccall with LIBCRYPTO_HANDLE[]
# ============================================================================

# Helper: call an OpenSSL function by raw pointer (Julia 1.12+ compat)
for (sym, name) in [(:F_keygen, :EVP_PKEY_Q_keygen),
    (:F_md_new, :EVP_MD_CTX_new), (:F_md_free, :EVP_MD_CTX_free),
    (:F_md_fetch, :EVP_MD_fetch), (:F_md_free2, :EVP_MD_free),
    (:F_sign_init, :EVP_DigestSignInit), (:F_sign, :EVP_DigestSign),
    (:F_verify_init, :EVP_DigestVerifyInit), (:F_verify, :EVP_DigestVerify),
    (:F_set1_id, :EVP_PKEY_CTX_set1_id),
    (:F_pkey_ctx_new, :EVP_PKEY_CTX_new_from_pkey), (:F_pkey_ctx_free, :EVP_PKEY_CTX_free),
    (:F_enc_init, :EVP_PKEY_encrypt_init), (:F_enc, :EVP_PKEY_encrypt),
    (:F_dec_init, :EVP_PKEY_decrypt_init), (:F_dec, :EVP_PKEY_decrypt),
    (:F_pkey_free, :EVP_PKEY_free)]
    @eval (($sym)()) = _F[$(QuoteNode(name))]
end

# Cached SM3 digest (fetched once from libcrypto)
const _SM3_MD = Ref{Ptr{Cvoid}}(C_NULL)
function _get_sm3_md()
    if _SM3_MD[] == C_NULL
        _SM3_MD[] = ccall(F_md_fetch(), Ptr{Cvoid},
                          (Ptr{Cvoid}, Cstring, Cstring),
                          C_NULL, "SM3", C_NULL)
    end
    return _SM3_MD[]
end

function ossl_keygen()
    pkey = ccall(F_keygen(), Ptr{Cvoid},
                 (Ptr{Cvoid}, Cstring, Cstring),
                 C_NULL, C_NULL, "SM2")
    if pkey == C_NULL
        error("ossl_keygen: EVP_PKEY_Q_keygen returned NULL")
    end
    return pkey
end

function ossl_keygen_free(pkey::Ptr{Cvoid})
    ccall(F_pkey_free(), Cvoid, (Ptr{Cvoid},), pkey)
end

function ossl_sign(pkey::Ptr{Cvoid}, msg::Vector{UInt8}, id::Vector{UInt8})
    mdctx = ccall(F_md_new(), Ptr{Cvoid}, ())
    pctx_ref = Ref{Ptr{Cvoid}}(C_NULL)
    sm3_md = _get_sm3_md()
    if sm3_md == C_NULL
        ccall(F_md_free(), Cvoid, (Ptr{Cvoid},), mdctx)
        error("ossl_sign: EVP_MD_fetch SM3 failed")
    end
    ret = ccall(F_sign_init(), Cint,
                (Ptr{Cvoid}, Ref{Ptr{Cvoid}}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
                mdctx, pctx_ref, sm3_md, C_NULL, pkey)
    if ret != 1
        ccall(F_md_free(), Cvoid, (Ptr{Cvoid},), mdctx)
        error("ossl_sign: EVP_DigestSignInit failed")
    end

    pctx = pctx_ref[]
    ret = ccall(F_set1_id(), Cint,
                (Ptr{Cvoid}, Ptr{UInt8}, Cint),
                pctx, id, Cint(length(id)))
    if ret <= 0
        ccall(F_md_free(), Cvoid, (Ptr{Cvoid},), mdctx)
        error("ossl_sign: EVP_PKEY_CTX_set1_id failed")
    end

    siglen = Ref{Csize_t}(0)
    ccall(F_sign(), Cint,
          (Ptr{Cvoid}, Ptr{Cvoid}, Ref{Csize_t}, Ptr{UInt8}, Csize_t),
          mdctx, C_NULL, siglen, msg, length(msg))
    sig = Vector{UInt8}(undef, siglen[])
    ret = ccall(F_sign(), Cint,
                (Ptr{Cvoid}, Ptr{UInt8}, Ref{Csize_t}, Ptr{UInt8}, Csize_t),
                mdctx, sig, siglen, msg, length(msg))
    ccall(F_md_free(), Cvoid, (Ptr{Cvoid},), mdctx)
    if ret != 1
        error("ossl_sign: EVP_DigestSign failed")
    end
    return sig[1:siglen[]]
end

function ossl_verify(pkey::Ptr{Cvoid}, msg::Vector{UInt8}, sig::Vector{UInt8}, id::Vector{UInt8})
    mdctx = ccall(F_md_new(), Ptr{Cvoid}, ())
    pctx_ref = Ref{Ptr{Cvoid}}(C_NULL)
    sm3_md = _get_sm3_md()
    if sm3_md == C_NULL
        ccall(F_md_free(), Cvoid, (Ptr{Cvoid},), mdctx)
        error("ossl_verify: EVP_MD_fetch SM3 failed")
    end
    ret = ccall(F_verify_init(), Cint,
                (Ptr{Cvoid}, Ref{Ptr{Cvoid}}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
                mdctx, pctx_ref, sm3_md, C_NULL, pkey)
    if ret != 1
        ccall(F_md_free(), Cvoid, (Ptr{Cvoid},), mdctx)
        error("ossl_verify: EVP_DigestVerifyInit failed")
    end

    pctx = pctx_ref[]
    ret = ccall(F_set1_id(), Cint,
                (Ptr{Cvoid}, Ptr{UInt8}, Cint),
                pctx, id, Cint(length(id)))
    if ret <= 0
        ccall(F_md_free(), Cvoid, (Ptr{Cvoid},), mdctx)
        error("ossl_verify: EVP_PKEY_CTX_set1_id failed")
    end

    ret = ccall(F_verify(), Cint,
                (Ptr{Cvoid}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t),
                mdctx, sig, length(sig), msg, length(msg))
    ccall(F_md_free(), Cvoid, (Ptr{Cvoid},), mdctx)
    return ret == 1
end

function ossl_encrypt(pkey::Ptr{Cvoid}, plaintext::Vector{UInt8})
    pctx = ccall(F_pkey_ctx_new(), Ptr{Cvoid},
                 (Ptr{Cvoid}, Ptr{Cvoid}, Cstring),
                 C_NULL, pkey, C_NULL)
    if pctx == C_NULL
        error("ossl_encrypt: EVP_PKEY_CTX_new_from_pkey failed")
    end

    ret = ccall(F_enc_init(), Cint, (Ptr{Cvoid},), pctx)
    if ret != 1
        ccall(F_pkey_ctx_free(), Cvoid, (Ptr{Cvoid},), pctx)
        error("ossl_encrypt: EVP_PKEY_encrypt_init failed")
    end

    outlen = Ref{Csize_t}(0)
    ccall(F_enc(), Cint,
          (Ptr{Cvoid}, Ptr{Cvoid}, Ref{Csize_t}, Ptr{UInt8}, Csize_t),
          pctx, C_NULL, outlen, plaintext, length(plaintext))
    out = Vector{UInt8}(undef, outlen[])
    ret = ccall(F_enc(), Cint,
                (Ptr{Cvoid}, Ptr{UInt8}, Ref{Csize_t}, Ptr{UInt8}, Csize_t),
                pctx, out, outlen, plaintext, length(plaintext))
    ccall(F_pkey_ctx_free(), Cvoid, (Ptr{Cvoid},), pctx)
    if ret != 1
        error("ossl_encrypt: EVP_PKEY_encrypt failed")
    end
    return out[1:outlen[]]
end

function ossl_decrypt(pkey::Ptr{Cvoid}, ciphertext::Vector{UInt8})
    pctx = ccall(F_pkey_ctx_new(), Ptr{Cvoid},
                 (Ptr{Cvoid}, Ptr{Cvoid}, Cstring),
                 C_NULL, pkey, C_NULL)
    if pctx == C_NULL
        error("ossl_decrypt: EVP_PKEY_CTX_new_from_pkey failed")
    end

    ret = ccall(F_dec_init(), Cint, (Ptr{Cvoid},), pctx)
    if ret != 1
        ccall(F_pkey_ctx_free(), Cvoid, (Ptr{Cvoid},), pctx)
        error("ossl_decrypt: EVP_PKEY_decrypt_init failed")
    end

    outlen = Ref{Csize_t}(0)
    ccall(F_dec(), Cint,
          (Ptr{Cvoid}, Ptr{Cvoid}, Ref{Csize_t}, Ptr{UInt8}, Csize_t),
          pctx, C_NULL, outlen, ciphertext, length(ciphertext))
    out = Vector{UInt8}(undef, outlen[])
    ret = ccall(F_dec(), Cint,
                (Ptr{Cvoid}, Ptr{UInt8}, Ref{Csize_t}, Ptr{UInt8}, Csize_t),
                pctx, out, outlen, ciphertext, length(ciphertext))
    ccall(F_pkey_ctx_free(), Cvoid, (Ptr{Cvoid},), pctx)
    if ret != 1
        error("ossl_decrypt: EVP_PKEY_decrypt failed")
    end
    return out[1:outlen[]]
end

# ============================================================================
# Sanity checks (self-consistency) before benchmarking
# ============================================================================

function sanity_check_julia()
    println("[Julia SM2 Sanity Check]")
    kp = sm2_generate_keypair()
    priv_hex = kp.privateKey
    pub_hex = bytes2hex(kp.publicKey)
    msg_bytes = Vector{UInt8}(TEST_MESSAGE)
    k_hex = random_hex(64)

    sig = sm2_sign(msg_bytes, priv_hex, k_hex)
    if length(sig) != 64
        error("Julia sign produced signature of length $(length(sig)), expected 64")
    end
    ok = sm2_verify(sig, msg_bytes, pub_hex)
    if !ok
        error("Julia sign/verify self-consistency check FAILED")
    end
    println("  sign/verify: OK")

    ct = sm2_encrypt(msg_bytes, pub_hex)
    pt = sm2_decrypt(ct, priv_hex)
    if pt === nothing || String(pt) != TEST_MESSAGE
        error("Julia encrypt/decrypt self-consistency check FAILED")
    end
    println("  encrypt/decrypt (C1C3C2): OK")

    # Cross-format: C1C2C3
    ct_c123 = sm2_encrypt(msg_bytes, pub_hex, format=:C1C2C3)
    pt_c123 = sm2_decrypt(ct_c123, priv_hex, format=:C1C2C3)
    if pt_c123 === nothing || String(pt_c123) != TEST_MESSAGE
        error("Julia encrypt/decrypt C1C2C3 check FAILED")
    end
    println("  encrypt/decrypt (C1C2C3): OK")

    # Format mix-up detection: C1C2C3 decrypted as C1C3C2 should fail
    pt_wrong = sm2_decrypt(ct_c123, priv_hex)
    if pt_wrong !== nothing && String(pt_wrong) == TEST_MESSAGE
        error("C1C2C3 decrypted as C1C3C2 should have FAILED")
    end
    println("  format mismatch detection: OK")
    return kp
end

function sanity_check_openssl()
    println("[OpenSSL SM2 Sanity Check]")
    pkey = ossl_keygen()
    msg_bytes = Vector{UInt8}(TEST_MESSAGE)
    id_bytes = SM2_ID_BYTES

    sig = ossl_sign(pkey, msg_bytes, id_bytes)
    if !ossl_verify(pkey, msg_bytes, sig, id_bytes)
        ossl_keygen_free(pkey)
        error("OpenSSL sign/verify self-consistency check FAILED")
    end
    println("  sign/verify: OK (sig $(length(sig)) bytes DER)")

    ct = ossl_encrypt(pkey, msg_bytes)
    pt = ossl_decrypt(pkey, ct)
    if String(pt) != TEST_MESSAGE
        ossl_keygen_free(pkey)
        error("OpenSSL encrypt/decrypt self-consistency check FAILED")
    end
    println("  encrypt/decrypt: OK (ct $(length(ct)) bytes)")
    ossl_keygen_free(pkey)
end

# ============================================================================
# Main Benchmark
# ============================================================================

function main()
    println("="^68)
    println("  SM2 Performance Benchmark: Pure Julia vs OpenSSL (libcrypto)")
    println("="^68)
    println()

    init_openssl()
    println()

    kp_jl = sanity_check_julia()
    if OPENSSL_AVAILABLE[]
        sanity_check_openssl()
    end
    println()

    # Test data
    priv_hex_jl = kp_jl.privateKey
    pub_hex_jl = bytes2hex(kp_jl.publicKey)
    msg_bytes = Vector{UInt8}(TEST_MESSAGE)

    k_hex = random_hex(64)
    sig_jl = sm2_sign(msg_bytes, priv_hex_jl, k_hex)
    ct_jl = sm2_encrypt(msg_bytes, pub_hex_jl)

    if OPENSSL_AVAILABLE[]
        ossl_pkey = ossl_keygen()
        ossl_msg = Vector{UInt8}(TEST_MESSAGE)
        ossl_id = SM2_ID_BYTES
        ossl_sig = ossl_sign(ossl_pkey, ossl_msg, ossl_id)
        ossl_ct = ossl_encrypt(ossl_pkey, ossl_msg)
    end

    N_ITER = 100
    WARMUP = 5

    # Pure Julia Benchmarks
    println("-"^68)
    println("  Pure Julia SM2 ($N_ITER iterations, $(WARMUP) warmup)")
    println("-"^68)

    r_jl_keygen = run_bench("keygen", () -> sm2_generate_keypair(), N_ITER, warmup=WARMUP)
    print_bench_result(r_jl_keygen)

    r_jl_sign = run_bench("sign", () -> begin
        k = random_hex(64)
        sm2_sign(msg_bytes, priv_hex_jl, k)
    end, N_ITER, warmup=WARMUP)
    print_bench_result(r_jl_sign)

    r_jl_verify = run_bench("verify", () -> sm2_verify(sig_jl, msg_bytes, pub_hex_jl), N_ITER, warmup=WARMUP)
    print_bench_result(r_jl_verify)

    r_jl_encrypt = run_bench("encrypt", () -> sm2_encrypt(msg_bytes, pub_hex_jl), N_ITER, warmup=WARMUP)
    print_bench_result(r_jl_encrypt)

    r_jl_decrypt = run_bench("decrypt", () -> sm2_decrypt(ct_jl, priv_hex_jl), N_ITER, warmup=WARMUP)
    print_bench_result(r_jl_decrypt)

    # OpenSSL Benchmarks
    if OPENSSL_AVAILABLE[]
        println()
        println("-"^68)
        println("  OpenSSL EVP SM2 ($N_ITER iterations, $(WARMUP) warmup)")
        println("-"^68)

        r_ossl_keygen = run_bench("keygen", () -> begin
            pk = ossl_keygen()
            ossl_keygen_free(pk)
        end, N_ITER, warmup=WARMUP)
        print_bench_result(r_ossl_keygen)

        r_ossl_sign = run_bench("sign", () -> ossl_sign(ossl_pkey, ossl_msg, ossl_id), N_ITER, warmup=WARMUP)
        print_bench_result(r_ossl_sign)

        r_ossl_verify = run_bench("verify", () -> ossl_verify(ossl_pkey, ossl_msg, ossl_sig, ossl_id), N_ITER, warmup=WARMUP)
        print_bench_result(r_ossl_verify)

        r_ossl_encrypt = run_bench("encrypt", () -> ossl_encrypt(ossl_pkey, ossl_msg), N_ITER, warmup=WARMUP)
        print_bench_result(r_ossl_encrypt)

        r_ossl_decrypt = run_bench("decrypt", () -> ossl_decrypt(ossl_pkey, ossl_ct), N_ITER, warmup=WARMUP)
        print_bench_result(r_ossl_decrypt)

        ossl_keygen_free(ossl_pkey)

        # Comparison Table
        println()
        println("="^68)
        println("  Comparison Summary (Julia median / OpenSSL median)")
        println("="^68)
        println()
        println("  $(rpad("Operation", 12)) $(rpad("Julia (ms)", 14)) $(rpad("OpenSSL (ms)", 14)) $(rpad("Speedup", 10))  Note")
        println("  $(repeat("-", 60))")

        for (name, r_jl, r_ossl) in [
            ("keygen", r_jl_keygen, r_ossl_keygen),
            ("sign",    r_jl_sign,    r_ossl_sign),
            ("verify",  r_jl_verify,  r_ossl_verify),
            ("encrypt", r_jl_encrypt, r_ossl_encrypt),
            ("decrypt", r_jl_decrypt, r_ossl_decrypt),
        ]
            jl_ms = r_jl.median * 1000
            ossl_ms = r_ossl.median * 1000
            speedup = jl_ms / ossl_ms
            note = speedup > 1.0 ? "x faster" : "x slower"
            println("  $(rpad(name, 12)) $(@sprintf("%10.3f", jl_ms))   $(@sprintf("%10.3f", ossl_ms))   $(@sprintf("%7.1f", speedup))   $note")
        end
    else
        println()
        println("="^68)
        println("  OpenSSL not available. Only pure Julia results shown.")
        println("  To enable OpenSSL benchmarks: install OpenSSL.jl")
        println("="^68)
    end

    println()
    println("Benchmark complete.")
end

main()
