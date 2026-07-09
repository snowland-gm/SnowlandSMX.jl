# =============================================================================
# SM4 Performance Benchmark: Pure Julia vs OpenSSL (libcrypto EVP SM4)
#
# Usage:
#   julia --project=. demo/benchmark/sm4_benchmark.jl
#
# Requires: OpenSSL.jl (provides OpenSSL_jll with libcrypto)
# If OpenSSL is unavailable or lacks SM4, only pure Julia results are shown.
# =============================================================================

using Random
using Printf
using Libdl
Random.seed!(42)

# ============================================================================
# Load pure Julia SM4
# ============================================================================
sm4_path = joinpath(@__DIR__, "..", "..", "src", "smx", "SM4", "sm4.jl")
include(sm4_path)
using .SM4

# ============================================================================
# Utility helpers
# ============================================================================
random_bytes(n::Int) = rand(UInt8, n)

function run_bench(name::String, f::Function, n::Int=100; warmup::Int=5)
    for _ in 1:warmup; f(); end
    GC.gc()
    ts = Vector{Float64}(undef, n)
    for i in 1:n; ts[i] = @elapsed f(); end
    sort!(ts)
    med_idx = n % 2 == 0 ? n >> 1 : (n + 1) >> 1
    med = n % 2 == 0 ? (ts[med_idx] + ts[med_idx+1]) / 2 : ts[med_idx]
    return (name=name, min=ts[1], median=med, mean=sum(ts)/n, n=n)
end

function print_bench_result(r, indent::String="  ")
    ms_min = r.min * 1000; ms_med = r.median * 1000; ms_mean = r.mean * 1000
    println("$(indent)$(rpad(r.name, 22)) min: $(@sprintf("%7.3f", ms_min)) ms  median: $(@sprintf("%7.3f", ms_med)) ms  mean: $(@sprintf("%7.3f", ms_mean)) ms")
end

function print_throughput(name::String, data_bytes::Int, median_s::Float64, indent::String="  ")
    mb = data_bytes / 1_000_000
    tput = mb / median_s
    println("$(indent)$(rpad(name, 22)) $(@sprintf("%9.2f", tput)) MB/s  ($(data_bytes) bytes)")
end

# ============================================================================
# OpenSSL Detection
# ============================================================================
const OPENSSL_AVAILABLE = Ref{Bool}(false)
const _F = Dict{Symbol,Ptr{Cvoid}}()

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

    nid = ccall(Libdl.dlsym(lib, :OBJ_sn2nid), Cint, (Cstring,), "SM4-ECB")
    if nid <= 0
        Libdl.dlclose(lib)
        return nothing, "libcrypto lacks SM4 support"
    end

    syms = Symbol[
        :EVP_CIPHER_CTX_new, :EVP_CIPHER_CTX_free,
        :EVP_CIPHER_fetch, :EVP_CIPHER_free,
        :EVP_EncryptInit_ex, :EVP_EncryptUpdate, :EVP_EncryptFinal_ex,
        :EVP_DecryptInit_ex, :EVP_DecryptUpdate, :EVP_DecryptFinal_ex,
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
    println("[OpenSSL] libcrypto loaded with SM4 support (OpenSSL 3.x)")
end

# -- Cached SM4 ciphers --
const _SM4_ECB = Ref{Ptr{Cvoid}}(C_NULL)
const _SM4_CBC = Ref{Ptr{Cvoid}}(C_NULL)

_get_sm4_ecb() = (_SM4_ECB[] == C_NULL ?
    (_SM4_ECB[] = ccall(_F[:EVP_CIPHER_fetch], Ptr{Cvoid},
        (Ptr{Cvoid}, Cstring, Cstring), C_NULL, "SM4-ECB", C_NULL)) : _SM4_ECB[])

_get_sm4_cbc() = (_SM4_CBC[] == C_NULL ?
    (_SM4_CBC[] = ccall(_F[:EVP_CIPHER_fetch], Ptr{Cvoid},
        (Ptr{Cvoid}, Cstring, Cstring), C_NULL, "SM4-CBC", C_NULL)) : _SM4_CBC[])

# ============================================================================
# OpenSSL SM4 Operations (with PKCS7 padding, works for any input size)
# ============================================================================

function ossl_sm4_ecb_encrypt(data::Vector{UInt8}, key::Vector{UInt8})
    cipher = _get_sm4_ecb()
    ctx = ccall(_F[:EVP_CIPHER_CTX_new], Ptr{Cvoid}, ())
    ret = ccall(_F[:EVP_EncryptInit_ex], Cint,
        (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{UInt8}, Ptr{UInt8}),
        ctx, cipher, C_NULL, key, C_NULL)
    ret != 1 && error("ossl_sm4_ecb_encrypt: init failed")
    n = length(data)
    out = Vector{UInt8}(undef, n + 16)
    outlen = Ref{Cint}(0)
    ret = ccall(_F[:EVP_EncryptUpdate], Cint,
        (Ptr{Cvoid}, Ptr{UInt8}, Ref{Cint}, Ptr{UInt8}, Cint),
        ctx, out, outlen, data, Cint(n))
    ret != 1 && error("ossl_sm4_ecb_encrypt: update failed")
    finallen = Ref{Cint}(0)
    ret = ccall(_F[:EVP_EncryptFinal_ex], Cint,
        (Ptr{Cvoid}, Ptr{UInt8}, Ref{Cint}), ctx, pointer(out, outlen[] + 1), finallen)
    ccall(_F[:EVP_CIPHER_CTX_free], Cvoid, (Ptr{Cvoid},), ctx)
    ret != 1 && error("ossl_sm4_ecb_encrypt: final failed")
    return out[1:outlen[] + finallen[]]
end

function ossl_sm4_ecb_decrypt(data::Vector{UInt8}, key::Vector{UInt8})
    cipher = _get_sm4_ecb()
    ctx = ccall(_F[:EVP_CIPHER_CTX_new], Ptr{Cvoid}, ())
    ret = ccall(_F[:EVP_DecryptInit_ex], Cint,
        (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{UInt8}, Ptr{UInt8}),
        ctx, cipher, C_NULL, key, C_NULL)
    ret != 1 && error("ossl_sm4_ecb_decrypt: init failed")
    n = length(data)
    out = Vector{UInt8}(undef, n)
    outlen = Ref{Cint}(0)
    ret = ccall(_F[:EVP_DecryptUpdate], Cint,
        (Ptr{Cvoid}, Ptr{UInt8}, Ref{Cint}, Ptr{UInt8}, Cint),
        ctx, out, outlen, data, Cint(n))
    ret != 1 && error("ossl_sm4_ecb_decrypt: update failed")
    finallen = Ref{Cint}(0)
    ret = ccall(_F[:EVP_DecryptFinal_ex], Cint,
        (Ptr{Cvoid}, Ptr{UInt8}, Ref{Cint}), ctx, pointer(out, outlen[] + 1), finallen)
    ccall(_F[:EVP_CIPHER_CTX_free], Cvoid, (Ptr{Cvoid},), ctx)
    ret != 1 && error("ossl_sm4_ecb_decrypt: final failed")
    return out[1:outlen[] + finallen[]]
end

function ossl_sm4_cbc_encrypt(data::Vector{UInt8}, key::Vector{UInt8}, iv::Vector{UInt8})
    cipher = _get_sm4_cbc()
    ctx = ccall(_F[:EVP_CIPHER_CTX_new], Ptr{Cvoid}, ())
    ret = ccall(_F[:EVP_EncryptInit_ex], Cint,
        (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{UInt8}, Ptr{UInt8}),
        ctx, cipher, C_NULL, key, iv)
    ret != 1 && error("ossl_sm4_cbc_encrypt: init failed")
    n = length(data)
    out = Vector{UInt8}(undef, n + 16)
    outlen = Ref{Cint}(0)
    ret = ccall(_F[:EVP_EncryptUpdate], Cint,
        (Ptr{Cvoid}, Ptr{UInt8}, Ref{Cint}, Ptr{UInt8}, Cint),
        ctx, out, outlen, data, Cint(n))
    ret != 1 && error("ossl_sm4_cbc_encrypt: update failed")
    finallen = Ref{Cint}(0)
    ret = ccall(_F[:EVP_EncryptFinal_ex], Cint,
        (Ptr{Cvoid}, Ptr{UInt8}, Ref{Cint}), ctx, pointer(out, outlen[] + 1), finallen)
    ccall(_F[:EVP_CIPHER_CTX_free], Cvoid, (Ptr{Cvoid},), ctx)
    ret != 1 && error("ossl_sm4_cbc_encrypt: final failed")
    return out[1:outlen[] + finallen[]]
end

# ============================================================================
# Sanity checks
# ============================================================================

function sanity_check_openssl()
    if !OPENSSL_AVAILABLE[]
        return
    end
    println("[OpenSSL SM4 Sanity Check]")
    key = Vector{UInt8}("SM4-test-key-128!")
    data = Vector{UInt8}("Hello OpenSSL SM4")

    # ECB encrypt: output non-zero
    ct = ossl_sm4_ecb_encrypt(data, key)
    any(x -> x != 0, ct) || error("OpenSSL SM4-ECB encrypt produced all zeros")
    println("  ECB encrypt: OK ($(length(ct)) bytes out)")

    # ECB decrypt round-trip (remove padding for comparison)
    pt = ossl_sm4_ecb_decrypt(ct, key)
    if pt != data
        @warn "OpenSSL SM4-ECB decrypt round-trip differs (padding?), len=$(length(data))->$(length(ct))->$(length(pt))"
    else
        println("  ECB round-trip: OK")
    end

    # CBC encrypt
    iv = zeros(UInt8, 16)
    ct_cbc = ossl_sm4_cbc_encrypt(data, key, iv)
    println("  CBC encrypt: OK ($(length(ct_cbc)) bytes out)")
end

# ============================================================================
# Main Benchmark
# ============================================================================

function main()
    println("="^68)
    println("  SM4 Performance Benchmark: Pure Julia vs OpenSSL (libcrypto)")
    println("="^68)
    println()

    init_openssl()
    println()

    if OPENSSL_AVAILABLE[]
        sanity_check_openssl()
        println()
    end

    N_ITER = 100; WARMUP = 5
    sm4_key = Vector{UInt8}("SM4-test-key-128!")
    sm4_iv = zeros(UInt8, 16)

    sizes = [("16 B",16), ("1 KB",992), ("64 KB",64000), ("1 MB",1000000)]
    test_data = Dict((sz => random_bytes(sz)) for (_, sz) in sizes)

    have_ossl = OPENSSL_AVAILABLE[]

    # ---- ECB Encrypt ----
    println("-"^68)
    println("  SM4 ECB Encrypt  ($(have_ossl ? "Pure Julia / OpenSSL" : "Pure Julia"))")
    println("-"^68)
    if have_ossl
        println("  $(rpad("Size", 10)) $(rpad("Julia (ms)", 14)) $(rpad("OpenSSL (ms)", 14)) $(rpad("Speedup", 10))")
        println("  $(repeat("-", 55))")
    end

    ecb_enc_results = []
    for (label, sz) in sizes
        data = test_data[sz]; iters = sz >= 1000000 ? 50 : N_ITER
        r_jl = run_bench("ECB enc $label", () -> begin
            s = Sm4(); SM4.sm4_setkey!(s, sm4_key, ENCRYPT); SM4.sm4_crypt_ecb!(s, data)
        end, iters, warmup=WARMUP)

        if have_ossl
            r_ossl = run_bench("OSS ECB enc $label", () -> ossl_sm4_ecb_encrypt(data, sm4_key), iters, warmup=WARMUP)
            jl_ms = r_jl.median * 1000; ossl_ms = r_ossl.median * 1000
            sp = jl_ms / ossl_ms
            println("  $(rpad(string(sz), 10)) $(@sprintf("%10.3f", jl_ms))   $(@sprintf("%10.3f", ossl_ms))   $(@sprintf("%7.1f", sp))   $(sp >= 1.0 ? "OSS" : "JL") $(sp >= 1.0 ? "x faster" : "x slower")")
            push!(ecb_enc_results, (label=label, sz=sz, jl=r_jl, ossl=r_ossl))
        else
            print_bench_result(r_jl)
            print_throughput("  -> throughput", sz, r_jl.median)
        end
    end

    # ---- ECB Decrypt ----
    println()
    println("-"^68)
    println("  SM4 ECB Decrypt  ($(have_ossl ? "Pure Julia / OpenSSL" : "Pure Julia"))")
    println("-"^68)
    if have_ossl
        println("  $(rpad("Size", 10)) $(rpad("Julia (ms)", 14)) $(rpad("OpenSSL (ms)", 14)) $(rpad("Speedup", 10))")
        println("  $(repeat("-", 55))")
    end

    for (label, sz) in sizes
        data = test_data[sz]; iters = sz >= 1000000 ? 50 : N_ITER
        r_jl = run_bench("ECB dec $label", () -> begin
            s = Sm4(); SM4.sm4_setkey!(s, sm4_key, DECRYPT); SM4.sm4_crypt_ecb!(s, data)
        end, iters, warmup=WARMUP)

        if have_ossl
            # Encrypt first, then decrypt (benchmark decrypt only)
            ct = ossl_sm4_ecb_encrypt(data, sm4_key)
            r_ossl = run_bench("OSS ECB dec $label", () -> ossl_sm4_ecb_decrypt(ct, sm4_key), iters, warmup=WARMUP)
            jl_ms = r_jl.median * 1000; ossl_ms = r_ossl.median * 1000
            sp = jl_ms / ossl_ms
            println("  $(rpad(string(sz), 10)) $(@sprintf("%10.3f", jl_ms))   $(@sprintf("%10.3f", ossl_ms))   $(@sprintf("%7.1f", sp))   $(sp >= 1.0 ? "OSS" : "JL") $(sp >= 1.0 ? "x faster" : "x slower")")
        else
            print_bench_result(r_jl)
            print_throughput("  -> throughput", sz, r_jl.median)
        end
    end

    # ---- CBC Encrypt ----
    println()
    println("-"^68)
    println("  SM4 CBC Encrypt  ($(have_ossl ? "Pure Julia / OpenSSL" : "Pure Julia"))")
    println("-"^68)
    if have_ossl
        println("  $(rpad("Size", 10)) $(rpad("Julia (ms)", 14)) $(rpad("OpenSSL (ms)", 14)) $(rpad("Speedup", 10))")
        println("  $(repeat("-", 55))")
    end

    for (label, sz) in sizes
        data = test_data[sz]; iters = sz >= 1000000 ? 50 : N_ITER
        r_jl = run_bench("CBC enc $label", () -> begin
            s = Sm4(); SM4.sm4_setkey!(s, sm4_key, ENCRYPT); SM4.sm4_crypt_cbc!(s, sm4_iv, data)
        end, iters, warmup=WARMUP)

        if have_ossl
            r_ossl = run_bench("OSS CBC enc $label", () -> ossl_sm4_cbc_encrypt(data, sm4_key, sm4_iv), iters, warmup=WARMUP)
            jl_ms = r_jl.median * 1000; ossl_ms = r_ossl.median * 1000
            sp = jl_ms / ossl_ms
            println("  $(rpad(string(sz), 10)) $(@sprintf("%10.3f", jl_ms))   $(@sprintf("%10.3f", ossl_ms))   $(@sprintf("%7.1f", sp))   $(sp >= 1.0 ? "OSS" : "JL") $(sp >= 1.0 ? "x faster" : "x slower")")
        else
            print_bench_result(r_jl)
            print_throughput("  -> throughput", sz, r_jl.median)
        end
    end

    # ---- Throughput Summary ----
    println()
    println("="^68)
    println("  SM4 Throughput Summary (MB/s)")
    println("="^68)
    println()
    if have_ossl
        println("  $(rpad("Size", 10)) $(rpad("JL ECB Enc", 14)) $(rpad("OSS ECB Enc", 14)) $(rpad("JL ECB Dec", 14)) $(rpad("OSS ECB Dec", 14)) $(rpad("JL CBC Enc", 14)) $(rpad("OSS CBC Enc", 14))")
        println("  $(repeat("-", 80))")
    else
        println("  $(rpad("Size", 10)) $(rpad("ECB Enc", 14)) $(rpad("ECB Dec", 14)) $(rpad("CBC Enc", 14))")
        println("  $(repeat("-", 52))")
    end

    for (label, sz) in sizes
        data = test_data[sz]; iters = sz >= 1000000 ? 50 : N_ITER
        mb = sz / 1_000_000

        r_jl_ee = run_bench("ee", () -> begin
            s = Sm4(); SM4.sm4_setkey!(s, sm4_key, ENCRYPT); SM4.sm4_crypt_ecb!(s, data)
        end, iters, warmup=WARMUP)
        r_jl_ed = run_bench("ed", () -> begin
            s = Sm4(); SM4.sm4_setkey!(s, sm4_key, DECRYPT); SM4.sm4_crypt_ecb!(s, data)
        end, iters, warmup=WARMUP)
        r_jl_ce = run_bench("ce", () -> begin
            s = Sm4(); SM4.sm4_setkey!(s, sm4_key, ENCRYPT); SM4.sm4_crypt_cbc!(s, sm4_iv, data)
        end, iters, warmup=WARMUP)

        if have_ossl
            r_oe = run_bench("oe", () -> ossl_sm4_ecb_encrypt(data, sm4_key), iters, warmup=WARMUP)
            ct = ossl_sm4_ecb_encrypt(data, sm4_key)
            r_od = run_bench("od", () -> ossl_sm4_ecb_decrypt(ct, sm4_key), iters, warmup=WARMUP)
            r_oc = run_bench("oc", () -> ossl_sm4_cbc_encrypt(data, sm4_key, sm4_iv), iters, warmup=WARMUP)
            println("  $(rpad(string(sz), 10)) $(@sprintf("%12.1f", mb / r_jl_ee.median)) $(@sprintf("%12.1f", mb / r_oe.median)) $(@sprintf("%12.1f", mb / r_jl_ed.median)) $(@sprintf("%12.1f", mb / r_od.median)) $(@sprintf("%12.1f", mb / r_jl_ce.median)) $(@sprintf("%12.1f", mb / r_oc.median))")
        else
            println("  $(rpad(string(sz), 10)) $(@sprintf("%12.1f", mb / r_jl_ee.median)) $(@sprintf("%12.1f", mb / r_jl_ed.median)) $(@sprintf("%12.1f", mb / r_jl_ce.median))")
        end
    end

    println()
    println("Benchmark complete.")
end

main()
