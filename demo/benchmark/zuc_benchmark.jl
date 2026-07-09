# =============================================================================
# ZUC Performance Benchmark: Pure Julia vs OpenSSL (libcrypto EVP ZUC)
#
# Usage:
#   julia --project=. demo/benchmark/zuc_benchmark.jl
#
# Note: Most OpenSSL builds do NOT include ZUC support (non-default build).
# In that case only pure Julia results are shown.
# =============================================================================

using Random
using Printf
using Libdl
Random.seed!(42)

# ============================================================================
# Load pure Julia ZUC
# ============================================================================
zuc_path = joinpath(@__DIR__, "..", "..", "src", "smx", "ZUC", "zuc.jl")
include(zuc_path)
using .ZUC

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
# OpenSSL Detection (probing ZUC support)
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

    # Probe ZUC support
    nid = ccall(Libdl.dlsym(lib, :OBJ_sn2nid), Cint, (Cstring,), "ZUC")
    if nid <= 0
        # Also try ZUC-128 (older name)
        nid = ccall(Libdl.dlsym(lib, :OBJ_sn2nid), Cint, (Cstring,), "ZUC-128")
    end
    if nid <= 0
        Libdl.dlclose(lib)
        return nothing, "libcrypto lacks ZUC support (NID not found)"
    end

    # Verify EVP_CIPHER_fetch actually returns a cipher
    syms = Symbol[:EVP_CIPHER_fetch, :EVP_CIPHER_free,
                  :EVP_CIPHER_CTX_new, :EVP_CIPHER_CTX_free,
                  :EVP_EncryptInit_ex, :EVP_EncryptUpdate, :EVP_EncryptFinal_ex,
                  :EVP_CIPHER_CTX_set_padding]
    for sym in syms
        try
            _F[sym] = Libdl.dlsym(lib, sym)
        catch
            Libdl.dlclose(lib)
            return nothing, "symbol $sym not found"
        end
    end

    # Actually try to fetch ZUC cipher
    for name in ["ZUC", "ZUC-128", "ZUC128"]
        cipher = ccall(_F[:EVP_CIPHER_fetch], Ptr{Cvoid},
                       (Ptr{Cvoid}, Cstring, Cstring), C_NULL, name, C_NULL)
        if cipher != C_NULL
            ccall(_F[:EVP_CIPHER_free], Cvoid, (Ptr{Cvoid},), cipher)
            return lib, ""
        end
    end

    Libdl.dlclose(lib)
    return nothing, "ZUC EVP_CIPHER_fetch returned NULL (OpenSSL built without ZUC)"
end

function init_openssl()
    lib, err = _try_load_openssl()
    if lib === nothing
        if !isempty(err)
            println("[OpenSSL] $err")
        end
        OPENSSL_AVAILABLE[] = false
        return
    end
    OPENSSL_AVAILABLE[] = true
    println("[OpenSSL] libcrypto loaded with ZUC support")
end

# ============================================================================
# OpenSSL ZUC Encrypt (only defined if ZUC is available)
# ============================================================================

const _ZUC_CIPHER = Ref{Ptr{Cvoid}}(C_NULL)

function _get_zuc_cipher()
    if _ZUC_CIPHER[] == C_NULL
        for name in ["ZUC", "ZUC-128"]
            _ZUC_CIPHER[] = ccall(_F[:EVP_CIPHER_fetch], Ptr{Cvoid},
                                  (Ptr{Cvoid}, Cstring, Cstring), C_NULL, name, C_NULL)
            if _ZUC_CIPHER[] != C_NULL
                break
            end
        end
    end
    return _ZUC_CIPHER[]
end

function ossl_zuc_encrypt(data::Vector{UInt8}, key::Vector{UInt8}, iv::Vector{UInt8})
    cipher = _get_zuc_cipher()
    ctx = ccall(_F[:EVP_CIPHER_CTX_new], Ptr{Cvoid}, ())
    ret = ccall(_F[:EVP_EncryptInit_ex], Cint,
                (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{UInt8}, Ptr{UInt8}),
                ctx, cipher, C_NULL, key, iv)
    ret != 1 && error("ossl_zuc_encrypt: init failed")

    ccall(_F[:EVP_CIPHER_CTX_set_padding], Cvoid, (Ptr{Cvoid}, Cint), ctx, 0)

    n = length(data)
    out = Vector{UInt8}(undef, n + 16)
    outlen = Ref{Cint}(0)
    ret = ccall(_F[:EVP_EncryptUpdate], Cint,
                (Ptr{Cvoid}, Ptr{UInt8}, Ref{Cint}, Ptr{UInt8}, Cint),
                ctx, out, outlen, data, Cint(n))
    ret != 1 && error("ossl_zuc_encrypt: update failed")

    finallen = Ref{Cint}(0)
    ret = ccall(_F[:EVP_EncryptFinal_ex], Cint,
                (Ptr{Cvoid}, Ptr{UInt8}, Ref{Cint}), ctx, out, finallen)
    ccall(_F[:EVP_CIPHER_CTX_free], Cvoid, (Ptr{Cvoid},), ctx)
    ret != 1 && error("ossl_zuc_encrypt: final failed")

    return out[1:outlen[] + finallen[]]
end

# ============================================================================
# Main Benchmark
# ============================================================================

function main()
    println("="^68)
    println("  ZUC Performance Benchmark: Pure Julia vs OpenSSL (libcrypto)")
    println("="^68)
    println()
    println("  Note: ZUC is NOT enabled by default in most OpenSSL builds.")
    println()

    init_openssl()
    if !OPENSSL_AVAILABLE[]
        println("  Only pure Julia benchmarks will run.")
    end
    println()

    N_ITER = 100; WARMUP = 5
    key = zeros(UInt8, 16); iv = zeros(UInt8, 16)

    sizes = [("16 B",16), ("1 KB",1000), ("64 KB",64000),
             ("1 MB",1000000), ("10 MB",10000000), ("50 MB",50000000)]
    test_data = Dict{Int,Vector{UInt8}}()
    for (_, sz) in sizes; test_data[sz] = random_bytes(sz); end

    have_ossl = OPENSSL_AVAILABLE[]

    # ---- Keystream Generation ----
    println("-"^68)
    println("  ZUC Keystream Generation  ($(have_ossl ? "Pure Julia / OpenSSL" : "Pure Julia only"))")
    println("-"^68)
    if have_ossl
        println("  $(rpad("Size", 10)) $(rpad("Julia (ms)", 14)) $(rpad("OpenSSL (ms)", 14)) $(rpad("Speedup", 10))")
        println("  $(repeat("-", 55))")
    end

    for (label, sz) in sizes
        iters = sz >= 1000000 ? (sz >= 10000000 ? 30 : 50) : N_ITER
        r_jl = run_bench("keystream $label", () -> zuc_generate_keystream(ZUCContext(key, iv), sz), iters, warmup=WARMUP)

        if have_ossl
            data = zeros(UInt8, sz)
            r_ossl = run_bench("OSS ks $label", () -> ossl_zuc_encrypt(data, key, iv), iters, warmup=WARMUP)
            jl_ms = r_jl.median * 1000; ossl_ms = r_ossl.median * 1000
            sp = jl_ms / ossl_ms
            println("  $(rpad(string(sz), 10)) $(@sprintf("%10.3f", jl_ms))   $(@sprintf("%10.3f", ossl_ms))   $(@sprintf("%7.1f", sp))   $(sp >= 1.0 ? "OSS" : "JL") $(sp >= 1.0 ? "x faster" : "x slower")")
        else
            print_bench_result(r_jl)
            print_throughput("  -> throughput", sz, r_jl.median)
        end
    end

    # ---- Encrypt ----
    println()
    println("-"^68)
    println("  ZUC Encrypt (init + encrypt)  ($(have_ossl ? "Pure Julia / OpenSSL" : "Pure Julia only"))")
    println("-"^68)
    if have_ossl
        println("  $(rpad("Size", 10)) $(rpad("Julia (ms)", 14)) $(rpad("OpenSSL (ms)", 14)) $(rpad("Speedup", 10))")
        println("  $(repeat("-", 55))")
    end

    for (label, sz) in sizes
        data = test_data[sz]
        iters = sz >= 1000000 ? (sz >= 10000000 ? 30 : 50) : N_ITER
        r_jl = run_bench("encrypt $label", () -> zuc_encrypt(ZUCContext(key, iv), data), iters, warmup=WARMUP)

        if have_ossl
            r_ossl = run_bench("OSS enc $label", () -> ossl_zuc_encrypt(data, key, iv), iters, warmup=WARMUP)
            jl_ms = r_jl.median * 1000; ossl_ms = r_ossl.median * 1000
            sp = jl_ms / ossl_ms
            println("  $(rpad(string(sz), 10)) $(@sprintf("%10.3f", jl_ms))   $(@sprintf("%10.3f", ossl_ms))   $(@sprintf("%7.1f", sp))   $(sp >= 1.0 ? "OSS" : "JL") $(sp >= 1.0 ? "x faster" : "x slower")")
        else
            print_bench_result(r_jl)
            print_throughput("  -> throughput", sz, r_jl.median)
        end
    end

    # ---- Context Init ----
    println()
    println("-"^68)
    println("  ZUC Init (context creation)  ($(N_ITER*10) iterations)")
    println("-"^68)
    r = run_bench("ZUCContext", () -> ZUCContext(key, iv), N_ITER*10, warmup=WARMUP)
    print_bench_result(r)

    # ---- Throughput Summary ----
    println()
    println("="^68)
    println("  ZUC Throughput Summary (MB/s)")
    println("="^68)
    println()
    if have_ossl
        println("  $(rpad("Size", 10)) $(rpad("JL Encrypt", 14)) $(rpad("OSS Encrypt", 14)) $(rpad("JL Keystream", 14)) $(rpad("OSS Keystr", 14))")
        println("  $(repeat("-", 66))")
    else
        println("  $(rpad("Size", 10)) $(rpad("Encrypt", 14)) $(rpad("Keystream", 14))")
        println("  $(repeat("-", 38))")
    end

    for (label, sz) in sizes
        data = test_data[sz]
        iters = sz >= 1000000 ? (sz >= 10000000 ? 30 : 50) : N_ITER
        mb = sz / 1_000_000

        r_enc = run_bench("enc", () -> zuc_encrypt(ZUCContext(key, iv), data), iters, warmup=WARMUP)
        r_ks = run_bench("ks", () -> zuc_generate_keystream(ZUCContext(key, iv), sz), iters, warmup=WARMUP)

        if have_ossl
            r_oe = run_bench("oe", () -> ossl_zuc_encrypt(data, key, iv), iters, warmup=WARMUP)
            r_ok = run_bench("ok", () -> ossl_zuc_encrypt(zeros(UInt8, sz), key, iv), iters, warmup=WARMUP)
            println("  $(rpad(string(sz), 10)) $(@sprintf("%12.1f", mb / r_enc.median)) $(@sprintf("%12.1f", mb / r_oe.median)) $(@sprintf("%12.1f", mb / r_ks.median)) $(@sprintf("%12.1f", mb / r_ok.median))")
        else
            println("  $(rpad(string(sz), 10)) $(@sprintf("%12.1f", mb / r_enc.median)) $(@sprintf("%12.1f", mb / r_ks.median))")
        end
    end

    println()
    println("Benchmark complete.")
end

main()
