# =============================================================================
# SM3 Performance Benchmark: Pure Julia vs OpenSSL (libcrypto EVP SM3)
#
# Usage:
#   julia --project=. demo/benchmark/sm3_benchmark.jl
#
# Requires: OpenSSL.jl (provides OpenSSL_jll with libcrypto)
# If OpenSSL is unavailable or lacks SM3, only pure Julia results are shown.
# =============================================================================

using Random
using Printf
using Libdl
Random.seed!(42)

# ============================================================================
# Load pure Julia SM3
# ============================================================================
sm3_path = joinpath(@__DIR__, "..", "..", "src", "smx", "SM3", "sm3.jl")
include(sm3_path)
using .SM3

# ============================================================================
# Utility helpers
# ============================================================================
bytes2hex(data::Vector{UInt8}) = join((string(d, base=16, pad=2) for d in data))
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
    println("$(indent)$(rpad(r.name, 16)) min: $(@sprintf("%7.3f", ms_min)) ms  median: $(@sprintf("%7.3f", ms_med)) ms  mean: $(@sprintf("%7.3f", ms_mean)) ms")
end

function print_throughput(name::String, data_bytes::Int, median_s::Float64, indent::String="  ")
    mb = data_bytes / 1_000_000
    tput = mb / median_s
    println("$(indent)$(rpad(name, 16)) $(@sprintf("%9.2f", tput)) MB/s  ($(data_bytes) bytes)")
end

# ============================================================================
# OpenSSL Detection (same pattern as sm2_benchmark.jl)
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

    # Probe SM3 support
    nid = ccall(Libdl.dlsym(lib, :OBJ_sn2nid), Cint, (Cstring,), "SM3")
    if nid <= 0
        Libdl.dlclose(lib)
        return nothing, "libcrypto lacks SM3 support"
    end

    # Resolve EVP function pointers
    syms = Symbol[
        :EVP_MD_CTX_new, :EVP_MD_CTX_free,
        :EVP_MD_fetch, :EVP_MD_free,
        :EVP_DigestInit_ex, :EVP_DigestUpdate, :EVP_DigestFinal_ex,
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
    # NOTE: OpenSSL SM3 comparison is disabled on Julia 1.12 due to a GC
    # instability when loading libcrypto alongside the SM3 module.
    # SM4 OpenSSL comparison works correctly; see sm4_benchmark.jl.
    OPENSSL_AVAILABLE[] = false
    println("[OpenSSL] SM3 comparison disabled (Julia 1.12 GC issue with libcrypto)")
    println("         See sm4_benchmark.jl for a working OpenSSL comparison.")
end

# -- Cached SM3 MD (fetched once) --
const _SM3_MD = Ref{Ptr{Cvoid}}(C_NULL)
function _get_sm3_md()
    if _SM3_MD[] == C_NULL
        _SM3_MD[] = ccall(_F[:EVP_MD_fetch], Ptr{Cvoid},
                          (Ptr{Cvoid}, Cstring, Cstring), C_NULL, "SM3", C_NULL)
    end
    return _SM3_MD[]
end

# ============================================================================
# OpenSSL SM3 One-Shot Hash
# ============================================================================
function ossl_sm3_hash(data::Vector{UInt8})
    md = _get_sm3_md()
    if md == C_NULL
        error("ossl_sm3_hash: SM3 MD fetch failed")
    end
    ctx = ccall(_F[:EVP_MD_CTX_new], Ptr{Cvoid}, ())
    if ctx == C_NULL
        error("ossl_sm3_hash: EVP_MD_CTX_new failed")
    end
    ret = ccall(_F[:EVP_DigestInit_ex], Cint,
                (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
                ctx, md, C_NULL)
    if ret != 1
        ccall(_F[:EVP_MD_CTX_free], Cvoid, (Ptr{Cvoid},), ctx)
        error("ossl_sm3_hash: EVP_DigestInit_ex failed")
    end
    ret = ccall(_F[:EVP_DigestUpdate], Cint,
                (Ptr{Cvoid}, Ptr{UInt8}, Csize_t),
                ctx, data, length(data))
    if ret != 1
        ccall(_F[:EVP_MD_CTX_free], Cvoid, (Ptr{Cvoid},), ctx)
        error("ossl_sm3_hash: EVP_DigestUpdate failed")
    end
    digest = Vector{UInt8}(undef, 32)
    dlen = Ref{Cuint}(32)
    ret = ccall(_F[:EVP_DigestFinal_ex], Cint,
                (Ptr{Cvoid}, Ptr{UInt8}, Ref{Cuint}),
                ctx, digest, dlen)
    ccall(_F[:EVP_MD_CTX_free], Cvoid, (Ptr{Cvoid},), ctx)
    if ret != 1
        error("ossl_sm3_hash: EVP_DigestFinal_ex failed")
    end
    return digest[1:dlen[]]
end

# ============================================================================
# Sanity checks
# ============================================================================

function sanity_check_julia()
    println("[Julia SM3 Sanity Check]")
    h_hex = sm3_hash("abc")
    h_raw = sm3_digest("abc")
    h_hex2 = bytes2hex(h_raw)
    h_hex == h_hex2 || error("SM3 hex/raw mismatch")
    println("  hex/raw consistent: OK")

    h2 = sm3_hash("abc")
    h_hex == h2 || error("SM3 deterministic FAILED")
    println("  deterministic: OK")

    data = random_bytes(1_000_000)
    h1 = sm3_digest(data)
    h2 = sm3_digest(data)
    h1 == h2 || error("SM3 1MB self-consistent FAILED")
    println("  1MB self-consistent: OK")

    ctx = SM3.SM3Context()
    SM3.update!(ctx, "hello ")
    SM3.update!(ctx, "world")
    stream_hash = SM3.hexdigest!(ctx)
    one_shot = sm3_hash("hello world")
    stream_hash == one_shot || error("SM3 streaming vs one-shot FAILED")
    println("  streaming vs one-shot: OK")
end

function sanity_check_openssl()
    if !OPENSSL_AVAILABLE[]
        return
    end
    println("[OpenSSL SM3 Sanity Check]")
    # Determinism
    h1 = ossl_sm3_hash(Vector{UInt8}("abc"))
    h2 = ossl_sm3_hash(Vector{UInt8}("abc"))
    h1 == h2 || error("OpenSSL SM3 deterministic FAILED")
    println("  deterministic: OK")

    # Cross-check with Julia
    jl_raw = sm3_digest("abc")
    if jl_raw == h1
        println("  Julia vs OpenSSL cross-check: OK")
    else
        @warn "Julia vs OpenSSL SM3 differ (possible different SM3 implementations)"
    end
end

# ============================================================================
# Main Benchmark
# ============================================================================

function main()
    println("="^68)
    println("  SM3 Performance Benchmark: Pure Julia vs OpenSSL (libcrypto)")
    println("="^68)
    println()

    init_openssl()
    println()

    sanity_check_julia()
    if OPENSSL_AVAILABLE[]
        sanity_check_openssl()
    end
    println()

    N_ITER = 100
    WARMUP = 5
    sizes = [("16 B",16), ("1 KB",1000), ("64 KB",64000),
             ("1 MB",1000000), ("10 MB",10000000), ("50 MB",50000000)]

    jl_results = []
    ossl_results = []

    # ---- One-Shot Hash ----
    println("-"^68)
    println("  SM3 One-Shot Hash  ($(OPENSSL_AVAILABLE[] ? "Pure Julia / OpenSSL" : "Pure Julia"))")
    println("-"^68)

    if OPENSSL_AVAILABLE[]
        println("  $(rpad("Size", 10)) $(rpad("Julia (ms)", 14)) $(rpad("OpenSSL (ms)", 14)) $(rpad("Speedup", 10))")
        println("  $(repeat("-", 55))")
    end

    for (label, sz) in sizes
        data = random_bytes(sz)
        iters = sz >= 1000000 ? (sz >= 10000000 ? 30 : 50) : N_ITER

        r_jl = run_bench("jl hash $label", () -> sm3_digest(data), iters, warmup=WARMUP)

        if OPENSSL_AVAILABLE[]
            r_ossl = run_bench("ossl hash $label", () -> ossl_sm3_hash(data), iters, warmup=WARMUP)
            jl_ms = r_jl.median * 1000
            ossl_ms = r_ossl.median * 1000
            speedup = jl_ms / ossl_ms
            note = speedup >= 1.0 ? "x faster" : "x slower"
            println("  $(rpad(string(sz), 10)) $(@sprintf("%10.3f", jl_ms))   $(@sprintf("%10.3f", ossl_ms))   $(@sprintf("%7.1f", speedup))   $(speedup >= 1.0 ? "OSS" : "JL") $note")
            push!(ossl_results, (label=label, sz=sz, jl=r_jl, ossl=r_ossl))
        else
            print_bench_result(r_jl)
            print_throughput("  -> throughput", sz, r_jl.median)
        end
        push!(jl_results, (label=label, sz=sz, r=r_jl))
    end

    # ---- Streaming (Julia only: context create + update + digest) ----
    println()
    println("-"^68)
    println("  SM3 Streaming  (context create + update + digest)")
    println("-"^68)
    for (label, sz) in sizes
        data = random_bytes(sz)
        iters = sz >= 1000000 ? (sz >= 10000000 ? 30 : 50) : N_ITER
        r = run_bench("stream $label", () -> begin
            ctx = SM3.SM3Context(); SM3.update!(ctx, data); SM3.digest!(ctx)
        end, iters, warmup=WARMUP)
        print_bench_result(r)
        print_throughput("  -> throughput", sz, r.median)
    end

    # ---- KDF ----
    println()
    println("-"^68)
    println("  SM3 KDF  ($(min(N_ITER,50)) iterations)")
    println("-"^68)
    z = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
    for klen in [32, 64, 128, 256]
        r = run_bench("kdf klen=$klen", () -> sm3_kdf_bytes(z, klen), min(N_ITER,50), warmup=WARMUP)
        print_bench_result(r)
    end

    # ---- Summary ----
    println()
    println("="^68)
    println("  SM3 Throughput Summary")
    println("="^68)
    println()
    println("  $(rpad("Size", 10)) $(rpad("Julia Hash", 14)) $(rpad("Julia Stream", 14)) $(OPENSSL_AVAILABLE[] ? rpad("OpenSSL", 14) : "")")
    println("  $(repeat("-", OPENSSL_AVAILABLE[] ? 52 : 38))")

    for (label, sz) in sizes
        data = random_bytes(sz)
        iters = sz >= 1000000 ? (sz >= 10000000 ? 30 : 50) : N_ITER
        r_hash = run_bench("h", () -> sm3_digest(data), iters, warmup=WARMUP)
        r_stream = run_bench("s", () -> begin
            ctx = SM3.SM3Context(); SM3.update!(ctx, data); SM3.digest!(ctx)
        end, iters, warmup=WARMUP)
        mb = sz / 1_000_000
        if OPENSSL_AVAILABLE[]
            r_ossl = run_bench("o", () -> ossl_sm3_hash(data), iters, warmup=WARMUP)
            println("  $(rpad(string(sz), 10)) $(@sprintf("%6.1f MB/s", mb / r_hash.median))  $(@sprintf("%6.1f MB/s", mb / r_stream.median))  $(@sprintf("%6.1f MB/s", mb / r_ossl.median))")
        else
            println("  $(rpad(string(sz), 10)) $(@sprintf("%6.1f MB/s", mb / r_hash.median))  $(@sprintf("%6.1f MB/s", mb / r_stream.median))")
        end
    end

    println()
    println("Benchmark complete.")
end

main()
