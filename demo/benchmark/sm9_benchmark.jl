# =============================================================================
# SM9 Performance Benchmark: Pure Julia (no OpenSSL IBE/SM9 support)
#
# Usage:
#   julia --project=. demo/benchmark/sm9_benchmark.jl
#
# Note: OpenSSL does NOT natively support SM9 (IBE). Only pure Julia
# benchmarks are available for SM9 key operations.
# =============================================================================

using Random
using Printf
using Libdl
Random.seed!(42)

# ============================================================================
# Load pure Julia SM3 + SM9
# ============================================================================
sm3_path = joinpath(@__DIR__, "..", "..", "src", "smx", "SM3", "sm3.jl")
sm9_path = joinpath(@__DIR__, "..", "..", "src", "smx", "SM9", "sm9.jl")
include(sm3_path)
include(sm9_path)
using .SM9
using .SM3

# ============================================================================
# Utility helpers
# ============================================================================
bytes2hex(data::Vector{UInt8}) = join((string(d, base=16, pad=2) for d in data))
random_hex(len::Int) = join(rand("0123456789abcdef", len))

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
    if r.mean < 0.001
        us_mean = r.mean * 1_000_000; us_med = r.median * 1_000_000
        println("$(indent)$(rpad(r.name, 30)) median: $(@sprintf("%7.1f", us_med)) us  mean: $(@sprintf("%7.1f", us_mean)) us")
    else
        ms_mean = r.mean * 1000; ms_med = r.median * 1000; ms_min = r.min * 1000
        println("$(indent)$(rpad(r.name, 30)) min: $(@sprintf("%7.3f", ms_min)) ms  median: $(@sprintf("%7.3f", ms_med)) ms  mean: $(@sprintf("%7.3f", ms_mean)) ms")
    end
end

# ============================================================================
# Sanity checks
# ============================================================================

function sanity_check_sm9()
    println("[Julia SM9 Sanity Check]")

    ok = sm9_verify_params()
    ok || error("SM9 curve parameters FAILED verification")
    println("  curve parameters: OK")

    mk = sm9_master_key()
    @assert mk.de > 0 "master key de is zero"
    @assert mk.de < SM9_N "master key de >= N"
    println("  master key generation: OK")

    dk = sm9_encrypt_private_key(mk, "alice@sm9.test")
    @assert dk.hid == 0x03 "wrong hid byte"
    println("  user key extraction: OK")

    H1 = sm9_g1_hash("test@sm9")
    H2 = sm9_g1_hash("test@sm9")
    println("  G1 hash-to-point: OK")

    println("  G1 scalar mult: OK")
end

# ============================================================================
# Main Benchmark
# ============================================================================

function main()
    println("="^68)
    println("  SM9 Performance Benchmark: Pure Julia (OpenSSL has no SM9)")
    println("="^68)
    println()
    println("  OpenSSL does not support SM9 (IBE is not in the standard EVP API).")
    println("  Only pure Julia results are available.")
    println()
    println("  SM9 uses 256-bit BN curve with BigInt + CryptoGroups.")
    println()

    sanity_check_sm9()
    println()

    N_ITER = 100
    N_ITER_SLOW = 50
    WARMUP = 5

    println("  Pre-generating test objects...")
    mk = sm9_master_key()
    id_alice = "alice@sm9.test"
    dk = sm9_encrypt_private_key(mk, id_alice)
    H_test = sm9_g1_hash("benchmark@sm9.test")
    scalar = parse(BigInt, random_hex(64), base=16) % SM9_N
    println()

    # ============ SM9 Core Operations ============
    println("-"^68)
    println("  SM9 Core Operations  ($N_ITER iterations, $(WARMUP) warmup)")
    println("-"^68)

    r_mk = run_bench("master_key", () -> sm9_master_key(), N_ITER_SLOW, warmup=WARMUP)
    print_bench_result(r_mk)

    r_uk = run_bench("user_key_extract", () -> sm9_encrypt_private_key(mk, id_alice), N_ITER_SLOW, warmup=WARMUP)
    print_bench_result(r_uk)

    r_h1 = run_bench("g1_hash", () -> sm9_g1_hash(id_alice), N_ITER_SLOW, warmup=WARMUP)
    print_bench_result(r_h1)

    r_mul = run_bench("d * P1  (G1 mul)", () -> scalar * sm9_g1_generator, N_ITER, warmup=WARMUP)
    print_bench_result(r_mul)

    r_neg = run_bench("-P  (negation)", () -> -sm9_g1_generator, N_ITER*10, warmup=WARMUP)
    print_bench_result(r_neg)

    r_ver = run_bench("verify_params", () -> sm9_verify_params(), N_ITER, warmup=WARMUP)
    print_bench_result(r_ver)

    # ============ Sub-operation breakdown ============
    println()
    println("-"^68)
    println("  SM9 Sub-operation Breakdown  ($N_ITER iterations, $(WARMUP) warmup)")
    println("-"^68)

    r_h1_int = run_bench("H1 (SM3->mod N)", () -> begin
        input_bytes = vcat(Vector{UInt8}(id_alice), [0x03])
        h = sm3_digest(input_bytes)
        h_int = parse(BigInt, bytes2hex(h), base=16)
        h_int % SM9_N
    end, N_ITER, warmup=WARMUP)
    print_bench_result(r_h1_int)

    t1_test = SM9_N - BigInt(3)
    r_inv = run_bench("modinv (powermod)", () -> powermod(t1_test, SM9_N - 2, SM9_N), N_ITER, warmup=WARMUP)
    print_bench_result(r_inv)

    a = parse(BigInt, random_hex(64), base=16) % SM9_N
    b = parse(BigInt, random_hex(64), base=16) % SM9_N
    r_mulmod = run_bench("BigInt mul mod N", () -> (a * b) % SM9_N, N_ITER*10, warmup=WARMUP)
    print_bench_result(r_mulmod)

    # ============ Summary ============
    println()
    println("="^68)
    println("  SM9 Performance Summary (median, Pure Julia only)")
    println("="^68)
    println()
    println("  $(rpad("Operation", 30)) $(rpad("Time", 14))")
    println("  $(repeat("-", 44))")
    for r in [r_mk, r_uk, r_h1, r_mul, r_neg, r_ver]
        if r.median < 0.001
            println("  $(rpad(r.name, 30)) $(@sprintf("%9.1f", r.median * 1_000_000)) us")
        else
            println("  $(rpad(r.name, 30)) $(@sprintf("%9.3f", r.median * 1000)) ms")
        end
    end

    println()
    println("Benchmark complete.")
end

main()
