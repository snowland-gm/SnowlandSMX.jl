# =============================================================================
# Pure Julia SM3 benchmark (standalone - direct include)
# Tests: small oneshot, chunked streaming (64B blocks), KDF, context init
# Note: One-shot hash > 64B is affected by Julia 1.12 GC bug
# =============================================================================

module BenchSM3
using Printf

function bench(f::Function; iters::Int=200, warmup::Int=5)
    for _ in 1:warmup; f(); end
    GC.gc()
    ts = Vector{Float64}(undef, iters)
    for i in 1:iters; ts[i] = @elapsed f(); end
    sort!(ts)
    mid = iters >> 1
    med = isodd(iters) ? ts[mid+1] : (ts[mid] + ts[mid+1]) / 2
    return (min=ts[1], median=med, mean=sum(ts)/iters)
end
fms(t) = @sprintf("%.3f", t * 1000.0)
fmb(sz, t) = @sprintf("%.1f", sz / 1_000_000.0 / t)
end

include(joinpath(@__DIR__, "..", "..", "src", "smx", "SM3", "sm3.jl"))
using .SM3

function run_one(name::String, sz::Int, f::Function; iters::Int=200)
    r = BenchSM3.bench(f; iters=iters)
    println("SM3|$name|$sz|$(BenchSM3.fms(r.median))|$(BenchSM3.fmb(sz, r.median))")
    return r
end

header(s) = println("\n=== SM3 $s ===")

# =============================================================================
# 1. One-Shot Hash (safe sizes <= 64B to avoid Julia 1.12 GC bug)
# =============================================================================
header("One-Shot Hash")
for sz in [16, 64]
    data = rand(UInt8, sz)
    run_one("oneshot", sz, () -> SM3.sm3_digest(data))
end

# =============================================================================
# 2. Streaming (single-update + digest)
# =============================================================================
header("Streaming (one-short)")
for sz in [16, 64]
    data = rand(UInt8, sz)
    run_one("stream", sz, () -> begin
        ctx = SM3.SM3Context(); SM3.update!(ctx, data); SM3.digest!(ctx)
    end)
end

# =============================================================================
# 3. Chunked Streaming (64B blocks -- real-world streaming pattern)
# =============================================================================
header("Chunked Streaming (64B blocks)")
chunk = rand(UInt8, 64)
for nblocks in [1, 10, 100, 1000]
    total_sz = nblocks * 64
    it = total_sz >= 64000 ? 200 : 500
    run_one("stream_chunked", total_sz, () -> begin
        ctx = SM3.SM3Context()
        for _ in 1:nblocks
            SM3.update!(ctx, chunk)
        end
        SM3.digest!(ctx)
    end; iters=it)
end

# =============================================================================
# 4. KDF
# =============================================================================
header("KDF")
z_bytes = rand(UInt8, 32)
for klen in [16, 32, 64]
    r = BenchSM3.bench(() -> SM3.sm3_kdf_from_bytes(z_bytes, klen); iters=500)
    println("SM3|kdf|$klen|$(BenchSM3.fms(r.median))|0")
end

# =============================================================================
# 5. Context Init
# =============================================================================
header("Context Init")
r = BenchSM3.bench(() -> SM3.SM3Context(); iters=5000)
println("SM3|ctx_init|0|$(BenchSM3.fms(r.median))|0")

println("DONE")
