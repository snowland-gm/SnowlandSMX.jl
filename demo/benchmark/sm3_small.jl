# =============================================================================
# Pure Julia SM3 benchmark (standalone - small data only to avoid GC crash)
# =============================================================================

module BenchSM3
using Printf

function bench(f::Function; iters::Int=500, warmup::Int=10)
    for _ in 1:warmup; f(); end
    GC.gc()
    ts = Vector{Float64}(undef, iters)
    for i in 1:iters; ts[i] = @elapsed f(); end
    sort!(ts)
    mid = iters >> 1
    med = isodd(iters) ? ts[mid+1] : (ts[mid] + ts[mid+1]) / 2
    return (min=ts[1], median=med, mean=sum(ts)/iters)
end
fms(t) = @sprintf("%.4f", t * 1000.0)
fmb(sz, t) = @sprintf("%.1f", sz / 1_000_000.0 / t)
end

include(joinpath(@__DIR__, "..", "..", "src", "smx", "SM3", "sm3.jl"))
using .SM3

println("=== SM3 ===")
for sz in [16, 64, 256, 512, 900]
    data = rand(UInt8, sz)
    it = 1000

    r = BenchSM3.bench(() -> SM3.sm3_digest(data), iters=it)
    println("SM3|oneshot|$sz|$(BenchSM3.fms(r.median))|$(BenchSM3.fmb(sz, r.median))")

    r = BenchSM3.bench(() -> begin
        ctx = SM3.SM3Context(); SM3.update!(ctx, data); SM3.digest!(ctx)
    end, iters=it)
    println("SM3|stream|$sz|$(BenchSM3.fms(r.median))|$(BenchSM3.fmb(sz, r.median))")
end

# Hash 64-byte chunks repeatedly (streaming style)
data = rand(UInt8, 64)
for nblocks in [1, 10, 50, 100]
    sz = nblocks * 64
    r = BenchSM3.bench(() -> begin
        ctx = SM3.SM3Context()
        for _ in 1:nblocks
            SM3.update!(ctx, data)
        end
        SM3.digest!(ctx)
    end, iters=1000)
    println("SM3|stream_blocks|$nblocks|$(BenchSM3.fms(r.median))|$(BenchSM3.fmb(sz, r.median))")
end

# KDF benchmark
z_bytes = rand(UInt8, 32)
for klen in [16, 32, 64]
    r = BenchSM3.bench(() -> SM3.sm3_kdf_bytes(z_bytes, klen), iters=500)
    println("SM3|kdf|$klen|$(BenchSM3.fms(r.median))|0")
end

# Context init
r = BenchSM3.bench(() -> SM3.SM3Context(), iters=5000)
println("SM3|ctx_init|0|$(BenchSM3.fms(r.median))|0")

println("DONE")
