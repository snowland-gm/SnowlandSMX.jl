# =============================================================================
# Pure Julia ZUC benchmark (standalone - direct include to avoid GC crash)
# =============================================================================

module BenchZUC
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

include(joinpath(@__DIR__, "..", "..", "src", "smx", "ZUC", "zuc.jl"))
using .ZUC

println("=== ZUC ===")
key = rand(UInt8, 16)
iv = rand(UInt8, 16)

for sz in [16, 1000, 64000, 100_000, 500_000]
    plaintext = rand(UInt8, sz)
    it = sz >= 100_000 ? 100 : 200

    r = BenchZUC.bench(() -> begin
        ctx = ZUC.ZUCContext(key, iv)
        ZUC.zuc_encrypt(ctx, plaintext)
    end, iters=it)
    println("ZUC|enc|$sz|$(BenchZUC.fms(r.median))|$(BenchZUC.fmb(sz, r.median))")
end

# Keystream generation only
for sz in [1000, 64000, 100_000]
    r = BenchZUC.bench(() -> begin
        ctx = ZUC.ZUCContext(key, iv)
        ZUC.zuc_generate_keystream(ctx, sz)
    end, iters=sz >= 64000 ? 100 : 200)
    println("ZUC|keystream|$sz|$(BenchZUC.fms(r.median))|$(BenchZUC.fmb(sz, r.median))")
end

# Context init
r = BenchZUC.bench(() -> ZUC.ZUCContext(key, iv), iters=5000)
println("ZUC|ctx_init|0|$(BenchZUC.fms(r.median))|0")

println("DONE")
