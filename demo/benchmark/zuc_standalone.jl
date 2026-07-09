# =============================================================================
# Pure Julia ZUC benchmark (standalone process)
# =============================================================================

module BenchZUC
using Printf
function bench(f::Function; iters::Int=100, warmup::Int=5)
    for _ in 1:warmup; f(); end
    GC.gc()
    ts = Vector{Float64}(undef, iters)
    for i in 1:iters; ts[i] = @elapsed f(); end
    sort!(ts)
    mid = iters ÷ 2
    med = isodd(iters) ? ts[mid+1] : (ts[mid] + ts[mid+1]) / 2
    return (; min=ts[1], median=med, mean=sum(ts)/iters)
end
fms(t) = @sprintf("%.3f", t * 1000.0)
fmb(sz, t) = @sprintf("%.1f", sz / 1_000_000.0 / t)
end

include(joinpath(@__DIR__, "..", "..", "src", "smx", "ZUC", "zuc.jl"))
using .ZUC

println("=== ZUC ===")
key = zeros(UInt8, 16); iv = zeros(UInt8, 16)
for sz in [16, 1000, 64000, 100_000]
    data = rand(UInt8, sz)
    it = sz >= 100_000 ? 50 : 200
    # encrypt (ctx init + encrypt)
    r = BenchZUC.bench(() -> begin
        ctx = ZUCContext(key, iv); zuc_encrypt(ctx, data)
    end; iters=it)
    println("ZUC|encrypt|$sz|$(BenchZUC.fms(r.median))|$(BenchZUC.fmb(sz, r.median))")
    # keystream gen
    r = BenchZUC.bench(() -> begin
        ctx = ZUCContext(key, iv); zuc_generate_keystream(ctx, sz)
    end; iters=it)
    println("ZUC|keystream|$sz|$(BenchZUC.fms(r.median))|$(BenchZUC.fmb(sz, r.median))")
end
println("DONE")
