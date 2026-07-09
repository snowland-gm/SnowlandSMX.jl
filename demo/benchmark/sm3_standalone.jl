# =============================================================================
# SM3 minimal benchmark (small data only to avoid GC crash)
# =============================================================================
using Printf, Random
using SnowlandSMX.SM3

function bench(f; iters=100, warmup=3)
    for _ in 1:warmup; f(); end
    GC.gc()
    ts = Vector{Float64}(undef, iters)
    for i in 1:iters; ts[i] = @elapsed f(); end
    sort!(ts)
    mid = iters ÷ 2
    return isodd(iters) ? ts[mid+1] : (ts[mid] + ts[mid+1]) / 2
end
fms(t) = @sprintf("%.3f", t * 1000.0)
fmb(sz, t) = @sprintf("%.1f", sz / 1_000_000.0 / t)

println("=== SM3 ===")
for sz in [16, 1000, 32000]
    data = rand(UInt8, sz)
    it = 200
    r = bench(() -> SM3.sm3_digest(data), iters=it)
    println("SM3|oneshot|$(sz)|$(fms(r))|$(fmb(sz, r))")
    r = bench(() -> begin
        ctx = SM3.SM3Context(); SM3.update!(ctx, data); SM3.digest!(ctx)
    end, iters=it)
    println("SM3|stream|$(sz)|$(fms(r))|$(fmb(sz, r))")
end
println("DONE")
