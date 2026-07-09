# =============================================================================
# Pure Julia SM4 benchmark (standalone process)
# =============================================================================

module BenchSM4
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

include(joinpath(@__DIR__, "..", "..", "src", "smx", "SM4", "sm4.jl"))
import .SM4

println("=== SM4 ===")
key = rand(UInt8, 16); iv = zeros(UInt8, 16)
for sz in [16, 1000, 64000, 100_000, 1_000_000]
    data = rand(UInt8, sz)
    it = sz >= 1_000_000 ? 50 : 200
    # ECB enc
    r = BenchSM4.bench(() -> begin
        s = SM4.Sm4(); SM4.sm4_setkey!(s, key, SM4.ENCRYPT); SM4.sm4_crypt_ecb!(s, data)
    end; iters=it)
    println("SM4|ECB_enc|$sz|$(BenchSM4.fms(r.median))|$(BenchSM4.fmb(sz, r.median))")
    # CBC enc
    r = BenchSM4.bench(() -> begin
        s = SM4.Sm4(); SM4.sm4_setkey!(s, key, SM4.ENCRYPT); SM4.sm4_crypt_cbc!(s, iv, data)
    end; iters=it)
    println("SM4|CBC_enc|$sz|$(BenchSM4.fms(r.median))|$(BenchSM4.fmb(sz, r.median))")
end

# --- Streaming benchmarks ---
println("=== SM4 Streaming ===")
for sz in [16, 1000, 64000, 100_000, 1_000_000]
    data = rand(UInt8, sz)
    out = zeros(UInt8, sz)
    it = sz >= 1_000_000 ? 50 : 200

    # CTR (in-place)
    r = BenchSM4.bench(() -> begin
        ctx = SM4.Sm4Ctr(key, iv)
        SM4.sm4_ctr_xor!(ctx, data, out)
    end; iters=it)
    println("SM4|CTR_enc|$sz|$(BenchSM4.fms(r.median))|$(BenchSM4.fmb(sz, r.median))")
end

# key setup
r = BenchSM4.bench(() -> begin
    s = SM4.Sm4(); SM4.sm4_setkey!(s, rand(UInt8, 16), SM4.ENCRYPT)
end; iters=10000)
println("SM4|keysetup|0|$(BenchSM4.fms(r.median))|0")

# CTR context init
r = BenchSM4.bench(() -> begin
    SM4.Sm4Ctr(rand(UInt8, 16), rand(UInt8, 16))
end; iters=10000)
println("SM4|CTR_init|0|$(BenchSM4.fms(r.median))|0")
println("DONE")
