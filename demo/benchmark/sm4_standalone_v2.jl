# =============================================================================
# SM4 Batch Benchmark - All Modes via Unified Sm4Stream API
# Covers: ECB batch, CBC batch, ECB stream, CBC stream enc/dec,
#         CFB stream, OFB stream, CTR stream, chunked streaming (64B blocks),
#         key/context init overhead.
# =============================================================================

module BenchSM4
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

include(joinpath(@__DIR__, "..", "..", "src", "smx", "SM4", "sm4.jl"))
using .SM4

const SIZES = [16, 1024, 64000, 100_000, 1_000_000]
key = rand(UInt8, 16)
iv  = rand(UInt8, 16)

function run_one(name::String, sz::Int, f::Function)
    it = sz >= 1_000_000 ? 50 : 200
    r = BenchSM4.bench(f; iters=it)
    println("SM4|$name|$sz|$(BenchSM4.fms(r.median))|$(BenchSM4.fmb(sz, r.median))")
    return r
end

header(s) = println("\n=== SM4 $s ===")

# =============================================================================
# 1. ECB Batch (legacy Sm4 API -- baseline)
# =============================================================================
header("ECB Batch Encrypt")
for sz in SIZES
    data = rand(UInt8, sz)
    run_one("ECB_batch_enc", sz, () -> begin
        s = SM4.Sm4(); SM4.sm4_setkey!(s, key, SM4.ENCRYPT); SM4.sm4_crypt_ecb!(s, data)
    end)
end

header("ECB Batch Decrypt")
for sz in SIZES
    data = rand(UInt8, sz)
    run_one("ECB_batch_dec", sz, () -> begin
        s = SM4.Sm4(); SM4.sm4_setkey!(s, key, SM4.DECRYPT); SM4.sm4_crypt_ecb!(s, data)
    end)
end

# =============================================================================
# 2. ECB Streaming (Sm4Stream)
# =============================================================================
header("ECB Streaming (Sm4Stream)")
for sz in SIZES
    data = rand(UInt8, sz)
    out = zeros(UInt8, sz + 32)
    run_one("ECB_stream_enc", sz, () -> begin
        ctx = SM4.Sm4Stream(key, iv, SM4.SM4_MODE_ECB, SM4.ENCRYPT)
        n = SM4.sm4_stream_update!(ctx, data, out)
        rem = SM4.sm4_stream_final!(ctx, out, n + 1)
        n + rem
    end)
end

# =============================================================================
# 3. CBC Batch (legacy Sm4 API -- baseline)
# =============================================================================
header("CBC Batch Encrypt")
for sz in SIZES
    data = rand(UInt8, sz)
    run_one("CBC_batch_enc", sz, () -> begin
        s = SM4.Sm4(); SM4.sm4_setkey!(s, key, SM4.ENCRYPT); SM4.sm4_crypt_cbc!(s, iv, data)
    end)
end

# =============================================================================
# 4. CBC Streaming Encrypt (Sm4Stream)
# =============================================================================
header("CBC Streaming Encrypt (Sm4Stream)")
for sz in SIZES
    data = rand(UInt8, sz)
    out = zeros(UInt8, sz + 32)
    run_one("CBC_stream_enc", sz, () -> begin
        ctx = SM4.Sm4Stream(key, iv, SM4.SM4_MODE_CBC, SM4.ENCRYPT)
        n = SM4.sm4_stream_update!(ctx, data, out)
        rem = SM4.sm4_stream_final!(ctx, out, n + 1)
        n + rem
    end)
end

# =============================================================================
# 5. CBC Streaming Decrypt (Sm4Stream)
# =============================================================================
header("CBC Streaming Decrypt (Sm4Stream)")
for sz in SIZES
    data = rand(UInt8, sz)
    enc_out = zeros(UInt8, sz + 32)
    enc_ctx = SM4.Sm4Stream(key, iv, SM4.SM4_MODE_CBC, SM4.ENCRYPT)
    enc_n   = SM4.sm4_stream_update!(enc_ctx, data, enc_out)
    enc_rem = SM4.sm4_stream_final!(enc_ctx, enc_out, enc_n + 1)
    ct_data = enc_out[1:enc_n + enc_rem]

    dec_out = zeros(UInt8, length(ct_data) + 16)
    run_one("CBC_stream_dec", sz, () -> begin
        ctx = SM4.Sm4Stream(key, iv, SM4.SM4_MODE_CBC, SM4.DECRYPT)
        n = SM4.sm4_stream_update!(ctx, ct_data, dec_out)
        rem = SM4.sm4_stream_final!(ctx, dec_out, n + 1)
        n + rem
    end)
end

# =============================================================================
# 6. CFB Streaming (Sm4Stream)
# =============================================================================
header("CFB Streaming (Sm4Stream)")
for sz in SIZES
    data = rand(UInt8, sz)
    out = zeros(UInt8, sz)
    run_one("CFB_stream_enc", sz, () -> begin
        ctx = SM4.Sm4Stream(key, iv, SM4.SM4_MODE_CFB, SM4.ENCRYPT)
        SM4.sm4_stream_update!(ctx, data, out)
    end)
end

# =============================================================================
# 7. OFB Streaming (Sm4Stream)
# =============================================================================
header("OFB Streaming (Sm4Stream)")
for sz in SIZES
    data = rand(UInt8, sz)
    out = zeros(UInt8, sz)
    run_one("OFB_stream_enc", sz, () -> begin
        ctx = SM4.Sm4Stream(key, iv, SM4.SM4_MODE_OFB)
        SM4.sm4_stream_update!(ctx, data, out)
    end)
end

# =============================================================================
# 8. CTR Streaming (Sm4Stream)
# =============================================================================
header("CTR Streaming (Sm4Stream)")
for sz in SIZES
    data = rand(UInt8, sz)
    out = zeros(UInt8, sz)
    run_one("CTR_stream_enc", sz, () -> begin
        ctx = SM4.Sm4Stream(key, iv, SM4.SM4_MODE_CTR)
        SM4.sm4_stream_update!(ctx, data, out)
    end)
end

# =============================================================================
# 9. Chunked Streaming (64B blocks) -- simulates real streaming use
# =============================================================================
for (mode_name, mode_val, dir_val, needs_pad) in [
    ("CBC_enc", SM4.SM4_MODE_CBC, SM4.ENCRYPT, true),
    ("CFB_enc", SM4.SM4_MODE_CFB, SM4.ENCRYPT, false),
    ("CTR_enc", SM4.SM4_MODE_CTR, 0, false),
    ("OFB_enc", SM4.SM4_MODE_OFB, 0, false),
]
    header("$mode_name Chunked (64B blocks)")
    chunk = rand(UInt8, 64)
    for nblocks in [1, 10, 100, 1000]
        total_sz = nblocks * 64
        out = zeros(UInt8, total_sz + 32)
        it = total_sz >= 64000 ? 200 : 500
        run_one("$(mode_name)_chunked", total_sz, () -> begin
            ctx = SM4.Sm4Stream(key, iv, mode_val, dir_val)
            off = 1
            for _ in 1:nblocks
                n = SM4.sm4_stream_update!(ctx, chunk, out)
                off += n
            end
            if needs_pad
                rem = SM4.sm4_stream_final!(ctx, out, off)
                off += rem
            end
            off
        end)
    end
end

# =============================================================================
# 10. Key & Context Init Overhead
# =============================================================================
header("Init Overhead")

r = BenchSM4.bench(() -> begin
    s = SM4.Sm4(); SM4.sm4_setkey!(s, rand(UInt8, 16), SM4.ENCRYPT)
end; iters=5000)
println("SM4|keysetup|0|$(BenchSM4.fms(r.median))|0")

r = BenchSM4.bench(() -> SM4.Sm4Stream(rand(UInt8, 16), rand(UInt8, 16), SM4.SM4_MODE_ECB, SM4.ENCRYPT); iters=5000)
println("SM4|ctx_init_ECB|0|$(BenchSM4.fms(r.median))|0")

r = BenchSM4.bench(() -> SM4.Sm4Stream(rand(UInt8, 16), rand(UInt8, 16), SM4.SM4_MODE_CBC, SM4.ENCRYPT); iters=5000)
println("SM4|ctx_init_CBC|0|$(BenchSM4.fms(r.median))|0")

r = BenchSM4.bench(() -> SM4.Sm4Stream(rand(UInt8, 16), rand(UInt8, 16), SM4.SM4_MODE_CFB, SM4.ENCRYPT); iters=5000)
println("SM4|ctx_init_CFB|0|$(BenchSM4.fms(r.median))|0")

r = BenchSM4.bench(() -> SM4.Sm4Stream(rand(UInt8, 16), rand(UInt8, 16), SM4.SM4_MODE_OFB); iters=5000)
println("SM4|ctx_init_OFB|0|$(BenchSM4.fms(r.median))|0")

r = BenchSM4.bench(() -> SM4.Sm4Stream(rand(UInt8, 16), rand(UInt8, 16), SM4.SM4_MODE_CTR); iters=5000)
println("SM4|ctx_init_CTR|0|$(BenchSM4.fms(r.median))|0")

println("DONE")
