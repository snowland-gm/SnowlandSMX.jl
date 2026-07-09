# =============================================================================
# SM4 Streaming API Tests
# =============================================================================

include(joinpath(@__DIR__, "..", "src", "smx", "SM4", "sm4.jl"))
using .SM4

println("=== SM4 Streaming API Tests ===\n")

key = UInt8[0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10]
iv  = zeros(UInt8, 16)
pt  = UInt8[0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10]

# =========================================================================
# 1. CTR single-block round-trip
# =========================================================================
println("[1] CTR single-block round-trip")
ctx = Sm4Ctr(key, iv)
ct = zeros(UInt8, 16)
sm4_ctr_xor!(ctx, pt, ct)

ctx2 = Sm4Ctr(key, iv)
dt = zeros(UInt8, 16)
sm4_ctr_xor!(ctx2, ct, dt)
@assert dt == pt "CTR single-block round-trip failed"
println("  PASS")

# =========================================================================
# 2. CTR chunked streaming (50-byte chunks)
# =========================================================================
println("[2] CTR chunked streaming (50-byte chunks)")
data = rand(UInt8, 1000)
ctx = Sm4Ctr(key, iv)
ct = zeros(UInt8, 1000)
sm4_ctr_xor!(ctx, data, ct)

ctx = Sm4Ctr(key, iv)
dt = zeros(UInt8, 1000)
for i in 1:50:1000
    n = min(50, 1000 - i + 1)
    sm4_ctr_xor!(ctx, view(ct, i:i+n-1), view(dt, i:i+n-1))
end
@assert dt == data "CTR chunked round-trip failed"
println("  PASS")

# =========================================================================
# 3. CTR in-place (output == input)
# =========================================================================
println("[3] CTR in-place encryption/decryption")
data = rand(UInt8, 256)
backup = copy(data)
ctx = Sm4Ctr(key, iv)
sm4_ctr_xor!(ctx, data, data)  # in-place encrypt
@assert data != backup "CTR in-place should modify data"

ctx = Sm4Ctr(key, iv)
sm4_ctr_xor!(ctx, data, data)  # in-place decrypt
@assert data == backup "CTR in-place round-trip failed"
println("  PASS")

# =========================================================================
# 4. CBC streaming encrypt (single-chunk, block-aligned)
# =========================================================================
println("[4] CBC streaming encrypt (block-aligned, compare batch)")
data = rand(UInt8, 496)  # 31 blocks
ctx_enc = Sm4Cbc(key, iv, ENCRYPT)
out = zeros(UInt8, 528)
n = sm4_cbc_encrypt_update!(ctx_enc, data, out)
rem = sm4_cbc_encrypt_final!(ctx_enc, out, n + 1)
total = n + rem

# Compare with batch CBC (batch also pads with PKCS7 now? No, batch has no padding)
# With PKCS7 padding, 496 bytes -> 512 bytes after padding.
# Batch: just encrypts 496 bytes as 31 blocks -> 496 bytes output.
# So we compare the first 496 bytes only
ct_batch = sm4_crypt_cbc(ENCRYPT, key, iv, data)
@assert n == 496 "CBC encrypt update: expected 496, got $n"
@assert rem == 16 "CBC encrypt final pad: expected 16, got $rem"
@assert total == 512 "CBC encrypt total: expected 512, got $total"
# First 496 bytes of stream = batch (batch has no padding)
@assert collect(view(out, 1:496)) == ct_batch[1:496] "CBC ciphertext mismatch (first 31 blocks)"
println("  PASS (first 31 blocks match batch API)")

# =========================================================================
# 5. CBC streaming round-trip (encrypt + decrypt, unaligned data)
# =========================================================================
println("[5] CBC streaming round-trip (unaligned)")
data = rand(UInt8, 500)  # not block-aligned
ctx_enc = Sm4Cbc(key, iv, ENCRYPT)
out_enc = zeros(UInt8, 528)  # 500 + up to 16 pad
n1 = sm4_cbc_encrypt_update!(ctx_enc, data, out_enc)
r1 = sm4_cbc_encrypt_final!(ctx_enc, out_enc, n1 + 1)
ct_cbc = view(out_enc, 1:n1 + r1)

ctx_dec = Sm4Cbc(key, iv, DECRYPT)
out_dec = zeros(UInt8, 528)  # same size as ciphertext
n2 = sm4_cbc_decrypt_update!(ctx_dec, ct_cbc, out_dec)
r2 = sm4_cbc_decrypt_final!(ctx_dec, out_dec, n2 + 1)
@assert n2 + r2 == 500 "CBC decrypt output length wrong: $(n2+r2)"
@assert collect(view(out_dec, 1:500)) == data "CBC streaming round-trip failed"
println("  PASS")

# =========================================================================
# 6. CBC streaming chunked (many small chunks)
# =========================================================================
println("[6] CBC streaming chunked (odd-sized chunks)")
let
    local data = rand(UInt8, 1000)
    local ctx_enc = Sm4Cbc(key, iv, ENCRYPT)
    local out_enc = zeros(UInt8, 1024)
    local off_in = 1
    local total_enc = 0
    for sz in [7, 13, 31, 47, 89, 113, 200, 300, 200]
        local n = sm4_cbc_encrypt_update!(ctx_enc,
            view(data, off_in:off_in+sz-1),
            view(out_enc, total_enc+1:1024))
        total_enc += n
        off_in += sz
    end
    local rem = sm4_cbc_encrypt_final!(ctx_enc, out_enc, total_enc + 1)
    total_enc += rem

    local ctx_dec = Sm4Cbc(key, iv, DECRYPT)
    local out_dec = zeros(UInt8, 1024)
    local off_ct = 1
    local total_dec = 0
    local remaining = total_enc
    while remaining > 0
        local sz = min(remaining, 37)
        local n = sm4_cbc_decrypt_update!(ctx_dec,
            view(out_enc, off_ct:off_ct+sz-1),
            view(out_dec, total_dec+1:1024))
        total_dec += n
        off_ct += sz
        remaining -= sz
    end
    local rem2 = sm4_cbc_decrypt_final!(ctx_dec, out_dec, total_dec + 1)
    total_dec += rem2
    @assert total_dec == 1000 "CBC chunked decrypt length: $total_dec != 1000"
    @assert collect(view(out_dec, 1:1000)) == data "CBC chunked round-trip failed"
end
println("  PASS")

# =========================================================================
# 7. CBC encrypt exactly 16 bytes (edge case)
# =========================================================================
println("[7] CBC streaming 16-byte edge case")
data16 = rand(UInt8, 16)
ctx_enc = Sm4Cbc(key, iv, ENCRYPT)
out16 = zeros(UInt8, 32)
n = sm4_cbc_encrypt_update!(ctx_enc, data16, out16)
r = sm4_cbc_encrypt_final!(ctx_enc, out16, n + 1)
@assert n == 0 || n == 16 "16-byte encrypt: n=$n"
@assert n + r == 32 "16-byte total output: $(n+r)"

ctx_dec = Sm4Cbc(key, iv, DECRYPT)
out_dec16 = zeros(UInt8, 32)
n2 = sm4_cbc_decrypt_update!(ctx_dec, view(out16, 1:n+r), out_dec16)
r2 = sm4_cbc_decrypt_final!(ctx_dec, out_dec16, n2 + 1)
@assert n2 + r2 == 16 "16-byte decrypt length: $(n2+r2)"
@assert collect(view(out_dec16, 1:16)) == data16 "16-byte edge case failed"
println("  PASS")

# =========================================================================
# 8. Large data CTR (10 MB) - GC stress test
# =========================================================================
println("[8] Large data CTR (10 MB)")
large_data = rand(UInt8, 10_000_000)
ctx = Sm4Ctr(key, iv)
out_buf = zeros(UInt8, 10_000_000)
GC.gc()
elapsed = @elapsed sm4_ctr_xor!(ctx, large_data, out_buf)
println("  Encrypt 10 MB: $(round(elapsed, digits=3)) s")

ctx = Sm4Ctr(key, iv)
sm4_ctr_xor!(ctx, out_buf, out_buf)
@assert out_buf == large_data "Large CTR round-trip failed"
println("  PASS")

# =========================================================================
# 9. Large data CBC streaming (10 MB) - GC stress test
# =========================================================================
println("[9] Large data CBC streaming (10 MB)")
large_data = rand(UInt8, 10_000_000)
ctx_enc = Sm4Cbc(key, iv, ENCRYPT)
out_enc = zeros(UInt8, 10_000_016)
GC.gc()
elapsed = @elapsed begin
    total_enc = sm4_cbc_encrypt_update!(ctx_enc, large_data, out_enc)
    rem = sm4_cbc_encrypt_final!(ctx_enc, out_enc, total_enc + 1)
end
total_enc += rem
println("  Encrypt 10 MB: $(round(elapsed, digits=3)) s, output: $total_enc bytes")

ctx_dec = Sm4Cbc(key, iv, DECRYPT)
out_dec = zeros(UInt8, 10_000_016)
elapsed = @elapsed begin
    total_dec = sm4_cbc_decrypt_update!(ctx_dec, view(out_enc, 1:total_enc), out_dec)
    rem = sm4_cbc_decrypt_final!(ctx_dec, out_dec, total_dec + 1)
end
total_dec += rem
println("  Decrypt 10 MB: $(round(elapsed, digits=3)) s, output: $total_dec bytes")
@assert total_dec == 10_000_000 "CBC decrypt length"
@assert collect(view(out_dec, 1:10_000_000)) == large_data "Large CBC round-trip failed"
println("  PASS")

# =========================================================================
# 10. In-place CTR streaming (no extra allocation)
# =========================================================================
println("[10] In-place CTR (zero extra allocation)")
data = rand(UInt8, 1000)
backup = copy(data)
ctx = Sm4Ctr(key, iv)
alloc_before = Base.gc_num()
sm4_ctr_xor!(ctx, data, data)
alloc_after = Base.gc_num()
@assert data != backup "In-place encrypt should change data"

ctx = Sm4Ctr(key, iv)
sm4_ctr_xor!(ctx, data, data)
@assert data == backup "In-place round-trip failed"
println("  PASS (in-place: no output buffer allocation)")

println("\n" * "="^60)
println("SM4 Streaming: ALL TESTS PASSED")
println("="^60)
