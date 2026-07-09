# =============================================================================
# ZUC Test Suite
# =============================================================================

const ZUC_KEY = zeros(UInt8, 16)
const ZUC_IV  = zeros(UInt8, 16)

# Test 1: Context creation
ctx = ZUC.ZUCContext(ZUC_KEY, ZUC_IV)
@assert ctx isa ZUC.ZUCContext "Context creation failed"
println("  ZUC context creation: PASS")

# Test 2: Encrypt/decrypt round-trip (small)
msg = UInt8[0x01, 0x02, 0x03, 0x04]
ctx1 = ZUC.ZUCContext(ZUC_KEY, ZUC_IV)
ct = ZUC.zuc_encrypt(ctx1, msg)
@assert length(ct) == length(msg) "Encrypt length mismatch"
ctx2 = ZUC.ZUCContext(ZUC_KEY, ZUC_IV)
dt = ZUC.zuc_encrypt(ctx2, ct)
@assert dt == msg "Decrypt round-trip failed"
println("  ZUC encrypt/decrypt small: PASS")

# Test 3: Keystream generation
ctx = ZUC.ZUCContext(ZUC_KEY, ZUC_IV)
ks = ZUC.zuc_generate_keystream(ctx, 64)
@assert length(ks) == 64 "Keystream length wrong"
@assert ks isa Vector{UInt32} "Keystream type wrong"
println("  ZUC keystream: PASS")

# Test 4: Keystream determinism
ctx1 = ZUC.ZUCContext(ZUC_KEY, ZUC_IV)
ks1 = ZUC.zuc_generate_keystream(ctx1, 32)
ctx2 = ZUC.ZUCContext(ZUC_KEY, ZUC_IV)
ks2 = ZUC.zuc_generate_keystream(ctx2, 32)
@assert ks1 == ks2 "Keystream not deterministic"
println("  ZUC determinism: PASS")

# Test 5: Encrypt/decrypt round-trip (1 KB)
msg = rand(UInt8, 1000)
ctx1 = ZUC.ZUCContext(ZUC_KEY, ZUC_IV)
ct = ZUC.zuc_encrypt(ctx1, msg)
@assert length(ct) == length(msg) "Encrypt 1KB length wrong"
ctx2 = ZUC.ZUCContext(ZUC_KEY, ZUC_IV)
dt = ZUC.zuc_encrypt(ctx2, ct)
@assert dt == msg "Encrypt/decrypt 1KB round-trip failed"
println("  ZUC encrypt/decrypt 1KB: PASS")

# Test 6: Non-zero key/IV (self-consistency)
key = UInt8[0x17, 0x3d, 0x14, 0xba, 0x50, 0x03, 0x73, 0x1d,
            0x7a, 0x60, 0x04, 0x94, 0x70, 0xf0, 0x0a, 0x29]
iv  = UInt8[0x66, 0x03, 0x54, 0x92, 0x78, 0x00, 0x00, 0x00,
            0x66, 0x03, 0x54, 0x92, 0x78, 0x00, 0x00, 0x00]
ctx1 = ZUC.ZUCContext(key, iv)
ks1 = ZUC.zuc_generate_keystream(ctx1, 32)
ctx2 = ZUC.ZUCContext(key, iv)
ks2 = ZUC.zuc_generate_keystream(ctx2, 32)
@assert ks1 == ks2 "Non-zero key/IV determinism failed"
println("  ZUC non-zero key/IV: PASS")

# Test 7: Encrypt returns UInt8
ctx = ZUC.ZUCContext(ZUC_KEY, ZUC_IV)
ct = ZUC.zuc_encrypt(ctx, UInt8[1, 2, 3])
@assert ct isa Vector{UInt8} "Encrypt return type wrong"
println("  ZUC return type: PASS")

println("ZUC: ALL TESTS PASSED")
