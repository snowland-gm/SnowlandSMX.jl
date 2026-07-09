# =============================================================================
# SM4 Test Suite
# =============================================================================

# SM4 reference test vector from GM/T 0002-2012 Appendix A
const SM4_KEY = UInt8[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                       0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10]
const SM4_PT  = UInt8[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                       0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10]
const SM4_CT  = UInt8[0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
                       0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46]

# ===== ECB Tests =====

# Test 1: Standard test vector
ct = SM4.sm4_crypt_ecb(SM4.ENCRYPT, SM4_KEY, SM4_PT)
@assert ct == SM4_CT "ECB standard vector failed"
println("  SM4 ECB standard vector: PASS")

# Test 2: Round-trip
ct = SM4.sm4_crypt_ecb(SM4.ENCRYPT, SM4_KEY, SM4_PT)
dt = SM4.sm4_crypt_ecb(SM4.DECRYPT, SM4_KEY, ct)
@assert dt == SM4_PT "ECB round-trip failed"
println("  SM4 ECB round-trip: PASS")

# Test 3: Multi-block
data = rand(UInt8, 48)
ct = SM4.sm4_crypt_ecb(SM4.ENCRYPT, SM4_KEY, data)
@assert length(ct) == 48 "Multi-block length wrong"
dt = SM4.sm4_crypt_ecb(SM4.DECRYPT, SM4_KEY, ct)
@assert dt == data "Multi-block round-trip failed"
println("  SM4 ECB multi-block: PASS")

# Test 4: Large data
data = rand(UInt8, 100_000)
ct = SM4.sm4_crypt_ecb(SM4.ENCRYPT, SM4_KEY, data)
dt = SM4.sm4_crypt_ecb(SM4.DECRYPT, SM4_KEY, ct)
@assert dt[1:100_000] == data "Large data round-trip failed"
println("  SM4 ECB large data: PASS")

# Test 5: ECB! returns new buffer
s = SM4.Sm4()
SM4.sm4_setkey!(s, SM4_KEY, SM4.ENCRYPT)
result = SM4.sm4_crypt_ecb!(s, SM4_PT)
@assert result == SM4_CT "SM4 in-place ECB wrong result"
println("  SM4 ECB!: PASS")

# ===== CBC Tests =====

# Test 6: CBC round-trip
iv = zeros(UInt8, 16)
data = rand(UInt8, 32)
ct = SM4.sm4_crypt_cbc(SM4.ENCRYPT, SM4_KEY, iv, data)
@assert length(ct) == 32 "CBC length wrong"
dt = SM4.sm4_crypt_cbc(SM4.DECRYPT, SM4_KEY, iv, ct)
@assert dt == data "CBC round-trip failed"
println("  SM4 CBC round-trip: PASS")

# Test 7: CBC with non-zero IV
iv2 = UInt8[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10]
data = rand(UInt8, 16)
ct_cbc = SM4.sm4_crypt_cbc(SM4.ENCRYPT, SM4_KEY, iv2, data)
ct_ecb = SM4.sm4_crypt_ecb(SM4.ENCRYPT, SM4_KEY, data)
@assert ct_cbc != ct_ecb "CBC should differ from ECB"
dt = SM4.sm4_crypt_cbc(SM4.DECRYPT, SM4_KEY, iv2, ct_cbc)
@assert dt == data "CBC non-zero IV round-trip failed"
println("  SM4 CBC non-zero IV: PASS")

# Test 8: CBC! round-trip
s = SM4.Sm4()
SM4.sm4_setkey!(s, SM4_KEY, SM4.ENCRYPT)
iv = zeros(UInt8, 16)
ct = SM4.sm4_crypt_cbc!(s, copy(iv), SM4_PT)
dec_s = SM4.Sm4()
SM4.sm4_setkey!(dec_s, SM4_KEY, SM4.DECRYPT)
dt = SM4.sm4_crypt_cbc!(dec_s, copy(iv), ct)
@assert dt == SM4_PT "CBC! round-trip failed"
println("  SM4 CBC!: PASS")

println("SM4: ALL TESTS PASSED")
