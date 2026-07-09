# =============================================================================
# CryptoHash (Hashlib) Test Suite
# =============================================================================

# Test 1: API exports
@assert isdefined(CryptoHash, :new_hash) "new_hash not exported"
@assert isdefined(CryptoHash, :supported_hashes) "supported_hashes not exported"
@assert isdefined(CryptoHash, :digest_size_for) "digest_size_for not exported"
println("  Hashlib API exports: PASS")

# Test 2: supported_hashes
@assert CryptoHash.supported_hashes == Set(["sm3"]) "supported_hashes wrong"
println("  Hashlib supported_hashes: PASS")

# Test 3: digest_size_for
@assert CryptoHash.digest_size_for("sm3") == 32
@assert CryptoHash.digest_size_for("SM3") == 32
@assert CryptoHash.digest_size_for("sha256") == 32
@assert CryptoHash.digest_size_for("sha512") == 64
println("  Hashlib digest_size_for: PASS")

# Test 4: digest_size_for unknown
try
    CryptoHash.digest_size_for("unknown_hash")
    @assert false "Should have thrown"
catch e
    @assert e isa ArgumentError "Wrong exception type"
end
println("  Hashlib digest_size_for unknown: PASS")

# Test 5: new_hash SM3
ctx = CryptoHash.new_hash("sm3")
@assert ctx isa CryptoHash.SM3HashCtx "SM3 context type wrong"
println("  Hashlib new_hash SM3: PASS")

# Test 6: new_hash SM3 with data
ctx = CryptoHash.new_hash("sm3", "abc")
h = CryptoHash.hexdigest(ctx)
@assert h == SM3.sm3_hash("abc") "SM3 hexdigest mismatch"
println("  Hashlib SM3+string: PASS")

# Test 7: new_hash SM3 with bytes
ctx = CryptoHash.new_hash("sm3", UInt8[0x61, 0x62, 0x63])
h = CryptoHash.hexdigest(ctx)
@assert h == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
println("  Hashlib SM3+bytes: PASS")

# Test 8: streaming
ctx = CryptoHash.SM3HashCtx()
CryptoHash.update!(ctx, "hello ")
CryptoHash.update!(ctx, "world")
h = CryptoHash.hexdigest(ctx)
@assert h == SM3.sm3_hash("hello world") "Streaming hash mismatch"
println("  Hashlib streaming: PASS")

# Test 9: digest returns 32 bytes
ctx = CryptoHash.new_hash("sm3", "test")
raw = CryptoHash.digest(ctx)
@assert length(raw) == 32
@assert raw isa Vector{UInt8}
println("  Hashlib digest: PASS")

# Test 10: unsupported algorithm
try
    CryptoHash.new_hash("sha256")
    @assert false "Should have thrown"
catch e
    @assert e isa ArgumentError "Wrong exception type"
end
println("  Hashlib unsupported: PASS")

println("Hashlib: ALL TESTS PASSED")
