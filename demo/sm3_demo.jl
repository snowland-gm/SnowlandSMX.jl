# =============================================================================
# SM3 Demo - Usage Examples
#
# Quick run (no install needed):
#   julia demo/sm3_demo.jl
#
# With package installed:
#   julia --project -e 'using Pkg; Pkg.develop(path=".")'
#   julia --project -e 'using SnowlandSMX; using SnowlandSMX.SM3; SM3.sm3_hash("abc")'
# =============================================================================

# Try loading as installed package first, fall back to include
if isdefined(Main, :SnowlandSMX)
    using SnowlandSMX.SM3
else
    pkg_dir = @__DIR__() |> dirname
    include(joinpath(pkg_dir, "src", "smx", "SM3", "sm3.jl"))
    using .SM3
end

println("="^60)
println("SM3 Hash Algorithm Demo")
println("="^60)

# ---------------------------------------------------------------------------
# 1. One-shot hashing (string input)
# ---------------------------------------------------------------------------
println("\n[1] One-shot hash (string input):")

result = sm3_hash("abc")
println("  SM3(\"abc\") = $result")
println("  Expected:    66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")
println("  Match:       $(result == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")")

result = sm3_hash("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd")
println("\n  SM3(64*\"abcd\") = $result")
println("  Expected:         debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732")
println("  Match:            $(result == "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732")")

result = sm3_hash("")
println("\n  SM3(\"\") = $result")

# ---------------------------------------------------------------------------
# 2. One-shot hashing (hex string input)
# ---------------------------------------------------------------------------
println("\n[2] One-shot hash (hex string input):")

result = sm3_hash("616263", hex_input=true)
println("  SM3(hex=\"616263\") = $result")
println("  Match:                $(result == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")")

# ---------------------------------------------------------------------------
# 3. Raw byte digest (32 bytes)
# ---------------------------------------------------------------------------
println("\n[3] Raw byte digest:")

raw = sm3_digest("abc")
println("  sm3_digest(\"abc\") = $(byte2hex(raw))")

# ---------------------------------------------------------------------------
# 4. Streaming hashing (incremental update)
# ---------------------------------------------------------------------------
println("\n[4] Streaming hash (SM3Context):")

ctx = SM3Context()
update!(ctx, "hello ")
update!(ctx, "world")
hash_result = hexdigest!(ctx)
println("  hash(\"hello world\") = $hash_result")

one_shot = sm3_hash("hello world")
println("  One-shot result      = $one_shot")
println("  Match:                $(hash_result == one_shot)")

# ---------------------------------------------------------------------------
# 5. Streaming with byte array input
# ---------------------------------------------------------------------------
println("\n[5] Streaming hash (byte array):")

ctx = SM3Context()
update!(ctx, UInt8[0x61, 0x62, 0x63])
hash_result = hexdigest!(ctx)
println("  hash([0x61, 0x62, 0x63]) = $hash_result")
println("  Match:                     $(hash_result == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")")

# ---------------------------------------------------------------------------
# 6. Key Derivation Function (KDF)
# ---------------------------------------------------------------------------
println("\n[6] SM3 KDF:")

z = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
klen = 64
derived = sm3_kdf(z, klen)
println("  Input Z:  $z")
println("  KDF(Z, $klen) = $derived")
println("  Length:   $(length(derived)) hex chars = $(length(derived)÷2) bytes")

# ---------------------------------------------------------------------------
# 7. Alias: hexdigest
# ---------------------------------------------------------------------------
println("\n[7] Alias hexdigest:")

result = hexdigest("abc")
println("  hexdigest(\"abc\") = $result")
println("  Match:              $(result == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")")

# ---------------------------------------------------------------------------
# 8. Core functions
# ---------------------------------------------------------------------------
println("\n[8] Core functions demo:")

x = UInt32(0x12345678)
rl = rotate_left(x, 4)
println("  rotate_left(0x12345678, 4) = 0x$(string(rl, base=16, pad=8))")

p0 = P_0(UInt32(0x12345678))
println("  P_0(0x12345678) = 0x$(string(p0, base=16, pad=8))")

p1 = P_1(UInt32(0x12345678))
println("  P_1(0x12345678) = 0x$(string(p1, base=16, pad=8))")

println("\n" * "="^60)
println("SM3 Demo Complete")
println("="^60)
