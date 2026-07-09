# =============================================================================
# Util Test Suite
# =============================================================================

# Test 1: _hex2bytes
@assert SM2._hex2bytes("616263") == UInt8[0x61, 0x62, 0x63] "hex2bytes 'abc'"
@assert SM2._hex2bytes("FF") == UInt8[0xff] "hex2bytes uppercase"
@assert SM2._hex2bytes("0") == UInt8[0x00] "hex2bytes single digit"
@assert SM2._hex2bytes("") == UInt8[] "hex2bytes empty"
@assert SM2._hex2bytes("  aB  ") == UInt8[0xab] "hex2bytes with whitespace"
println("  Util _hex2bytes: PASS")

# Test 2: _bytes2hex
@assert SM2._bytes2hex(UInt8[0x61, 0x62, 0x63]) == "616263" "bytes2hex 'abc'"
@assert SM2._bytes2hex(UInt8[0xff, 0x00]) == "ff00" "bytes2hex mixed"
@assert SM2._bytes2hex(UInt8[]) == "" "bytes2hex empty"
println("  Util _bytes2hex: PASS")

# Test 3: Round-trip
data = rand(UInt8, 32)
hex = SM2._bytes2hex(data)
bytes = SM2._hex2bytes(hex)
@assert bytes == data "hex round-trip failed"
println("  Util hex round-trip: PASS")

# Test 4: _bigint_to_hex
@assert SM2._bigint_to_hex(BigInt(0x1234), 4) == "1234"
@assert SM2._bigint_to_hex(BigInt(0), 8) == "00000000"
@assert length(SM2._bigint_to_hex(BigInt(0xabcd), 4)) == 4
println("  Util _bigint_to_hex: PASS")

# Test 5: _rand_bytes
r = SM2._rand_bytes(32)
@assert length(r) == 32
@assert r isa Vector{UInt8}
@assert any(x -> x != 0, r) "random bytes all zero"
println("  Util _rand_bytes: PASS")

# Test 6: _rand_bigint
x = SM2._rand_bigint(32)
@assert x isa BigInt
@assert x >= BigInt(0)
println("  Util _rand_bigint: PASS")

# Test 7: _put_u32_be! and _get_u32_be
buf = zeros(UInt8, 8)
SM2._put_u32_be!(buf, 1, UInt32(0x01020304))
SM2._put_u32_be!(buf, 5, UInt32(0x05060708))
@assert buf == UInt8[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
@assert SM2._get_u32_be(buf, 1) == UInt32(0x01020304)
@assert SM2._get_u32_be(buf, 5) == UInt32(0x05060708)
println("  Util _put/get_u32_be: PASS")

# Test 8: Edge values
buf = zeros(UInt8, 4)
SM2._put_u32_be!(buf, 1, UInt32(0))
@assert buf == UInt8[0, 0, 0, 0] "zero value failed"
SM2._put_u32_be!(buf, 1, UInt32(0xffffffff))
@assert buf == UInt8[0xff, 0xff, 0xff, 0xff] "max value failed"
println("  Util edge values: PASS")

println("Util: ALL TESTS PASSED")
