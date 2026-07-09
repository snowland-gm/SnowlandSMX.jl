# =============================================================================
# SM3 Test Suite
# =============================================================================

# SM3 reference test vectors from GB/T 32905-2016 Appendix A
const SM3_TEST_VECTORS = Dict(
    "abc" =>
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
    "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd" =>
        "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
)

@testset "SM3 module" begin

    @testset "One-shot hash - string input" begin
        for (msg, expected) in SM3_TEST_VECTORS
            result = SM3.sm3_hash(msg)
            @test result == expected
        end
    end

    @testset "One-shot hash - hex input" begin
        result = SM3.sm3_hash("616263", hex_input=true)
        @test result == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    end

    @testset "One-shot hash - empty message" begin
        result = SM3.sm3_hash("")
        @test result == "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"
    end

    @testset "Digest returns 32 bytes" begin
        raw = SM3.sm3_digest("abc")
        @test length(raw) == 32
        @test SM3.sm3_hash("test") == SM3.sm3_hexdigest("test")
    end

    @testset "Alias hexdigest == sm3_hash" begin
        result = SM3.hexdigest("abc")
        @test result == SM3.sm3_hash("abc")
    end

    @testset "Streaming SM3Context" begin
        ctx = SM3.SM3Context()
        SM3.update!(ctx, "hello ")
        SM3.update!(ctx, "world")
        hash1 = SM3.hexdigest!(ctx)
        hash2 = SM3.sm3_hash("hello world")
        @test hash1 == hash2
    end

    @testset "Streaming with byte array" begin
        ctx = SM3.SM3Context()
        SM3.update!(ctx, UInt8[0x61, 0x62, 0x63])
        hash = SM3.hexdigest!(ctx)
        @test hash == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    end

    @testset "SM3Context digest! produces 32 bytes" begin
        ctx = SM3.SM3Context("abc")
        raw = SM3.digest!(ctx)
        @test length(raw) == 32
    end

    @testset "SM3Context with initial data" begin
        ctx = SM3.SM3Context("abc")
        hash = SM3.hexdigest!(ctx)
        @test hash == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    end

    @testset "SM3 KDF" begin
        z = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        result = SM3.sm3_kdf(z, 32)
        @test length(result) == 64  # 32 bytes = 64 hex chars
        raw = SM3.sm3_kdf_bytes(z, 32)
        @test length(raw) == 32
    end

    @testset "Core functions" begin
        x = UInt32(0x12345678)
        rl = SM3.rotate_left(x, 4)
        @test rl == UInt32(0x23456781)

        p0 = SM3.P_0(UInt32(0x12345678))
        @test p0 isa UInt32

        p1 = SM3.P_1(UInt32(0x12345678))
        @test p1 isa UInt32

        ff0 = SM3.FF_j(UInt32(1), UInt32(2), UInt32(3), 0)
        @test ff0 == UInt32(1 ⊻ 2 ⊻ 3)

        ff16 = SM3.FF_j(UInt32(1), UInt32(2), UInt32(3), 16)
        @test ff16 == (UInt32(1) & 2) | (UInt32(1) & 3) | (UInt32(2) & 3)
    end

    @testset "PUT_UINT32_BE" begin
        bytes = SM3.PUT_UINT32_BE(UInt32(0x01020304))
        @test bytes == UInt8[0x01, 0x02, 0x03, 0x04]
    end

    @testset "Large message padding (1 block)" begin
        msg = repeat("a", 63)
        result = SM3.sm3_hash(msg)
        @test length(result) == 64
        @test result isa String
    end

    @testset "SM3 KDF from bytes" begin
        z_bytes = UInt8[0x01, 0x02, 0x03, 0x04]
        raw = SM3.sm3_kdf_from_bytes(z_bytes, 16)
        @test length(raw) == 16
        @test raw isa Vector{UInt8}
    end

end
