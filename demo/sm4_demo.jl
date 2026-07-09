# =============================================================================
# SM4 Demo - Usage Examples
#
# Quick run (no install needed):
#   julia --project=. demo/sm4_demo.jl
# =============================================================================

sm4_path = joinpath(@__DIR__, "..", "src", "smx", "SM4", "sm4.jl")
include(sm4_path)
using .SM4

println("="^60)
println("SM4 Block Cipher Demo")
println("="^60)

# ---------------------------------------------------------------------------
# 1. SM4-ECB Encryption/Decryption
# ---------------------------------------------------------------------------
println("\n[1] SM4-ECB Mode:")

key = Vector{UInt8}("hello world, err")  # 16 bytes
# Pad plaintext to 16-byte boundary
plaintext = Vector{UInt8}("SM4 ECB test msg" * "   ")  # 16 bytes
println("  Plaintext: $(String(plaintext))")

ciphertext = sm4_crypt_ecb(ENCRYPT, key, plaintext)
println("  Ciphertext: $(join(string.(ciphertext, base=16, pad=2)))")

decrypted = sm4_crypt_ecb(DECRYPT, key, ciphertext)
println("  Decrypted:  $(String(decrypted))")
println("  Match: $(plaintext == decrypted)")

# ---------------------------------------------------------------------------
# 2. SM4-CBC Encryption/Decryption
# ---------------------------------------------------------------------------
println("\n[2] SM4-CBC Mode:")

iv = zeros(UInt8, 16)  # all-zero IV
plaintext2 = Vector{UInt8}("CBC mode testing!" * "   ")  # 16 bytes
println("  Plaintext: $(String(plaintext2))")

ciphertext2 = sm4_crypt_cbc(ENCRYPT, key, iv, plaintext2)
println("  Ciphertext: $(join(string.(ciphertext2, base=16, pad=2)))")

decrypted2 = sm4_crypt_cbc(DECRYPT, key, iv, ciphertext2)
println("  Decrypted:  $(String(decrypted2))")
println("  Match: $(plaintext2 == decrypted2)")

# ---------------------------------------------------------------------------
# 3. Multiple-block ECB
# ---------------------------------------------------------------------------
println("\n[3] Multi-block ECB:")
msg = Vector{UInt8}("This is a longer message for testing SM4 ECB mode with multiple blocks!")
println("  Plaintext ($(length(msg)) bytes): $(String(msg))")

ct = sm4_crypt_ecb(ENCRYPT, key, msg)
dt = sm4_crypt_ecb(DECRYPT, key, ct)
println("  Decrypted: $(String(dt))")
println("  Match: $(msg == dt)")

println("\n" * "="^60)
println("SM4 Demo Complete")
println("="^60)

# ---------------------------------------------------------------------------
# 4. SM4-CTR Streaming Mode (recommended for large data)
# ---------------------------------------------------------------------------
println("\n[4] SM4-CTR Streaming Mode:")
data = Vector{UInt8}("CTR streaming test! test!")
println("  Plaintext ($(length(data)) bytes): $(String(data))")

ctx = Sm4Ctr(key, iv)
ct = zeros(UInt8, length(data))
sm4_ctr_xor!(ctx, data, ct)
println("  Ciphertext: $(join(string.(ct, base=16, pad=2)))")

ctx2 = Sm4Ctr(key, iv)
dt = zeros(UInt8, length(ct))
sm4_ctr_xor!(ctx2, ct, dt)
println("  Decrypted:  $(String(dt))")
println("  Match: $(data == dt)")

# In-place CTR
data2 = Vector{UInt8}("in-place CTR test! ")
ctx = Sm4Ctr(key, iv)
sm4_ctr_xor!(ctx, data2, data2)  # encrypt
ctx = Sm4Ctr(key, iv)
sm4_ctr_xor!(ctx, data2, data2)  # decrypt
println("  In-place CTR: $(String(data2))")

# ---------------------------------------------------------------------------
# 5. SM4-CBC Streaming Mode
# ---------------------------------------------------------------------------
println("\n[5] SM4-CBC Streaming Mode:")
msg = Vector{UInt8}("Streaming CBC test message with pad")
println("  Plaintext ($(length(msg)) bytes): $(String(msg))")

# Encrypt
ctx_enc = Sm4Cbc(key, iv, ENCRYPT)
out_enc = zeros(UInt8, length(msg) + 16)
n = sm4_cbc_encrypt_update!(ctx_enc, msg, out_enc)
r = sm4_cbc_encrypt_final!(ctx_enc, out_enc, n + 1)
println("  Ciphertext ($(n+r) bytes): $(join(string.(view(out_enc, 1:n+r), base=16, pad=2)))")

# Decrypt
ctx_dec = Sm4Cbc(key, iv, DECRYPT)
out_dec = zeros(UInt8, n + r)
n2 = sm4_cbc_decrypt_update!(ctx_dec, view(out_enc, 1:n+r), out_dec)
r2 = sm4_cbc_decrypt_final!(ctx_dec, out_dec, n2 + 1)
decrypted = String(view(out_dec, 1:n2+r2))
println("  Decrypted:  $decrypted")
println("  Match: $(String(msg) == decrypted)")

println("\n" * "="^60)
println("SM4 Demo Complete")
println("="^60)
