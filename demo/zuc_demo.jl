# =============================================================================
# ZUC Demo - Usage Examples
#
# Quick run (no install needed):
#   julia --project=. demo/zuc_demo.jl
# =============================================================================

zuc_path = joinpath(@__DIR__, "..", "src", "smx", "ZUC", "zuc.jl")
include(zuc_path)
using .ZUC

println("="^60)
println("ZUC Stream Cipher Demo")
println("="^60)

# ---------------------------------------------------------------------------
# 1. Basic Encryption/Decryption
# ---------------------------------------------------------------------------
println("\n[1] ZUC Encrypt/Decrypt:")

key = zeros(UInt8, 16)
iv = zeros(UInt8, 16)

ctx1 = ZUCContext(key, iv)
plaintext = Vector{UInt8}("i love u")
ciphertext = zuc_encrypt(ctx1, plaintext)
println("  Plaintext:  $(String(plaintext))")
println("  Ciphertext: $(join([string(c, base=16, pad=8) for c in ciphertext], " "))")

ctx2 = ZUCContext(key, iv)
decrypted = zuc_encrypt(ctx2, Vector{UInt8}(ciphertext))
println("  Decrypted:  $(String(Vector{UInt8}(decrypted)))")
println("  Match: $(plaintext == Vector{UInt8}(decrypted))")

# ---------------------------------------------------------------------------
# 2. Longer Message
# ---------------------------------------------------------------------------
println("\n[2] Longer Message:")

key2 = UInt8[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
             0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10]
iv2 = UInt8[0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20]

msg = Vector{UInt8}("ZUC stream cipher test message with longer data")
println("  Message length: $(length(msg)) bytes")

ctx3 = ZUCContext(key2, iv2)
ct = zuc_encrypt(ctx3, msg)

ctx4 = ZUCContext(key2, iv2)
pt = zuc_encrypt(ctx4, Vector{UInt8}(ct))
println("  Decrypted: $(String(Vector{UInt8}(pt)))")
println("  Match: $(msg == Vector{UInt8}(pt))")

# ---------------------------------------------------------------------------
# 3. Keystream Generation
# ---------------------------------------------------------------------------
println("\n[3] Keystream Generation:")

ctx5 = ZUCContext(key, iv)
ks = zuc_generate_keystream(ctx5, 4)
println("  First 4 keystream words: $(join([string(k, base=16, pad=8) for k in ks], " "))")

println("\n" * "="^60)
println("ZUC Demo Complete")
println("="^60)
