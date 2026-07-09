# =============================================================================
# SM2 Demo - Usage Examples
#
# Quick run (no install needed):
#   julia --project=. demo/sm2_demo.jl
# =============================================================================

# Load SM3 first (SM2 depends on SM3 module)
sm3_path = joinpath(@__DIR__, "..", "src", "smx", "SM3", "sm3.jl")
include(sm3_path)

# Load SM2 module
sm2_path = joinpath(@__DIR__, "..", "src", "smx", "SM2", "sm2.jl")
include(sm2_path)
using .SM2
using Random
Random.seed!(42)

# Local helpers (previously available as internal functions in SM2)
bytes2hex(data::Vector{UInt8}) = join((string(d, base=16, pad=2) for d in data))
random_hex_string(n::Int) = join(rand("0123456789abcdef", n))

println("="^60)
println("SM2 Elliptic Curve Cryptography Demo")
println("="^60)

# ---------------------------------------------------------------------------
# 1. Key Generation
# ---------------------------------------------------------------------------
println("\n[1] Key Generation:")
keypair = sm2_generate_keypair()
println("  Private key: $(keypair.privateKey)")
println("  Public key:  $(bytes2hex(keypair.publicKey))")

# ---------------------------------------------------------------------------
# 2. Sign and Verify
# ---------------------------------------------------------------------------
println("\n[2] Sign and Verify:")

message = "Hello, SM2!"
priv_hex = keypair.privateKey
pub_hex = bytes2hex(keypair.publicKey)
k_hex = random_hex_string(64)

sig = sm2_sign(message, priv_hex, k_hex)
println("  Message: $message")
println("  Signature: $(bytes2hex(sig))")

valid = sm2_verify(sig, message, pub_hex)
println("  Verification: $valid")
println("  (Expected: true)")

# Sign with hex input
msg_hash = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba0e0"
sig2 = sm2_sign(msg_hash, priv_hex, k_hex, Hexstr=true)
valid2 = sm2_verify(sig2, msg_hash, pub_hex, Hexstr=true)
println("  Hex sign/verify: $valid2")

# ---------------------------------------------------------------------------
# 3. Encryption and Decryption (default C1C3C2, GmSSL-compatible)
# ---------------------------------------------------------------------------
println("\n[3] Encryption and Decryption (format=:C1C3C2, GmSSL-compatible):")

plaintext = "Secret data for SM2 encryption"
println("  Plaintext: $plaintext")

ciphertext = sm2_encrypt(plaintext, pub_hex)
println("  Ciphertext C1C3C2 ($(length(ciphertext)) bytes): $(bytes2hex(ciphertext))")

decrypted = sm2_decrypt(ciphertext, priv_hex)
if decrypted !== nothing
    decrypted_str = String(decrypted)
    println("  Decrypted: $decrypted_str")
    println("  Match: $(decrypted_str == plaintext)")
else
    println("  Decryption failed!")
end

# ---------------------------------------------------------------------------
# 4. Encryption and Decryption (legacy C1C2C3 format)
# ---------------------------------------------------------------------------
println("\n[4] Encryption and Decryption (format=:C1C2C3, legacy):")

ciphertext_c123 = sm2_encrypt(plaintext, pub_hex, format=:C1C2C3)
println("  Ciphertext C1C2C3 ($(length(ciphertext_c123)) bytes): $(bytes2hex(ciphertext_c123))")

# Format mismatch check: decrypting C1C2C3 as C1C3C2 should fail
wrong = sm2_decrypt(ciphertext_c123, priv_hex)
println("  Decrypt C1C2C3 as C1C3C2 (should fail): $(wrong === nothing)")

# Correct format
decrypted_c123 = sm2_decrypt(ciphertext_c123, priv_hex, format=:C1C2C3)
if decrypted_c123 !== nothing
    decrypted_str = String(decrypted_c123)
    println("  Decrypted (C1C2C3): $decrypted_str")
    println("  Match: $(decrypted_str == plaintext)")
else
    println("  Decryption failed!")
end

# ---------------------------------------------------------------------------
# 5. Cross-format interoperability
# ---------------------------------------------------------------------------
println("\n[5] Cross-format interoperability:")
# C1C3C2 ciphertext decrypted with explicit format
pt1 = sm2_decrypt(ciphertext, priv_hex, format=:C1C3C2)
println("  C1C3C2 encrypt → C1C3C2 decrypt: $(pt1 !== nothing && String(pt1) == plaintext)")
# C1C2C3 ciphertext decrypted with explicit format
pt2 = sm2_decrypt(ciphertext_c123, priv_hex, format=:C1C2C3)
println("  C1C2C3 encrypt → C1C2C3 decrypt: $(pt2 !== nothing && String(pt2) == plaintext)")

println("\n" * "="^60)
println("SM2 Demo Complete")
println("="^60)
