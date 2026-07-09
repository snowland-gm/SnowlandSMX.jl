# =============================================================================
# SM9 Test Suite
#
# Tests SM9 API availability and parameter verification.
# NOTE: SM9 module is a work-in-progress. Full crypto operations are
# still under development.
# =============================================================================

println("  Testing SM9 API presence...")

# API symbol check
api_symbols = [:SM9_q, :SM9_N, :SM9_P1, :SM9_t, :SM9_a, :SM9_b,
               :sm9_master_key, :sm9_encrypt_private_key,
               :sm9_g1_hash, :sm9_g1_generator, :SM9G1Point,
               :generate_prime, :is_probable_prime,
               :sm9_verify_params]
for sym in api_symbols
    @assert isdefined(SM9, sym) "SM9.$sym not exported"
end
println("  SM9 API exports: PASS")

# Parameter verification
result = SM9.sm9_verify_params()
@assert result "SM9 parameter verification failed"
println("  SM9 parameters: PASS")

# Basic types
@assert SM9.SM9G1Point <: Any "SM9G1Point not defined"
println("  SM9 types: PASS")

println("SM9: ALL TESTS PASSED")
