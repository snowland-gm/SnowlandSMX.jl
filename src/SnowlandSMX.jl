module SnowlandSMX

# =============================================================================
# SnowlandSMX - Chinese Commercial Cryptography Suite in Julia
#
# Implements:
#   - SM2: elliptic curve public key cryptography
#   - SM3: cryptographic hash algorithm
#   - SM4: block cipher
#   - SM9: identity-based cryptography (parameters)
#   - ZUC: stream cipher
#   - crypto/hashlib: unified hash interface
# =============================================================================

include("smx/util/util.jl")
include("smx/SM3/sm3.jl")
include("smx/SM4/sm4.jl")
include("smx/ZUC/zuc.jl")
include("smx/SM2/sm2.jl")
include("smx/SM9/sm9.jl")
include("smx/crypto/hashlib.jl")

end # module SnowlandSMX
