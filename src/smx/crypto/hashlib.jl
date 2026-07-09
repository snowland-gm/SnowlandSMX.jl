module CryptoHash

# =============================================================================
# Crypto/Hashlib - Unified Hash Interface
#
# Optimizations:
#   1. Uses SM3.digest for one-shot hashing (no duplicate SM3 implementation)
#   2. SM3HashCtx buffers data then uses SM3 digest at finalize
#   3. Clean API
# =============================================================================

export new_hash, sm3_hashlib, supported_hashes, digest_size_for

using ..SM3: sm3_hash, sm3_digest, byte2hex

const supported_hashes = Set(["sm3"])

function digest_size_for(name::AbstractString)
    name_lower = lowercase(name)
    if name_lower == "sm3" || name_lower == "sha256"
        return 32
    elseif name_lower == "sha224"
        return 28
    elseif name_lower == "sha384"
        return 48
    elseif name_lower == "sha512"
        return 64
    elseif name_lower == "md5"
        return 16
    elseif name_lower == "sha1"
        return 20
    elseif name_lower == "sha3_224"
        return 28
    elseif name_lower == "sha3_256"
        return 32
    elseif name_lower == "sha3_384"
        return 48
    elseif name_lower == "sha3_512"
        return 64
    else
        throw(ArgumentError("Unknown hash algorithm: $name"))
    end
end

# =============================================================================
# SM3HashCtx
# =============================================================================

mutable struct SM3HashCtx
    data::Vector{UInt8}

    function SM3HashCtx()
        return new(UInt8[])
    end

    function SM3HashCtx(initial_data::Vector{UInt8})
        return new(copy(initial_data))
    end
end

function update!(ctx::SM3HashCtx, data::Vector{UInt8})
    append!(ctx.data, data)
end

function update!(ctx::SM3HashCtx, data::AbstractString)
    append!(ctx.data, Vector{UInt8}(data))
end

function digest(ctx::SM3HashCtx)
    return sm3_digest(ctx.data)
end

function hexdigest(ctx::SM3HashCtx)
    return byte2hex(digest(ctx))
end

# =============================================================================
# Factory
# =============================================================================

function new_hash(name::AbstractString,
                  data::Union{Vector{UInt8}, AbstractString, Nothing}=nothing)
    name_lower = lowercase(name)
    if name_lower == "sm3"
        if data isa Vector{UInt8}
            return SM3HashCtx(data)
        elseif data isa AbstractString && !isempty(data)
            return SM3HashCtx(Vector{UInt8}(data))
        else
            return SM3HashCtx()
        end
    else
        throw(ArgumentError(
            "Hash '$name' is not built-in. Use SM3 via this module, " *
            "or SHA from Julia's stdlib."
        ))
    end
end

const sm3_hashlib = SM3HashCtx

end # module CryptoHash
