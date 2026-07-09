# =============================================================================
# SM9 - Prime Field Fq arithmetic (modular BigInt)
# =============================================================================

struct Fq
    n::BigInt
function Fq(x::Integer)
    p = _FQ_MODULUS[]
    if p == 0
        x == 0 || error("Fq: field modulus not initialized (non-zero value)")
        return new(BigInt(0))
    end
    return new(mod(BigInt(x), p))
end
end

const _FQ_MODULUS = Ref{BigInt}(BigInt(0))

function _fq_set_modulus(p::BigInt)
    _FQ_MODULUS[] = p
end

function _fq_modulus()
    return _FQ_MODULUS[]
end

# Unsafe constructors for pre-initialization use
function _fq_raw(x::BigInt)
    return Fq(x)  # skip validation - caller must ensure modulus is set
end

Base.zero(::Type{Fq}) = begin
    _fq_modulus() == 0 && error("Fq: zero() called before modulus set")
    Fq(0)
end

Base.one(::Type{Fq}) = begin
    _fq_modulus() == 0 && error("Fq: one() called before modulus set")
    Fq(1)
end

Base.:(==)(a::Fq, b::Fq) = a.n == b.n
Base.hash(a::Fq, h::UInt) = hash(a.n, h)

Base.:+(a::Fq, b::Fq) = Fq(a.n + b.n)
Base.:-(a::Fq, b::Fq) = Fq(a.n - b.n + _fq_modulus())
Base.:-(a::Fq) = Fq(_fq_modulus() - a.n)
Base.:*(a::Fq, b::Fq) = Fq(a.n * b.n)

function Base.inv(a::Fq)
    a.n == 0 && throw(DivideError())
    g, x, _ = gcdx(a.n, _fq_modulus())
    return Fq(mod(x, _fq_modulus()))
end

Base.:/(a::Fq, b::Fq) = a * inv(b)
Base.:^(a::Fq, e::Integer) = Fq(powermod(a.n, BigInt(e), _fq_modulus()))

function Base.show(io::IO, a::Fq)
    print(io, string(a.n, base=16))
end

# ---------------------------------------------------------------------------
# Square root in Fq (Tonelli-Shanks)
#
# Since SM9 q ≡ 3 (mod 4), we can use the simple formula:
#   sqrt(a) = a^((q+1)/4)  if Legendre(a|q) = 1
# ---------------------------------------------------------------------------
function _fq_sqrt(a::Fq)
    p = _fq_modulus()
    # Check Legendre symbol: a^((p-1)/2) mod p
    if a.n == 0
        return Fq(0), true
    end
    leg = powermod(a.n, (p - 1) >> 1, p)
    if leg != 1
        return Fq(0), false  # not a quadratic residue
    end
    # Since p ≡ 3 mod 4: sqrt = a^((p+1)/4)
    exp = (p + 1) >> 2
    r = powermod(a.n, exp, p)
    return Fq(r), true
end

function Base.iszero(a::Fq)
    return a.n == 0
end

# ---------------------------------------------------------------------------
# Modular inverse for integer n mod prime field order
# ---------------------------------------------------------------------------
function _prime_field_inv(a::BigInt, n::BigInt)
    g, x, _ = gcdx(a, n)
    g != 1 && error("Modular inverse does not exist")
    return mod(x, n)
end
