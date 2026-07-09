# =============================================================================
# SM9 - Quadratic Extension Field Fq^2 = Fq[u] / (u^2 + 1)
#
# Since SM9 q = 3 (mod 4), -1 is a quadratic non-residue in Fq.
# Representation: a + b*u  where u^2 = -1
# =============================================================================

struct Fq2
    a::Fq  # real part
    b::Fq  # u-coefficient
end

Fq2(a::Integer, b::Integer) = Fq2(Fq(a), Fq(b))

Base.zero(::Type{Fq2}) = Fq2(Fq(0), Fq(0))
Base.one(::Type{Fq2})  = Fq2(Fq(1), Fq(0))

Base.:(==)(x::Fq2, y::Fq2) = x.a == y.a && x.b == y.b

Base.:+(x::Fq2, y::Fq2) = Fq2(x.a + y.a, x.b + y.b)
Base.:-(x::Fq2, y::Fq2) = Fq2(x.a - y.a, x.b - y.b)
Base.:-(x::Fq2) = Fq2(-x.a, -x.b)

# (a + b*u) * (c + d*u) = (ac - bd) + (ad + bc)*u  [since u^2 = -1]
function Base.:*(x::Fq2, y::Fq2)
    ac = x.a * y.a
    bd = x.b * y.b
    return Fq2(ac - bd, (x.a + x.b) * (y.a + y.b) - ac - bd)
end

# Scalar multiplication
Base.:*(s::Fq, y::Fq2) = Fq2(s * y.a, s * y.b)
Base.:*(x::Fq2, s::Fq) = s * x

function Base.inv(x::Fq2)
    # (a + bu)^(-1) = (a - bu) / (a^2 + b^2)
    den = x.a * x.a + x.b * x.b
    inv_den = inv(den)
    return Fq2(x.a * inv_den, -x.b * inv_den)
end

Base.:/(x::Fq2, y::Fq2) = x * inv(y)

function Base.:^(x::Fq2, e::Integer)
    if e == 0
        return one(Fq2)
    elseif e < 0
        return inv(x)^(-e)
    end
    result = one(Fq2)
    base = x
    n = BigInt(e)
    while n > 0
        if n & 1 == 1
            result = result * base
        end
        base = base * base
        n >>= 1
    end
    return result
end

# Frobenius map: (a + bu)^q = a - bu  (since u^q = u * u^(q-1) = u * (u^2)^((q-1)/2) = u * (-1)^((q-1)/2) = -u)
# Because q ≡ 3 (mod 4), (q-1)/2 is odd, so (-1)^((q-1)/2) = -1, thus u^q = -u
# Actually wait, Fq2 with u^2 = -1: u^q = u * (u^2)^((q-1)/2) = u * (-1)^((q-1)/2)
# For q ≡ 3 mod 4, (q-1)/2 is odd, so (-1)^((q-1)/2) = -1, thus u^q = u * (-1) = -u
# So (a + bu)^q = a^q + b^q * u^q = a - b*u  (since a^q = a in Fq by Fermat)
function frobenius_fq2(x::Fq2)
    return Fq2(x.a, -x.b)
end

# Frobenius^2: (a + b*u)^(q^2) = a + b*u = x
function frobenius2_fq2(x::Fq2)
    return x
end

function Base.show(io::IO, x::Fq2)
    print(io, "(", x.a, ") + (", x.b, ")*u")
end

# ---------------------------------------------------------------------------
# Square root in Fq2
#
# For z = a + b*u, find w = c + d*u with w^2 = z.
# This requires: c^2 - d^2 = a, 2cd = b  (mod p)
#
# Formula: if a^2 + b^2 is QR in Fq:
#   c = sqrt((a + sqrt(a^2 + b^2)) / 2)
#   d = b / (2c)
# ---------------------------------------------------------------------------
function _fq2_sqrt(z::Fq2)
    if z.a.n == 0 && z.b.n == 0
        return Fq2(Fq(0), Fq(0)), true
    end

    # Compute norm = a^2 + b^2
    norm = z.a * z.a + z.b * z.b
    nr, ok = _fq_sqrt(norm)
    if !ok
        return zero(Fq2), false
    end

    # c = sqrt((a + sqrt(norm)) / 2)
    two = Fq(2)
    c2 = (z.a + nr) / two
    c, ok2 = _fq_sqrt(c2)
    if !ok2
        # Try the other branch: a - sqrt(norm)
        c2 = (z.a - nr) / two
        c, ok2 = _fq_sqrt(c2)
        if !ok2
            return zero(Fq2), false
        end
    end

    d = z.b / (two * c)
    return Fq2(c, d), true
end

function Base.iszero(x::Fq2)
    return iszero(x.a) && iszero(x.b)
end
