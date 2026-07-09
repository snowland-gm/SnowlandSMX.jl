# =============================================================================
# SM9 - Degree-6 and Degree-12 Extension Fields
#
# Tower: Fq^2 = Fq[u]/(u^2+1)
#        Fq^6 = Fq^2[v]/(v^3 - xi)    where xi = u+1 (non-cube in Fq^2)
#        Fq^12 = Fq^6[w]/(w^2 - v)
#
# Fq6 element: c0 + c1*v + c2*v^2  (c_i in Fq2)
# Fq12 element: hi + lo*w  (hi, lo in Fq6)
# =============================================================================

# Sextic non-residue xi = u + 1 for the cubic extension
# Initialized lazily after Fq modulus is set (called from __init__)
const _FQ6_XI = Ref{Fq2}()

function _fq6_set_xi(xi::Fq2)
    _FQ6_XI[] = xi
end

function _fq6_xi()
    return _FQ6_XI[]
end

# =============================================================================
# Fq6 - Cubic extension of Fq2
# =============================================================================

struct Fq6
    c0::Fq2
    c1::Fq2
    c2::Fq2
end

Fq6(c0::Integer, c1::Integer, c2::Integer) = Fq6(Fq2(c0, 0), Fq2(c1, 0), Fq2(c2, 0))

Base.zero(::Type{Fq6}) = Fq6(zero(Fq2), zero(Fq2), zero(Fq2))
Base.one(::Type{Fq6})  = Fq6(one(Fq2),  zero(Fq2), zero(Fq2))

Base.:(==)(x::Fq6, y::Fq6) = x.c0 == y.c0 && x.c1 == y.c1 && x.c2 == y.c2

Base.:+(x::Fq6, y::Fq6) = Fq6(x.c0 + y.c0, x.c1 + y.c1, x.c2 + y.c2)
Base.:-(x::Fq6, y::Fq6) = Fq6(x.c0 - y.c0, x.c1 - y.c1, x.c2 - y.c2)
Base.:-(x::Fq6) = Fq6(-x.c0, -x.c1, -x.c2)

# Karatsuba-inspired multiplication for Fq6 / (v^3 - xi)
function Base.:*(x::Fq6, y::Fq6)
    xi = _FQ6_XI[]
    a0, a1, a2 = x.c0, x.c1, x.c2
    b0, b1, b2 = y.c0, y.c1, y.c2

    # Compute 5 products
    t0 = a0 * b0
    t1 = a1 * b1
    t2 = a2 * b2
    t3 = (a0 + a1) * (b0 + b1)  # a0*b0 + a0*b1 + a1*b0 + a1*b1
    t4 = (a0 + a2) * (b0 + b2)
    t5 = (a1 + a2) * (b1 + b2)

    # c0 = a0*b0 + xi*(a1*b2 + a2*b1)
    c0 = t0 + xi * ((a1 + a2) * (b1 + b2) - t1 - t2)

    # c1 = a0*b1 + a1*b0 + xi*a2*b2
    c1 = (t3 - t0 - t1) + xi * t2

    # c2 = a0*b2 + a1*b1 + a2*b0
    c2 = (t4 - t0 - t2) + t1 + (t5 - t1 - t2)  # = a0*b2 + a1*b1 + a2*b0
    # Simplify: c2 = a0*b2 + a1*b1 + a2*b0
    # t4 = a0*b0 + a0*b2 + a2*b0 + a2*b2
    # c2 = t4 - t0 - t2 + t1 + (a1*b2 + a2*b1 + a2*b2)
    # Actually let me just use the direct formula for correctness:
    c2 = a0 * b2 + a1 * b1 + a2 * b0

    return Fq6(c0, c1, c2)
end

Base.:*(s::Fq2, x::Fq6) = Fq6(s * x.c0, s * x.c1, s * x.c2)
Base.:*(x::Fq6, s::Fq2) = s * x

function Base.inv(x::Fq6)
    xi = _FQ6_XI[]
    a0, a1, a2 = x.c0, x.c1, x.c2

    t0 = a0 * a0 - xi * a1 * a2
    t1 = xi * a2 * a2 - a0 * a1
    t2 = a1 * a1 - a0 * a2

    det = a0 * t0 + xi * (a1 * t2 + a2 * t1)
    inv_det = inv(det)

    return Fq6(t0 * inv_det, t1 * inv_det, t2 * inv_det)
end

Base.:/(x::Fq6, y::Fq6) = x * inv(y)

# Exponentiation
function _fq6_pow(x::Fq6, e::BigInt)
    e == 0 && return one(Fq6)
    e < 0 && return inv(x)^(-e)
    result = one(Fq6)
    base = x
    n = e
    while n > 0
        if n & 1 == 1
            result = result * base
        end
        base = base * base
        n >>= 1
    end
    return result
end

# Frobenius maps for Fq6
# For BN curve with twist xi = u+1:
# (c0+c1*v+c2*v^2)^q = frob(c0) + frob(c1)*v^q + frob(c2)*(v^q)^2
function frobenius_fq6(x::Fq6, q_power::Int=1)
    # This is a simplified version; needs proper twist-dependent Frobenius constants
    # For now implement basic structure
    return Fq6(
        frobenius_fq2(x.c0),
        frobenius_fq2(x.c1),
        frobenius_fq2(x.c2)
    )
end

# =============================================================================
# Fq12 - Quadratic extension of Fq6: w^2 = v
# =============================================================================

struct Fq12
    hi::Fq6   # a part
    lo::Fq6   # b part  (element = hi + lo*w)
end

Base.zero(::Type{Fq12}) = Fq12(zero(Fq6), zero(Fq6))
Base.one(::Type{Fq12})  = Fq12(one(Fq6),  zero(Fq6))

Base.:(==)(x::Fq12, y::Fq12) = x.hi == y.hi && x.lo == y.lo

Base.:+(x::Fq12, y::Fq12) = Fq12(x.hi + y.hi, x.lo + y.lo)
Base.:-(x::Fq12, y::Fq12) = Fq12(x.hi - y.hi, x.lo - y.lo)
Base.:-(x::Fq12) = Fq12(-x.hi, -x.lo)

# (a + b*w)(c + d*w) = ac + bd*v + (ad+bc)*w   [since w^2 = v]
# v is the Fq6 generator, accessible as Fq6(0,Fq2(Fq(1),Fq(0)),Fq2(Fq(0),Fq(0)))
function Base.:*(x::Fq12, y::Fq12)
    a, b = x.hi, x.lo
    c, d = y.hi, y.lo

    v  = Fq6(zero(Fq2), one(Fq2), zero(Fq2))

    ac = a * c
    bd = b * d
    return Fq12(ac + v * bd, a * d + b * c)
end

Base.:*(s::Integer, x::Fq12) = begin
    f = Fq(s)
    Fq12(
        Fq6(Fq2(f, Fq(0)), Fq2(Fq(0), Fq(0)), Fq2(Fq(0), Fq(0))) * x.hi,
        Fq6(Fq2(f, Fq(0)), Fq2(Fq(0), Fq(0)), Fq2(Fq(0), Fq(0))) * x.lo
    )
end

function Base.inv(x::Fq12)
    a, b = x.hi, x.lo
    v  = Fq6(zero(Fq2), one(Fq2), zero(Fq2))
    # (a+bw)^(-1) = (a-bw)/(a^2 - v*b^2)
    den = a * a - v * (b * b)
    inv_den = inv(den)
    return Fq12(a * inv_den, -b * inv_den)
end

Base.:/(x::Fq12, y::Fq12) = x * inv(y)

function Base.:^(x::Fq12, e::BigInt)
    e == 0 && return one(Fq12)
    e < 0 && return inv(x)^(-e)
    result = one(Fq12)
    base = x
    n = e
    while n > 0
        if n & 1 == 1
            result = result * base
        end
        base = base * base
        n >>= 1
    end
    return result
end

# Frobenius map for Fq12
function frobenius_fq12(x::Fq12)
    return Fq12(
        frobenius_fq6(x.hi),
        frobenius_fq6(x.lo)
    )
end

# =============================================================================
# Helper: construct Fq12 from G1-point coordinates for pairing input
# =============================================================================
function _fq12_from_g1_coords(x::Fq, y::Fq)
    # Lift Fq point to Fq12: (x + 0*u + ..., y + 0*u + ...)
    x2 = Fq2(x, Fq(0))
    y2 = Fq2(y, Fq(0))
    x6 = Fq6(x2, zero(Fq2), zero(Fq2))
    y6 = Fq6(y2, zero(Fq2), zero(Fq2))
    return Fq12(x6, y6)
end

# Construct Fq6 from Fq2 coordinates for G2 point
function _fq6_from_g2_coords(x::Fq2, y::Fq2)
    return Fq6(x, zero(Fq2), zero(Fq2)), Fq6(y, zero(Fq2), zero(Fq2))
end
