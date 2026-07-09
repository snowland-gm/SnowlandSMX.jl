# =============================================================================
# SM9 - Elliptic Curve Operations (Jacobian coordinates)
#
# G1: E/Fq:  y^2 = x^3 + b   (b = 5)
# G2: E'/Fq^2: y^2 = x^3 + b/beta  (sextic twist, beta = u+1)
#
# Jacobian: (X, Y, Z) where affine = (X/Z^2, Y/Z^3)
# Curve equation: Y^2 = X^3 + b*Z^6  (for G1)
# =============================================================================

# =============================================================================
# Curve Parameters
# =============================================================================

const _SM9_B = Ref{Fq}()
const _SM9_B2 = Ref{Fq2}()    # b/beta for twisted curve
const _SM9_B12 = Ref{Fq12}()

function _curve_set_b(b::BigInt)
    _SM9_B[] = Fq(b)
    # Sextic twist parameter beta = u + 1
    beta = Fq2(Fq(1), Fq(1))
    _SM9_B2[] = Fq2(Fq(b), Fq(0)) / beta
end

function _curve_b()
    return _SM9_B[]
end

function _curve_b2()
    return _SM9_B2[]
end

# =============================================================================
# G1 Point (Jacobian on Fq)
# =============================================================================

struct G1Point
    x::Fq
    y::Fq
    z::Fq
end

const G1_INF = G1Point(Fq(0), Fq(0), Fq(0))

function Base.:(==)(p::G1Point, q::G1Point)
    if isinf_g1(p) && isinf_g1(q)
        return true
    end
    if isinf_g1(p) || isinf_g1(q)
        return false
    end
    z2p = p.z^2; z2q = q.z^2
    z3p = p.z * z2p; z3q = q.z * z2q
    return p.x * z2q == q.x * z2p && p.y * z3q == q.y * z3p
end

isinf_g1(p::G1Point) = p.z.n == 0

function is_on_curve_g1(p::G1Point)
    if isinf_g1(p)
        return true
    end
    z2 = p.z^2
    z6 = z2^3
    rhs = p.x^3 + _SM9_B[] * z6
    lhs = p.y^2
    return lhs == rhs
end

function _g1_double(p::G1Point)
    if isinf_g1(p) || p.y.n == 0
        return G1_INF
    end
    z2 = p.z^2
    a = p.x^2 * Fq(3)
    b = p.y * p.z * Fq(2)
    c = a * a
    d = p.x * b^2 * Fq(2)
    e = c - Fq(2) * d
    nx = b * (c - Fq(2) * d)  # Wait, let me use standard formulas

    # Standard Jacobian doubling:
    # A = 3*X1^2
    # B = Y1^2
    # C = X1*B
    # D = A^2 - 8*C
    # X3 = 2*D*Y1
    # Y3 = A*(4*C - D) - 8*B^2
    # Z3 = 2*Y1*Z1

    y2 = p.y^2
    a = Fq(3) * p.x^2
    b = y2
    c = p.x * p.y^2  # X1 * Y1^2
    d = a^2 - Fq(8) * c
    nx = Fq(2) * d * p.y
    ny = a * (Fq(4) * c - d) - Fq(8) * y2^2
    nz = Fq(2) * p.y * p.z

    return G1Point(nx, ny, nz)
end

function _g1_add(p1::G1Point, p2::G1Point)
    if isinf_g1(p1); return p2; end
    if isinf_g1(p2); return p1; end
    if p1 == p2; return _g1_double(p1); end

    z1_2 = p1.z^2
    z2_2 = p2.z^2
    u1 = p1.x * z2_2
    u2 = p2.x * z1_2
    s1 = p1.y * p2.z * z2_2
    s2 = p2.y * p1.z * z1_2

    if u1 == u2
        if s1 == s2
            return _g1_double(p1)
        else
            return G1_INF
        end
    end

    h = u2 - u1
    r = s2 - s1
    h2 = h^2
    h3 = h * h2
    u1h2 = u1 * h2

    nx = r^2 - h3 - Fq(2) * u1h2
    ny = r * (u1h2 - nx) - s1 * h3
    nz = p1.z * p2.z * h

    return G1Point(nx, ny, nz)
end

function _g1_mul(p::G1Point, n::BigInt)
    if n == 0 || isinf_g1(p); return G1_INF; end
    if n < 0; return _g1_mul(_g1_neg(p), -n); end

    result = G1_INF
    addend = p
    k = n
    while k > 0
        if k & 1 == 1
            result = _g1_add(result, addend)
        end
        addend = _g1_double(addend)
        k >>= 1
    end
    return result
end

function _g1_neg(p::G1Point)
    return G1Point(p.x, -p.y, p.z)
end

function affine_g1(p::G1Point)
    if isinf_g1(p); return (Fq(0), Fq(0)); end
    z_inv = inv(p.z)
    z2_inv = z_inv^2
    return (p.x * z2_inv, p.y * z_inv * z2_inv)
end

# =============================================================================
# G2 Point (Jacobian on Fq^2)
# =============================================================================

struct G2Point
    x::Fq2
    y::Fq2
    z::Fq2
end

const G2_INF = G2Point(zero(Fq2), zero(Fq2), zero(Fq2))

Base.:(==)(p::G2Point, q::G2Point) = begin
    if isinf_g2(p) && isinf_g2(q); return true; end
    if isinf_g2(p) || isinf_g2(q); return false; end
    z2p = p.z^2; z2q = q.z^2
    z3p = p.z * z2p; z3q = q.z * z2q
    return p.x * z2q == q.x * z2p && p.y * z3q == q.y * z3p
end

isinf_g2(p::G2Point) = p.z.a.n == 0 && p.z.b.n == 0

function is_on_curve_g2(p::G2Point)
    if isinf_g2(p); return true; end
    z2 = p.z^2
    z6 = z2^3
    rhs = p.x^3 + _SM9_B2[] * z6
    lhs = p.y^2
    return lhs == rhs
end

function _g2_double(p::G2Point)
    if isinf_g2(p) || (p.y.a.n == 0 && p.y.b.n == 0)
        return G2_INF
    end
    y2 = p.y^2
    a = Fq2(Fq(3), Fq(0)) * p.x^2
    c = p.x * y2
    d = a^2 - Fq2(Fq(8), Fq(0)) * c
    nx = Fq2(Fq(2), Fq(0)) * d * p.y
    ny = a * (Fq2(Fq(4), Fq(0)) * c - d) - Fq2(Fq(8), Fq(0)) * y2^2
    nz = Fq2(Fq(2), Fq(0)) * p.y * p.z
    return G2Point(nx, ny, nz)
end

function _g2_add(p1::G2Point, p2::G2Point)
    if isinf_g2(p1); return p2; end
    if isinf_g2(p2); return p1; end
    if p1 == p2; return _g2_double(p1); end

    z1_2 = p1.z^2
    z2_2 = p2.z^2
    u1 = p1.x * z2_2
    u2 = p2.x * z1_2
    s1 = p1.y * p2.z * z2_2
    s2 = p2.y * p1.z * z1_2

    if u1 == u2
        if s1 == s2
            return _g2_double(p1)
        else
            return G2_INF
        end
    end

    h = u2 - u1
    r = s2 - s1
    h2 = h^2
    h3 = h * h2
    u1h2 = u1 * h2

    nx = r^2 - h3 - Fq2(Fq(2), Fq(0)) * u1h2
    ny = r * (u1h2 - nx) - s1 * h3
    nz = p1.z * p2.z * h

    return G2Point(nx, ny, nz)
end

function _g2_mul(p::G2Point, n::BigInt)
    if n == 0 || isinf_g2(p); return G2_INF; end
    if n < 0; return _g2_mul(_g2_neg(p), -n); end

    result = G2_INF
    addend = p
    k = n
    while k > 0
        if k & 1 == 1
            result = _g2_add(result, addend)
        end
        addend = _g2_double(addend)
        k >>= 1
    end
    return result
end

function _g2_neg(p::G2Point)
    return G2Point(p.x, -p.y, p.z)
end

function affine_g2(p::G2Point)
    if isinf_g2(p); return (zero(Fq2), zero(Fq2)); end
    z_inv = inv(p.z)
    z2_inv = z_inv^2
    return (p.x * z2_inv, p.y * z_inv * z2_inv)
end

# =============================================================================
# G2 Twist Map: E'(Fq^2) -> E(Fq^12)
#
# For the sextic twist with beta = u+1:
# The twist isomorphism psi: E'(Fq^2) -> E(Fq^12)
# maps (x, y) -> (beta * x', beta^(3/2) * y')
# where x', y' are the images of x, y under the embedding Fq^2 -> Fq^12.
#
# In the tower Fq^12 = Fq^6[w]/(w^2-v), Fq^6 = Fq^2[v]/(v^3-xi):
# The twist uses:
# - "w" maps to beta^(1/2) essentially
# - The embedding uses w^2 = v and maps Fq^2 elements appropriately
#
# For the SM9 BN curve with beta = u+1:
# The twist map embeds (x, y) in Fq^2 to Fq^12 as:
#   x' = w^2 * embed(x)  (multiply by w^2)
#   y' = w^3 * embed(y)  (multiply by w^3)
# where embed: Fq^2 -> Fq^12 lifts a+bu to Fq12 coefficients.
# =============================================================================

# Embed Fq2 element into Fq12: a + b*u -> a + b*u + 0*v + ... (in Fq6 hi part)
function _fq2_to_fq12_hi(x::Fq2)
    return Fq12(
        Fq6(x, zero(Fq2), zero(Fq2)),
        Fq6(zero(Fq2), zero(Fq2), zero(Fq2))
    )
end

# w element in Fq12 (the quadratic extension generator)
# w is represented as Fq12(zero(Fq6), one(Fq6))
function _fq12_w()
    return Fq12(zero(Fq6), one(Fq6))
end

function twist_g2_to_fq12(p::G2Point)
    if isinf_g2(p); return (one(Fq12), one(Fq12)); end

    ax, ay = affine_g2(p)

    # Embed affine coords
    X = _fq2_to_fq12_hi(ax)
    Y = _fq2_to_fq12_hi(ay)

    w = _fq12_w()
    w2 = w * w    # w^2 = v: Fq12 with v in hi position
    w3 = w2 * w   # w^3

    return (w2 * X, w3 * Y)
end
