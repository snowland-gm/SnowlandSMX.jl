# =============================================================================
# SM9 - Optimal Ate Pairing over BN Curve (GM/T 0044-2016 Part 5)
# =============================================================================

# =============================================================================
# Pairing Parameters
# =============================================================================

const _ATE_LOOP_COUNT = Ref{BigInt}(BigInt(0))
const _ATE_LOOP_BITS  = Ref{Vector{Int}}(Int[])
const _FINAL_HARD_EXP = Ref{BigInt}(BigInt(0))  # (q^4 - q^2 + 1) / N

# ---------------------------------------------------------------------------
# Initialize pairing parameters from SM9 BN curve
#   t : BN curve parameter
#   q : field prime  = 36t^4 + 36t^3 + 24t^2 + 6t + 1
#   N : group order  = 36t^4 + 36t^3 + 18t^2 + 6t + 1
# ---------------------------------------------------------------------------
function _pairing_init(t::BigInt, q::BigInt, N::BigInt)
    # Ate loop count: s = |6t + 2|
    s = abs(BigInt(6) * t + BigInt(2))
    _ATE_LOOP_COUNT[] = s

    bits = Int[]
    n = s
    while n > 0
        pushfirst!(bits, Int(n & 1))
        n >>= 1
    end
    _ATE_LOOP_BITS[] = bits

    # Hard exponent: (q^4 - q^2 + 1) / N
    q2 = q * q
    q4 = q2 * q2
    _FINAL_HARD_EXP[] = (q4 - q2 + 1) ÷ N
end

# =============================================================================
# Miller Loop: Line Function
#
# Evaluate line through T1, T2 (G2 points) at P (G1 point lifted to Fq12).
# Returns (num, den) in Fq12.
# =============================================================================

function _miller_line(T1::G2Point, T2::G2Point, Px::Fq12, Py::Fq12)
    if isinf_g2(T1) || isinf_g2(T2)
        return (one(Fq12), one(Fq12))
    end

    # Affine coordinates
    x1, y1 = if T1.z == one(Fq2)
        T1.x, T1.y
    else
        iz  = inv(T1.z)
        iz2 = iz^2
        T1.x * iz2, T1.y * iz * iz2
    end

    x2, y2 = if T2.z == one(Fq2)
        T2.x, T2.y
    else
        iz  = inv(T2.z)
        iz2 = iz^2
        T2.x * iz2, T2.y * iz * iz2
    end

    X1 = _fq2_to_fq12_hi(x1)
    Y1 = _fq2_to_fq12_hi(y1)
    X2 = _fq2_to_fq12_hi(x2)
    Y2 = _fq2_to_fq12_hi(y2)

    if X1 == X2 && Y1 == Y2
        # Tangent: lambda = 3*x1^2 / (2*y1)
        t3 = _fq2_to_fq12_hi(Fq2(Fq(3), Fq(0)))
        t2 = _fq2_to_fq12_hi(Fq2(Fq(2), Fq(0)))
        lam = t3 * X1 * X1 / (t2 * Y1)
    elseif X1 == X2
        return (Px - X1, one(Fq12))  # vertical line
    else
        lam = (Y2 - Y1) / (X2 - X1)
    end

    num = Py - Y1 - lam * (Px - X1)
    return (num, one(Fq12))
end

# =============================================================================
# Miller Loop: f_{s,Q}(P)
# =============================================================================

function _miller_loop(Q::G2Point, P::G1Point)
    if isinf_g2(Q) || isinf_g1(P)
        return one(Fq12)
    end

    ax, ay = affine_g1(P)
    Px = _fq2_to_fq12_hi(Fq2(ax, Fq(0)))
    Py = _fq2_to_fq12_hi(Fq2(ay, Fq(0)))

    R = Q
    f = one(Fq12)

    bits = _ATE_LOOP_BITS[]
    for i in 2:length(bits)
        bit = bits[i]
        lnum, lden = _miller_line(R, R, Px, Py)
        f = f * f * lnum / lden
        R = _g2_double(R)

        if bit == 1
            lnum, lden = _miller_line(R, Q, Px, Py)
            f = f * lnum / lden
            R = _g2_add(R, Q)
        end
    end

    # Additional steps for optimal Ate pairing
    Q1  = _g2_frobenius_map(Q, 1)
    nQ2 = _g2_neg(_g2_frobenius_map(Q, 2))

    lnum, lden = _miller_line(R, Q1, Px, Py)
    f = f * lnum / lden
    R = _g2_add(R, Q1)

    lnum, lden = _miller_line(R, nQ2, Px, Py)
    f = f * lnum / lden

    return f
end

# =============================================================================
# G2 Frobenius Maps
# =============================================================================

function _g2_frobenius_map(Q::G2Point, pow::Int)
    if isinf_g2(Q); return Q; end
    if pow == 1
        return G2Point(frobenius_fq2(Q.x), frobenius_fq2(Q.y), frobenius_fq2(Q.z))
    elseif pow == 2
        return G2Point(frobenius2_fq2(Q.x), frobenius2_fq2(Q.y), frobenius2_fq2(Q.z))
    else
        # Apply recursively
        result = Q
        for _ in 1:pow
            result = _g2_frobenius_map(result, 1)
        end
        return result
    end
end

# =============================================================================
# Fq12 Frobenius / Conjugation
# =============================================================================

function _fq12_frobenius2(x::Fq12)
    return Fq12(
        Fq6(frobenius2_fq2(x.hi.c0), frobenius2_fq2(x.hi.c1), frobenius2_fq2(x.hi.c2)),
        Fq6(frobenius2_fq2(x.lo.c0), frobenius2_fq2(x.lo.c1), frobenius2_fq2(x.lo.c2))
    )
end

function _fq12_conj(x::Fq12)
    # For BN Fq12 = Fq6[w]/(w^2-v), conjugation sends w -> -w
    return Fq12(x.hi, -x.lo)
end

# =============================================================================
# Final Exponentiation: f → f^((q^12 - 1)/N)
#
# Decomposition:
#   (q^12 - 1)/N = (q^6 - 1) * (q^2 + 1) * (q^4 - q^2 + 1)/N
#
# Part 1+2 (easy): f^(q^6-1) * f^(q^2+1)  [cheap, uses Frobenius]
# Part 3 (hard):   f^((q^4-q^2+1)/N)       [~768-bit exponent]
# =============================================================================

function _final_exp_easy(f::Fq12)
    # Step 1: f^(q^6 - 1) = f^(q^6) / f
    # For elements in Fq12 eventually going to cyclotomic subgroup,
    # Frobenius^6 acts as conjugation: f^(q^6) = conj(f)
    f_inv = inv(f)
    f_conj = _fq12_conj(f)
    f1 = f_conj * f_inv

    # Step 2: f^(q^2 + 1) = f^(q^2) * f
    f_frob2 = _fq12_frobenius2(f1)
    f2 = f_frob2 * f1

    return f2
end

function _final_exp_hard(f::Fq12)
    # Direct exponentiation with precomputed hard exponent
    exp = _FINAL_HARD_EXP[]
    if exp == 0
        error("Final hard exponent not initialized")
    end
    result = one(Fq12)
    base = f
    n = exp
    while n > 0
        if n & 1 == 1
            result = result * base
        end
        base = base * base
        n >>= 1
    end
    return result
end

function _final_exponentiate(f::Fq12)
    return _final_exp_hard(_final_exp_easy(f))
end

# =============================================================================
# Optimal Ate Pairing
#
#   ate_pairing(Q, P): G2 x G1 -> GT
#
# Returns an element in GT (subgroup of Fq12).
# =============================================================================

function ate_pairing(Q::G2Point, P::G1Point)
    return _final_exponentiate(_miller_loop(Q, P))
end
