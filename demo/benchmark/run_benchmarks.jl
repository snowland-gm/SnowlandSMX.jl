# =============================================================================
# Parent benchmark runner: spawns each module in its own Julia process
# to avoid Julia 1.12 GC crashes.
# =============================================================================

const REPO_ROOT = joinpath(dirname(@__FILE__), "..", "..")

function run_bench_script(name::String, file::String)
    fp = joinpath(dirname(@__FILE__), file)
    println("Running: $name ...")
    p = run(`$(Base.julia_cmd()) --project=$(REPO_ROOT) $fp`)
    if p.exitcode != 0
        println("  FAILED (exit code: $(p.exitcode))")
        return false
    end
    println("  OK")
    return true
end

println("="^50)
println("SnowlandSMX.jl Performance Benchmarks")
println("="^50)
println()

all_ok = true
all_ok &= run_bench_script("SM4", "sm4_standalone_v2.jl")
println()
all_ok &= run_bench_script("SM3", "sm3_standalone_v2.jl")
println()
all_ok &= run_bench_script("ZUC", "zuc_standalone_v2.jl")

println()
println("Benchmarks complete.")
exit(all_ok ? 0 : 1)
