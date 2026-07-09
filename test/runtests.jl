#!/usr/bin/env julia
# =============================================================================
# SnowlandSMX Test Runner
#
# Runs each module test in an independent Julia process to avoid GC
# instability issues in Julia 1.12 on Windows.
# =============================================================================

const TEST_DIR = @__DIR__
const TEST_MODULES = [
    ("SM3",     "using SnowlandSMX.SM3; using Test",       "sm3_test.jl"),
    ("SM4",     "using SnowlandSMX.SM4",                   "sm4_test.jl"),
    ("SM4Str",  "include(joinpath(@__DIR__, \"..\", \"src\", \"smx\", \"SM4\", \"sm4.jl\"))", "sm4_stream_test.jl"),
    ("ZUC",     "using SnowlandSMX.ZUC",                   "zuc_test.jl"),
    ("Hashlib", "using SnowlandSMX.SM3, SnowlandSMX.CryptoHash", "hashlib_test.jl"),
    ("Util",    "using SnowlandSMX.SM2",                   "util_test.jl"),
    ("SM2",     "using SnowlandSMX.SM3, SnowlandSMX.SM2, Random", "sm2_test.jl"),
    ("SM9",     "using SnowlandSMX.SM3, SnowlandSMX.SM2, SnowlandSMX.SM9, Random", "sm9_test.jl"),
]

function run_test(name::String, import_stmt::String, file::String)
    # Use forward slashes to avoid Windows backslash escape issues in Julia strings
    test_path = joinpath(TEST_DIR, file)
    project_path = joinpath(TEST_DIR, "..")
    # Double backslashes for Julia string literal in generated script
    escaped_test_path = replace(test_path, '\\' => "\\\\")
    script = """
    $import_stmt
    try
        include("$escaped_test_path")
        println("PASS: $name")
    catch e
        println("FAIL: $name")
        print(typeof(e), ": ", e)
        bt = catch_backtrace()
        for (i, frame) in enumerate(stacktrace(bt))
            i > 8 && break
            println("  ", frame)
        end
    end
    """
    tmpfile = joinpath(TEST_DIR, "_tmp_test.jl")
    write(tmpfile, script)
    try
        p = run(`$(Base.julia_cmd()) --project=$project_path $tmpfile`)
        return p.exitcode == 0
    finally
        rm(tmpfile, force=true)
    end
end

function main()
    println("=" ^ 60)
    println("SnowlandSMX Test Suite")
    println("=" ^ 60)
    println()

    passed = 0
    failed = 0
    results = Pair{String,Bool}[]

    for (name, imports, file) in TEST_MODULES
        print("Testing $name... ")
        flush(stdout)
        ok = run_test(name, imports, file)
        push!(results, name => ok)
        if ok
            passed += 1
        else
            failed += 1
        end
        println()
    end

    println()
    println("=" ^ 60)
    println("Results:")
    for (name, ok) in results
        println("  $name: ", ok ? "PASS" : "FAIL")
    end
    println("-" ^ 60)
    println("  TOTAL: $(passed)/$(length(TEST_MODULES)) passed")
    println("=" ^ 60)

    if failed > 0
        exit(1)
    end
end

main()
