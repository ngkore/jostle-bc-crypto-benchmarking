#!/bin/bash

# =============================================================================
# Benchmark Configuration
# Modify these values to customize the benchmark run.
# =============================================================================

# Number of warmup iterations (default: 2)
# Warmup iterations are crucial to allow the JVM to optimize the code (JIT compilation) 
# and for the system to reach a steady state before actual measurements begin. 
# Too few warmups might lead to inconsistent results due to cold-start effects.
WARMUP=1

# Number of measurement iterations (default: 3)
# These are the actual benchmark runs where data is collected. 
# More iterations provide better statistical significance and reduce the impact of noise.
# However, increasing this linearly increases the total runtime.
ITERATIONS=3

# Time per iteration (default: "5s")
# The duration for each warmup and measurement iteration.
# "5s" means 5 seconds. Longer times allow for more samples per iteration,
# smoothing out short-term fluctuations.
TIME="1s"

# Number of forks (default: 1)
# How many times to run the benchmark in a fresh JVM.
# Using multiple forks helps to reduce the effects of OS/JVM variance.
# For quick tests, 1 is sufficient. For final results, use 2 or more.
FORK=1

# Benchmark mode: thrpt, avgt, sample, ss, or all (default: "thrpt")
# Determines what metric is measured:
# - thrpt: Throughput (ops/time) - Good for measuring overall capacity.
# - avgt: Average time (time/op) - Good for latency measurements.
# - sample: Sampling time - percentiles of execution time.
# - ss: Single shot - measures cold start performance.
# - all: Runs all of the above.
MODE="all"

# =============================================================================
# Environment Setup
# =============================================================================

# Set these defaults to the known paths in the user's environment for convenience,
# but allow them to be overridden by environment variables.
DEFAULT_NATIVE_LIB_PATH="/home/ubuntu/openssl_3_6/lib64:/home/ubuntu/bouncy-jostle/openssl-jostle/jostle/build/resources/main/native/linux/x86_64"

# Use provided NATIVE_LIB_PATH or fallback to default
if [ -z "$NATIVE_LIB_PATH" ]; then
    echo "NATIVE_LIB_PATH not set. Using default paths from development environment."
    export NATIVE_LIB_PATH="$DEFAULT_NATIVE_LIB_PATH"
else
    echo "Using provided NATIVE_LIB_PATH: $NATIVE_LIB_PATH"
fi

# Ensure commands are run from the project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR/.."

cd "$PROJECT_ROOT"

echo "----------------------------------------------------------------"
echo "Starting Benchmarks"
echo "  Warmup:     $WARMUP"
echo "  Iterations: $ITERATIONS"
echo "  Time:       $TIME"
echo "  Forks:      $FORK"
echo "  Mode:       $MODE"

echo "----------------------------------------------------------------"


# Define Log File
# Ensure the output directory exists
mkdir -p "$PROJECT_ROOT/results"
LOG_FILE="$PROJECT_ROOT/results/benchmark_run.log"

GRADLE_ARGS="-PjmhWarmup=$WARMUP -PjmhIterations=$ITERATIONS -PjmhTime=$TIME -PjmhForks=$FORK -PjmhMode=$MODE"

# Run gradle and pipe output to both console and log file
./gradlew jmh $GRADLE_ARGS --console=plain 2>&1 | tee "$LOG_FILE"
