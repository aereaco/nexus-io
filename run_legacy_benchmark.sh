#!/bin/bash
set -e

# Path to nexus-io-legacy binary
NEXUS_LEGACY=/home/aerea/development/nexus-io-legacy/target/release/nexus-io-legacy
CWD=$(pwd)

echo "=== 1. Inception (JS -> C) ==="
$NEXUS_LEGACY js benchmark_legacy_external.js

echo "=== 2. Crystalization (C -> Native) ==="
clang -O3 out.c -o out.bin -Wno-everything

echo "=== 3. Execution (Native AOT) ==="
start_time=$(date +%s%N)
./out.bin
end_time=$(date +%s%N)
duration=$(( (end_time - start_time) / 1000000 ))
echo "Native AOT Execution took ${duration}ms"

echo "=== 4. Baseline (Interpreter) ==="
$NEXUS_LEGACY js -e "
function fib(n) {
  if (n <= 1) return n;
  return fib(n - 1) + fib(n - 2);
}
const start = Date.now();
console.log(fib(40));
console.log('Interpreter Baseline took ' + (Date.now() - start) + 'ms');
"

# Clean up
rm out.c out.bin benchmark_legacy_external.js
