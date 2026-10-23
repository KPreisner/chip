#!/usr/bin/env sh
# Assemble the demo site: the page, the chip package sources, and benchmark data.
# Usage: sh demo/build.sh [output-dir]   (default: _site)
set -eu
out="${1:-_site}"
rm -rf "$out"
mkdir -p "$out/chip"
cp demo/index.html demo/worker.js "$out/"
cp src/chip/__init__.py src/chip/core.py src/chip/passwords.py "$out/chip/"
cp benchmarks/results/iterations.csv "$out/"
echo "Built demo in $out/"
