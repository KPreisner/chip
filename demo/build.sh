#!/usr/bin/env sh
# Assemble the site: the demo and explainer page, its scripts, the chip package sources, and
# benchmark data.
# Usage: sh demo/build.sh [output-dir]   (default: _site)
set -eu
out="${1:-_site}"
rm -rf "$out"
mkdir -p "$out/chip"
cp demo/index.html demo/worker.js demo/chain.js demo/explainer.js "$out/"
cp src/chip/__init__.py src/chip/core.py src/chip/passwords.py "$out/chip/"
cp benchmarks/results/iterations.csv benchmarks/results/distribution.csv \
   benchmarks/results/memory.csv "$out/"
echo "Built site in $out/"
