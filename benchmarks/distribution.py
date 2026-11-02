"""Record the iteration count of every chain at one (b, C), for the demo page's histograms.

`iterations.py` keeps only the mean and standard deviation. The demo page's explainer also
needs the shape of the distribution: how many salts a given upper bound rejects, and how
unevenly chains finish when guesses run side by side. Runs unbounded chains with random
inputs and writes one row per chain:

- distribution.csv   iterations at each collision (columns c1 ... cC), one row per chain

Usage: uv run python benchmarks/distribution.py [--bits 32] [--collisions 5] [--runs 1000]
"""

import argparse
import csv
import os
import statistics
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from iterations import measure


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bits", type=int, default=32)
    parser.add_argument("--collisions", type=int, default=5)
    parser.add_argument("--runs", type=int, default=1000)
    parser.add_argument("--workers", type=int, default=os.cpu_count())
    parser.add_argument("--out", type=Path, default=Path(__file__).parent / "results")
    args = parser.parse_args()

    with ProcessPoolExecutor(args.workers) as pool:
        results = measure(pool, args.bits, args.collisions, args.runs)

    args.out.mkdir(parents=True, exist_ok=True)
    path = args.out / "distribution.csv"
    with path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([f"c{c}" for c in range(1, args.collisions + 1)])
        writer.writerows(results)

    final = [row[-1] for row in results]
    print(
        f"b={args.bits} C={args.collisions}: {args.runs:,} chains, "
        f"mean {statistics.mean(final):,.0f}, std {statistics.pstdev(final):,.0f}"
    )
    print(f"Wrote {path}")


if __name__ == "__main__":
    main()
