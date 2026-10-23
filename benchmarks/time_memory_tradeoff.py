"""Show that CHIP's memory requirement can be traded for a little extra hashing.

`Chip.compute` stores every digest so a collision can XOR in the earlier digest D_j.
This script computes the same final digest while storing only each low-bit value's
iteration index, plus one full digest every `--checkpoint` iterations. When a
collision needs D_j, it replays the chain from the nearest checkpoint before j.

For each trial it checks that the digest matches `Chip.compute` exactly, and reports
the extra hashing and the raw memory of both approaches.

Usage: uv run python benchmarks/time_memory_tradeoff.py [--bits 32] [--trials 5]
"""

import argparse
import secrets
from collections.abc import Callable
from typing import Any

from chip import Chip

KEY_BYTES = 4  # a b-bit key (b <= 32) and an iteration index each fit in 4 bytes
INDEX_BYTES = 4


def low_memory_chain(
    data: bytes,
    bits: int,
    collisions: int,
    hash_func: Callable[[bytes], Any],
    checkpoint: int,
) -> tuple[bytes, int, int, int]:
    """Return (digest, iterations, extra hashes, checkpoints stored)."""
    mask = (1 << bits) - 1
    seen: dict[int, int] = {}  # low bits -> iteration index (not the digest)
    checkpoints: dict[int, bytes] = {}  # iteration -> digest, every `checkpoint` steps
    perturbations: dict[int, int] = {}  # iteration -> XOR mask applied after that step
    extra = 0

    def digest_at(j: int) -> bytes:
        """Recompute D_j (before any perturbation at j) by replaying the chain."""
        nonlocal extra
        start = j - j % checkpoint
        h = checkpoints[start] if start else data
        for n in range(start, j):
            if n in perturbations:
                h = (int.from_bytes(h, "big") ^ perturbations[n]).to_bytes(len(h), "big")
            h = hash_func(h).digest()
            extra += 1
        return h

    h = data
    iterations = 0
    while len(perturbations) < collisions:
        h = hash_func(h).digest()
        iterations += 1
        if iterations % checkpoint == 0:
            checkpoints[iterations] = h
        key = int.from_bytes(h, "big") & mask
        j = seen.get(key)
        if j is None:
            seen[key] = iterations
        else:
            mask_value = int.from_bytes(digest_at(j), "big")
            perturbations[iterations] = mask_value
            h = (int.from_bytes(h, "big") ^ mask_value).to_bytes(len(h), "big")
    return hash_func(h).digest(), iterations, extra, len(checkpoints)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bits", type=int, default=32)
    parser.add_argument("--collisions", type=int, default=5)
    parser.add_argument("--checkpoint", type=int, default=1000)
    parser.add_argument("--trials", type=int, default=5)
    args = parser.parse_args()

    chip = Chip(bits=args.bits, collisions=args.collisions)
    for _ in range(args.trials):
        data = secrets.token_bytes(16) + b"hunter2"
        expected = chip.compute(data, bounded=False)
        digest, iterations, extra, stored_checkpoints = low_memory_chain(
            data, chip.bits, chip.collisions, chip.hash_func, args.checkpoint
        )
        assert digest == expected.digest, "digest differs from Chip.compute"

        digest_size = len(digest)
        full = (iterations - chip.collisions) * digest_size
        low = (iterations - chip.collisions) * (KEY_BYTES + INDEX_BYTES)
        low += stored_checkpoints * digest_size
        print(
            f"identical digest, {iterations:,} iterations, "
            f"{extra:,} extra hashes ({extra / iterations:.1%}), "
            f"raw memory {full / 1e6:.1f} MB -> {low / 1e6:.1f} MB"
        )


if __name__ == "__main__":
    main()
