"""Core CHIP algorithm.

CHIP iterates a hash function until it has seen `collisions` repeats among the low
`bits` bits of the digests (the paper calls these parameters C and b). Each repeat
perturbs the chain by XOR-ing the current digest with the earlier digest it collided
with, so computing the chain requires keeping every digest in memory.

This module is the algorithm only. Salts, retries, and stored hash strings live in
`chip.passwords`.
"""

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

# Hash functions CHIP accepts, by name: every fixed-size hash hashlib guarantees on all
# platforms (shake_* is left out because its digest() needs a length). verify() uses this
# to turn the `h=` name in a stored string back into the function, like bcrypt and Argon2.
HASH_FUNCS: dict[str, Callable[[bytes], Any]] = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
    "sha3_224": hashlib.sha3_224,
    "sha3_256": hashlib.sha3_256,
    "sha3_384": hashlib.sha3_384,
    "sha3_512": hashlib.sha3_512,
    "blake2b": hashlib.blake2b,
    "blake2s": hashlib.blake2s,
}

# Upper limits on parameters. verify() takes its parameters from the stored string, so
# without these a crafted string could make one call run for hours and exhaust memory.
MAX_BITS = 40
MAX_COLLISIONS = 100
MAX_ITERATIONS = 2_000_000


@dataclass(frozen=True)
class Chain:
    """Result of running one CHIP hash chain."""

    digest: bytes
    """Final digest (one extra hash after the last perturbation)."""
    iterations: int
    """Number of hash iterations before the final hash."""
    collision_iterations: tuple[int, ...]
    """Iteration number at which each collision occurred."""


class Chip:
    """CHIP parameters.

    Defaults follow the paper's recommendation (b = 32, C = 5, about 200,000 iterations
    per chain on average), with SHA-256 instead of MD5 and an upper bound of roughly one
    standard deviation above the mean. That bound rejects about 15% of salts, so a hash
    costs about 235,000 iterations on average including retries.
    """

    def __init__(
        self,
        bits: int = 32,
        collisions: int = 5,
        min_iterations: int = 0,
        max_iterations: int = 250_000,
        hash_func: Callable[[bytes], Any] = hashlib.sha256,
        max_attempts: int = 1000,
    ) -> None:
        hash_name = hash_func(b"").name
        if hash_name not in HASH_FUNCS:
            raise ValueError(f"hash_func must be one of hashlib.{{{', '.join(HASH_FUNCS)}}}")
        if not 1 <= bits <= MAX_BITS:
            raise ValueError(f"bits must be in [1, {MAX_BITS}], got {bits}")
        if not 1 <= collisions <= MAX_COLLISIONS:
            raise ValueError(f"collisions must be in [1, {MAX_COLLISIONS}], got {collisions}")
        if not 0 <= min_iterations <= max_iterations <= MAX_ITERATIONS:
            raise ValueError(f"need 0 <= min_iterations <= max_iterations <= {MAX_ITERATIONS}")
        # The first iteration can never collide, so C collisions need more than C iterations.
        if max_iterations <= collisions:
            raise ValueError(f"max_iterations must be > collisions ({collisions})")
        if max_attempts < 1:
            raise ValueError(f"max_attempts must be >= 1, got {max_attempts}")

        self.bits = bits
        self.collisions = collisions
        self.min_iterations = min_iterations
        self.max_iterations = max_iterations
        self.hash_name = hash_name
        self.max_attempts = max_attempts
        self.hash_func = hash_func

    def compute(self, data: bytes, bounded: bool = True) -> Chain:
        """Run the CHIP hash chain on `data` (normally `salt + password`).

        Stops after `collisions` collisions, or after `max_iterations` iterations if
        `bounded`. The benchmarks use unbounded runs to measure iteration counts; with
        `bits <= MAX_BITS` those take about C * 2^(b/2) iterations, so they finish.
        """
        hash_func = self.hash_func  # local lookup is faster in the hot loop
        mask: int = (1 << self.bits) - 1
        seen: dict[int, int] = {}  # low bits -> full digest, both as ints
        collision_iterations: list[int] = []
        h: bytes = data
        iterations: int = 0

        while len(collision_iterations) < self.collisions:
            if bounded and iterations >= self.max_iterations:
                break
            h = hash_func(h).digest()
            iterations += 1

            h_int = int.from_bytes(h, "big")
            key = h_int & mask
            earlier = seen.get(key)
            if earlier is None:
                seen[key] = h_int
            else:
                collision_iterations.append(iterations)
                h = (h_int ^ earlier).to_bytes(len(h), "big")

        return Chain(hash_func(h).digest(), iterations, tuple(collision_iterations))

    def run(self, password: str, salt: bytes) -> Chain | None:
        """Run the chain for one salt; return None if it misses the iteration bounds."""
        chain = self.compute(salt + password.encode("utf-8"))
        if (
            len(chain.collision_iterations) == self.collisions
            and self.min_iterations <= chain.iterations <= self.max_iterations
        ):
            return chain
        return None
