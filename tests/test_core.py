import hashlib
import math
import secrets
import statistics

import pytest

from chip import Chip

# Small parameters keep tests fast: b = 16, C = 5 averages about 800 iterations.
FAST = Chip(bits=16, collisions=5, max_iterations=2000)


def test_compute_is_deterministic() -> None:
    data = b"salt" + b"password"
    chip = Chip(bits=16, collisions=5)
    first = chip.compute(data, bounded=False)
    second = chip.compute(data, bounded=False)
    assert first == second
    assert len(first.collision_iterations) == 5
    assert list(first.collision_iterations) == sorted(first.collision_iterations)
    assert first.iterations == first.collision_iterations[-1]


def test_perturbation_changes_the_chain() -> None:
    # With XOR perturbation, a different collision count changes the final digest.
    data = b"salt" + b"password"
    four = Chip(bits=16, collisions=4).compute(data, bounded=False)
    five = Chip(bits=16, collisions=5).compute(data, bounded=False)
    assert four.digest != five.digest


@pytest.mark.parametrize(
    "kwargs",
    [
        {"hash_func": hashlib.shake_128},
        {"bits": 0},
        {"bits": 41},
        {"collisions": 0},
        {"collisions": 101},
        {"min_iterations": 10, "max_iterations": 5},
        {"max_iterations": 2_000_001},
        {"collisions": 5, "max_iterations": 5},
        {"max_attempts": 0},
    ],
)
def test_invalid_parameters(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        Chip(**kwargs)  # type: ignore[arg-type]


def test_bounded_compute_stops_at_max_iterations() -> None:
    chain = Chip(bits=16, collisions=5, max_iterations=10).compute(b"data")
    assert chain.iterations == 10
    assert len(chain.collision_iterations) < 5


def test_chain_is_immutable_and_hashable() -> None:
    chain = FAST.compute(b"data", bounded=False)
    assert isinstance(chain.collision_iterations, tuple)
    assert hash(chain) == hash(FAST.compute(b"data", bounded=False))


def test_first_collision_matches_birthday_bound() -> None:
    # Expected iterations to the first repeat among 2**b values is about sqrt(pi/2 * 2**b).
    bits = 12
    chip = Chip(bits=bits, collisions=1)
    firsts = [chip.compute(secrets.token_bytes(16), bounded=False).iterations for _ in range(500)]
    expected = math.sqrt(math.pi / 2 * 2**bits)
    assert statistics.mean(firsts) == pytest.approx(expected, rel=0.15)


def test_explainer_example_chain() -> None:
    # The worked example in the demo page's explainer (demo/explainer.js, EXAMPLE). The page
    # recomputes this chain with the browser's SHA-256, so the two must agree.
    salt = bytes.fromhex("5c1e4a9b7f0362d8e1a74c2b90f3d65e")
    chain = Chip(bits=4, collisions=3).compute(salt + b"hunter2", bounded=False)
    assert chain.collision_iterations == (9, 11, 12)
    assert chain.digest.hex() == "063a918a4bcd790bf964fdaf7d64ad03ec5fef6b85bcbc21fe02ceb12f4e7093"
