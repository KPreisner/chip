import base64
import logging
from collections.abc import Callable
from typing import Any

import pytest

from chip import Chip, hash_password, verify
from chip.core import HASH_FUNCS

# Small parameters keep tests fast: b = 16, C = 5 averages about 800 iterations.
FAST = Chip(bits=16, collisions=5, max_iterations=2000)


def test_round_trip() -> None:
    encoded = hash_password("hunter2", FAST)
    assert verify("hunter2", encoded)
    assert not verify("hunter3", encoded)


def test_same_password_gets_different_salts() -> None:
    a = hash_password("hunter2", FAST)
    b = hash_password("hunter2", FAST)
    assert a != b
    assert verify("hunter2", a)
    assert verify("hunter2", b)


def test_encoded_format() -> None:
    encoded = hash_password("pw", FAST)
    _, name, params, salt, digest = encoded.split("$")
    assert name == "chip"
    assert params == "h=sha256,b=16,c=5,min=0,max=2000"
    assert len(base64.b64decode(salt + "==")) == 16
    assert len(base64.b64decode(digest + "=")) == 32


def test_unicode_password() -> None:
    encoded = hash_password("pässwörd 🔑", FAST)
    assert verify("pässwörd 🔑", encoded)


def test_hash_is_recomputable_after_salt_retries() -> None:
    # Each salt attempt must start from fresh state. If stored digests leaked from a
    # rejected salt into the next attempt, the hash couldn't be recomputed from its salt.
    # b = 12, C = 5 averages about 200 iterations, so max = 200 rejects ~half the salts.
    retrying = Chip(bits=12, collisions=5, max_iterations=200)
    for i in range(20):
        password = f"pw{i}"
        assert verify(password, hash_password(password, retrying))


def test_iteration_bounds_are_respected() -> None:
    bounded = Chip(bits=16, collisions=5, min_iterations=700, max_iterations=900)
    encoded = hash_password("pw", bounded)
    salt = base64.b64decode(encoded.split("$")[3] + "==")
    chain = bounded.run("pw", salt)
    assert chain is not None
    assert 700 <= chain.iterations <= 900


@pytest.mark.parametrize("hash_func", HASH_FUNCS.values(), ids=HASH_FUNCS.keys())
def test_supported_hashes(hash_func: Callable[[bytes], Any]) -> None:
    chip = Chip(bits=16, collisions=5, max_iterations=2000, hash_func=hash_func)
    encoded = hash_password("pw", chip)
    assert f"h={hash_func(b'').name}," in encoded
    assert verify("pw", encoded)


def test_impossible_bounds_raise() -> None:
    # Valid parameters, but 5 collisions among 65,536 values within 10 iterations is
    # practically impossible, so every salt is rejected.
    impossible = Chip(bits=16, collisions=5, min_iterations=10, max_iterations=10, max_attempts=3)
    with pytest.raises(RuntimeError):
        hash_password("pw", impossible)


@pytest.mark.parametrize(
    "encoded",
    [
        "",
        "not a hash",
        "$argon2id$v=19$m=65536$salt$hash",
        "$chip$h=crc32,b=16,c=5,min=0,max=2000$AAAA$AAAA",
        "$chip$h=sha256,b=16$AAAA$AAAA",
        "$chip$h=sha256,b=16,c=5,min=0,max=2000$!!!!$AAAA",
    ],
)
def test_malformed_hash_strings(encoded: str) -> None:
    with pytest.raises(ValueError):
        verify("pw", encoded)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("b=16", "b=+16"),  # sign
        ("b=16", "b=1_6"),  # underscore
        ("b=16", "b=016"),  # leading zero
        ("c=5", "c= 5"),  # space
        ("max=2000", "max=2000,x=1"),  # unknown key
        ("b=16,c=5", "c=5,b=16"),  # reordered keys
        ("h=sha256", "h=sha256,h=md5"),  # duplicate key
    ],
)
def test_non_canonical_hash_strings_rejected(old: str, new: str) -> None:
    encoded = hash_password("pw", FAST)
    assert verify("pw", encoded)
    with pytest.raises(ValueError):
        verify("pw", encoded.replace(old, new, 1))


def test_non_canonical_base64_rejected() -> None:
    # A 16-byte salt is 22 base64 characters; the last one carries 4 unused bits.
    # Changing those bits decodes to the same salt but must still be rejected.
    encoded = hash_password("pw", FAST)
    parts = encoded.split("$")
    last = parts[3][-1]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    parts[3] = parts[3][:-1] + alphabet[alphabet.index(last) ^ 1]
    with pytest.raises(ValueError):
        verify("pw", "$".join(parts))


def test_wrong_digest_length_rejected() -> None:
    encoded = hash_password("pw", FAST)
    with pytest.raises(ValueError):
        verify("pw", encoded.replace("h=sha256", "h=md5"))


def test_huge_parameters_rejected_before_any_work() -> None:
    # A crafted string must not be able to make verify() run for hours.
    salt_and_digest = hash_password("pw", FAST).split("$", 3)[3]
    crafted = f"$chip$h=sha512,b=511,c=5,min=0,max=1000000000${salt_and_digest}"
    with pytest.raises(ValueError):
        verify("pw", crafted)


def test_surrounding_whitespace_is_ignored() -> None:
    encoded = hash_password("pw", FAST)
    assert verify("pw", encoded + "\n")
    assert verify("pw", "  " + encoded)


def test_hash_password_logs_retries(caplog: pytest.LogCaptureFixture) -> None:
    # 5 collisions within 200 iterations at b = 12 fails about half the time.
    with caplog.at_level(logging.DEBUG, logger="chip"):
        for i in range(10):
            hash_password(f"pw{i}", Chip(bits=12, collisions=5, max_iterations=200))
    messages = [r.getMessage() for r in caplog.records]
    assert any(m.startswith("attempt 1: salt ") for m in messages)
    assert any("rejected: only" in m for m in messages)
    assert sum("accepted:" in m for m in messages) == 10


def test_min_iterations_rejection_is_logged(caplog: pytest.LogCaptureFixture) -> None:
    chip = Chip(bits=16, collisions=1, min_iterations=1_000_000, max_iterations=1_000_000)
    with caplog.at_level(logging.DEBUG, logger="chip"):
        assert chip.run("pw", b"0" * 16) is None
    assert "below min_iterations" in caplog.text
