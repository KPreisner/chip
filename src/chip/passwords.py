"""Password hashing API: salts, retries, and stored hash strings.

`hash_password` draws a random salt and runs the CHIP chain. If the iteration count falls
outside `[min_iterations, max_iterations]`, it draws a new salt and starts over. The result
is a self-describing string (in the style of the PHC string format) holding the salt and
every parameter, so `verify` needs only the password and that string.
"""

import base64
import hmac
import re
import secrets

from chip.core import HASH_FUNCS, Chip

SALT_BYTES = 16

# Strict format for stored strings: fixed key order, plain decimal numbers, base64 fields.
_NUMBER = r"(0|[1-9][0-9]*)"
_B64 = r"([A-Za-z0-9+/]+)"
_ENCODED = re.compile(
    rf"\$chip\$h=({'|'.join(HASH_FUNCS)}),b={_NUMBER},c={_NUMBER},"
    rf"min={_NUMBER},max={_NUMBER}\${_B64}\${_B64}"
)


def hash_password(password: str, chip: Chip | None = None) -> str:
    """Hash `password`, returning a self-describing string like
    `$chip$h=sha256,b=32,c=5,min=0,max=250000$<salt>$<hash>`.
    """
    chip = chip or Chip()
    for _ in range(chip.max_attempts):
        salt = secrets.token_bytes(SALT_BYTES)
        chain = chip.run(password, salt)
        if chain is not None:
            return _encode(chip, salt, chain.digest)
    raise RuntimeError(
        f"no salt met the iteration bounds in {chip.max_attempts} attempts; "
        "widen [min_iterations, max_iterations]"
    )


def verify(password: str, encoded: str) -> bool:
    """Check `password` against a string produced by `hash_password`.

    Surrounding whitespace (e.g. a trailing newline from a file) is ignored.
    Raises `ValueError` if `encoded` is malformed or its parameters exceed the limits.
    """
    chip, salt, expected = _decode(encoded.strip())
    chain = chip.run(password, salt)
    return chain is not None and hmac.compare_digest(chain.digest, expected)


def _encode(chip: Chip, salt: bytes, digest: bytes) -> str:
    params = (
        f"h={chip.hash_name},b={chip.bits},c={chip.collisions},"
        f"min={chip.min_iterations},max={chip.max_iterations}"
    )
    return f"$chip${params}${_b64encode(salt)}${_b64encode(digest)}"


def _decode(encoded: str) -> tuple[Chip, bytes, bytes]:
    match = _ENCODED.fullmatch(encoded)
    if match is None:
        raise ValueError("not a valid CHIP hash string")
    hash_name, bits, collisions, min_iter, max_iter, salt_text, digest_text = match.groups()
    chip = Chip(  # raises ValueError if any parameter is out of range
        bits=int(bits),
        collisions=int(collisions),
        min_iterations=int(min_iter),
        max_iterations=int(max_iter),
        hash_func=HASH_FUNCS[hash_name],  # the regex only allows names in the table
    )
    salt = _b64decode(salt_text)
    digest = _b64decode(digest_text)
    if len(salt) != SALT_BYTES or len(digest) != chip.hash_func(b"").digest_size:
        raise ValueError("CHIP hash string has a wrong salt or digest length")
    return chip, salt, digest


def _b64encode(data: bytes) -> str:
    # Unpadded standard base64, as in the PHC string format.
    return base64.b64encode(data).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes:
    data = base64.b64decode(text + "=" * (-len(text) % 4), validate=True)
    # Reject non-canonical encodings (e.g. stray low bits in the last character), so each
    # hash has exactly one valid string.
    if _b64encode(data) != text:
        raise ValueError("non-canonical base64 in CHIP hash string")
    return data
