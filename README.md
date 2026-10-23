# CHIP: Confounding Hash Iteration for Passwords

[![Lint](https://github.com/KPreisner/chip/actions/workflows/lint.yml/badge.svg)](https://github.com/KPreisner/chip/actions/workflows/lint.yml)
[![Test](https://github.com/KPreisner/chip/actions/workflows/test.yml/badge.svg)](https://github.com/KPreisner/chip/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

CHIP is an iterated password hash I designed in 2018 in response to the
[Password Hashing Competition](https://www.password-hashing.net). Instead of hashing a
fixed number of times, it keeps hashing until it has seen **C** collisions among the low
**b** bits of the digests. That makes the iteration count depend on the password and salt
in a way you can't predict without running the whole chain, and it forces the hasher to
keep every digest in memory.

📄 **Paper:** *Frustrating Brute-Force Password Recovery* (Karl Preisner, July 2018). A revised
version is in progress.

> [!WARNING]
> This is research and portfolio code, not a production password hash. Use
> [Argon2id](https://www.rfc-editor.org/rfc/rfc9106) for real systems. The code and paper
> are being revisited.

## How it works

```
h = salt || password
repeat:
    h = SHA256(h)
    if low_b_bits(h) was seen before (as low_b_bits(D_j)):
        collisions += 1
        h = h XOR D_j            # perturb using the earlier digest
    else:
        remember h
until collisions == C
return salt, SHA256(h)
```

- **b** sets how many bits are compared. Each extra bit roughly doubles the work.
- **C** sets how many collisions to wait for. More collisions mean more iterations, with
  diminishing growth.
- If a salt needs more than an upper bound of iterations, a new random salt is drawn.

With `b = 32, C = 5`, one chain takes about 200,000 iterations on average. The default upper
bound (250,000) rejects about 15% of salts, so a full hash costs about 235,000 iterations
including retries.

## Quick start

Requires [uv](https://docs.astral.sh/uv/).

```sh
uv sync
```

```python
from chip import Chip, hash_password, verify

stored = hash_password("hunter2")
# '$chip$h=sha256,b=32,c=5,min=0,max=250000$SOXeJ7iDuFTAnzpA54YPoA$jtbB33Sm...'

verify("hunter2", stored)  # True
verify("hunter3", stored)  # False

# Tune the cost: fewer bits = faster, more collisions = slower
fast = Chip(bits=20, collisions=5, max_iterations=4000)
verify("hunter2", hash_password("hunter2", fast))  # True
```

The hash string records the salt and every parameter (in the style of the
[PHC string format](https://github.com/P-H-C/phc-string-format)), so `verify` needs only
the password and the stored string.

## Command line

`uv sync` also installs a `chip` command. Passwords are prompted for (without echo) when
left off the command line.

In this example, `HASH_NAME` is the hash function applied on every iteration, `BITS` is
how many low bits of each digest are compared, `COLLISIONS` is how many repeats end the
chain, and `MAX_ITERATIONS` is the upper bound: a salt whose chain runs longer is
rejected, and hashing restarts with a new salt. `chip verify` exits with code 0 on a
match and 1 otherwise.

```sh
PASSWORD=hunter2
HASH_NAME=sha256
BITS=20
COLLISIONS=5
MAX_ITERATIONS=4000

HASH=$(uv run chip hash "$PASSWORD" \
  --hash "$HASH_NAME" \
  --bits "$BITS" \
  --collisions "$COLLISIONS" \
  --max "$MAX_ITERATIONS")

echo "$HASH"
uv run chip verify "$HASH" "$PASSWORD"
uv run chip verify "$HASH" hunter3
```

Output:

```text
$chip$h=sha256,b=20,c=5,min=0,max=4000$D4tvj5zpImPdw43O8TKZrA$BM3hGUyB80m/Ee2Apqlz3dCsrmtZFvydS4Qn5Mzr9GY
match
no match
```

Add `-v` to watch hashing happen: each salt attempt, each collision, and why a salt was
rejected, with the time since the program started. The log goes to stderr, so
`HASH=$(...)` still captures only the hash.

```sh
uv run chip hash "$PASSWORD" \
  --hash "$HASH_NAME" \
  --bits "$BITS" \
  --collisions "$COLLISIONS" \
  --max "$MAX_ITERATIONS" \
  --verbose
```

Output:

```text
     11.3 ms  attempt 1: salt a0ddff62a7b9b2531ef4a6fbc508b61b
     12.0 ms    collision 1 at iteration 1415
     12.4 ms    collision 2 at iteration 2095
     12.5 ms    collision 3 at iteration 2199
     12.6 ms    collision 4 at iteration 2578
     13.4 ms    rejected: only 4 of 5 collisions within max_iterations (4000)
     13.4 ms  attempt 2: salt 1361852c3dcdab7c910e57ddb2240fff
     13.8 ms    collision 1 at iteration 724
     13.8 ms    collision 2 at iteration 835
     13.9 ms    collision 3 at iteration 1013
     14.1 ms    collision 4 at iteration 1233
     14.4 ms    collision 5 at iteration 1900
     14.5 ms    accepted: 1900 iterations
$chip$h=sha256,b=20,c=5,min=0,max=4000$E2GFLD3Nq3yRDlfdsiQP/w$AWUuE8Zu55tWv2ajJNQ0uFxWBwjOFzsr9B2dgiVS5b0
```

Run `uv run chip <command> --help` for all options.

## Development

| Tool | Purpose |
|------|---------|
| [uv](https://docs.astral.sh/uv/) | environments, dependencies, lockfile |
| [ruff](https://docs.astral.sh/ruff/) | linting, import sorting, formatting |
| [mypy](https://mypy-lang.org/) | static type checking (strict) |
| [pytest](https://docs.pytest.org/) | unit tests |
| [Task](https://taskfile.dev/) | command shortcuts (`brew install go-task`) |

| Command | What it does |
|---|---|
| `task uv-sync` | install/update the environment |
| `task py-lint` | ruff check + format check + mypy (same as CI) |
| `task py-format` | auto-format and apply safe lint fixes |
| `task py-test` | run unit tests (extra args pass through: `task py-test -- -k verify`) |
| `task bench` | quick benchmark run |
| `task bench-full` | full benchmark; regenerates `benchmarks/results/` |

The same checks run in GitHub Actions on every push and pull request.

## Project layout

```
src/chip/       the CHIP package (standard library only)
tests/          unit tests (pytest)
```

## License

[MIT](LICENSE)
