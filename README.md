# CHIP: Confounding Hash Iteration for Passwords

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
    h = MD5(h)
    if low_b_bits(h) was seen before (as low_b_bits(D_j)):
        collisions += 1
        h = h XOR D_j            # perturb using the earlier digest
    else:
        remember h
until collisions == C
return salt, MD5(h)
```

- **b** sets how many bits are compared. Each extra bit roughly doubles the work.
- **C** sets how many collisions to wait for. More collisions mean more iterations, with
  diminishing growth.
- If a salt needs more than an upper bound of iterations, a new random salt is drawn.

With `b = 32, C = 5`, a hash takes about 200,000 iterations on average.

## Quick start

Requires [uv](https://docs.astral.sh/uv/).

> [!NOTE]
> The implementation is being rewritten from the 2018 original. Usage examples are coming
> soon.

```sh
uv sync
```

## Development

| Tool | Purpose |
|------|---------|
| [uv](https://docs.astral.sh/uv/) | environments, dependencies, lockfile |
| [ruff](https://docs.astral.sh/ruff/) | linting, import sorting, formatting |
| [mypy](https://mypy-lang.org/) | static type checking (strict) |
| [pytest](https://docs.pytest.org/) | unit tests |
| [Task](https://taskfile.dev/) | command shortcuts (`brew install go-task`) |

```sh
task uv-sync     # install/update the environment
task py-lint     # ruff check + format check + mypy (same as CI)
task py-format   # auto-format and apply safe lint fixes
task py-test     # run unit tests (extra args pass through: task py-test -- -k verify)
```

The same checks run in GitHub Actions on every push and pull request.

## Project layout

```
src/chip/       the CHIP package (standard library only)
tests/          unit tests (pytest)
```
