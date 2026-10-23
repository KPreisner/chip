# CHIP: Confounding Hash Iteration for Passwords

Karl Preisner

*Originally developed and written in 2018; revised in 2026.*

## Abstract

In 2013, an outside group ran a public [Password Hashing Competition](https://www.password-hashing.net)
(PHC). They solicited new password hashing algorithms that, in addition to being secure,
have parameters that can be adjusted to frustrate brute-force password recovery. We
describe CHIP, a variant of an iterated hash with these properties. CHIP is a salted,
iterated hash with adjustable parameters. Together with the password being hashed, the
parameters determine how much computation time and memory the hash takes, and the
number of iterations cannot be known without running the hash. We measure how the cost
grows with each parameter and discuss what this design does, and does not, protect
against.

## Introduction

Brute-force password recovery means running the password hash on a large space of
candidate passwords. Message digest algorithms, upon which password hashes are built,
are designed to be fast. To make each password hash more expensive to compute, the
traditional approach has been to require many iterations of the message digest.

The PHC proposals share a common theme: the ability to control both the time and the
memory needed to compute a password hash. They use three approaches, often together:

- **Require more memory.** This makes the hash harder to implement on processors with
  limited on-chip memory, such as GPUs (graphics processing units).
- **Require more iterations.** This increases the computation time.
- **Make the computation time depend on the input.** This reduces the gains from
  parallel hardware that processes many guesses in lockstep, since threads that finish
  early sit idle while they wait for the slowest one.

CHIP implements all three. While many PHC proposals contrive entirely new hashing
algorithms, CHIP builds on an existing, well-studied hash function and applies it in a
way that adds memory and input-dependent cost.

## How CHIP works

CHIP uses a standard hash function: SHA-256 by default, though any fixed-size hash
can be substituted (the implementation supports 12 from Python's `hashlib`, including
MD5, SHA-512, SHA-3, and BLAKE2). For a password $P$ and a random salt $S$, CHIP
computes the hash recursively:

$$D_1 = H(S \,\|\, P), \quad D_2 = H(D_1), \quad \ldots, \quad D_i = H(D_{i-1})$$

We call $D_1, D_2, \ldots$ the *D-sequence*. Let $L_i$ be the low-order $b$ bits of
$D_i$, and call $L_1, L_2, \ldots$ the *L-sequence*.

Because hash outputs are effectively random, we do not expect repeated values in the
D-sequence. However, because of the birthday paradox, we expect to see duplicate values
in the L-sequence after approximately

$$\sqrt{2^b} = 2^{b/2}$$

iterations, because this is when the number of pairs in the L-sequence approaches the
number of possible $b$-bit values. More precisely, the probability of a duplicate passes
one half after about $1.18 \cdot 2^{b/2}$ iterations, and the expected wait for the first
duplicate is $\sqrt{\frac{\pi}{2} \cdot 2^b} \approx 1.25 \cdot 2^{b/2}$ iterations, which
matches our measurements (about 81,000 at $b = 32$). See the
[birthday problem](https://en.wikipedia.org/wiki/Birthday_problem#Average_number_of_people_to_get_at_least_one_shared_birthday)
for the derivation.

CHIP counts these repeats (*collisions*) and stops after $C$ of them, a second
parameter. If it stops after $T$ iterations, it has seen $T - C$ distinct $b$-bit
values. Together, $b$ and $C$ give probabilistic control over the expected number of
iterations.

Detecting collisions requires storing the L-sequence. CHIP uses a hash table, which
has $O(1)$ lookup and insertion, the only two operations it needs.

### Perturbation: why the chain needs memory

Imagine someone guesses a password and wants to check it against a stored hash. If
they check each digest $D_i$ against the target as they compute it, they would not
care when the iteration actually stopped. They would only need to run enough
iterations to be fairly sure there had been $C$ collisions, and they would not need to
store the L-sequence at all.

To prevent this, computing the D-sequence must require knowing exactly when each
collision occurred. When $L_i$ matches an earlier $L_j$ ($j < i$), CHIP *perturbs*
$D_i$ by XOR-ing it with $D_j$, the full digest whose low bits it collided with:

$$D_i \leftarrow D_i \oplus D_j$$

This means a hasher must store the entire D-sequence, not just the L-sequence. A
simpler perturbation that ignores $D_j$ (for example, flipping one bit) could be
computed with only a bitmap of $2^b$ bits recording which $b$-bit values had been seen.
The stored D-sequence is specific to the password and salt being hashed, so it cannot
be shared between guesses.

After the last collision, CHIP hashes once more so the final perturbation affects the
output.

### Salts and bounds on the iteration count

The number of iterations varies a lot between inputs. With $b = 32$ and $C = 5$, a
chain takes about 200,000 iterations on average, with a standard deviation of about
45,000. For some passwords, an impractically large number of iterations could be
needed.

To bound this, CHIP prepends a random 128-bit salt to the password. If a salt produces
a chain longer than an upper bound, CHIP rejects it, picks a new random salt, and
starts over with fresh state. A lower bound works the same way and keeps the cost from
being too low for an unlucky password and salt. As with other salted hashes, the salt
is stored as part of the result:

```
function chip_hash(password, b, C, min_iterations, max_iterations):
    repeat:                                   # retry with a new salt if out of bounds
        salt = 16 random bytes
        h = salt || password
        seen = {}                             # low b bits -> full digest
        collisions = 0
        iterations = 0
        while collisions < C and iterations < max_iterations:
            h = SHA256(h)
            iterations += 1
            key = low_bits(h, b)
            if key in seen:
                collisions += 1
                h = h XOR seen[key]           # perturb with the earlier digest
            else:
                seen[key] = h
        if collisions == C and min_iterations <= iterations <= max_iterations:
            return encode(salt, SHA256(h))    # final hash uses the last perturbation
```

The result is a self-describing string recording every parameter and the salt, so it
can be verified later with nothing but the password:

```
$chip$h=sha256,b=32,c=5,min=0,max=250000$<salt>$<hash>
```

The upper bound trades cost for retries. With the default bound of 250,000 iterations
(about one standard deviation above the mean), about 15% of salts are rejected, so a
hash takes about 1.2 attempts on average. A bound at the mean would reject about half
of all salts.

## Parameters and cost

To measure how the cost depends on $b$ and $C$, we ran CHIP without an upper bound on
1,000 random inputs for every combination of $b$ from 1 to 32 and $C$ from 1 to 20.

![Mean iterations by bits compared (b)](../benchmarks/results/iterations_by_bits.png)

Increasing $b$ by one doubles the pool of possible values, so the expected number of
iterations grows by a factor of about $\sqrt{2} \approx 1.41$, in line with the
birthday bound.

![Mean iterations by collisions (C)](../benchmarks/results/iterations_by_collisions.png)

As $C$ increases, the number of iterations grows, but at a decreasing rate: each
collision arrives sooner than the last, because more values have already been seen.

The full tables of means and standard deviations are in
[`benchmarks/results/iterations.md`](../benchmarks/results/iterations.md). At the
defaults ($b = 32$, $C = 5$, SHA-256):

| Measure | Value |
|---|---|
| Mean iterations per chain | about 200,000 (standard deviation about 45,000) |
| Salts rejected by the default upper bound (250,000, about mean + 1σ) | about 15% |
| Attempts per hash, including retries | about 1.2 |
| Iterations per hash, including retries | about 235,000 |
| Peak memory, this Python implementation | about 29 MB |
| Memory for the raw digests alone (32 bytes each) | about 7 MB |
| Time per hash, this Python implementation | about 0.2 s |

Any $b$ and $C$ that give a mean of around 200,000 iterations, such as $b = 32$ and
$C = 5$, make a reasonable choice for an interactive login, with an upper bound zero
to one standard deviations above the mean.

## Security discussion and limitations

CHIP makes each guess cost time and memory, and makes that cost vary from guess to
guess. It does not make brute-force recovery impossible, and some of its effects are
smaller than they first appear:

- **Parallelism.** Separate password guesses are independent, so an attacker can
  still run many of them in parallel. Variable run time only hurts hardware that
  processes guesses in lockstep, such as GPUs, and even there an attacker can group
  guesses by run length or abandon any guess that passes the upper bound.
- **Cost asymmetry.** The defender pays for about 1.2 chains per hash because of salt
  retries. An attacker who has the stored hash knows the final salt and pays for
  exactly one chain per guess, which slightly favors the attacker.
- **Memory.** About 7 MB of raw digests is small next to typical Argon2 or scrypt
  settings (64 MB to several GB). An attacker writing in a low-level language needs
  only those raw digests, not the overhead of a Python dictionary.
- **Side channels.** The run time and memory access pattern depend on the password,
  which can leak information to an observer on the same machine.
  [Argon2d](https://en.wikipedia.org/wiki/Argon2) has the same weakness, and
  [Argon2id](https://www.rfc-editor.org/rfc/rfc9106#section-1) was designed to reduce
  it.

CHIP is an interesting design to study, but for real systems, use Argon2id.

## Related work

- **[PBKDF2](https://www.rfc-editor.org/rfc/rfc8018#section-5.2)** makes hashing
  expensive through iterations alone.
- **[bcrypt](https://www.usenix.org/legacy/events/usenix99/provos/provos.pdf)** adds a
  small, fixed memory requirement (about 4 KB) to its iterations.
- **[scrypt](https://www.rfc-editor.org/rfc/rfc7914)** adds a large, tunable memory
  requirement.
- **[Argon2](https://www.password-hashing.net/)** won the Password Hashing Competition in
  2015. It tunes time, memory, and parallelism separately, and its Argon2id variant is
  the recommended choice ([RFC 9106](https://www.rfc-editor.org/rfc/rfc9106)).

## Conclusions

A brute-force password attack requires running the password hash on a large space of
candidate passwords. CHIP makes each run more expensive by iterating a well-studied
hash function a number of times that depends on the password and salt, and by forcing
every digest to be kept in memory. Its parameters, chosen by the implementer, control
the cost, and its results are easy to verify from a self-describing hash string.

CHIP shows how a few simple ideas (birthday-paradox collisions, perturbation, and salt
retries) combine into a tunable, memory-dependent password hash. Measured honestly, its
memory cost is modest and its variable run time is only a partial defense against
parallel attacks, which is why purpose-built designs like Argon2id remain the right
choice in practice.

## Try it

`HASH_NAME` is the hash function applied on every iteration, `BITS` is $b$, the number
of low bits compared, and `COLLISIONS` is $C$, the number of repeats that end the
chain. `MAX_ITERATIONS` is the upper bound: a salt whose chain runs longer is rejected,
and hashing restarts with a new salt. `chip verify` prints `match`, and `-v` logs each
salt attempt and collision as it happens.

```sh
uv sync

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
uv run chip hash "$PASSWORD" \
  --hash "$HASH_NAME" \
  --bits "$BITS" \
  --collisions "$COLLISIONS" \
  --max "$MAX_ITERATIONS" \
  --verbose
```

See the [README](../README.md) for the Python API.
