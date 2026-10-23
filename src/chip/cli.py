"""Command-line interface: `chip hash`, `chip verify`, and `chip trace`.

Passwords can be passed as an argument, but are prompted for (without echo) when
omitted, so they don't end up in shell history.
"""

import argparse
import getpass
import secrets
import sys

from chip.core import HASH_FUNCS, Chip
from chip.passwords import SALT_BYTES, hash_password, verify

EPILOG = """\
options:
  hash   -b, --bits N  -c, --collisions N  --hash NAME  --min N  --max N
  trace  -b, --bits N  -c, --collisions N  --hash NAME

examples:
  chip hash hunter2 -b 20 --max 4000
  chip verify "$HASH" hunter2
  chip trace hunter2 -b 20

Run `chip <command> --help` for details."""


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        exit_code: int = args.command(args)
        return exit_code
    except (ValueError, RuntimeError) as e:
        print(f"chip: error: {e}", file=sys.stderr)
        return 2
    except EOFError:  # stdin closed at the password prompt
        print("\nchip: error: no password given", file=sys.stderr)
        return 2
    except KeyboardInterrupt:  # Ctrl-C, usually at the password prompt
        print(file=sys.stderr)
        return 130


def _hash(args: argparse.Namespace) -> int:
    chip = Chip(
        bits=args.bits,
        collisions=args.collisions,
        min_iterations=args.min_iterations,
        max_iterations=args.max_iterations,
        hash_func=HASH_FUNCS[args.hash_name],
    )
    print(hash_password(_password(args, confirm=True), chip))
    return 0


def _verify(args: argparse.Namespace) -> int:
    matched = verify(_password(args), args.hash)
    print("match" if matched else "no match")
    return 0 if matched else 1


def _trace(args: argparse.Namespace) -> int:
    chip = Chip(bits=args.bits, collisions=args.collisions, hash_func=HASH_FUNCS[args.hash_name])
    salt = secrets.token_bytes(SALT_BYTES)
    chain = chip.compute(salt + _password(args).encode("utf-8"), bounded=False)
    print(f"salt        {salt.hex()}")
    for n, iteration in enumerate(chain.collision_iterations, start=1):
        print(f"collision {n:<2} at iteration {iteration:,}")
    print(f"total       {chain.iterations:,} iterations")
    print(f"digest      {chain.digest.hex()}")
    return 0


def _password(args: argparse.Namespace, confirm: bool = False) -> str:
    if args.password is not None:
        return str(args.password)
    password = getpass.getpass("Password: ")
    # A typo at a hidden prompt would otherwise be hashed and stored without notice.
    if confirm and getpass.getpass("Confirm password: ") != password:
        raise ValueError("passwords do not match")
    return password


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chip",
        description="CHIP: Confounding Hash Iteration for Passwords.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,  # keep the epilog's layout
    )
    commands = parser.add_subparsers(required=True, metavar="command")

    # Chain options shared by `hash` and `trace`; defaults come from Chip.
    defaults = Chip()
    params = argparse.ArgumentParser(add_help=False)
    params.add_argument(
        "-b",
        "--bits",
        type=int,
        default=defaults.bits,
        metavar="N",
        help="low bits compared (default: %(default)s)",
    )
    params.add_argument(
        "-c",
        "--collisions",
        type=int,
        default=defaults.collisions,
        metavar="N",
        help="collisions before stopping (default: %(default)s)",
    )
    params.add_argument(
        "--hash",
        dest="hash_name",
        choices=list(HASH_FUNCS),
        default=defaults.hash_name,
        metavar="NAME",
        help="hash function: %(choices)s (default: %(default)s)",
    )

    # Iteration bounds only matter for `hash`, which redraws salts outside them.
    bounds = argparse.ArgumentParser(add_help=False)
    bounds.add_argument(
        "--min",
        dest="min_iterations",
        type=int,
        default=defaults.min_iterations,
        metavar="N",
        help="reject salts that finish sooner (default: %(default)s)",
    )
    bounds.add_argument(
        "--max",
        dest="max_iterations",
        type=int,
        default=defaults.max_iterations,
        metavar="N",
        help="reject salts that take longer (default: %(default)s)",
    )
    hash_cmd = commands.add_parser("hash", parents=[params, bounds], help="hash a password")
    hash_cmd.add_argument("password", nargs="?", help="prompted for if omitted")
    hash_cmd.set_defaults(command=_hash)

    verify_cmd = commands.add_parser(
        "verify", help="check a password against a stored hash (exit code 1 if no match)"
    )
    verify_cmd.add_argument("hash", help="stored hash string from `chip hash`")
    verify_cmd.add_argument("password", nargs="?", help="prompted for if omitted")
    verify_cmd.set_defaults(command=_verify)

    trace_cmd = commands.add_parser(
        "trace", parents=[params], help="show when each collision happens for one chain"
    )
    trace_cmd.add_argument("password", nargs="?", help="prompted for if omitted")
    trace_cmd.set_defaults(command=_trace)

    return parser


if __name__ == "__main__":
    sys.exit(main())
