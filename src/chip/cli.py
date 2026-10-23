"""Command-line interface: `chip hash` and `chip verify`.

Passwords can be passed as an argument, but are prompted for (without echo) when
omitted, so they don't end up in shell history.
"""

import argparse
import getpass
import logging
import sys

from chip.core import HASH_FUNCS, Chip
from chip.passwords import hash_password, verify

EPILOG = """\
options for hash:
  -b, --bits N  -c, --collisions N  --hash NAME  --min N  --max N  -v, --verbose

examples:
  chip hash hunter2 -b 20 --max 4000
  chip hash hunter2 -b 20 --max 4000 -v
  chip verify "$HASH" hunter2

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
    chip = _chip(args)
    password = _password(args, confirm=True)
    # -v: show the library's debug log (attempts, salts, collisions) on stderr, so
    # stdout still carries only the hash. Times are ms since the program started.
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(relativeCreated)9.1f ms  %(message)s"))
    package_logger = logging.getLogger("chip")
    if args.verbose:
        package_logger.addHandler(handler)
        package_logger.setLevel(logging.DEBUG)
    try:
        print(hash_password(password, chip))
    finally:
        package_logger.removeHandler(handler)
    return 0


def _verify(args: argparse.Namespace) -> int:
    matched = verify(_password(args), args.hash)
    print("match" if matched else "no match")
    return 0 if matched else 1


def _chip(args: argparse.Namespace) -> Chip:
    return Chip(
        bits=args.bits,
        collisions=args.collisions,
        min_iterations=args.min_iterations,
        max_iterations=args.max_iterations,
        hash_func=HASH_FUNCS[args.hash_name],
    )


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

    hash_cmd = commands.add_parser("hash", help="hash a password")
    defaults = Chip()  # option defaults come from Chip
    hash_cmd.add_argument(
        "-b",
        "--bits",
        type=int,
        default=defaults.bits,
        metavar="N",
        help="low bits compared (default: %(default)s)",
    )
    hash_cmd.add_argument(
        "-c",
        "--collisions",
        type=int,
        default=defaults.collisions,
        metavar="N",
        help="collisions before stopping (default: %(default)s)",
    )
    hash_cmd.add_argument(
        "--hash",
        dest="hash_name",
        choices=list(HASH_FUNCS),
        default=defaults.hash_name,
        metavar="NAME",
        help="hash function: %(choices)s (default: %(default)s)",
    )
    hash_cmd.add_argument(
        "--min",
        dest="min_iterations",
        type=int,
        default=defaults.min_iterations,
        metavar="N",
        help="reject salts that finish sooner (default: %(default)s)",
    )
    hash_cmd.add_argument(
        "--max",
        dest="max_iterations",
        type=int,
        default=defaults.max_iterations,
        metavar="N",
        help="reject salts that take longer (default: %(default)s)",
    )
    hash_cmd.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="log each salt attempt and collision, with elapsed time, to stderr",
    )
    hash_cmd.add_argument("password", nargs="?", help="prompted for if omitted")
    hash_cmd.set_defaults(command=_hash)

    verify_cmd = commands.add_parser(
        "verify", help="check a password against a stored hash (exit code 1 if no match)"
    )
    verify_cmd.add_argument("hash", help="stored hash string from `chip hash`")
    verify_cmd.add_argument("password", nargs="?", help="prompted for if omitted")
    verify_cmd.set_defaults(command=_verify)

    return parser


if __name__ == "__main__":
    sys.exit(main())
