"""evidence-chain - append to a chain, verify it, hand it to someone else."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

from evidence_chain.core import Chain, ChainError, verify_file

EXIT_BROKEN = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="evidence-chain", description=__doc__)
    parser.add_argument("--db", type=Path, default=Path("evidence.db"))
    sub = parser.add_subparsers(dest="command", required=True)

    append = sub.add_parser("append", help="append one entry")
    append.add_argument("event_type")
    append.add_argument("payload", help="a JSON object, or - to read stdin")

    verify = sub.add_parser("verify", help="re-hash the whole chain")
    verify.add_argument(
        "--since-checkpoint",
        action="store_true",
        help="only what was appended since the last full verification",
    )

    log = sub.add_parser("log", help="print entries as JSON lines")
    log.add_argument("--since", type=int, default=None)
    log.add_argument("--limit", type=int, default=None)

    export = sub.add_parser("export", help="write the chain as JSONL")
    export.add_argument("destination", type=Path)

    check = sub.add_parser("check", help="verify an exported file, with no database")
    check.add_argument("source", type=Path)
    return parser


def _payload(raw: str) -> dict[str, object]:
    text = sys.stdin.read() if raw == "-" else raw
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ChainError(f"payload is not JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ChainError("payload must be a JSON object")
    return data


def _run(args: argparse.Namespace) -> int:
    if args.command == "check":
        result = verify_file(args.source)
        print(result.describe())
        return 0 if result.ok else EXIT_BROKEN

    with Chain(args.db) as chain:
        if args.command == "append":
            entry = chain.append(args.event_type, _payload(args.payload))
            print(json.dumps(entry.as_dict(), ensure_ascii=False))
            return 0
        if args.command == "verify":
            result = (
                chain.verify_since_checkpoint() if args.since_checkpoint else chain.verify()
            )
            print(result.describe())
            return 0 if result.ok else EXIT_BROKEN
        if args.command == "log":
            for number, entry in enumerate(chain.entries(since=args.since), start=1):
                print(json.dumps(entry.as_dict(), ensure_ascii=False))
                if args.limit is not None and number >= args.limit:
                    break
            return 0
        written = chain.export(args.destination)
        print(f"{written} entries -> {args.destination}")
        return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _run(args)
    except (ChainError, sqlite3.Error, OSError) as exc:
        # Exit 2, never 0: "could not check" must not read as "the chain holds".
        print(f"evidence-chain: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
