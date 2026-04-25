"""kiprio-redact CLI entry point."""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter

from . import ALL_TYPES, __version__, find_spans, redact


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="kiprio-redact",
        description=(
            "Local PII redaction. Reads stdin or a file, writes redacted "
            "output to stdout or a file. For context-aware / higher-recall "
            "needs see https://kiprio.com/v1/redact/"
        ),
    )
    p.add_argument("-i", "--input", help="input file (default: stdin)")
    p.add_argument("-o", "--output", help="output file (default: stdout)")
    p.add_argument(
        "-t", "--types",
        default=",".join(ALL_TYPES),
        help=(
            "comma-separated PII types (default: all). Available: "
            + ",".join(ALL_TYPES)
        ),
    )
    g = p.add_mutually_exclusive_group()
    g.add_argument(
        "-m", "--mask",
        help="replace each char of a match with this single character",
    )
    g.add_argument(
        "-r", "--replace",
        default="[REDACTED]",
        help="replace whole match with this string (default: [REDACTED])",
    )
    p.add_argument(
        "--json", action="store_true",
        help="emit findings as JSON instead of redacted text",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="print finding count by type to stderr",
    )
    p.add_argument("--version", action="version", version=f"kiprio-redact {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    types = [t.strip() for t in args.types.split(",") if t.strip()]
    unknown = [t for t in types if t not in ALL_TYPES]
    if unknown:
        sys.stderr.write(
            f"kiprio-redact: unknown type(s): {','.join(unknown)}\n"
            f"  available: {','.join(ALL_TYPES)}\n"
        )
        return 2

    if args.mask is not None and len(args.mask) != 1:
        sys.stderr.write("kiprio-redact: --mask must be a single character\n")
        return 2

    if args.input:
        with open(args.input, "r", encoding="utf-8") as fh:
            text = fh.read()
    else:
        text = sys.stdin.read()

    if args.json:
        findings = find_spans(text, types)
        payload = {"findings": findings, "count": len(findings)}
        out = json.dumps(payload, indent=2) + "\n"
    else:
        redacted, findings = redact(
            text, types,
            mask=args.mask,
            replacement=None if args.mask is not None else args.replace,
        )
        out = redacted

    if args.verbose:
        if "findings" not in locals():
            findings = find_spans(text, types)
        counts = Counter(f["type"] for f in findings)
        sys.stderr.write(
            "kiprio-redact: "
            + (", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "no findings")
            + f" (total={sum(counts.values())})\n"
        )

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
    else:
        sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
