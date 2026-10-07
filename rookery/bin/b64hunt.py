#!/usr/bin/env -S python3 -I -B
import argparse
import base64
import pathlib
import re
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description="Find base64-like values in a bounded file tree.")
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--max-files", type=int, default=10000)
    parser.add_argument("--max-bytes", type=int, default=5_000_000)
    args = parser.parse_args()
    if args.max_files <= 0 or args.max_bytes <= 0:
        parser.error("--max-files and --max-bytes must be positive")

    root = pathlib.Path(args.root)
    pattern = re.compile(rb"[A-Za-z0-9+/]{16,}={0,2}")
    scanned = 0
    truncated = False
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if scanned >= args.max_files:
            truncated = True
            break
        scanned += 1
        try:
            with path.open("rb") as handle:
                data = handle.read(args.max_bytes)
        except OSError:
            continue
        for match in pattern.finditer(data):
            encoded = match.group(0)
            try:
                decoded = base64.b64decode(encoded, validate=False)
            except ValueError:
                continue
            if any(32 <= byte < 127 or byte in (9, 10, 13) for byte in decoded) and len(decoded) > 4:
                print(f"{path}:{match.start()} {encoded[:80]!r} -> {decoded[:200]!r}")
    if truncated:
        print(f"b64hunt: stopped after {scanned} files; increase --max-files to continue", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
