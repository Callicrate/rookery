#!/usr/bin/env -S python3 -I -B
import argparse
import pathlib
import re
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract URLs from a bounded file tree.")
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--max-files", type=int, default=10000)
    parser.add_argument("--max-bytes", type=int, default=5_000_000)
    args = parser.parse_args()
    if args.max_files <= 0 or args.max_bytes <= 0:
        parser.error("--max-files and --max-bytes must be positive")

    root = pathlib.Path(args.root)
    pattern = re.compile(r'https?://[^\s\]"\'<>]+')
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
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                text = handle.read(args.max_bytes)
        except OSError:
            continue
        for url in pattern.findall(text):
            print(f"{path}: {url}")
    if truncated:
        print(f"urlgrab: stopped after {scanned} files; increase --max-files to continue", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
