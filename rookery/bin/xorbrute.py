#!/usr/bin/env -S python3 -I -B
import sys
import pathlib
import string

if len(sys.argv) < 2:
    print("usage: xorbrute.py file", file=sys.stderr)
    sys.exit(2)
with pathlib.Path(sys.argv[1]).open("rb") as handle:
    data = handle.read(4000)
for k in range(256):
    out = bytes(b ^ k for b in data)
    score = sum(chr(c) in string.printable for c in out) / max(1, len(out))
    if score > 0.85:
        print(f"key={k:#x} score={score:.2f} sample={out[:200]!r}")
