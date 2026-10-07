#!/usr/bin/env -S python3 -I -B
import argparse
import json
import sys
from pathlib import Path


if sys.version_info < (3, 11):
    print(
        "Rookery requires Python 3.11 or newer; "
        "found Python {}.{}.{}.".format(
            sys.version_info.major,
            sys.version_info.minor,
            sys.version_info.micro,
        ),
        file=sys.stderr,
    )
    raise SystemExit(2)


sys.dont_write_bytecode = True

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "lib"))

from rookery.portable.validator import validate_tree  # noqa: E402

parser = argparse.ArgumentParser()
parser.add_argument("--adapter")
parser.add_argument("--release", action="store_true")
parser.add_argument("--source-checkout", action="store_true")
arguments = parser.parse_args()
if arguments.source_checkout and not arguments.release:
    parser.error("--source-checkout requires --release")
report = validate_tree(
    root,
    adapter=arguments.adapter,
    strict_release=arguments.release,
    source_checkout=arguments.source_checkout,
)
print(json.dumps(report, indent=2))
raise SystemExit(0 if report["ok"] else 1)
