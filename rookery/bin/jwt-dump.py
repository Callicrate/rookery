#!/usr/bin/env -S python3 -I -B
import sys
import json
import base64

if len(sys.argv) < 2:
    print("usage: jwt-dump.py token", file=sys.stderr)
    sys.exit(2)
for part in sys.argv[1].split(".")[:2]:
    pad = "=" * ((4 - len(part) % 4) % 4)
    try:
        print(json.dumps(json.loads(base64.urlsafe_b64decode(part + pad)), indent=2))
    except Exception as e:
        print(e)
