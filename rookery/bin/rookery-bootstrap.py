"""Start Rookery's public CLI after Python's ambient startup path is closed."""

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


ROOT = Path(__file__).resolve().parents[1]
LIBRARY = ROOT / "lib"

# This script is reached only through ``python3 -I -S -B`` in ``bin/rookery``.
# Keep the post-startup import surface exact: no current directory, parent
# PYTHONPATH, user site, or arbitrary project path is introduced.
sys.path.insert(0, str(LIBRARY))

from rookery.portable.cli import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
