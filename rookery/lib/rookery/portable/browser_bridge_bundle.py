"""Create a small, release-bound Windows browser bridge bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tempfile
from pathlib import Path

from .release import ReleaseVerificationError, extract_release_archive, verify_release_archive


class BrowserBridgeBundleError(ValueError):
    """Raised when a bridge bundle cannot be published safely."""


_FILES = (
    "bin/start-chrome-cdp.ps1",
    "bin/browser-scope-gateway.py",
)
_LIBRARY = "lib/rookery"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _new_external_directory(path: Path) -> Path:
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise BrowserBridgeBundleError("browser_bridge_bundle_destination_invalid")
    parent = path.parent
    if not parent.is_dir() or parent.is_symlink():
        raise BrowserBridgeBundleError("browser_bridge_bundle_parent_invalid")
    return path


def build_browser_bridge_bundle(archive: Path, manifest: Path, destination: Path) -> dict[str, object]:
    """Verify a release, then publish its bridge code into a new directory."""

    target = _new_external_directory(destination)
    try:
        verified = verify_release_archive(archive, manifest)
    except ReleaseVerificationError as exc:
        raise BrowserBridgeBundleError(str(exc)) from exc
    staging_parent = Path(tempfile.mkdtemp(prefix=f".{target.name}.bridge-", dir=target.parent))
    extracted = staging_parent / "release"
    try:
        try:
            extract_release_archive(archive, manifest, extracted)
        except ReleaseVerificationError as exc:
            raise BrowserBridgeBundleError(str(exc)) from exc
        source = extracted / "rookery"
        if not source.is_dir() or source.is_symlink():
            raise BrowserBridgeBundleError("browser_bridge_bundle_release_missing")
        bundle = staging_parent / "bundle"
        (bundle / "bin").mkdir(parents=True)
        for relative in _FILES:
            item = source / relative
            if not item.is_file() or item.is_symlink():
                raise BrowserBridgeBundleError("browser_bridge_bundle_release_missing")
            shutil.copyfile(item, bundle / relative)
        library = source / _LIBRARY
        if not library.is_dir() or library.is_symlink():
            raise BrowserBridgeBundleError("browser_bridge_bundle_release_missing")
        shutil.copytree(library, bundle / _LIBRARY, symlinks=False)
        rows: list[dict[str, object]] = []
        for item in sorted(bundle.rglob("*")):
            if item.is_file() and not item.is_symlink():
                rows.append({"path": item.relative_to(bundle).as_posix(), "sha256": _sha256(item)})
        document = {
            "schema_version": "1",
            "release": verified,
            "files": rows,
        }
        metadata = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        (bundle / "bridge-bundle.json").write_bytes(metadata)
        # Claim the name before copying.  `rename` can replace an empty
        # directory on POSIX, which would violate the no-clobber contract.
        target.mkdir(mode=0o700)
        sentinel = target / ".bridge-bundle-incomplete"
        sentinel.write_text("incomplete\n", encoding="ascii")
        shutil.copytree(bundle, target, dirs_exist_ok=True)
        sentinel.unlink()
        return {"ok": True, "destination": str(target), "file_count": len(rows), "release": verified}
    except BrowserBridgeBundleError:
        raise
    except OSError as exc:
        raise BrowserBridgeBundleError("browser_bridge_bundle_publish_failed") from exc
    finally:
        shutil.rmtree(staging_parent, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = build_browser_bridge_bundle(args.archive, args.manifest, args.output)
    except BrowserBridgeBundleError as exc:
        print(f"error: {exc}")
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
