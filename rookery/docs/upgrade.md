# Install, Upgrade, and Rollback

Rookery installations are immutable release extractions with editable live configuration and private runtime state. Install and upgrade side by side. Never overlay an existing workspace or import runtime state into new source.

For a first installation built from a trusted checkout, use [Getting started](getting-started.md). This guide covers a received release and later replacement.

## Contents

- [Trust and artifact set](#trust-and-artifact-set)
- [Target environment](#target-environment)
- [Verify and install a received release](#verify-and-install-a-received-release)
- [Optional reproducibility check](#optional-reproducibility-check)
- [Quiescent backup and restore rehearsal](#quiescent-backup-and-restore-rehearsal)
- [Side-by-side upgrade](#side-by-side-upgrade)
- [External Chrome bridge upgrade](#external-chrome-bridge-upgrade)
- [Rollback](#rollback)

## Trust and artifact set

A release handoff has three files with the same version:

- `rookery-$VERSION.zip`
- `rookery-$VERSION.zip.sha256`
- `rookery-$VERSION.manifest.json`

The sidecar detects ZIP transfer corruption. The manifest and bounded receiver verify archive paths, types, modes, sizes, compression, and per-file hashes. These checks establish local integrity; they do not authenticate a publisher who could replace the whole set.

Choose and verify the publisher or source checkout through a separately trusted channel. This repository does not define a canonical remote, publisher signature, signed index, or hosted release service. If you have neither a trusted source checkout nor a separately trusted receiver, stop. Do not execute `bin/build-release` from the candidate archive to verify itself.

## Target environment

Run the operational workspace on Linux or Ubuntu under WSL. Store it on a filesystem that enforces private POSIX modes. Under WSL, use a directory beneath the Linux home directory; do not use `/mnt/c/...` for evidence-bearing state.

The artifact set may be transferred through Windows storage, but copy it to WSL's Linux filesystem before extraction.

## Verify and install a received release

Set `TRUSTED_RECEIVER` to an existing trusted Rookery source tree. Set `ROOKERY_RELEASE_VERSION` from separately trusted release metadata:

```bash
TRUSTED_RECEIVER="$HOME/src/rookery/rookery"
VERSION="${ROOKERY_RELEASE_VERSION:?set the trusted release version}"
case "$VERSION" in
  ""|"."|".."|*[!0-9A-Za-z._-]*) echo "invalid release version" >&2; exit 2;;
esac

RELEASE_DIR="$HOME/rookery-received/$VERSION"
INSTALL_DIR="$HOME/rookery-installs/$VERSION"
cd "$RELEASE_DIR"

test -x "$TRUSTED_RECEIVER/bin/build-release"
test ! -e "$INSTALL_DIR"
sha256sum --check "rookery-$VERSION.zip.sha256"
PYTHONDONTWRITEBYTECODE=1 "$TRUSTED_RECEIVER/bin/build-release" \
  --extract-archive "$RELEASE_DIR/rookery-$VERSION.zip" \
  --manifest "$RELEASE_DIR/rookery-$VERSION.manifest.json" \
  --extract-dir "$INSTALL_DIR"

cd "$INSTALL_DIR/rookery"
test "$(<VERSION)" = "$VERSION"
```

The extraction destination must not exist. The receiver stages verified members and publishes the directory only after the complete set passes. Any checksum mismatch, receiver error, or version mismatch is a stop condition.

The installed `.env` is the single editable configuration file synthesized from the reviewed example. Configure it, run `./bin/rookery validate --release` to validate the complete resolved configuration, and create the private baseline before the first `./go`; follow [Getting started](getting-started.md#5-configure-the-event) from configuration onward.

## Optional reproducibility check

To compare the received archive with a rebuild from its fresh extraction, use a new output directory:

```bash
cd "$RELEASE_DIR"
REBUILT_DIR="$RELEASE_DIR/rebuilt"
mkdir -p "$REBUILT_DIR"
PYTHONDONTWRITEBYTECODE=1 "$INSTALL_DIR/rookery/bin/build-release" \
  --output-dir "$REBUILT_DIR"
cmp "rookery-$VERSION.zip" "$REBUILT_DIR/rookery-$VERSION.zip"
cmp "rookery-$VERSION.zip.sha256" "$REBUILT_DIR/rookery-$VERSION.zip.sha256"
cmp "rookery-$VERSION.manifest.json" "$REBUILT_DIR/rookery-$VERSION.manifest.json"
```

This proves deterministic equivalence with the received extraction. It does not add publisher authentication.

## Quiescent backup and restore rehearsal

Upgrade only between events. Before replacing an existing workspace:

1. Run its `./go stop` and inspect `unmanaged` and `unacknowledged` actors. Resolve anything still writing.
2. Use an operator-approved snapshot or backup tool to capture the complete directory, including hidden files and SQLite sidecars.
3. Store the backup in a private operator-only location. It can contain credentials, exact candidates, requests, responses, and session material.
4. Restore the backup into a new private rehearsal directory while both copies remain quiescent.
5. Verify the backup tool's integrity and metadata checks, confirm private modes, and run only the restored copy's `./go status`.

Accept the backup for rollback only after the rehearsal proves that the complete directory can be restored and read without changing the original. Rookery ships no file-level recovery tool, runtime importer, or runtime schema migrator.

## Side-by-side upgrade

1. Complete the backup and restore rehearsal.
2. Preserve the old workspace unchanged as private evidence and rollback material.
3. Verify and extract the new release into a new versioned directory.
4. Compare the old live configuration with the new `.env.example`. Deliberately merge supported settings into the new private `.env` and keep mode `0600`. For a legacy two-file workspace, use the explicit no-clobber migration described in [Configuration](configuration.md#legacy-event-migration), review the draft, then replace `.env` using ordinary private local file operations.
5. Create a new release-bound baseline for the new workspace.
6. Run the new strict validator and `./go status`.
7. Start the new workspace with its own `./go` only when the event remains authorized.

Never copy runtime paths such as `state/`, `analysis/`, `evidence/`, `submissions/`, `logs/`, `captures/`, `downloads/`, `work/`, `writeups/`, `control/`, or `platform/runtime/` into the new tree. Generated prompts and views also belong to the old runtime.

The new `bin/telemetry-report` may read a preserved old runtime with `--source-root`. That read-only analysis is not migration.

## External Chrome bridge upgrade

An adapter that declares the external Chrome bridge adds a Windows-side tuple
to the side-by-side workspace. Export a new immutable bridge bundle from the verified new release,
create a new release-bound gateway policy, and select a new dedicated Chrome
profile path. Do not run the new bridge from the mutable source checkout or
reuse an old profile with a new policy.

For an overlapping transition, assign the new bridge distinct CDP, gateway
proxy, and gateway status ports. Start it with current WSL address resolution,
then require both the Windows bridge health check and the new installed
release's `bin/browser-health` to pass. Do not operate both workspaces against
the same event concurrently. After selecting the new tuple, stop the old bridge
through its old bundle's guarded ownership record. For SkillBit, finish with a
read-only production `sync()` that proves the configured account and exact
event card. The complete export, health, stop, restart, and rollback sequence
is in [Browser bridge](browser_bridge.md).

## Rollback

1. Stop the new workspace with its own `./go stop`.
2. Preserve it separately if it produced evidence.
3. Return to the untouched old directory.
4. If the selected adapter uses the external Chrome bridge, select the matching
   old bridge bundle, policy, and profile as one tuple and pass both health checks.
5. Run the old directory's `./go status`.
6. Explicitly resume it with its own `./go` only if the event remains authorized and rollback is still desired.

Do not copy new runtime files backward. Rollback is selection of a complete, previously rehearsed directory.
