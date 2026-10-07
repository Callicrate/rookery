# Rookery

Rookery is a Codex-native coordinator for authorized CTFs and security labs. It gives agents broad local shell access while keeping event scope, scoring review, authorization, evidence, and stop state explicit.

The operator surface stays small:

```bash
./go
./go status
./go stop
```

`./go status` is a pure read. `./go stop` advances the stop generation and revokes unused action authority before it asks owned work to shut down.

## Contents

- [Start here](#start-here)
- [Codex runs with full access](#codex-runs-with-full-access)
- [Build a release](#build-a-release)
- [How Rookery works](#how-rookery-works)
- [Documentation](#documentation)
- [License](#license)

## Start here

The runtime requires Bash, Python 3.11 or newer, and the Codex CLI with a working login.

Use [Getting started](docs/getting-started.md) for the complete first run from a trusted source checkout. The short path is:

1. Obtain the source through a channel you trust. Rookery does not define a canonical remote or publisher signature.
2. Work inside Linux or Ubuntu on WSL, with the checkout, release, and runtime on the Linux filesystem.
3. Run the strict read-only source validation.
4. Build and extract a release into a new directory.
5. Edit the private `.env` and validate the resolved configuration.
6. Create the release-bound measurement baseline, prepare any required external session, and run `./go` only when the event and scope are authorized.

The release ZIP, manifest, and SHA-256 sidecar establish local content integrity. They do not authenticate the publisher when all three arrive through the same untrusted channel. Source trust comes from the operator's chosen trusted channel.

## Codex runs with full access

Rookery currently launches Codex in its intentional autonomous mode:

```toml
approval_policy = "never"
sandbox_mode = "danger-full-access"
```

Rookery launches exactly one Codex session. Before it starts, Rookery renders
the shared spawned-thread ceiling from `CODEX_SUBAGENT_THREADS` in `.env`.
The main coordinator runs at depth 0, challenge coordinators run as native
subagents at depth 1, and their bounded workers run at depth 2. All spawned
agents share the 96-thread session ceiling; `CONCURRENCY_MAX_WORKERS`
independently limits registered worker attempts. See
[Configuration](docs/configuration.md) for how the limits interact. Codex can
read and write files, start processes, and use the network with the authority
of the operator account. Run Rookery only in a disposable, authorized
workspace after reviewing [`.codex/config.toml`](.codex/config.toml),
[`configs/codex-base.toml`](configs/codex-base.toml), and the event scope.

Rookery's own helpers enforce compiled scope where their contracts say they do. Raw shell access remains available and still depends on the operator-declared authorization boundary.

## Build a release

From a trusted source checkout on Linux or WSL ext4:

```bash
PYTHONDONTWRITEBYTECODE=1 ./bin/rookery validate --release --source-checkout
VERSION="$(<VERSION)"
BUILD_DIR="$HOME/rookery-builds/$VERSION"
mkdir -p "$BUILD_DIR"
PYTHONDONTWRITEBYTECODE=1 ./bin/build-release --output-dir "$BUILD_DIR"
```

The builder writes a deterministic ZIP, a per-file manifest, and a ZIP SHA-256 sidecar. It fails closed on runtime residue, links, special files, source changes during the build, source/output overlap, configured size limits, or existing artifact names.

Live `.env` is private operator data and is ignored by Git. The builder creates the archive's `.env` from the reviewed `.env.example`, so live event values do not enter release artifacts.

Building an archive does not approve it for distribution. See [Install, upgrade, and rollback](docs/upgrade.md) for receiving, verification, side-by-side upgrades, and rollback.

## How Rookery works

- The operator owns event facts, scope, action authorization, resume, and stop.
- The main coordinator asks how many challenges to keep active, assigns one
  native coordinator subagent per challenge, and refills completed slots.
- Challenge coordinators delegate bounded work one level and preserve their
  workers' reports.
- Solvers propose scoring actions; independent reviewers assess them; a separate executor performs only authorized mutations.
- Authorization starts at zero. Transport success never overrides scorer truth.
- Canonical events live in SQLite. Markdown and JSON views are projections and handoffs.
- Exact captured evidence stays private in the runtime. Specified bounded response summaries omit or replace sensitive authentication and cookie headers by design; see [Evidence and state](docs/evidence_state.md).
- Completed objectives receive a solve capsule and a reproducible writeup.

The built-in `manual` adapter is the platform-neutral default. Packaged platform integrations live under `adapters/`, and optional activity modes live under `extensions/`. Unselected integrations are not part of the active surface.

Operational Agent Skills live under `.agents/skills/` and ship with the release so an installed workspace can guide event preparation, browser-bridge operation, reviewed browser scoring, and post-event retrospectives. Skills for developing Rookery itself remain in the outer maintainer repository and are not packaged.

## Documentation

The [documentation index](docs/README.md) groups the operator path and the deeper contracts. Start with:

- [Getting started](docs/getting-started.md)
- [Release changes](CHANGELOG.md)
- [Configuration](docs/configuration.md)
- [Operator guide](docs/operator.md)
- [Preparation](docs/preparation.md)
- [Install, upgrade, and rollback](docs/upgrade.md)

`ACTIVE_SURFACE.md` and `PREPARATION.md` are generated inside an initialized runtime. They describe the exact agents, tools, and capabilities selected for that event.

## License

Rookery is available under the [MIT License](LICENSE).
