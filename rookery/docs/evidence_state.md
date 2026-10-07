# Evidence and State

Rookery preserves exact runtime evidence inside the event workspace. It retains exact candidates, command output, transcripts, sessions, source artifacts, and credential-bearing operational records when their storage contract captures them. This is why a runtime is private evidence, never a public release artifact.

An adapter can deliberately replace sensitive authentication or cookie response-header values when it writes a bounded response summary. That narrow storage-format rule prevents a summary from leaking a credential; it does not make the private runtime safe to publish.

The public release boundary is defined by [`release.json`](../release.json). It excludes runtime directories and live configuration data. Preserve or move a completed runtime only through an operator-approved private workflow; do not copy its state files into a source release.

## Canonical state and projections

`state/events.sqlite3` is the transactional record. JSON snapshots, Markdown ledgers, queue and frontier views, and status files are derived projections. They can be rebuilt byte-stably from canonical state, but they do not replace it. See [State, policy, and stop](./state_policy_stop.md) for the lifecycle and generation boundary.

Runtime status, command envelopes, telemetry reports, and stop lessons carry the release version from `VERSION`. That version identifies the producing source; it does not make a runtime safe to distribute.

## Command evidence

A command envelope records UTC start and end, working directory, exact argv, exit code, output paths, timeout, mutation classification, and provenance. Schema 2 assigns a collision-resistant command ID before launch, records monotonic elapsed time and termination class, atomically publishes stdout and stderr, and stores exact byte counts and SHA-256 hashes.

`runq` applies one combined output ceiling, writes private files, and records `output_limit`, `timeout`, `spawn_error`, `signal`, or `capture_error` as terminal truth. Large artifacts can receive compact digests, but a digest never replaces retained raw evidence. Where Linux exposes it, owned-job stop paths capture a bounded CPU and RSS summary before signalling and record it with terminal reconciliation.

## Storage boundary

Runtime roots are private: directories are 0700 and canonical state, projections, command/job/watcher output, exact evidence, and live configuration are 0600. Rookery verifies the applied mode and fails closed when the filesystem cannot enforce it. Under WSL, use the Linux home filesystem or an equivalently verified mount and ACL configuration.

Same-UID agents operate within the operator's trust boundary. That is not a claim that the runtime is safe for an unrelated account, a shared artifact store, or a public repository.

## Preservation and completeness

A preserved runtime is the complete quiescent directory, including any SQLite sidecars and private adapter or session material. Rookery provides no file-level recovery tool or runtime schema migration. Backup, restore rehearsal, and rollback therefore operate on the whole directory; the [upgrade guide](./upgrade.md) defines that procedure.

Before export or closeout, `bin/evidence-manifest --require-complete` writes a private bounded manifest of canonical state, plans, submissions, analysis, writeups, command and job evidence, and every evidence path referenced by an execution event. Missing or rejected references fail the gate while retaining the exact internal location and status needed to repair it.

## Read-only analysis

`bin/telemetry-report` reads a preserved runtime without changing it. It opens SQLite in immutable read-only mode, compares canonical JSONL with SQLite, summarizes bounded command lifecycle data, and reports evidence-reference completeness without returning candidates, command arguments, or output text. SQLite WAL or SHM sidecars cause a fail-closed result because an immutable main-database read cannot safely include them.

Use `--source-root` only to map retained absolute paths to the deployed source root and write `--output` outside the analyzed runtime. The [measurement protocol](./measurement.md) defines when a report or comparison is eligible and how its descriptive results should be read.
