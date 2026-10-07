from __future__ import annotations

import json
import os
import sqlite3
import stat
import time
import uuid
from collections.abc import Iterable
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .environment import (
    LaunchBinding,
    is_deployed_workspace,
    verify_launch_binding_integrity,
)
from .util import (
    atomic_write_json,
    atomic_write_text,
    canonical_json,
    ensure_private_dir,
    ensure_private_file,
    iso_now,
)
from .util import event_id as stable_event_id

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    created_at TEXT NOT NULL,
    generation INTEGER NOT NULL,
    actor TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type, seq);
"""

PRIVATE_FILE_MODE = 0o600
PROJECTION_LOCK_FILE = "projection.lock"
PROJECTION_FILES = (
    "events.jsonl",
    "runtime.json",
    "current.json",
    "policy_effective.json",
    "queue_state.json",
)
_BINDING_META_KEYS = (
    "launch_binding_sha256",
    "launch_workspace_identity",
    "immutable_source_sha256",
)
_EMERGENCY_EVENT_TYPES = frozenset(
    {
        "control.stop",
        "authorization.revoked",
        "retry.cancelled",
        "agent.stopping",
        "job.stopping",
        "agent.closed",
        "agent.unacknowledged",
        "agent.unmanaged",
        "job.cancelled",
        "job.unacknowledged",
        "job.unmanaged",
    }
)


class _SnapshotMetadata:
    """Read-only metadata facade used while reducing one SQLite snapshot."""

    def __init__(self, values: dict[str, str]):
        self._values = values

    def get_meta(self, key: str, default: str = "") -> str:
        return self._values.get(key, default)


class SnapshotStopGenerationChanged(RuntimeError):
    """A queued mutation no longer belongs to the captured stop generation."""


class EventStore:
    def __init__(
        self,
        root: Path,
        *,
        launch_binding: LaunchBinding | None = None,
        emergency_stop: bool = False,
    ):
        self.root = root.resolve()
        self.state_dir = self.root / "state"
        self.db_path = self.state_dir / "events.sqlite3"
        self._deployed = is_deployed_workspace(self.root)
        self._emergency_stop = bool(emergency_stop)
        self._database_existed = self.db_path.exists() or self.db_path.is_symlink()
        self._launch_binding = self._require_launch_binding(launch_binding)
        if self._emergency_stop:
            self._open_emergency_stop_store()
            return
        ensure_private_dir(self.state_dir)
        self._tighten_existing_projections()
        ensure_private_file(self.db_path)
        self._tighten_database_permissions()
        self._initialize()

    def _require_launch_binding(
        self, supplied: LaunchBinding | None
    ) -> LaunchBinding | None:
        """Require a gate-produced binding before a deployed workspace's first DB.

        Small isolated library fixtures do not have the installed Rookery command
        surface and cannot represent a production launch. Shipped commands do,
        and must pass the object published by the pure gate for the first store.
        Subsequent helpers still validate the private on-disk binding.
        """

        if not self._deployed:
            if self._emergency_stop:
                raise RuntimeError("emergency stop requires a deployed workspace")
            return None
        if self._emergency_stop:
            if not self._database_existed:
                raise RuntimeError("emergency stop requires an existing event database")
            return None
        try:
            stored = verify_launch_binding_integrity(self.root)
        except ValueError as exc:
            raise RuntimeError(f"launch binding integrity: {exc}") from exc
        if supplied is not None and supplied.sha256 != stored.sha256:
            raise RuntimeError("launch binding does not match the published binding")
        if not self.db_path.exists() and supplied is None:
            raise RuntimeError("new EventStore requires an explicit launch binding")
        return stored

    def _open_emergency_stop_store(self) -> None:
        """Open only an existing canonical DB; never bootstrap during a revoke."""

        self._tighten_database_permissions()
        con = sqlite3.connect(self.db_path, timeout=30, isolation_level=None)
        try:
            tables = {
                str(row[0])
                for row in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            if not {"events", "meta"}.issubset(tables):
                raise RuntimeError("emergency stop requires canonical event tables")
        finally:
            con.close()

    @staticmethod
    def _tighten_existing_file(path: Path) -> None:
        """Tighten an existing final path without following links or special files."""

        try:
            path.lstat()
        except FileNotFoundError:
            return
        ensure_private_file(path)

    def _tighten_existing_projections(self) -> None:
        for name in PROJECTION_FILES:
            self._tighten_existing_file(self.state_dir / name)

    def _tighten_database_permissions(self) -> None:
        """Tighten existing SQLite artifacts without following final links."""

        for path in (
            self.db_path,
            self.db_path.with_name(self.db_path.name + "-wal"),
            self.db_path.with_name(self.db_path.name + "-shm"),
        ):
            self._tighten_existing_file(path)

    @staticmethod
    def _prepare_private_projection(path: Path) -> None:
        """Reject unsafe final projection paths before an atomic replacement."""

        ensure_private_file(path)

    def _connect(self) -> sqlite3.Connection:
        self._tighten_database_permissions()
        con = sqlite3.connect(self.db_path, timeout=30, isolation_level=None)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA busy_timeout=30000")
        self._tighten_database_permissions()
        return con

    def _expected_binding_meta(self, binding: LaunchBinding) -> dict[str, str]:
        return {
            "launch_binding_sha256": binding.sha256,
            "launch_workspace_identity": str(binding.record["workspace_identity"]),
            "immutable_source_sha256": str(binding.record["immutable_source_sha256"]),
        }

    def _verify_database_binding(
        self, con: sqlite3.Connection, binding: LaunchBinding
    ) -> None:
        expected = self._expected_binding_meta(binding)
        rows = con.execute(
            "SELECT key,value FROM meta WHERE key IN (?,?,?)", _BINDING_META_KEYS
        ).fetchall()
        actual = {str(row["key"]): str(row["value"]) for row in rows}
        if set(actual) != set(expected):
            raise RuntimeError("launch binding database metadata missing")
        if actual != expected:
            raise RuntimeError("launch binding database metadata drift")

    def _verify_mutation_integrity(self, con: sqlite3.Connection) -> None:
        """Re-read binding/source/config immediately before each DB mutation."""

        if not self._deployed or self._emergency_stop:
            return
        try:
            binding = verify_launch_binding_integrity(self.root)
        except ValueError as exc:
            raise RuntimeError(f"launch binding integrity: {exc}") from exc
        if (
            self._launch_binding is None
            or binding.sha256 != self._launch_binding.sha256
        ):
            raise RuntimeError("launch binding changed after EventStore construction")
        self._verify_database_binding(con, binding)

    def _verify_projection_integrity(self) -> None:
        """Prevent a stale open store from publishing derived state."""

        if not self._deployed or self._emergency_stop:
            return
        con = self._connect()
        try:
            self._verify_mutation_integrity(con)
        finally:
            con.close()

    def _require_emergency_event(self, event_type: str) -> None:
        if self._emergency_stop and event_type not in _EMERGENCY_EVENT_TYPES:
            raise RuntimeError("emergency stop permits revocation events only")

    def _initialize(self) -> None:
        con = self._connect()
        try:
            con.executescript(SCHEMA)
            con.execute("BEGIN IMMEDIATE")
            if self._deployed:
                if (
                    self._launch_binding is None
                ):  # defensive; normal construction sets it.
                    raise RuntimeError(
                        "new EventStore requires an explicit launch binding"
                    )
                binding_rows = con.execute(
                    "SELECT key,value FROM meta WHERE key IN (?,?,?)",
                    _BINDING_META_KEYS,
                ).fetchall()
                if binding_rows:
                    self._verify_mutation_integrity(con)
                elif self._database_existed:
                    raise RuntimeError("launch binding database metadata missing")
                else:
                    for key, value in self._expected_binding_meta(
                        self._launch_binding
                    ).items():
                        con.execute(
                            "INSERT INTO meta(key,value) VALUES(?,?)", (key, value)
                        )
            con.execute(
                "INSERT OR IGNORE INTO meta(key,value) VALUES('stop_generation','0')"
            )
            con.execute(
                "INSERT OR IGNORE INTO meta(key,value) VALUES('policy_generation','0')"
            )
            con.execute(
                "INSERT OR IGNORE INTO meta(key,value) VALUES('projection_generation','0')"
            )
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            try:
                self._tighten_database_permissions()
            finally:
                con.close()

    def get_meta(self, key: str, default: str = "") -> str:
        con = self._connect()
        try:
            row = con.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
            return str(row[0]) if row else default
        finally:
            try:
                self._tighten_database_permissions()
            finally:
                con.close()

    def set_meta(self, key: str, value: Any) -> None:
        if self._emergency_stop and key not in {"stop_generation", "watcher_epoch"}:
            raise RuntimeError("emergency stop permits revocation metadata only")
        con = self._connect()
        try:
            con.execute("BEGIN IMMEDIATE")
            self._verify_mutation_integrity(con)
            con.execute(
                "INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, str(value)),
            )
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            try:
                self._tighten_database_permissions()
            finally:
                con.close()

    def current_stop_generation(self) -> int:
        return int(self.get_meta("stop_generation", "0"))

    def append(
        self,
        event_type: str,
        payload: dict[str, Any],
        *,
        actor: str = "system",
        generation: int | None = None,
        event_id: str | None = None,
        nonce: str | None = None,
    ) -> tuple[str, bool]:
        self._require_emergency_event(event_type)
        generation = (
            self.current_stop_generation() if generation is None else int(generation)
        )
        nonce = nonce if nonce is not None else uuid.uuid4().hex
        eid = event_id or stable_event_id(event_type, payload, nonce)
        created = iso_now()
        con = self._connect()
        inserted = False
        try:
            con.execute("BEGIN IMMEDIATE")
            self._verify_mutation_integrity(con)
            cur = con.execute(
                "INSERT OR IGNORE INTO events(event_id,event_type,created_at,generation,actor,payload_json) VALUES(?,?,?,?,?,?)",
                (eid, event_type, created, generation, actor, canonical_json(payload)),
            )
            inserted = cur.rowcount == 1
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            try:
                self._tighten_database_permissions()
            finally:
                con.close()
        return eid, inserted

    def append_many(
        self,
        events: Iterable[dict[str, Any]],
        *,
        actor: str = "system",
        generation: int | None = None,
        expected_stop_generation: int | None = None,
    ) -> list[tuple[str, bool]]:
        if isinstance(expected_stop_generation, bool):
            raise TypeError("expected stop generation must be an integer")
        if expected_stop_generation is not None:
            expected_stop_generation = int(expected_stop_generation)
        generation = (
            self.current_stop_generation() if generation is None else int(generation)
        )
        con = self._connect()
        results: list[tuple[str, bool]] = []
        try:
            con.execute("BEGIN IMMEDIATE")
            self._verify_mutation_integrity(con)
            if expected_stop_generation is not None:
                row = con.execute(
                    "SELECT value FROM meta WHERE key='stop_generation'"
                ).fetchone()
                current_stop_generation = int(row[0]) if row else 0
                if current_stop_generation != expected_stop_generation:
                    raise SnapshotStopGenerationChanged(
                        "snapshot stop generation changed before queued mutation"
                    )
            for item in events:
                event_type = str(item["event_type"])
                self._require_emergency_event(event_type)
                payload = dict(item.get("payload", {}))
                eid = str(
                    item.get("event_id")
                    or stable_event_id(
                        event_type, payload, str(item.get("nonce") or uuid.uuid4().hex)
                    )
                )
                created = str(item.get("created_at") or iso_now())
                cur = con.execute(
                    "INSERT OR IGNORE INTO events(event_id,event_type,created_at,generation,actor,payload_json) VALUES(?,?,?,?,?,?)",
                    (
                        eid,
                        event_type,
                        created,
                        int(item.get("generation", generation)),
                        str(item.get("actor", actor)),
                        canonical_json(payload),
                    ),
                )
                results.append((eid, cur.rowcount == 1))
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            try:
                self._tighten_database_permissions()
            finally:
                con.close()
        return results

    def transaction(self, callback):
        con = self._connect()
        try:
            con.execute("BEGIN IMMEDIATE")
            self._verify_mutation_integrity(con)
            result = callback(con)
            con.commit()
            return result
        except Exception:
            con.rollback()
            raise
        finally:
            try:
                self._tighten_database_permissions()
            finally:
                con.close()

    def events(self, event_type: str | None = None) -> list[dict[str, Any]]:
        con = self._connect()
        try:
            if event_type:
                rows = con.execute(
                    "SELECT * FROM events WHERE event_type=? ORDER BY seq",
                    (event_type,),
                ).fetchall()
            else:
                rows = con.execute("SELECT * FROM events ORDER BY seq").fetchall()
        finally:
            try:
                self._tighten_database_permissions()
            finally:
                con.close()
        return self._event_rows(rows)

    def latest_event(self, event_type: str) -> dict[str, Any] | None:
        """Return the newest canonical event of one exact type without a full scan."""

        if not isinstance(event_type, str) or not event_type:
            raise ValueError("event_type must be non-empty text")
        con = self._connect()
        try:
            row = con.execute(
                "SELECT * FROM events WHERE event_type=? ORDER BY seq DESC LIMIT 1",
                (event_type,),
            ).fetchone()
        finally:
            try:
                self._tighten_database_permissions()
            finally:
                con.close()
        return self._event_rows([row])[0] if row is not None else None

    @staticmethod
    def _event_rows(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
        return [
            {
                "seq": int(row["seq"]),
                "event_id": row["event_id"],
                "event_type": row["event_type"],
                "created_at": row["created_at"],
                "generation": int(row["generation"]),
                "actor": row["actor"],
                "payload": json.loads(row["payload_json"]),
            }
            for row in rows
        ]

    def read_snapshot(self) -> dict[str, Any]:
        """Read canonical events and metadata from one non-mutating snapshot.

        Queue watchers use this rather than separately rebuilding projections,
        checking metadata, and re-querying authority for every proposal.  The
        explicit deferred transaction pins both reads to one SQLite sequence
        without acquiring a write reservation.
        """

        con = self._connect()
        try:
            con.execute("BEGIN")
            event_rows = con.execute("SELECT * FROM events ORDER BY seq").fetchall()
            meta_rows = con.execute(
                "SELECT key,value FROM meta ORDER BY key"
            ).fetchall()
            con.rollback()
            return {
                "events": self._event_rows(event_rows),
                "meta": {str(row["key"]): str(row["value"]) for row in meta_rows},
            }
        except Exception:
            con.rollback()
            raise
        finally:
            try:
                self._tighten_database_permissions()
            finally:
                con.close()

    def projection_from_snapshot(self, snapshot: dict[str, Any]) -> dict[str, Any]:
        """Reduce a previously captured snapshot without opening another DB."""

        from .reducers import reduce_events

        events = snapshot.get("events")
        meta = snapshot.get("meta")
        if not isinstance(events, list) or not isinstance(meta, dict):
            raise TypeError("event snapshot is malformed")
        return reduce_events(events, _SnapshotMetadata(meta))

    def count(self) -> int:
        con = self._connect()
        try:
            return int(con.execute("SELECT COUNT(*) FROM events").fetchone()[0])
        finally:
            try:
                self._tighten_database_permissions()
            finally:
                con.close()

    def increment_meta_in_transaction(self, con: sqlite3.Connection, key: str) -> int:
        if self._emergency_stop and key not in {"stop_generation", "watcher_epoch"}:
            raise RuntimeError("emergency stop permits revocation metadata only")
        row = con.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        value = int(row[0]) + 1 if row else 1
        con.execute(
            "INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )
        return value

    def insert_in_transaction(
        self,
        con: sqlite3.Connection,
        event_type: str,
        payload: dict[str, Any],
        *,
        actor: str,
        generation: int,
        event_id: str | None = None,
    ) -> str:
        self._require_emergency_event(event_type)
        eid = event_id or stable_event_id(event_type, payload, uuid.uuid4().hex)
        con.execute(
            "INSERT OR IGNORE INTO events(event_id,event_type,created_at,generation,actor,payload_json) VALUES(?,?,?,?,?,?)",
            (eid, event_type, iso_now(), generation, actor, canonical_json(payload)),
        )
        return eid

    def _read_private_projection(self, path: Path) -> bytes:
        """Read a final projection only after no-follow private-path checks."""

        self._prepare_private_projection(path)
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise OSError(f"projection path is not a regular file: {path}")
            chunks: list[bytes] = []
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block:
                    return b"".join(chunks)
                chunks.append(block)
        finally:
            os.close(descriptor)

    def _publish_text_if_changed(self, path: Path, text: str) -> bool:
        """Atomically publish only a changed projection, retaining safe bytes."""

        expected = text.encode("utf-8")
        if self._read_private_projection(path) == expected:
            return False
        atomic_write_text(path, text, mode=PRIVATE_FILE_MODE)
        return True

    def _publish_json_if_changed(self, path: Path, payload: Any) -> bool:
        """Atomically publish JSON only when its deterministic bytes differ."""

        text = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        if self._read_private_projection(path) == text.encode("utf-8"):
            return False
        atomic_write_json(path, payload, mode=PRIVATE_FILE_MODE)
        return True

    def _projection_lock(self):
        """Serialize publication through the no-follow lock inode we validated."""

        path = self.state_dir / PROJECTION_LOCK_FILE
        self._prepare_private_projection(path)
        if os.name != "posix":
            raise OSError("projection publication locking requires POSIX support")
        try:
            import fcntl
        except ImportError as exc:  # pragma: no cover - POSIX CPython provides it.
            raise OSError("projection publication locking requires fcntl") from exc
        no_follow = getattr(os, "O_NOFOLLOW", 0)
        directory_only = getattr(os, "O_DIRECTORY", 0)
        if not no_follow or not directory_only:
            raise OSError(
                "projection publication locking requires no-follow descriptors"
            )
        directory_flags = (
            os.O_RDONLY | directory_only | getattr(os, "O_CLOEXEC", 0) | no_follow
        )
        file_flags = (
            os.O_RDWR
            | getattr(os, "O_CLOEXEC", 0)
            | no_follow
            | getattr(os, "O_NONBLOCK", 0)
        )
        try:
            directory_descriptor = os.open(self.state_dir, directory_flags)
        except OSError as exc:
            raise OSError("projection lock directory is unsafe") from exc
        descriptor: int | None = None
        try:
            try:
                descriptor = os.open(
                    PROJECTION_LOCK_FILE,
                    file_flags,
                    dir_fd=directory_descriptor,
                )
            except OSError as exc:
                raise OSError("projection lock path is unsafe") from exc
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise OSError("projection lock path is not a private regular file")
            os.fchmod(descriptor, PRIVATE_FILE_MODE)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        except OSError:
            if descriptor is not None:
                os.close(descriptor)
            raise
        finally:
            os.close(directory_descriptor)

        @contextmanager
        def held_lock():
            try:
                yield
            finally:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                finally:
                    os.close(descriptor)

        return held_lock()

    def _export_events_locked(self, snapshot: dict[str, Any]) -> bool:
        """Publish JSONL while the caller owns the projection boundary."""

        rows = snapshot["events"]
        text = "".join(canonical_json(row) + "\n" for row in rows)
        path = self.state_dir / "events.jsonl"
        return self._publish_text_if_changed(path, text)

    def export_events(self, snapshot: dict[str, Any] | None = None) -> bool:
        """Publish JSONL without interleaving another projection publication."""

        with self._projection_lock():
            self._verify_projection_integrity()
            # Derived files are never an authority boundary. Read canonical
            # SQLite only after taking the publication lock, so a delayed
            # caller cannot regress a newer/tampered/missing projection.
            snapshot = self.read_snapshot()
            return self._export_events_locked(snapshot)

    def rebuild(self, snapshot: dict[str, Any] | None = None) -> dict[str, Any]:
        """Publish a coherent snapshot, replacing only changed projection bytes."""

        with self._projection_lock():
            # Verify the launch binding once before all derived-file work. The
            # individual no-follow checks below still fail closed for every
            # path. The supplied snapshot is advisory only: the locked fresh
            # canonical read is the sole publication authority.
            self._verify_projection_integrity()
            snapshot = self.read_snapshot()
            projection = self.projection_from_snapshot(snapshot)
            runtime_path = self.state_dir / "runtime.json"
            current_path = self.state_dir / "current.json"
            policy_path = self.state_dir / "policy_effective.json"
            queue_path = self.state_dir / "queue_state.json"
            for path, payload in (
                (runtime_path, projection),
                (current_path, projection.get("current", {})),
                (policy_path, projection.get("policy", {})),
                (queue_path, projection.get("queue", {})),
            ):
                self._publish_json_if_changed(path, payload)
            self._export_events_locked(snapshot)
        return projection

    def wait_for_event_count(self, expected: int, timeout: float = 10.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.count() >= expected:
                return True
            time.sleep(0.05)
        return self.count() >= expected
