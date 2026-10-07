#!/usr/bin/env python3
"""Canonical scoring verdict parser for the Rookery.

Design rules:
- Prefer structured fields over raw text.
- HTTP 2xx and wrapper success mean transport health only, not scorer truth.
- Explicit scorer rejection such as correct:false or status:incorrect overrides
  helper-level success:true / ok:true.
- Fall back to raw text only when no structured scorer fields exist.
"""

from __future__ import annotations
from dataclasses import dataclass, asdict
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any, Iterable
import re

ACCEPTED = "accepted"
REJECTED = "rejected"
ALREADY_ACCEPTED = "already-accepted"
AUTH_BLOCKED = "auth_blocked"
BLOCKED_BY_AUTH = "blocked-by-auth"
TRANSPORT_ERROR = "transport_error"
UNKNOWN = "unknown"
NON_SCORING = "non_scoring"

AUTH_WORDS = (
    "unauthorized",
    "unauthenticated",
    "forbidden",
    "csrf",
    "login required",
    "login_required",
    "auth expired",
    "credential expired",
    "cookie expired",
    "not authenticated",
    "signin",
    "sign in",
    "token expired",
    "session expired",
    "auth_blocked",
    "blocked-by-auth",
    "platform-heavy pause",
    "platform heavy pause",
)
REJECT_WORDS = (
    "incorrect",
    "wrong",
    "invalid answer",
    "not correct",
    "not_correct",
    "rejected",
    "reject",
    "try again",
    "failed",
    "failure",
    "mismatch",
    "bad answer",
    "not accepted",
)
ACCEPT_WORDS = (
    "scorer accepted",
    "answer accepted",
    "flag accepted",
    "already solved",
    "already_solved",
    "already captured",
    "alreadycaptured",
    "successfully completed",
    "challenge complete",
    "task complete",
    "task_completed",
    "lab_completed",
    "solved",
    "correct answer",
)
BOOL_ACCEPT_KEYS = {
    "accepted",
    "isaccepted",
    "captured",
    "iscaptured",
    "alreadycaptured",
    "alreadysolved",
    "solved",
    "completed",
    "complete",
    "taskcompleted",
    "labcompleted",
    "answeraccepted",
}
BOOL_CORRECT_KEYS = {"correct", "iscorrect", "valid", "isvalid", "answercorrect"}
BOOL_REJECT_KEYS = {"incorrect", "wrong", "rejected", "invalid", "answerincorrect"}
STATUS_KEYS = {
    "status",
    "state",
    "verdict",
    "result",
    "outcome",
    "answerstatus",
    "submissionstatus",
    "scoringstatus",
    "resultstatus",
}
MESSAGE_KEYS = {"message", "error", "errors", "detail", "details", "reason"}
TRANSPORT_KEYS = {
    "ok",
    "success",
    "httpok",
    "transportok",
    "statuscode",
    "httpstatus",
    "returncode",
    "exitcode",
    "responsecode",
    "code",
}
ACCEPT_STATUS = {
    "correct",
    "accepted",
    "solved",
    "complete",
    "completed",
    "already_solved",
    "already solved",
    "alreadycaptured",
    "already captured",
}
REJECT_STATUS = {
    "incorrect",
    "wrong",
    "rejected",
    "invalid",
    "bad",
    "failure",
    "failed",
    "not_correct",
    "not correct",
}
AUTH_STATUS = {
    "unauthorized",
    "forbidden",
    "auth_expired",
    "auth expired",
    "auth_blocked",
    "blocked-by-auth",
    "blocked by auth",
    "expired",
    "login_required",
    "login required",
    "csrf",
}
MAX_VERDICT_DOCUMENT_BYTES = 8 * 1024 * 1024
MAX_VERDICT_JSON_DEPTH = 32
MAX_VERDICT_JSON_ITEMS = 8_192
MAX_VERDICT_JSON_STRING_BYTES = 64 * 1024


class ContainedEvidenceError(ValueError):
    """A response or request artifact failed the contained-read contract."""


class EvidenceJsonSyntaxError(ContainedEvidenceError):
    """The bounded bytes are plain text or syntactically invalid JSON."""


@dataclass(frozen=True)
class ContainedEvidence:
    """Bounded bytes and privacy-safe provenance for one workspace artifact."""

    relative_path: str
    data: bytes
    sha256: str
    mode: int
    nlink: int

    def provenance(self) -> dict[str, Any]:
        return {
            "path": self.relative_path,
            "sha256": self.sha256,
            "bytes": len(self.data),
        }


def _norm_key(k: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(k).lower())


def _norm_word(s: Any) -> str:
    return re.sub(r"\s+", " ", str(s).strip().lower())


def _safe_json(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False, sort_keys=True)
    except Exception:
        return str(obj)


def _contained_relative_parts(root: Path | str, path: Path | str) -> tuple[Path, tuple[str, ...]]:
    """Return lexical workspace-relative parts without resolving any link."""

    workspace = Path(os.path.abspath(os.fspath(root)))
    candidate = Path(path)
    if candidate.is_absolute():
        absolute = Path(os.path.abspath(os.fspath(candidate)))
        try:
            relative = absolute.relative_to(workspace)
        except ValueError as exc:
            raise ContainedEvidenceError(
                "evidence artifact is outside the workspace"
            ) from exc
    else:
        relative = candidate
    parts = relative.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ContainedEvidenceError("evidence artifact is not workspace-relative")
    if any("\\" in part or "\x00" in part for part in parts):
        raise ContainedEvidenceError("evidence artifact path is invalid")
    return workspace, tuple(parts)


def contained_relative_path(root: Path | str, path: Path | str) -> str:
    """Return one safe, portable evidence reference without opening the path."""

    _workspace, parts = _contained_relative_parts(root, path)
    return "/".join(parts)


def _identity(info: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    """Return every stable attribute relied on by a contained evidence read."""

    return (
        int(info.st_dev),
        int(info.st_ino),
        stat.S_IFMT(info.st_mode),
        int(info.st_size),
        int(info.st_mtime_ns),
        int(info.st_ctime_ns),
        int(info.st_nlink),
    )


def _read_descriptor_bytes(descriptor: int, maximum: int) -> bytes:
    data = bytearray()
    while len(data) <= maximum:
        block = os.read(descriptor, min(64 * 1024, maximum + 1 - len(data)))
        if not block:
            break
        data.extend(block)
    if len(data) > maximum:
        raise ContainedEvidenceError("evidence artifact exceeds configured byte limit")
    return bytes(data)


def read_contained_evidence(
    root: Path | str,
    path: Path | str,
    *,
    max_bytes: int = MAX_VERDICT_DOCUMENT_BYTES,
) -> ContainedEvidence:
    """Read one stable, regular workspace file through no-follow descriptors.

    This deliberately rejects rather than repairs link, special-file, and
    replacement races.  The resulting descriptor remains tied to the entry
    checked before and after the read, so the reconciliation record never
    attests to a path that was swapped while it was being consumed.
    """

    if max_bytes <= 0:
        raise ValueError("evidence document byte limit must be positive")
    workspace, parts = _contained_relative_parts(root, path)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    directory_only = getattr(os, "O_DIRECTORY", 0)
    if not no_follow or not directory_only or os.name != "posix":
        raise OSError("contained evidence reads require POSIX no-follow descriptors")
    common = os.O_RDONLY | no_follow | getattr(os, "O_CLOEXEC", 0)
    descriptors: list[int] = []
    checks: list[tuple[int, str, tuple[int, int, int, int, int, int, int]]] = []
    try:
        root_descriptor = os.open(workspace, common | directory_only)
        descriptors.append(root_descriptor)
        if not stat.S_ISDIR(os.fstat(root_descriptor).st_mode):
            raise ContainedEvidenceError("workspace root is not a directory")
        parent = root_descriptor
        target = -1
        for index, name in enumerate(parts):
            is_final = index == len(parts) - 1
            try:
                before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                raise
            if is_final:
                if not stat.S_ISREG(before.st_mode):
                    raise ContainedEvidenceError("evidence artifact is not a regular file")
                if before.st_size > max_bytes:
                    raise ContainedEvidenceError(
                        "evidence artifact exceeds configured byte limit"
                    )
                flags = common | getattr(os, "O_NONBLOCK", 0)
            else:
                if not stat.S_ISDIR(before.st_mode):
                    raise ContainedEvidenceError(
                        "evidence artifact has a non-directory path component"
                    )
                flags = common | directory_only
            try:
                descriptor = os.open(name, flags, dir_fd=parent)
            except OSError as exc:
                raise ContainedEvidenceError("evidence artifact cannot be opened safely") from exc
            descriptors.append(descriptor)
            opened = os.fstat(descriptor)
            if _identity(before) != _identity(opened):
                raise ContainedEvidenceError("evidence artifact changed during open")
            try:
                after_open = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError as exc:
                raise ContainedEvidenceError("evidence artifact changed during open") from exc
            if _identity(opened) != _identity(after_open):
                raise ContainedEvidenceError("evidence artifact changed during open")
            checks.append((parent, name, _identity(opened)))
            parent = descriptor
            if is_final:
                target = descriptor
        if target < 0 or not stat.S_ISREG(os.fstat(target).st_mode):
            raise ContainedEvidenceError("evidence artifact is not a regular file")
        initial_target_info = os.fstat(target)
        initial_target = _identity(initial_target_info)
        data = _read_descriptor_bytes(target, max_bytes)
        if len(data) != initial_target[3]:
            raise ContainedEvidenceError("evidence artifact size changed during read")
        if _identity(os.fstat(target)) != initial_target:
            raise ContainedEvidenceError("evidence artifact changed during read")
        try:
            os.lseek(target, 0, os.SEEK_SET)
        except OSError as exc:
            raise ContainedEvidenceError("evidence artifact cannot be re-verified") from exc
        verified = _read_descriptor_bytes(target, max_bytes)
        if len(verified) != initial_target[3] or verified != data:
            raise ContainedEvidenceError("evidence artifact changed during read")
        if _identity(os.fstat(target)) != initial_target:
            raise ContainedEvidenceError("evidence artifact changed during read")
        for parent_descriptor, name, expected in checks:
            try:
                current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            except FileNotFoundError as exc:
                raise ContainedEvidenceError("evidence artifact changed during read") from exc
            if _identity(current) != expected:
                raise ContainedEvidenceError("evidence artifact changed during read")
        return ContainedEvidence(
            relative_path="/".join(parts),
            data=data,
            sha256=hashlib.sha256(data).hexdigest(),
            mode=stat.S_IMODE(initial_target_info.st_mode),
            nlink=int(initial_target_info.st_nlink),
        )
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _json_preflight(data: bytes, *, max_depth: int, max_items: int) -> str:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContainedEvidenceError("evidence JSON must be valid UTF-8") from exc
    depth = 0
    separators = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "{[":
            depth += 1
            if depth > max_depth:
                raise ContainedEvidenceError("evidence JSON exceeds depth limit")
        elif character in "}]":
            depth -= 1
            if depth < 0:
                raise EvidenceJsonSyntaxError("evidence JSON is malformed")
        elif character in ",:":
            separators += 1
            if separators > max_items * 2:
                raise ContainedEvidenceError("evidence JSON exceeds item limit")
    return text


def _validate_json_shape(
    value: Any,
    *,
    max_depth: int = MAX_VERDICT_JSON_DEPTH,
    max_items: int = MAX_VERDICT_JSON_ITEMS,
) -> None:
    items = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        items += 1
        if items > max_items:
            raise ContainedEvidenceError("evidence JSON exceeds item limit")
        if depth > max_depth:
            raise ContainedEvidenceError("evidence JSON exceeds depth limit")
        if isinstance(current, str):
            if len(current.encode("utf-8")) > MAX_VERDICT_JSON_STRING_BYTES:
                raise ContainedEvidenceError("evidence JSON string exceeds byte limit")
        elif isinstance(current, dict):
            for key, child in current.items():
                if len(str(key).encode("utf-8")) > MAX_VERDICT_JSON_STRING_BYTES:
                    raise ContainedEvidenceError("evidence JSON string exceeds byte limit")
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)


def _bounded_json(data: bytes) -> Any:
    text = _json_preflight(
        data,
        max_depth=MAX_VERDICT_JSON_DEPTH,
        max_items=MAX_VERDICT_JSON_ITEMS,
    )
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise EvidenceJsonSyntaxError("evidence JSON is malformed") from exc
    _validate_json_shape(value)
    return value


def read_contained_json(
    root: Path | str,
    path: Path | str,
    *,
    max_bytes: int = MAX_VERDICT_DOCUMENT_BYTES,
) -> tuple[Any, ContainedEvidence]:
    """Return bounded JSON and stable provenance for one contained artifact."""

    evidence = read_contained_evidence(root, path, max_bytes=max_bytes)
    return _bounded_json(evidence.data), evidence


def _load_text_or_json(
    path: Path, max_bytes: int = MAX_VERDICT_DOCUMENT_BYTES
) -> Any:
    if max_bytes <= 0:
        raise ValueError("verdict document byte limit must be positive")
    if path.stat().st_size > max_bytes:
        raise ValueError("verdict document exceeds configured byte limit")
    data = path.read_bytes()
    if len(data) > max_bytes:
        raise ValueError("verdict document exceeds configured byte limit")
    try:
        return _bounded_json(data)
    except EvidenceJsonSyntaxError:
        # A response may legitimately be plain text.  Structural-limit failures
        # are not text and must never be reclassified through raw fallback.
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("verdict document is not valid UTF-8") from exc
        return text


def iter_fields(obj: Any, prefix: str = "") -> Iterable[tuple[str, str, Any]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            yield path, _norm_key(k), v
            if isinstance(v, (dict, list)):
                yield from iter_fields(v, path)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            path = f"{prefix}[{i}]" if prefix else f"[{i}]"
            if isinstance(v, (dict, list)):
                yield from iter_fields(v, path)


@dataclass
class Verdict:
    verdict: str
    scorer_truth: str
    transport_truth: str
    confidence: str
    reason: str
    path: str = ""
    matched_key: str = ""
    matched_value: str = ""
    structured: bool = False
    notes: tuple[str, ...] = ()
    http_status: int | None = None
    process_returncode: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _transport(
    obj: Any, *, http_status: int | None = None, process_returncode: int | None = None
) -> tuple[str, list[str]]:
    notes: list[str] = []
    if http_status is not None:
        notes.append(f"http_status={http_status}")
        if http_status in (401, 403):
            return AUTH_BLOCKED, notes
        if http_status >= 400:
            return TRANSPORT_ERROR, notes
        if 200 <= http_status < 300:
            return "transport_ok", notes
    if process_returncode is not None:
        notes.append(f"process_returncode={process_returncode}")
        if process_returncode != 0:
            return TRANSPORT_ERROR, notes
    if isinstance(obj, dict):
        for p, key, v in iter_fields(obj):
            if key in {"statuscode", "httpstatus", "responsecode", "code"}:
                try:
                    iv = int(v)
                    notes.append(f"{p}={iv}")
                    if iv in (401, 403):
                        return AUTH_BLOCKED, notes
                    if iv >= 400:
                        return TRANSPORT_ERROR, notes
                    if 200 <= iv < 300:
                        return "transport_ok", notes
                except Exception:
                    pass
            if key in {"returncode", "exitcode"}:
                try:
                    iv = int(v)
                    notes.append(f"{p}={iv}")
                    if iv != 0:
                        return TRANSPORT_ERROR, notes
                except Exception:
                    pass
            if key in {"ok", "success", "httpok", "transportok"} and isinstance(
                v, bool
            ):
                # ok/success is transport only. Never scoring acceptance.
                notes.append(f"transport:{p}={v}")
                if v is False:
                    return TRANSPORT_ERROR, notes
                return "transport_ok", notes
    return UNKNOWN, notes


def parse_verdict(
    obj: Any,
    *,
    source_path: str = "",
    allow_text_fallback: bool = True,
    http_status: int | None = None,
    process_returncode: int | None = None,
) -> Verdict:
    if isinstance(obj, Path):
        return parse_file(
            obj,
            allow_text_fallback=allow_text_fallback,
            http_status=http_status,
            process_returncode=process_returncode,
        )
    transport, notes = _transport(
        obj, http_status=http_status, process_returncode=process_returncode
    )

    # Structured scorer truth first. Rejection beats acceptance if both appear.
    structured_matches: list[tuple[str, str, str, Any, str]] = []
    metadataish = False
    if isinstance(obj, dict):
        for path, key, val in iter_fields(obj):
            if key in {
                "joinurl",
                "token",
                "cluster",
                "clusterid",
                "connectionid",
                "attemptid",
                "activityid",
            }:
                metadataish = True
            if key in BOOL_CORRECT_KEYS and isinstance(val, bool):
                structured_matches.append(
                    (ACCEPTED if val else REJECTED, path, key, val, "correct boolean")
                )
            elif key in BOOL_REJECT_KEYS and isinstance(val, bool):
                if val:
                    structured_matches.append(
                        (REJECTED, path, key, val, "negative scorer boolean")
                    )
            elif key in BOOL_ACCEPT_KEYS and isinstance(val, bool):
                if val:
                    meaning = (
                        ALREADY_ACCEPTED
                        if key in {"alreadycaptured", "alreadysolved"}
                        else ACCEPTED
                    )
                    structured_matches.append(
                        (meaning, path, key, val, "accepted/completed boolean")
                    )
            elif key in STATUS_KEYS:
                status = _norm_word(val)
                if status in REJECT_STATUS or any(status == w for w in REJECT_STATUS):
                    structured_matches.append(
                        (REJECTED, path, key, val, "rejection status")
                    )
                elif status in AUTH_STATUS or any(w in status for w in AUTH_WORDS):
                    structured_matches.append(
                        (AUTH_BLOCKED, path, key, val, "auth status")
                    )
                elif status in ACCEPT_STATUS:
                    meaning = ALREADY_ACCEPTED if "already" in status else ACCEPTED
                    structured_matches.append(
                        (meaning, path, key, val, "accepted status")
                    )
            elif key in MESSAGE_KEYS:
                msg = _norm_word(val)
                if any(w in msg for w in AUTH_WORDS):
                    structured_matches.append(
                        (AUTH_BLOCKED, path, key, str(val)[:500], "auth message")
                    )
                # Message text can reject, but keep acceptance by message to text fallback unless no structured answer fields exist.
                elif any(w in msg for w in REJECT_WORDS):
                    structured_matches.append(
                        (REJECTED, path, key, str(val)[:500], "rejection message")
                    )

    priority = {REJECTED: 0, ACCEPTED: 1, ALREADY_ACCEPTED: 1, AUTH_BLOCKED: 2}
    scorer_matches = [
        m for m in structured_matches if m[0] in {REJECTED, ACCEPTED, ALREADY_ACCEPTED}
    ]
    auth_matches = [m for m in structured_matches if m[0] == AUTH_BLOCKED]
    chosen = None
    if scorer_matches:
        chosen = sorted(scorer_matches, key=lambda m: priority[m[0]])[0]
    elif auth_matches or transport == AUTH_BLOCKED:
        chosen = (
            auth_matches[0]
            if auth_matches
            else (AUTH_BLOCKED, "transport", "transport", transport, "auth transport")
        )
    if chosen:
        verdict, path, key, value, reason = chosen
        return Verdict(
            verdict,
            verdict,
            transport,
            "high",
            reason,
            source_path,
            str(path),
            str(value),
            True,
            tuple(notes),
            http_status,
            process_returncode,
        )

    if allow_text_fallback:
        text = _safe_json(obj).lower() if not isinstance(obj, str) else obj.lower()
        # Explicit false/reject patterns before acceptance because "not correct" contains "correct".
        if re.search(r'"(?:correct|iscorrect|valid|isvalid)"\s*:\s*false', text) or any(
            w in text for w in REJECT_WORDS
        ):
            return Verdict(
                REJECTED,
                REJECTED,
                transport,
                "medium",
                "raw text rejection fallback",
                source_path,
                "raw_text",
                "",
                False,
                tuple(notes),
                http_status,
                process_returncode,
            )
        if re.search(
            r'"(?:status|verdict|result)"\s*:\s*"(?:incorrect|wrong|rejected|invalid|not correct)"',
            text,
        ):
            return Verdict(
                REJECTED,
                REJECTED,
                transport,
                "medium",
                "raw text status rejection fallback",
                source_path,
                "raw_text",
                "",
                False,
                tuple(notes),
                http_status,
                process_returncode,
            )
        if any(w in text for w in AUTH_WORDS):
            return Verdict(
                AUTH_BLOCKED,
                AUTH_BLOCKED,
                transport,
                "medium",
                "raw text auth fallback",
                source_path,
                "raw_text",
                "",
                False,
                tuple(notes),
                http_status,
                process_returncode,
            )
        if re.search(r'"(?:correct|iscorrect|valid|isvalid)"\s*:\s*true', text) or any(
            w in text for w in ACCEPT_WORDS
        ):
            return Verdict(
                ACCEPTED,
                ACCEPTED,
                transport,
                "medium",
                "raw text accepted fallback",
                source_path,
                "raw_text",
                "",
                False,
                tuple(notes),
                http_status,
                process_returncode,
            )

    if metadataish:
        return Verdict(
            NON_SCORING,
            NON_SCORING,
            transport,
            "medium",
            "metadata/session response without scorer truth",
            source_path,
            "",
            "",
            True,
            tuple(notes),
            http_status,
            process_returncode,
        )
    if transport == TRANSPORT_ERROR:
        return Verdict(
            TRANSPORT_ERROR,
            UNKNOWN,
            transport,
            "medium",
            "transport failed without scorer truth",
            source_path,
            "",
            "",
            False,
            tuple(notes),
            http_status,
            process_returncode,
        )
    return Verdict(
        UNKNOWN,
        UNKNOWN,
        transport,
        "low",
        "no scorer truth found",
        source_path,
        "",
        "",
        False,
        tuple(notes),
        http_status,
        process_returncode,
    )


def parse_file(
    path: str | Path,
    *,
    allow_text_fallback: bool = True,
    http_status: int | None = None,
    process_returncode: int | None = None,
    max_bytes: int = MAX_VERDICT_DOCUMENT_BYTES,
) -> Verdict:
    p = Path(path)
    obj = _load_text_or_json(p, max_bytes=max_bytes)
    return parse_verdict(
        obj,
        source_path=str(p),
        allow_text_fallback=allow_text_fallback,
        http_status=http_status,
        process_returncode=process_returncode,
    )


def parse_contained_document(
    root: Path | str,
    path: Path | str,
    *,
    allow_text_fallback: bool = True,
    http_status: int | None = None,
    process_returncode: int | None = None,
    max_bytes: int = MAX_VERDICT_DOCUMENT_BYTES,
) -> tuple[Verdict, Any | None, ContainedEvidence]:
    """Parse one descriptor-verified response and retain its bounded document."""

    evidence = read_contained_evidence(root, path, max_bytes=max_bytes)
    try:
        obj = _bounded_json(evidence.data)
    except EvidenceJsonSyntaxError:
        try:
            text = evidence.data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("verdict document is not valid UTF-8") from exc
        obj = text
        document: Any | None = None
    else:
        document = obj
    return (
        parse_verdict(
            obj,
            source_path=evidence.relative_path,
            allow_text_fallback=allow_text_fallback,
            http_status=http_status,
            process_returncode=process_returncode,
        ),
        document,
        evidence,
    )


def parse_contained_file(
    root: Path | str,
    path: Path | str,
    *,
    allow_text_fallback: bool = True,
    http_status: int | None = None,
    process_returncode: int | None = None,
    max_bytes: int = MAX_VERDICT_DOCUMENT_BYTES,
) -> tuple[Verdict, ContainedEvidence]:
    """Compatibility wrapper for callers that only need verdict provenance."""

    verdict, _document, evidence = parse_contained_document(
        root,
        path,
        allow_text_fallback=allow_text_fallback,
        http_status=http_status,
        process_returncode=process_returncode,
        max_bytes=max_bytes,
    )
    return verdict, evidence


def ledger_state(verdict: str) -> str:
    v = _norm_key(verdict)
    if v in {"accepted", "alreadyaccepted"}:
        return "platform_accepted"
    if v == "rejected":
        return "platform_rejected"
    if v in {"authblocked", "blockedbyauth"}:
        return "blocked_by_auth"
    if v in {"nonscoring"}:
        return "non_scoring"
    if v in {"transporterror"}:
        return "transport_error"
    return "unknown_or_other"


def exit_code_for_verdict(verdict: str) -> int:
    v = _norm_key(verdict)
    if v in {"accepted", "alreadyaccepted"}:
        return 0
    if v in {"rejected", "authblocked", "blockedbyauth", "transporterror"}:
        return 1
    return 2


def sibling_request_metadata(
    response_path: str | Path,
    *,
    workspace_root: Path | str | None = None,
    max_bytes: int = MAX_VERDICT_DOCUMENT_BYTES,
) -> dict[str, Any]:
    p = Path(response_path)
    candidates = [
        p.parent / "request.json",
        p.parent / "request-body.json",
        p.parent / "request_meta.json",
        p.with_name("request.json"),
    ]
    out: dict[str, Any] = {
        "response_path": str(p),
        "request_path": "",
        "challenge": "",
        "objective": "",
        "candidate": "",
        "activity_id": "",
        "attempt_id": "",
        "cluster_id": "",
        "question_id": "",
        "mission_id": "",
    }
    aliases = {
        "challenge": ["challenge", "challenge_id", "challengeId", "slug", "id"],
        "objective": [
            "objective",
            "objective_id",
            "objectiveId",
            "mission",
            "mission_id",
            "missionId",
        ],
        "candidate": [
            "candidate",
            "value",
            "answer",
            "answer_value",
            "answerValue",
            "submission",
        ],
        "activity_id": ["activity_id", "activityId"],
        "attempt_id": ["attempt_id", "attemptId"],
        "cluster_id": ["cluster_id", "clusterId"],
        "question_id": ["question_id", "questionId"],
        "mission_id": ["mission_id", "missionId"],
    }
    # Refuse to read adjacent metadata until a caller supplies the workspace
    # containment root.  This helper is often used while importing platform
    # output, where a pathname alone is attacker-controlled evidence.
    if workspace_root is None:
        return out
    for req in candidates:
        try:
            obj, evidence = read_contained_json(
                workspace_root, req, max_bytes=max_bytes
            )
        except FileNotFoundError:
            continue
        out["request_path"] = evidence.relative_path
        sources = [obj]
        if isinstance(obj, dict):
            for k in ["request", "body", "variables", "payload", "metadata", "meta"]:
                if isinstance(obj.get(k), dict):
                    sources.append(obj[k])
        for src in sources:
            if not isinstance(src, dict):
                continue
            for key, names in aliases.items():
                if out.get(key):
                    continue
                for name in names:
                    if name in src and src[name] not in (None, ""):
                        out[key] = str(src[name])
                        break
        break
    return out


def attach_metadata(
    response_path: str | Path,
    *,
    workspace_root: Path | str | None = None,
) -> dict[str, Any]:
    p = Path(response_path)
    if workspace_root is None:
        workspace_root = Path.cwd()
    verdict, _evidence = parse_contained_file(workspace_root, p)
    return {
        **sibling_request_metadata(p, workspace_root=workspace_root),
        "verdict": verdict.verdict,
        "ledger_state": ledger_state(verdict.verdict),
        "verdict_detail": verdict.to_dict(),
    }
