from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
import re
import stat
from typing import Any

from rookery.verdict_parser import (
    ContainedEvidence,
    ContainedEvidenceError,
    contained_relative_path,
    ledger_state,
    parse_contained_document,
    read_contained_evidence,
    read_contained_json,
)

from .scoring import terminal_retry_metadata
from .store import EventStore
from .util import canonical_json, ensure_private_dir, file_lock, iso_now, sha256_bytes


MAX_RECONCILIATION_METADATA_BYTES = 8 * 1024
_RETAINED_EVIDENCE_DIR = ("evidence", "imports", "sha256")
LOWER_SHA256 = re.compile(r"[0-9a-f]{64}")
TERMINAL_EXECUTION_STATES = {
    "completed",
    "rejected",
    "indeterminate",
    "blocked",
    "failed",
}

_IDENTITY_ALIASES = {
    "proposal_id": ("proposal_id", "proposalId"),
    "objective_id": (
        "objective",
        "objective_id",
        "objectiveId",
        "challenge",
        "challenge_id",
        "challengeId",
        "slug",
    ),
    "candidate": (
        "candidate",
        "value",
        "answer",
        "answer_value",
        "answerValue",
        "submission",
        "exact_value",
    ),
    "adapter_id": ("adapter_id", "adapterId", "adapter"),
    "action_kind": ("action_kind", "actionKind"),
    "artifact_digest": (
        "artifact_sha256",
        "artifactSha256",
        "artifact_digest",
        "artifactDigest",
    ),
    "activity_id": ("activity_id", "activityId"),
    "attempt_id": ("attempt_id", "attemptId"),
    "cluster_id": ("cluster_id", "clusterId"),
    "question_id": ("question_id", "questionId"),
    "mission_id": ("mission_id", "missionId"),
}
_ATTEMPT_SCOPE_KEYS = (
    "activity_id",
    "attempt_id",
    "cluster_id",
    "question_id",
    "mission_id",
)


def _metadata_text(value: Any) -> str:
    if isinstance(value, bool) or isinstance(value, (dict, list, tuple, set)):
        raise ContainedEvidenceError("evidence metadata field is invalid")
    text = str(value)
    if not text or len(text.encode("utf-8")) > MAX_RECONCILIATION_METADATA_BYTES:
        raise ContainedEvidenceError("evidence metadata field exceeds byte limit")
    return text


def _nested_mappings(body: Any) -> list[dict[str, Any]]:
    if not isinstance(body, dict):
        return []
    sources = [body]
    for key in (
        "request",
        "body",
        "variables",
        "payload",
        "metadata",
        "meta",
        "proposal",
        "data",
        "envelope",
    ):
        nested = body.get(key)
        if isinstance(nested, dict):
            sources.append(nested)
    return sources


def _single_value(values: list[str]) -> tuple[str, bool]:
    unique = list(dict.fromkeys(values))
    return (unique[0], len(unique) > 1) if unique else ("", False)


def _scope_mapping(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ContainedEvidenceError("evidence attempt scope is invalid")
    return {_metadata_text(key): _metadata_text(item) for key, item in value.items()}


def _sibling_request(
    root: Path, response_path: Path | str
) -> tuple[Any | None, ContainedEvidence | None]:
    response_relative = Path(contained_relative_path(root, response_path))
    for candidate in (
        response_relative.parent / "request.json",
        response_relative.parent / "request-body.json",
        response_relative.parent / "request_meta.json",
    ):
        try:
            return read_contained_json(root, candidate)
        except FileNotFoundError:
            continue
    return None, None


def _metadata_from_response(
    root: Path, path: Path
) -> tuple[dict[str, Any], Any, ContainedEvidence, ContainedEvidence | None]:
    verdict, response_body, checked_response = parse_contained_document(root, path)
    request_body, request_evidence = _sibling_request(root, path)
    values: dict[str, list[str]] = {field: [] for field in _IDENTITY_ALIASES}
    scope_values: dict[str, list[str]] = {}
    scope_present = False
    for body in (response_body, request_body):
        for source in _nested_mappings(body):
            for target, aliases in _IDENTITY_ALIASES.items():
                for alias in aliases:
                    value = source.get(alias)
                    if value not in (None, ""):
                        values[target].append(_metadata_text(value))
            for alias in ("attempt_scope", "attemptScope", "session_scope", "sessionScope"):
                if alias in source and source[alias] is not None:
                    scope_present = True
                    for key, value in _scope_mapping(source[alias]).items():
                        scope_values.setdefault(key, []).append(value)
    for field in _ATTEMPT_SCOPE_KEYS:
        if values[field]:
            scope_present = True
            scope_values.setdefault(field, []).extend(values[field])
    metadata: dict[str, Any] = {
        "response_path": checked_response.relative_path,
        "request_path": request_evidence.relative_path if request_evidence else "",
        "evidence": {
            "response": checked_response.provenance(),
            "request": request_evidence.provenance() if request_evidence else None,
        },
        "attempt_scope": {},
        "scope_present": scope_present,
        "conflict": False,
    }
    for field, found in values.items():
        value, conflict = _single_value(found)
        metadata[field] = value
        metadata["conflict"] = bool(metadata["conflict"] or conflict)
    for field, found in scope_values.items():
        value, conflict = _single_value(found)
        metadata["attempt_scope"][field] = value
        metadata["conflict"] = bool(metadata["conflict"] or conflict)
    if metadata["artifact_digest"] and not LOWER_SHA256.fullmatch(
        metadata["artifact_digest"]
    ):
        # Never retain an attacker-supplied value that only resembles a digest.
        metadata["artifact_digest"] = ""
        metadata["conflict"] = True
    return metadata, verdict, checked_response, request_evidence


def _artifact_digest(proposal: dict[str, Any]) -> str:
    reference = str(proposal.get("artifact_reference") or "")
    return sha256_bytes(reference.encode("utf-8")) if reference else ""


def _canonical_scope(proposal: dict[str, Any]) -> dict[str, str]:
    scope = proposal.get("attempt_scope") or {}
    return _scope_mapping(scope)


def _proposal_matches(proposal: dict[str, Any], metadata: dict[str, Any]) -> bool:
    if str(proposal.get("objective_id") or "") != metadata["objective_id"]:
        return False
    if str(proposal.get("action_kind") or "") != metadata["action_kind"]:
        return False
    if str(proposal.get("adapter_id") or "") != metadata["adapter_id"]:
        return False
    if _canonical_scope(proposal) != metadata["attempt_scope"]:
        return False
    exact_value = str(proposal.get("exact_value") or "")
    if exact_value:
        return bool(metadata["candidate"]) and hmac.compare_digest(
            exact_value, metadata["candidate"]
        )
    digest = _artifact_digest(proposal)
    return bool(digest) and hmac.compare_digest(digest, metadata["artifact_digest"])


def _bind_explicit_proposal(
    proposal: dict[str, Any], metadata: dict[str, Any]
) -> tuple[dict[str, Any] | None, str]:
    canonical = {
        "objective_id": str(proposal.get("objective_id") or ""),
        "action_kind": str(proposal.get("action_kind") or ""),
        "adapter_id": str(proposal.get("adapter_id") or ""),
    }
    mismatches = {
        field
        for field, expected in canonical.items()
        if metadata[field] and metadata[field] != expected
    }
    canonical_scope = _canonical_scope(proposal)
    if metadata["scope_present"]:
        mismatches.update(
            f"attempt_scope.{field}"
            for field, value in metadata["attempt_scope"].items()
            if canonical_scope.get(field) != value
        )

    exact_value = str(proposal.get("exact_value") or "")
    canonical_artifact_digest = _artifact_digest(proposal)
    if exact_value:
        if metadata["artifact_digest"]:
            mismatches.add("artifact_digest")
        if metadata["candidate"] and not hmac.compare_digest(
            exact_value, metadata["candidate"]
        ):
            mismatches.add("candidate")
    else:
        if metadata["candidate"]:
            mismatches.add("candidate")
        if not canonical_artifact_digest:
            mismatches.add("artifact_digest")
        elif metadata["artifact_digest"] and not hmac.compare_digest(
            canonical_artifact_digest, metadata["artifact_digest"]
        ):
            mismatches.add("artifact_digest")
    if mismatches:
        return None, "response tuple conflicts with canonical proposal"

    # The proposal is authoritative. Preserve verified explicit values and fill
    # only fields that the response and sibling request genuinely omitted.
    for field, value in canonical.items():
        if not metadata[field]:
            metadata[field] = value
    if not metadata["scope_present"]:
        metadata["attempt_scope"] = canonical_scope
        metadata["scope_present"] = True
    else:
        metadata["attempt_scope"] = {
            **canonical_scope,
            **metadata["attempt_scope"],
        }
    if exact_value:
        if not metadata["candidate"]:
            metadata["candidate"] = exact_value
    elif not metadata["artifact_digest"]:
        metadata["artifact_digest"] = canonical_artifact_digest
    return proposal, "linked"


def _match_proposal(
    proposals: dict[str, dict[str, Any]], metadata: dict[str, Any]
) -> tuple[dict[str, Any] | None, str]:
    if metadata["conflict"]:
        return None, "conflicting response metadata"
    explicit = metadata["proposal_id"]
    if explicit:
        proposal = proposals.get(explicit)
        if not isinstance(proposal, dict):
            return None, "proposal identifier is not canonical"
        return _bind_explicit_proposal(proposal, metadata)
    if not all(
        (
            metadata["objective_id"],
            metadata["action_kind"],
            metadata["adapter_id"],
            metadata["scope_present"],
        )
    ):
        return None, "incomplete canonical proposal tuple"
    if not metadata["candidate"] and not metadata["artifact_digest"]:
        return None, "proposal value or artifact digest is absent"
    if metadata["candidate"] and metadata["artifact_digest"]:
        return None, "response tuple has conflicting value and artifact identity"
    matches = [
        proposal
        for proposal in proposals.values()
        if isinstance(proposal, dict) and _proposal_matches(proposal, metadata)
    ]
    if len(matches) == 1:
        return matches[0], "linked"
    return (
        None,
        "ambiguous canonical proposal tuple" if matches else "no canonical proposal tuple",
    )


def _safe_verdict(verdict: Any) -> dict[str, Any]:
    return {
        "verdict": str(verdict.verdict),
        "scorer_truth": str(verdict.scorer_truth),
        "transport_truth": str(verdict.transport_truth),
        "confidence": str(verdict.confidence),
        "reason": str(verdict.reason),
        "structured": bool(verdict.structured),
    }


def _import_digest(metadata: dict[str, Any]) -> str:
    return hashlib.sha256(
        canonical_json(
            {
                "response": metadata["evidence"]["response"],
                "request": metadata["evidence"]["request"],
            }
        ).encode("utf-8")
    ).hexdigest()


def _value_free_evidence_provenance(metadata: dict[str, Any]) -> dict[str, Any]:
    evidence = metadata["evidence"]

    def summary(item: Any) -> dict[str, Any] | None:
        if not isinstance(item, dict):
            return None
        digest = str(item.get("sha256") or "")
        if not LOWER_SHA256.fullmatch(digest):
            raise ContainedEvidenceError("evidence provenance digest is invalid")
        return {"sha256": digest, "bytes": int(item.get("bytes", 0))}

    return {
        "response": summary(evidence.get("response")),
        "request": summary(evidence.get("request")),
    }


def _record_observation(
    store: EventStore,
    metadata: dict[str, Any],
    verdict: Any,
    *,
    reason: str,
    actor: str,
) -> dict[str, Any]:
    digest = _import_digest(metadata)
    artifact_digest = str(metadata.get("artifact_digest") or "")
    if artifact_digest and not LOWER_SHA256.fullmatch(artifact_digest):
        raise ContainedEvidenceError("artifact digest is not lowercase SHA-256")
    payload = {
        "schema_version": "1",
        "observation_id": f"observation-import-{digest}",
        "classification": "unlinked_platform_observation",
        "link_status": reason,
        "artifact_digest": artifact_digest,
        "verdict": _safe_verdict(verdict),
        "evidence_provenance": _value_free_evidence_provenance(metadata),
        "observed_at": iso_now(),
    }
    _event_id, inserted = store.append(
        "platform.observed", payload, actor=actor, event_id=payload["observation_id"]
    )
    return {
        "status": "observed",
        "reason": reason,
        "response_path": metadata["response_path"],
        "verdict": _safe_verdict(verdict),
        "import_status": "observed" if inserted else "already-observed",
    }


def _retained_evidence_relative(digest: str) -> str:
    if not LOWER_SHA256.fullmatch(digest):
        raise ContainedEvidenceError("retained evidence digest is invalid")
    return "/".join((*_RETAINED_EVIDENCE_DIR, digest))


def _directory_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        int(info.st_dev),
        int(info.st_ino),
        stat.S_IFMT(info.st_mode),
        int(info.st_size),
        int(info.st_mtime_ns),
        int(info.st_ctime_ns),
        int(info.st_nlink),
    )


def _open_retained_evidence_directory(root: Path) -> int:
    """Open the fixed retention directory without following a raced component."""

    directory = root.joinpath(*_RETAINED_EVIDENCE_DIR)
    ensure_private_dir(directory)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    directory_only = getattr(os, "O_DIRECTORY", 0)
    if not no_follow or not directory_only or os.name != "posix":
        raise OSError("retained evidence requires POSIX no-follow descriptors")
    flags = os.O_RDONLY | directory_only | no_follow | getattr(os, "O_CLOEXEC", 0)
    descriptors: list[int] = []
    try:
        current = os.open(root, flags)
        descriptors.append(current)
        if not stat.S_ISDIR(os.fstat(current).st_mode):
            raise ContainedEvidenceError("workspace root is not a directory")
        for component in _RETAINED_EVIDENCE_DIR:
            before = os.stat(component, dir_fd=current, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode):
                raise ContainedEvidenceError("retained evidence directory is invalid")
            child = os.open(component, flags, dir_fd=current)
            descriptors.append(child)
            opened = os.fstat(child)
            after = os.stat(component, dir_fd=current, follow_symlinks=False)
            if (
                _directory_identity(before) != _directory_identity(opened)
                or _directory_identity(opened) != _directory_identity(after)
            ):
                raise ContainedEvidenceError("retained evidence directory changed during open")
            os.close(current)
            descriptors.remove(current)
            current = child
        final_info = os.fstat(current)
        if not stat.S_ISDIR(final_info.st_mode) or final_info.st_mode & 0o777 != 0o700:
            raise ContainedEvidenceError("retained evidence directory is not private")
        descriptors.remove(current)
        return current
    except BaseException:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            raise OSError("unable to retain evidence bytes")
        offset += written


def _verify_retained_evidence(
    root: Path, relative_path: str, source: ContainedEvidence
) -> ContainedEvidence:
    retained = read_contained_evidence(
        root, relative_path, max_bytes=max(1, len(source.data))
    )
    if (
        retained.sha256 != source.sha256
        or len(retained.data) != len(source.data)
        or retained.mode != 0o600
        or retained.nlink != 1
        or not hmac.compare_digest(retained.data, source.data)
    ):
        raise ContainedEvidenceError("retained evidence content collision")
    return retained


def _retain_evidence(root: Path, source: ContainedEvidence) -> ContainedEvidence:
    """Create or verify one immutable private content-addressed evidence copy."""

    relative_path = _retained_evidence_relative(source.sha256)
    directory = _open_retained_evidence_directory(root)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | no_follow
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        try:
            descriptor = os.open(source.sha256, flags, 0o600, dir_fd=directory)
        except FileExistsError:
            return _verify_retained_evidence(root, relative_path, source)
        try:
            _write_all(descriptor, source.data)
            os.fchmod(descriptor, 0o600)
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_size != len(source.data)
                or info.st_nlink != 1
                or info.st_mode & 0o777 != 0o600
            ):
                raise ContainedEvidenceError("retained evidence file is invalid")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(directory)
    finally:
        os.close(directory)
    return _verify_retained_evidence(root, relative_path, source)


def _retain_import_evidence(
    root: Path, response: ContainedEvidence, request: ContainedEvidence | None
) -> tuple[dict[str, ContainedEvidence | None], dict[str, Any]]:
    """Durably retain the exact descriptor bytes before terminal mutation."""

    retained_response = _retain_evidence(root, response)
    retained_request = _retain_evidence(root, request) if request else None
    return (
        {"response": retained_response, "request": retained_request},
        {
            "response": {
                "sha256": retained_response.sha256,
                "bytes": len(retained_response.data),
                "retained_content_sha256": retained_response.sha256,
            },
            "request": (
                {
                    "sha256": retained_request.sha256,
                    "bytes": len(retained_request.data),
                    "retained_content_sha256": retained_request.sha256,
                }
                if retained_request
                else None
            ),
        },
    )


def _metadata_evidence_identity(
    metadata: dict[str, Any],
) -> tuple[str, str, int, str, str, int]:
    response = metadata["evidence"]["response"]
    request = metadata["evidence"]["request"]
    return (
        sha256_bytes(str(response["path"]).encode("utf-8")),
        str(response["sha256"]),
        int(response["bytes"]),
        sha256_bytes(str(request["path"]).encode("utf-8")) if request else "",
        str(request["sha256"]) if request else "",
        int(request["bytes"]) if request else 0,
    )


def _source_evidence_identity(metadata: dict[str, Any]) -> dict[str, Any]:
    response = metadata["evidence"]["response"]
    request = metadata["evidence"]["request"]

    def summary(item: dict[str, Any] | None) -> dict[str, Any] | None:
        if item is None:
            return None
        return {
            "path_sha256": sha256_bytes(str(item["path"]).encode("utf-8")),
            "sha256": str(item["sha256"]),
            "bytes": int(item["bytes"]),
        }

    return {"response": summary(response), "request": summary(request)}


def _preserved_evidence_identity(
    execution: dict[str, Any],
) -> tuple[str, str, int, str, str, int] | None:
    source_identity = execution.get("source_evidence_identity")
    if isinstance(source_identity, dict):
        def source_values(item: Any) -> tuple[str, str, int] | None:
            if item is None:
                return None
            if not isinstance(item, dict):
                raise ValueError("invalid source evidence identity")
            path_digest = str(item.get("path_sha256") or "")
            content_digest = str(item.get("sha256") or "")
            length = int(item.get("bytes", -1))
            if (
                not LOWER_SHA256.fullmatch(path_digest)
                or not LOWER_SHA256.fullmatch(content_digest)
                or length < 0
            ):
                raise ValueError("invalid source evidence identity")
            return (path_digest, content_digest, length)

        try:
            response = source_values(source_identity.get("response"))
            request = source_values(source_identity.get("request"))
        except (TypeError, ValueError):
            return None
        if response is None:
            return None
        return (
            response[0],
            response[1],
            response[2],
            request[0] if request else "",
            request[1] if request else "",
            request[2] if request else 0,
        )

    preserved = execution.get("evidence_provenance")
    if not isinstance(preserved, dict):
        return None

    def values(item: Any) -> tuple[str, str, int] | None:
        if item is None:
            return None
        if not isinstance(item, dict):
            raise ValueError("invalid preserved evidence provenance")
        try:
            path = str(item.get("path") or "")
            digest = str(item.get("sha256") or "")
            length = int(item.get("bytes", -1))
            if not path or not LOWER_SHA256.fullmatch(digest) or length < 0:
                raise ValueError("invalid preserved evidence provenance")
            return (sha256_bytes(path.encode("utf-8")), digest, length)
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid preserved evidence provenance") from exc

    try:
        response = values(preserved.get("response"))
        request = values(preserved.get("request"))
    except ValueError:
        return None
    if response is None:
        return None
    return (
        response[0],
        response[1],
        response[2],
        request[0] if request else "",
        request[1] if request else "",
        request[2] if request else 0,
    )


def _verify_execution_retention(root: Path, execution: dict[str, Any]) -> None:
    """Fail closed if a retained import object was removed or altered later."""

    if not isinstance(execution.get("source_evidence_identity"), dict):
        # Pre-retention canonical events are immutable history; preserve their
        # legacy reconciliation behavior without claiming they were retained.
        return
    provenance = execution.get("evidence_provenance")
    if not isinstance(provenance, dict):
        raise ContainedEvidenceError("retained execution provenance is invalid")

    def verify(path: Any, item: Any, *, required: bool) -> None:
        if item is None:
            if required:
                raise ContainedEvidenceError("retained execution evidence is missing")
            return
        if not isinstance(item, dict):
            raise ContainedEvidenceError("retained execution provenance is invalid")
        digest = str(item.get("sha256") or "")
        length = int(item.get("bytes", -1))
        relative = contained_relative_path(root, str(path or ""))
        if (
            not LOWER_SHA256.fullmatch(digest)
            or length < 0
            or relative != _retained_evidence_relative(digest)
        ):
            raise ContainedEvidenceError("retained execution provenance is invalid")
        retained = read_contained_evidence(root, relative, max_bytes=max(1, length))
        if retained.sha256 != digest or len(retained.data) != length:
            raise ContainedEvidenceError("retained execution evidence changed")

    verify(execution.get("response_path"), provenance.get("response"), required=True)
    verify(execution.get("request_path"), provenance.get("request"), required=False)


def _execution_has_source_response_path(
    root: Path, execution: dict[str, Any], metadata: dict[str, Any]
) -> bool:
    source_identity = execution.get("source_evidence_identity")
    if isinstance(source_identity, dict):
        response = source_identity.get("response")
        if not isinstance(response, dict):
            return False
        return hmac.compare_digest(
            str(response.get("path_sha256") or ""),
            sha256_bytes(metadata["response_path"].encode("utf-8")),
        )
    response_path = str(execution.get("response_path") or "")
    if not response_path:
        return False
    try:
        return contained_relative_path(root, response_path) == metadata["response_path"]
    except ContainedEvidenceError:
        return False


def _terminal_evidence_decision(
    root: Path,
    current: dict[str, Any],
    metadata: dict[str, Any],
    verdict: Any,
) -> tuple[str, dict[str, Any] | None]:
    incoming_identity = _metadata_evidence_identity(metadata)
    candidates: list[dict[str, Any]] = []
    for execution in current.get("executions", {}).values():
        if str(execution.get("status") or "") not in TERMINAL_EXECUTION_STATES:
            continue
        if not _execution_has_source_response_path(root, execution, metadata):
            continue
        candidates.append(execution)

    resolutions: list[dict[str, Any]] = []
    for execution in candidates:
        preserved_identity = _preserved_evidence_identity(execution)
        if preserved_identity is not None:
            exact = hmac.compare_digest(
                canonical_json(preserved_identity), canonical_json(incoming_identity)
            )
        else:
            prior_verdict = execution.get("verdict")
            exact = isinstance(prior_verdict, dict) and str(
                prior_verdict.get("verdict") or ""
            ) == str(verdict.verdict)
        if exact:
            _verify_execution_retention(root, execution)
            return "already-recorded", execution
        if (
            str(execution.get("status") or "") == "indeterminate"
            and str(verdict.verdict)
            in {"accepted", "already-accepted", "rejected"}
        ):
            resolutions.append(execution)
    if len(resolutions) == 1:
        return "resolve", resolutions[0]
    if candidates:
        return "quarantine", None
    return "new", None


def _terminal_for_proposal(
    current: dict[str, Any], proposal_id: str
) -> list[dict[str, Any]]:
    return [
        execution
        for execution in current.get("executions", {}).values()
        if str(execution.get("proposal_id") or "") == proposal_id
        and str(execution.get("status") or "") in TERMINAL_EXECUTION_STATES
    ]


def _admitted_execution_claim(
    store: EventStore, proposal: dict[str, Any]
) -> dict[str, Any] | None:
    """Find the one durable, canonical, independently authorized plan claim."""

    proposal_id = str(proposal.get("proposal_id") or "")
    if not proposal_id:
        return None
    events = store.events()
    plan_events: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        if event["event_type"] != "execution.planned":
            continue
        plan_id = str(event["payload"].get("plan_id") or "")
        if plan_id:
            plan_events.setdefault(plan_id, []).append(event)
    review_events = {
        str(event["event_id"]): event
        for event in events
        if event["event_type"] == "review.recorded"
        and isinstance(event.get("payload"), dict)
    }
    starts = [
        event
        for event in events
        if event["event_type"] == "execution.started"
        and str(event["payload"].get("proposal_id") or "") == proposal_id
    ]
    valid: list[dict[str, Any]] = []
    for start in starts:
        start_payload = start["payload"]
        plan_id = str(start_payload.get("plan_id") or "")
        plan_records = plan_events.get(plan_id, [])
        if len(plan_records) != 1:
            continue
        plan_event = plan_records[0]
        plan = plan_event["payload"]
        predicates = plan.get("predicates")
        envelope = plan.get("envelope")
        if not isinstance(predicates, dict) or not isinstance(envelope, dict):
            continue
        review_event_id = str(predicates.get("review_event_id") or "")
        review_event = review_events.get(review_event_id)
        review = review_event.get("payload", {}) if review_event else {}
        if (
            str(plan.get("proposal_id") or "") != proposal_id
            or str(plan.get("objective_id") or "")
            != str(proposal.get("objective_id") or "")
            or str(plan.get("semantic_action") or "")
            != str(proposal.get("action_kind") or "")
            or str(plan.get("adapter_id") or "")
            != str(proposal.get("adapter_id") or "")
            or canonical_json(envelope.get("attempt_scope", {}))
            != canonical_json(proposal.get("attempt_scope", {}))
            or str(start_payload.get("objective_id") or "")
            != str(proposal.get("objective_id") or "")
            or str(start_payload.get("action_kind") or "")
            != str(proposal.get("action_kind") or "")
        ):
            continue
        if (
            int(plan.get("generation", -1)) != int(start["generation"])
            or int(start_payload.get("stop_generation", -1))
            != int(start["generation"])
            or int(plan.get("policy_generation", -1))
            != int(start_payload.get("policy_generation", -2))
            or int(start_payload.get("scope_generation", -1))
            != int(predicates.get("scope_generation", -2))
            or str(predicates.get("proposal_event_id") or "")
            != str(proposal.get("event_id") or "")
            or not review_event_id
            or review_event is None
            or int(review_event["seq"]) >= int(plan_event["seq"])
            or int(plan_event["seq"]) >= int(start["seq"])
            or int(review_event["generation"]) != int(plan_event["generation"])
            or review.get("proposal_id") != proposal_id
            or review.get("verdict") != "approved"
            or int(review.get("stop_generation", -1))
            != int(plan.get("generation", -2))
            or int(review.get("policy_generation", -1))
            != int(plan.get("policy_generation", -2))
            or str(start_payload.get("review_event_id") or "")
            != review_event_id
        ):
            continue
        authorization_id = str(predicates.get("authorization_id") or "")
        if str(proposal.get("action_kind") or "") == "no_submit_evidence":
            if authorization_id or str(start_payload.get("authorization_id") or ""):
                continue
        else:
            consumptions = [
                event
                for event in events
                if event["event_type"] == "authorization.consumed"
                and str(event["payload"].get("consumed_for_plan") or "") == plan_id
            ]
            if (
                len(consumptions) != 1
                or not authorization_id
                or str(start_payload.get("authorization_id") or "")
                != authorization_id
                or str(consumptions[0]["payload"].get("authorization_id") or "")
                != authorization_id
                or int(consumptions[0]["generation"]) != int(start["generation"])
            ):
                continue
        valid.append(start)
    return valid[0] if len(valid) == 1 else None


def _import_response_locked(
    store: EventStore,
    root: Path,
    metadata: dict[str, Any],
    verdict: Any,
    response_evidence: ContainedEvidence,
    request_evidence: ContainedEvidence | None,
    *,
    include_unbound: bool = False,
    actor: str = "reconciler",
) -> dict[str, Any]:
    projection = store.rebuild()
    current = projection["current"]
    evidence_decision, recorded = _terminal_evidence_decision(
        root, current, metadata, verdict
    )
    if evidence_decision == "already-recorded" and recorded is not None:
        return {
            "status": "already-recorded",
            "reason": "exact evidence already has a canonical terminal execution",
            "response_path": metadata["response_path"],
            "verdict": _safe_verdict(verdict),
            # Preserve the legacy repeat-import label while exposing the
            # stronger cross-path evidence decision through `status`.
            "import_status": (
                "already-imported" if recorded.get("imported") else "already-recorded"
            ),
        }
    if evidence_decision == "quarantine":
        return _record_observation(
            store,
            metadata,
            verdict,
            reason="changed evidence contradicts a canonical terminal execution",
            actor=actor,
        )
    proposals = current.get("proposals", {})
    proposal, link_reason = _match_proposal(proposals, metadata)
    has_platform_tuple = bool(
        metadata["objective_id"]
        and (metadata["candidate"] or metadata["artifact_digest"])
    )
    if proposal is None:
        if (
            metadata["proposal_id"]
            or metadata["conflict"]
            or has_platform_tuple
            or include_unbound
        ):
            return _record_observation(
                store, metadata, verdict, reason=link_reason, actor=actor
            )
        return {
            "status": "skipped",
            "reason": "unbound response artifact",
            "response_path": metadata["response_path"],
            "verdict": _safe_verdict(verdict),
        }
    proposal_id = str(proposal["proposal_id"])
    admitted_claim = _admitted_execution_claim(store, proposal)
    if admitted_claim is None:
        return _record_observation(
            store,
            metadata,
            verdict,
            reason="canonical authorized execution claim is unavailable",
            actor=actor,
        )
    if current.get("stopped") and int(admitted_claim["generation"]) >= int(
        current.get("stop_generation") or 0
    ):
        return _record_observation(
            store,
            metadata,
            verdict,
            reason="workspace stopped without a pre-stop durable execution claim",
            actor=actor,
        )
    existing_terminals = _terminal_for_proposal(current, proposal_id)
    if existing_terminals and not (
        evidence_decision == "resolve"
        and recorded is not None
        and any(
            str(terminal.get("plan_id") or "")
            == str(recorded.get("plan_id") or "")
            for terminal in existing_terminals
        )
    ):
        return _record_observation(
            store,
            metadata,
            verdict,
            reason="canonical proposal already has a terminal execution",
            actor=actor,
        )
    if evidence_decision == "resolve" and (
        recorded is None
        or str(recorded.get("proposal_id") or "")
        != str(proposal.get("proposal_id") or "")
    ):
        return _record_observation(
            store,
            metadata,
            verdict,
            reason="changed evidence does not match the canonical terminal proposal",
            actor=actor,
        )
    digest = _import_digest(metadata)
    resolving_terminal = True
    plan_id = str(admitted_claim["payload"]["plan_id"])
    if not plan_id:
        return _record_observation(
            store,
            metadata,
            verdict,
            reason="canonical terminal plan identifier is unavailable",
            actor=actor,
        )
    if verdict.verdict in {"accepted", "already-accepted"}:
        status = "completed"
    elif verdict.verdict == "rejected":
        status = "rejected"
    elif verdict.verdict in {"auth_blocked", "blocked-by-auth"}:
        # An explicit authentication gate proves this request was not scored.
        status = "blocked"
    else:
        # A bound response that lacks positive scorer truth could have applied
        # remotely; it must never become queue-eligible.
        status = "indeterminate"
    retained, retained_provenance = _retain_import_evidence(
        root, response_evidence, request_evidence
    )
    retained_response = retained["response"]
    retained_request = retained["request"]
    if retained_response is None:  # pragma: no cover - response evidence is required.
        raise ContainedEvidenceError("retained response evidence is unavailable")
    payload = {
        "plan_id": plan_id,
        "proposal_id": proposal_id,
        "objective_id": str(proposal.get("objective_id") or "unknown"),
        "action_kind": str(proposal.get("action_kind") or "unknown"),
        "adapter_id": str(proposal.get("adapter_id") or "unknown"),
        "status": status,
        "verdict": _safe_verdict(verdict),
        "response_path": retained_response.relative_path,
        "request_path": retained_request.relative_path if retained_request else "",
        "evidence_root": str(Path(retained_response.relative_path).parent),
        "evidence_paths": [
            item
            for item in (
                retained_response.relative_path,
                retained_request.relative_path if retained_request else "",
            )
            if item
        ],
        "evidence_provenance": retained_provenance,
        "source_evidence_identity": _source_evidence_identity(metadata),
        "exact_value": str(proposal.get("exact_value") or ""),
        "artifact_reference": str(proposal.get("artifact_reference") or ""),
        "attempt_scope": dict(proposal.get("attempt_scope") or {}),
        "execution_start_generation": int(admitted_claim["generation"]),
        "stop_generation": int(current.get("stop_generation") or 0),
        "policy_generation": int(
            admitted_claim["payload"].get("policy_generation", -1)
        ),
        "imported_at": iso_now(),
        "imported": not resolving_terminal,
        "reconciled": resolving_terminal,
    }
    if status in {"rejected", "indeterminate"}:
        payload["retry"] = terminal_retry_metadata(
            payload,
            proposal,
            _safe_verdict(verdict),
            terminal_state=status,
        )
        if status == "rejected":
            payload["rejection"] = payload["retry"]
    event_id = (
        "execution-reconcile-"
        + sha256_bytes(f"{plan_id}\0{digest}".encode("utf-8"))[:32]
        if resolving_terminal
        else f"execution-import-{digest}"
    )
    objective = payload["objective_id"]
    challenge = {
        "id": objective,
        "last_scorer_verdict": verdict.verdict,
        "last_scorer_response": retained_response.relative_path,
        "reconciled_plan_id": plan_id,
        "reconciliation_evidence": retained_provenance,
        "updated_at": iso_now(),
    }
    if verdict.verdict in {"accepted", "already-accepted"}:
        challenge.update({"solved": True, "classification": "solved"})
    results = store.append_many(
        [
            {
                "event_type": f"execution.{status}",
                "payload": payload,
                "event_id": event_id,
            },
            {
                "event_type": "challenge.upsert",
                "payload": challenge,
                "event_id": f"challenge-reconcile-{digest}",
            },
        ],
        actor=actor,
    )
    inserted = results[0][1]
    store.rebuild()
    return {
        **payload,
        "import_status": (
            "reconciled"
            if resolving_terminal and inserted
            else "already-reconciled"
            if resolving_terminal
            else "imported"
            if inserted
            else "already-imported"
        ),
    }


def import_response(
    store: EventStore,
    root: Path,
    path: Path,
    *,
    include_unbound: bool = False,
    actor: str = "reconciler",
) -> dict[str, Any]:
    """Reconcile one bounded response under the workspace mutation barrier."""

    root = Path(os.path.abspath(os.fspath(root)))
    metadata, verdict, response_evidence, request_evidence = _metadata_from_response(
        root, path
    )
    with file_lock(root / "state" / "mutation.lock"):
        # The pre-lock descriptor read fixes the exact evidence bytes.  Every
        # authority decision and its atomic canonical append are then made from
        # one serialized current state, so a second artifact cannot win an
        # independent terminal race for the same proposal.
        return _import_response_locked(
            store,
            root,
            metadata,
            verdict,
            response_evidence,
            request_evidence,
            include_unbound=include_unbound,
            actor=actor,
        )


def response_candidates(root: Path) -> list[Path]:
    patterns = (
        "submissions/**/response*.json",
        "submissions/**/result*.json",
        "evidence/**/submission/**/response*.json",
        "evidence/**/submissions/**/response*.json",
    )
    root = Path(os.path.abspath(os.fspath(root)))
    out: dict[str, Path] = {}
    for pattern in patterns:
        for path in root.glob(pattern):
            try:
                os.lstat(path)
            except FileNotFoundError:
                continue
            # Let the descriptor reader reject links and special files rather
            # than silently dropping an apparent response artifact.
            out[contained_relative_path(root, path)] = path
    return [out[key] for key in sorted(out)]


def reconcile_all(
    store: EventStore, root: Path, *, include_unbound: bool = False
) -> dict[str, Any]:
    rows = [
        import_response(store, root, path, include_unbound=include_unbound)
        for path in response_candidates(root)
    ]
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    return {"count": len(rows), "counts": counts, "rows": rows}


def answer_ledger(
    store: EventStore, *, include_unknown: bool = False
) -> dict[str, Any]:
    projection = store.rebuild()
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for event in projection.get("scoring_events", []):
        if event.get("class") != "scorer_truth":
            continue
        verdict_obj = (
            event.get("verdict", {}) if isinstance(event.get("verdict"), dict) else {}
        )
        verdict = str(verdict_obj.get("verdict") or event.get("state") or "unknown")
        if not include_unknown and verdict in {
            "unknown",
            "non_scoring",
            "transport_error",
        }:
            continue
        key = (
            str(event.get("proposal_id") or ""),
            str(event.get("response_path") or ""),
            str(event.get("plan_id") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            {
                "objective_id": str(event.get("objective_id") or "unknown"),
                "proposal_id": str(event.get("proposal_id") or ""),
                "plan_id": str(event.get("plan_id") or ""),
                "action_kind": str(event.get("action_kind") or "unknown"),
                "verdict": verdict,
                "ledger_state": ledger_state(verdict),
                "response_path": str(event.get("response_path") or ""),
                "request_path": str(event.get("request_path") or ""),
                "exact_value": str(event.get("exact_value") or ""),
                "event_id": str(event.get("event_id") or ""),
                "event_at": str(event.get("event_at") or ""),
            }
        )
    rows.sort(key=lambda row: (row["event_at"], row["objective_id"], row["plan_id"]))
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["ledger_state"]] = counts.get(row["ledger_state"], 0) + 1
    return {"rows": rows, "counts": counts, "count": len(rows)}


def correlation_ledger(store: EventStore) -> dict[str, Any]:
    """Materialize the privacy-safe proposal-to-terminal decision chain."""

    projection = store.rebuild()
    current = projection["current"]
    authorization_events: dict[str, dict[str, Any]] = {}
    start_events: dict[str, dict[str, Any]] = {}
    for event in store.events():
        payload = event["payload"]
        plan_id = str(payload.get("consumed_for_plan") or payload.get("plan_id") or "")
        if not plan_id:
            continue
        if event["event_type"] == "authorization.consumed":
            authorization_events[plan_id] = {
                "event_id": event["event_id"],
                "authorization_id": str(payload.get("authorization_id") or ""),
                "event_at": event["created_at"],
            }
        elif event["event_type"] == "execution.started":
            start_events[plan_id] = {
                "event_id": event["event_id"],
                "event_at": event["created_at"],
            }

    rows: list[dict[str, Any]] = []
    terminal_statuses = {
        "completed",
        "rejected",
        "indeterminate",
        "blocked",
        "failed",
    }
    for proposal_id, proposal in sorted(
        current.get("proposals", {}).items(),
        key=lambda item: (str(item[1].get("event_at") or ""), item[0]),
    ):
        review = current.get("reviews", {}).get(proposal_id, {})
        plans = [
            execution
            for execution in current.get("executions", {}).values()
            if str(execution.get("proposal_id") or "") == proposal_id
        ]
        plan_rows = []
        for plan in sorted(
            plans,
            key=lambda item: (str(item.get("created_at") or item.get("event_at") or ""), str(item.get("plan_id") or "")),
        ):
            plan_id = str(plan.get("plan_id") or "")
            authorization = authorization_events.get(plan_id, {})
            started = start_events.get(plan_id, {})
            status = str(plan.get("status") or "planned")
            plan_rows.append(
                {
                    "plan_id": plan_id,
                    "plan_sha256": str(plan.get("plan_sha256") or ""),
                    "status": status,
                    "authorization_id": str(
                        authorization.get("authorization_id")
                        or plan.get("predicates", {}).get("authorization_id")
                        or ""
                    ),
                    "authorization_event_id": str(
                        authorization.get("event_id") or ""
                    ),
                    "started_event_id": str(started.get("event_id") or ""),
                    "verdict": str(
                        plan.get("verdict", {}).get("verdict")
                        if isinstance(plan.get("verdict"), dict)
                        else "unknown"
                    ),
                    "response_path": str(plan.get("response_path") or ""),
                    "evidence_root": str(plan.get("evidence_root") or ""),
                    "evidence_paths": [
                        str(path) for path in plan.get("evidence_paths", [])
                    ]
                    if isinstance(plan.get("evidence_paths", []), list)
                    else [],
                    "rejection_fingerprint": str(
                        plan.get("rejection", {}).get("fingerprint")
                        if isinstance(plan.get("rejection"), dict)
                        else ""
                    ),
                    "complete_chain": bool(
                        review.get("verdict") == "approved"
                        and authorization.get("event_id")
                        and started.get("event_id")
                        and status in terminal_statuses
                    ),
                }
            )
        rows.append(
            {
                "proposal_id": proposal_id,
                "objective_id": str(proposal.get("objective_id") or ""),
                "action_kind": str(proposal.get("action_kind") or "unknown"),
                "agent_attempt_id": str(proposal.get("agent_attempt_id") or ""),
                "value_sha256": str(proposal.get("value_sha256") or ""),
                "proposal_event_id": str(proposal.get("event_id") or ""),
                "review_event_id": str(review.get("event_id") or ""),
                "review_verdict": str(review.get("verdict") or "pending"),
                "verifier_report": str(review.get("verifier_report") or ""),
                "parent_rejection_fingerprint": str(
                    proposal.get("parent_rejection_fingerprint") or ""
                ),
                "discriminator": str(proposal.get("discriminator") or ""),
                "plans": plan_rows,
            }
        )
    plan_rows = [plan for row in rows for plan in row["plans"]]
    return {
        "schema_version": "1",
        "count": len(rows),
        "counts": {
            "proposals": len(rows),
            "reviewed": sum(1 for row in rows if row["review_event_id"]),
            "planned": sum(1 for row in rows if row["plans"]),
            "plans": len(plan_rows),
            "complete_chains": sum(
                1 for plan in plan_rows if plan["complete_chain"]
            ),
            "terminal_plans": sum(
                1 for plan in plan_rows if plan["status"] in terminal_statuses
            ),
        },
        "rows": rows,
    }


def record_task_completion(
    store: EventStore,
    *,
    plan_id: str,
    actor: str = "reviewer",
) -> dict[str, Any]:
    # Import lazily: completion reuses this module's durable admission helper.
    from .completion import resolve_canonical_plan_completion

    resolution = resolve_canonical_plan_completion(store, plan_id=plan_id)
    if resolution.get("state") != "accepted":
        raise ValueError(
            "task completion requires canonical accepted scorer truth: "
            + str(resolution.get("reason") or "completion resolution failed")
        )
    objective_id = resolution.get("objective_id")
    attempt_scope = resolution.get("attempt_scope")
    evidence_path = resolution.get("terminal_evidence_path")
    if (
        not isinstance(objective_id, str)
        or not objective_id
        or not isinstance(attempt_scope, dict)
        or not isinstance(evidence_path, str)
        or not evidence_path
    ):
        raise ValueError("accepted completion lacks canonical terminal evidence")
    payload = {
        "completion_id": "completion_"
        + hashlib.sha256(
            canonical_json(
                {
                    "plan_id": plan_id,
                    "objective_id": objective_id,
                    "attempt_scope": attempt_scope,
                    "evidence_path": evidence_path,
                }
            ).encode()
        ).hexdigest()[:24],
        "plan_id": plan_id,
        "objective_id": str(objective_id),
        "attempt_scope": dict(attempt_scope),
        "evidence_path": evidence_path,
        "completed_at": iso_now(),
    }
    store.append(
        "task.completed", payload, actor=actor, event_id=payload["completion_id"]
    )
    store.rebuild()
    return payload


def task_completion_audit(store: EventStore) -> dict[str, Any]:
    # Import lazily: completion reuses this module's durable admission helper.
    from .completion import resolve_canonical_plan_completion

    projection = store.rebuild()
    completions = projection["current"].get("task_completions", {})
    accepted: dict[str, dict[str, Any]] = {}
    for event in store.events("execution.completed"):
        payload = event.get("payload")
        if not isinstance(payload, dict):
            continue
        plan_id = payload.get("plan_id")
        if not isinstance(plan_id, str) or not plan_id:
            continue
        resolution = resolve_canonical_plan_completion(store, plan_id=plan_id)
        if resolution.get("state") == "accepted":
            accepted[plan_id] = resolution

    valid_by_plan: dict[str, list[dict[str, Any]]] = {}
    invalid_records: list[dict[str, str]] = []
    for completion_id, row in completions.items():
        if not isinstance(row, dict):
            invalid_records.append(
                {"completion_id": str(completion_id), "reason": "malformed completion"}
            )
            continue
        plan_id = row.get("plan_id")
        if not isinstance(plan_id, str) or not plan_id:
            invalid_records.append(
                {"completion_id": str(completion_id), "reason": "orphan completion plan"}
            )
            continue
        resolution = accepted.get(plan_id)
        if resolution is None:
            invalid_records.append(
                {
                    "completion_id": str(completion_id),
                    "reason": "completion plan lacks accepted scorer truth",
                }
            )
            continue
        if (
            row.get("objective_id") != resolution.get("objective_id")
            or row.get("attempt_scope") != resolution.get("attempt_scope")
            or row.get("evidence_path") != resolution.get("terminal_evidence_path")
        ):
            invalid_records.append(
                {
                    "completion_id": str(completion_id),
                    "reason": "completion does not match canonical plan evidence",
                }
            )
            continue
        valid_by_plan.setdefault(plan_id, []).append(row)

    for plan_id, rows in valid_by_plan.items():
        if len(rows) > 1:
            for row in rows:
                invalid_records.append(
                    {
                        "completion_id": str(row.get("completion_id") or ""),
                        "reason": "completion plan has duplicate records",
                    }
                )

    open_rows = []
    for plan_id, resolution in accepted.items():
        scope = resolution.get("attempt_scope")
        if not isinstance(scope, dict) or not scope:
            continue
        matched = len(valid_by_plan.get(plan_id, [])) == 1
        if not matched:
            open_rows.append(
                {
                    "objective_id": str(resolution.get("objective_id") or ""),
                    "plan_id": plan_id,
                    "response_path": str(
                        resolution.get("terminal_evidence_path") or ""
                    ),
                    "attempt_scope": scope,
                    "reason": "accepted scoring action has no matching task/lab completion event",
                }
            )
    return {
        "accepted_dynamic_actions": sum(
            1
            for resolution in accepted.values()
            if isinstance(resolution.get("attempt_scope"), dict)
            and bool(resolution["attempt_scope"])
        ),
        "completion_records": len(completions),
        "needs_completion_check": open_rows,
        "invalid_completion_records": invalid_records,
        "ok": not open_rows and not invalid_records,
    }
