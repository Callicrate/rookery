from __future__ import annotations

import base64
import binascii
import json
import re
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rookery.portable.adapters import (
    Adapter,
    CapabilityHealth,
    capture_file as capture_adapter_file,
    normalized_snapshot,
)
from rookery.portable.browser_gateway_policy import (
    BrowserGatewayPolicyError,
    browser_gateway_origin,
    compile_browser_gateway_policy,
    policy_sha256,
    resolve_browser_gateway_policy,
    scope_sha256,
)
from rookery.portable.browser_ui_cdp import (
    BrowserUiCdpChannel,
    BrowserUiCdpError,
    OwnedBrowserTarget,
    deadline_after,
    open_owned_browser_target,
)
from rookery.portable.environment import (
    BrowserGatewayReadiness,
    ChildEnvironment,
    EnvClass,
    EnvKey,
    EnvSource,
    EnvironmentPolicyError,
    resolve_browser_gateway_endpoint,
    verify_browser_cdp_endpoint,
    verify_browser_gateway_endpoint,
    verify_launch_binding_integrity,
)
from rookery.portable.network_policy import ExplicitNetworkPolicy
from rookery.portable.scope import open_scoped_url
from rookery.portable.util import atomic_write_json, ensure_private_dir, iso_now
from rookery.verdict_parser import parse_verdict


_EVENT_ID = re.compile(r"[1-9][0-9]{0,15}\Z")
_CHALLENGE_ID = re.compile(r"[1-9][0-9]{0,15}\Z")
_CATEGORY_MAP = {
    "binary exploitation": "pwn",
    "binex": "pwn",
    "crypto": "crypto",
    "cryptography": "crypto",
    "cyber": "misc",
    "foren": "forensics",
    "forensics": "forensics",
    "misc": "misc",
    "miscellaneous": "misc",
    "osint": "advanced-research",
    "pcap": "forensics",
    "pwn": "pwn",
    "recon": "advanced-research",
    "reverse": "rev",
    "reverse engineering": "rev",
    "reven": "rev",
    "trivia": "misc",
    "web": "web",
    "web exploitation": "web",
    "webex": "web",
}
_MAX_CHALLENGES = 512
_INVENTORY_PAGE_SIZE = 32
_MAX_CANDIDATE_BYTES = 16 * 1024
_MAX_DETAIL_TEXT_BYTES = 32 * 1024
_MAX_DETAIL_HTML_BYTES = 48 * 1024
_MAX_DETAIL_METADATA_BYTES = 16 * 1024
_MAX_RESOURCE_URL_BYTES = 4 * 1024
_MAX_RESOURCES = 32
_MAX_GATEWAY_STATUS_BYTES = 64 * 1024
_MAX_TITLE_BYTES = 1024
_MAX_CATEGORY_BYTES = 256
_ATTACHMENT_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~-]{0,511}\Z")
_COOKIE_NAME = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,256}\Z")
_PUBLIC_FILE_ORIGINS = frozenset(
    {
        "https://cfstatic.mctf.io",
        "https://cyberlabhost.com",
        "https://metactf-problems.s3.us-east-1.amazonaws.com",
        "https://metachallenge-artifacts-158909019700-us-east-1-an.s3.amazonaws.com",
        "https://metaproblems.com",
        "https://static.metaproblems.com",
    }
)
_PUBLIC_FILE_SUFFIXES = frozenset(
    {
        ".2", ".6", ".apk", ".cf32", ".csv", ".docx", ".enc", ".exe",
        ".g", ".gif", ".html", ".img", ".java", ".jpg", ".jpeg", ".log",
        ".pcap", ".pcapng", ".pdf", ".png", ".py", ".sqlite", ".txt",
        ".wav", ".xpng", ".zip",
    }
)


_PAGE_STATE_FUNCTION = r"""function(loginOrigin, platformOrigin, eventId, expectedUser) {
  const safeLocation = location.origin + location.pathname;
  if (location.origin === loginOrigin && location.pathname === '/login') {
    const form = document.querySelector('#login_form');
    const email = document.querySelector('#email_input[type="email"]');
    const password = document.querySelector('#password_input[type="password"]');
    const button = document.querySelector('#login_page_button[type="submit"]');
    return {kind: form && email && password && button ? 'login' : 'interaction_required', url: safeLocation};
  }
  if (location.origin === loginOrigin && (location.pathname === '/' || location.pathname === '/dashboard')) {
    const identityMatches = expectedUser
      ? Array.from(document.querySelectorAll('b')).filter((node) => (node.textContent || '').trim() === expectedUser)
      : [];
    const identityMatched = expectedUser ? identityMatches.length === 1 : null;
    if (expectedUser && identityMatches.length === 0) {
      return {kind: 'dashboard_loading', url: safeLocation, identityMatched: false};
    }
    if (identityMatches.length > 1) {
      return {kind: 'identity_mismatch', url: safeLocation, identityMatched: false};
    }
    const cardId = 'contest_card_' + eventId;
    const cards = Array.from(document.querySelectorAll('[id="' + cardId + '"]'));
    if (cards.length === 0) {
      if (document.readyState !== 'complete') {
        return {kind: 'dashboard_loading', url: safeLocation};
      }
      return {kind: 'registration_required', url: safeLocation, registration: 'missing'};
    }
    if (cards.length !== 1) {
      return {kind: 'event_ambiguous', url: safeLocation, registration: 'ambiguous'};
    }
    const prefix = platformOrigin + '/' + eventId + '/';
    const links = Array.from(cards[0].querySelectorAll('a[href]'))
      .map((node) => node.href)
      .filter((href) => href.startsWith(prefix));
    const unique = Array.from(new Set(links));
    if (unique.length === 0) {
      return {kind: 'registration_required', url: safeLocation, registration: 'unverifiable'};
    }
    if (unique.length !== 1) {
      return {kind: 'event_ambiguous', url: safeLocation, registration: 'ambiguous'};
    }
    return {
      kind: 'dashboard',
      url: safeLocation,
      identityMatched,
      registration: 'registered',
      handoffCount: unique.length,
      handoff: unique[0]
    };
  }
  const eventRoot = '/' + eventId + '/';
  if (location.origin === platformOrigin && location.pathname === eventRoot) {
    return {kind: 'event', url: safeLocation};
  }
  if (location.origin === platformOrigin && location.pathname === eventRoot + 'problems') {
    const registry = typeof problems === 'object' && problems !== null && typeof problems.get === 'function';
    const ready = registry && Array.isArray(problems.problem_ids) && problems.problem_ids.length > 0;
    return {kind: ready ? 'problems' : (registry ? 'problems_loading' : 'interaction_required'), url: safeLocation};
  }
  return {kind: 'unexpected', url: safeLocation};
}"""


_LOGIN_FUNCTION = r"""function(emailValue, passwordValue) {
  const form = document.querySelector('#login_form');
  const email = document.querySelector('#email_input[type="email"]');
  const password = document.querySelector('#password_input[type="password"]');
  const button = document.querySelector('#login_page_button[type="submit"]');
  if (!form || !email || !password || !button) return false;
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
  if (typeof setter !== 'function') return false;
  setter.call(email, emailValue);
  email.dispatchEvent(new Event('input', {bubbles: true}));
  email.dispatchEvent(new Event('change', {bubbles: true}));
  setter.call(password, passwordValue);
  password.dispatchEvent(new Event('input', {bubbles: true}));
  password.dispatchEvent(new Event('change', {bubbles: true}));
  if (email.value !== emailValue || password.value !== passwordValue) return false;
  button.click();
  return true;
}"""


_INVENTORY_FUNCTION = r"""function(platformOrigin, eventId, maximum, offset, pageSize) {
  if (location.origin !== platformOrigin || location.pathname !== '/' + eventId + '/problems') {
    return {ok: false, reason: 'route'};
  }
  if (typeof problems !== 'object' || problems === null || typeof problems.get !== 'function') {
    return {ok: false, reason: 'registry'};
  }
  if (!Array.isArray(problems.problem_ids)) return {ok: false, reason: 'registry_ids'};
  const ids = problems.problem_ids.map((value) => String(value));
  const unique = Array.from(new Set(ids));
  if (!unique.length || unique.length !== ids.length || unique.length > maximum) {
    return {ok: false, reason: 'ids'};
  }
  if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize > 64) {
    return {ok: false, reason: 'page'};
  }
  const rows = [];
  for (const rawId of unique.slice(offset, offset + pageSize)) {
    if (!/^[1-9][0-9]{0,15}$/.test(rawId)) return {ok: false, reason: 'id'};
    const numericId = Number(rawId);
    const problem = problems.get(numericId);
    const detail = problem && problem.p;
    if (!problem || !detail || Number(problem.id) !== numericId || Number(detail.id) !== numericId) {
      return {ok: false, reason: 'binding'};
    }
    const title = typeof detail.title === 'string' ? detail.title.trim() : '';
    const category = typeof detail.category === 'string' ? detail.category.trim() : '';
    const points = Number(detail.points);
    if (!title || !category || !Number.isSafeInteger(points) || points < 0 || points > 1000000) {
      return {ok: false, reason: 'fields'};
    }
    const solved = problem.solved === true;
    const platformSubmittable = detail.submittable !== false && detail.submittable !== 0 && detail.submittable !== '0';
    const solvable = detail.solvable !== false && detail.solvable !== 0 && detail.solvable !== '0';
    const manualGrade = detail.manual_grade === true || Number(detail.manual_grade) > 0;
    const input = document.querySelector('#inp' + rawId);
    const form = document.querySelector('#form' + rawId + ' form');
    let submissionMode = 'unsupported';
    if (solved) submissionMode = 'already_solved';
    else if (!solvable || !platformSubmittable) submissionMode = 'locked';
    else if (manualGrade) submissionMode = 'manual';
    else if (input && input.tagName === 'INPUT' && input.type === 'text' && form && typeof problem.submit === 'function') submissionMode = 'text';
    else if (document.querySelector('#form' + rawId + ' select, #form' + rawId + ' input[type="radio"], #form' + rawId + ' input[type="checkbox"]')) submissionMode = 'multiple_choice';
    rows.push({
      id: rawId,
      title,
      category,
      points,
      solved,
      hidden: problem.hidden === true,
      recorded: problem.recorded === true,
      solvable,
      platformSubmittable,
      submissionMode,
      submittable: submissionMode === 'text'
    });
  }
  return {ok: true, total: unique.length, challenges: rows};
}"""


_DETAIL_FUNCTION = r"""function(platformOrigin, eventId, challengeId, maximumText, maximumHtml, maximumResources) {
  if (location.origin !== platformOrigin || location.pathname !== '/' + eventId + '/problems') {
    return {ok: false, reason: 'route'};
  }
  if (typeof problems !== 'object' || problems === null || typeof problems.get !== 'function') {
    return {ok: false, reason: 'registry'};
  }
  if (!Number.isSafeInteger(challengeId) || challengeId < 1 || challengeId > Number.MAX_SAFE_INTEGER) {
    return {ok: false, reason: 'id'};
  }
  const problem = problems.get(challengeId);
  const detail = problem && problem.p;
  if (!problem || !detail || Number(problem.id) !== challengeId || Number(detail.id) !== challengeId) {
    return {ok: false, reason: 'binding'};
  }
  const clipped = (value, maximum) => typeof value === 'string' ? value.slice(0, maximum) : '';
  const sourceHtml = [detail.description, detail.extra_description]
    .filter((value) => typeof value === 'string')
    .join('\n');
  const parsed = new DOMParser().parseFromString(sourceHtml, 'text/html');
  const text = clipped(parsed.body?.textContent || '', maximumText);
  const html = clipped(sourceHtml, maximumHtml);
  const bounded = (value, depth = 0) => {
    if (typeof value === 'string') return clipped(value, 1024);
    if (typeof value === 'boolean') return value;
    if (typeof value === 'number' && Number.isFinite(value)) return value;
    if (Array.isArray(value) && depth < 2) return value.slice(0, 16).map((item) => bounded(item, depth + 1)).filter((item) => item !== null);
    if (value && typeof value === 'object' && depth < 2) {
      const out = {};
      for (const [key, item] of Object.entries(value).slice(0, 16)) {
        if (key.length <= 128) {
          const normalized = bounded(item, depth + 1);
          if (normalized !== null) out[key] = normalized;
        }
      }
      return out;
    }
    return null;
  };
  const field = (...names) => {
    for (const name of names) if (Object.prototype.hasOwnProperty.call(detail, name)) return bounded(detail[name]);
    return null;
  };
  const resources = [];
  const publicFileOrigins = new Set([
    'https://cfstatic.mctf.io',
    'https://metachallenge-artifacts-158909019700-us-east-1-an.s3.amazonaws.com',
    'https://metactf-problems.s3.us-east-1.amazonaws.com',
    'https://static.metaproblems.com',
    'https://metaproblems.com',
    'https://cyberlabhost.com'
  ]);
  const fileExtension = /\.(?:2|6|apk|cf32|csv|docx|enc|exe|g|gif|html|img|java|jpg|jpeg|log|pcap|pcapng|pdf|png|py|sqlite|txt|wav|xpng|zip)$/i;
  const nodes = Array.from(parsed.querySelectorAll('a[href], img[src], source[src], audio[src], video[src]'));
  for (const node of nodes.slice(0, maximumResources)) {
    const attribute = node.hasAttribute('href') ? 'href' : 'src';
    const rawLocation = node.getAttribute(attribute) || '';
    let resolved;
    try { resolved = new URL(rawLocation, location.href); } catch (_) { continue; }
    if ((resolved.protocol !== 'https:' && resolved.protocol !== 'http:') || resolved.href.length > 4096) continue;
    const pathParts = resolved.pathname.split('/').filter((part) => part.length > 0);
    let decodedParts = [];
    try { decodedParts = pathParts.map((part) => decodeURIComponent(part)); } catch (_) { decodedParts = []; }
    const safeParts = decodedParts.length === pathParts.length && decodedParts.every((part) =>
      part && part !== '.' && part !== '..' && !part.includes('/') && !part.includes('\\') && !/[\u0000-\u001f\u007f]/.test(part)
    );
    const authenticatedFile = node.tagName === 'A'
      && node.classList.contains('mctf-s3dl')
      && rawLocation.startsWith('/')
      && !rawLocation.startsWith('//')
      && resolved.protocol === 'https:'
      && resolved.origin === platformOrigin
      && !resolved.search
      && !resolved.hash
      && safeParts
      && decodedParts.length === 5
      && decodedParts[0] === eventId
      && decodedParts[1] === 'api'
      && decodedParts[2] === 'attachments';
    const publicFile = !authenticatedFile
      && resolved.protocol === 'https:'
      && publicFileOrigins.has(resolved.origin)
      && (node.tagName === 'IMG' || fileExtension.test(resolved.pathname));
    const resourceName = decodedParts.at(-1) || resolved.pathname.split('/').pop() || 'resource';
    resources.push({
      url: resolved.href,
      name: clipped((node.textContent || node.getAttribute('alt') || resourceName).trim(), 512),
      kind: authenticatedFile ? 'authenticated_file' : (publicFile ? 'public_file' : 'link'),
      source: node.tagName.toLowerCase()
    });
  }
  const solved = problem.solved === true;
  const platformSubmittable = detail.submittable !== false && detail.submittable !== 0 && detail.submittable !== '0';
  const solvable = detail.solvable !== false && detail.solvable !== 0 && detail.solvable !== '0';
  const manualGrade = detail.manual_grade === true || Number(detail.manual_grade) > 0;
  const input = document.querySelector('#inp' + challengeId);
  const form = document.querySelector('#form' + challengeId + ' form');
  let submissionMode = 'unsupported';
  if (solved) submissionMode = 'already_solved';
  else if (!solvable || !platformSubmittable) submissionMode = 'locked';
  else if (manualGrade) submissionMode = 'manual';
  else if (input && input.tagName === 'INPUT' && input.type === 'text' && form && typeof problem.submit === 'function') submissionMode = 'text';
  else if (document.querySelector('#form' + challengeId + ' select, #form' + challengeId + ' input[type="radio"], #form' + challengeId + ' input[type="checkbox"]')) submissionMode = 'multiple_choice';
  return {
    ok: true,
    id: String(challengeId),
    description_text: text,
    description_html: html,
    submission_mode: submissionMode,
    platform_submittable: platformSubmittable,
    manual_grade: field('manual_grade', 'manual_grading', 'manualGrading', 'manual'),
    manual_grading: field('manual_grade', 'manual_grading', 'manualGrading', 'manual'),
    points_graded: field('points_graded', 'pointsGraded'),
    hints: field('hints', 'hint'),
    penalties: field('penalties', 'penalty', 'hint_penalty', 'hintPenalty'),
    ratings: field('ratings', 'rating'),
    tags: field('tags', 'tag'),
    solve_count: field('solve_count', 'solveCount', 'solves', 'num_solves'),
    solved_by: field('solved_by', 'solvedBy'),
    teammates_solved: field('teammates_solved', 'teammatesSolved'),
    resources_complete: nodes.length <= maximumResources,
    resources_truncated: nodes.length > maximumResources,
    resources
  };
}"""


_SET_CANDIDATE_FUNCTION = r"""function(challengeId, candidate, platformOrigin, eventId) {
  if (location.origin !== platformOrigin || location.pathname !== '/' + eventId + '/problems') {
    return {ok: false, reason: 'route'};
  }
  if (typeof problems !== 'object' || problems === null || typeof problems.get !== 'function') {
    return {ok: false, reason: 'runtime'};
  }
  const problem = problems.get(challengeId);
  const input = document.querySelector('#inp' + challengeId);
  if (!problem || !input || input.tagName !== 'INPUT' || input.type !== 'text') {
    return {ok: false, reason: 'binding'};
  }
  if (problem.solved === true) return {ok: true, alreadySolved: true};
  const source = String(problem.submit);
  for (const required of ['api/submit.php', 'data: {id: this.id, answer: submission}', 'type: "post"']) {
    if (!source.includes(required)) return {ok: false, reason: 'contract'};
  }
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
  if (typeof setter !== 'function') return {ok: false, reason: 'setter'};
  setter.call(input, candidate);
  input.dispatchEvent(new Event('input', {bubbles: true}));
  input.dispatchEvent(new Event('change', {bubbles: true}));
  return {ok: input.value === candidate, alreadySolved: false};
}"""

_TRIGGER_SUBMISSION_FUNCTION = r"""function(challengeId) {
  if (typeof problems !== 'object' || problems === null || typeof problems.get !== 'function') return false;
  const problem = problems.get(challengeId);
  if (!problem || problem.solved === true || typeof problem.submit !== 'function') return false;
  problem.submit();
  return true;
}"""

_CLEAR_CANDIDATE_FUNCTION = r"""function(challengeId) {
  const input = document.querySelector('#inp' + challengeId);
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
  if (!input || input.tagName !== 'INPUT' || input.type !== 'text' || typeof setter !== 'function') return false;
  setter.call(input, '');
  input.dispatchEvent(new Event('input', {bubbles: true}));
  input.dispatchEvent(new Event('change', {bubbles: true}));
  return input.value === '';
}"""


class _SkillBitSubmissionError(RuntimeError):
    """Value-free SkillBit submission failure with one commit boundary."""

    def __init__(
        self,
        reason: str,
        *,
        committed: bool,
        fetch_interception_armed: bool = False,
        candidate_cleanup_confirmed: bool | None = None,
    ) -> None:
        super().__init__(reason)
        self.committed = committed
        self.fetch_interception_armed = fetch_interception_armed
        self.candidate_cleanup_confirmed = candidate_cleanup_confirmed

@dataclass
class _SkillBitLease:
    challenge_id: str
    event_id: str
    account_id: str
    participation_identity: str
    origin: str
    scope_sha256: str
    gateway_boot_nonce: str
    gateway_policy_sha256: str
    gateway_expires_at: str
    expires_at: float = field(repr=False)


def _unhealthy_capabilities(detail: str) -> list[CapabilityHealth]:
    return [
        CapabilityHealth("browser_cdp", "available", "unhealthy", "stale", "read-only", (), detail),
        CapabilityHealth("browser_gateway", "available", "unhealthy", "stale", "read-only", (), detail),
        CapabilityHealth("session", "available", "unhealthy", "stale", "credentialed-browser", (), detail),
        CapabilityHealth("platform_inventory", "available", "unhealthy", "stale", "read-only", (), detail),
        CapabilityHealth("challenge_details", "available", "unhealthy", "stale", "read-only", (), detail),
        CapabilityHealth(
            "scoring",
            "available",
            "unhealthy",
            "stale",
            "reviewer-only",
            ("flag", "free_text"),
            detail,
        ),
    ]


class SkillBitAdapter(Adapter):
    """Bounded SkillBit competition adapter using the platform's own browser UI."""

    id = "skillbit"

    def __init__(self, root: Path, manifest: dict[str, Any], scope: dict[str, Any]):
        super().__init__(root, manifest, scope)
        self._lease: _SkillBitLease | None = None

    def _positive_int(self, name: str, default: int, maximum: int) -> int:
        value = self.config.get(name, default)
        if isinstance(value, bool):
            raise RuntimeError("skillbit_configuration_invalid")
        try:
            resolved = int(value)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("skillbit_configuration_invalid") from exc
        if not 1 <= resolved <= maximum:
            raise RuntimeError("skillbit_configuration_invalid")
        return resolved

    def _timeout(self) -> float:
        return float(self._positive_int("timeout", 45, 120))

    def _lease_seconds(self) -> int:
        return self._positive_int("session_lease_seconds", 60, 300)

    def _response_limit(self) -> int:
        return self._positive_int("max_response_bytes", 262_144, 1_048_576)

    def _configured_origins(self) -> tuple[str, str, str, str]:
        base = self.config.get("base_url")
        login = self.config.get("login_origin")
        raw_event_id = self.config.get("event_id")
        raw_account_id = self.config.get("account_id")
        support_origins = self.config.get("browser_support_origins")
        if (
            not isinstance(base, str)
            or not isinstance(login, str)
            or isinstance(raw_event_id, bool)
            or not isinstance(raw_event_id, int)
            or isinstance(raw_account_id, bool)
            or not isinstance(raw_account_id, int)
            or not isinstance(support_origins, list)
            or login not in support_origins
        ):
            raise RuntimeError("skillbit_configuration_invalid")
        event_id = str(raw_event_id)
        account_id = str(raw_account_id)
        if not _EVENT_ID.fullmatch(event_id) or not _CHALLENGE_ID.fullmatch(account_id):
            raise RuntimeError("skillbit_configuration_invalid")
        if base != "https://compete.metactf.com" or login != "https://app.metactf.com":
            raise RuntimeError("skillbit_origin_invalid")
        return base, login, event_id, account_id

    def _endpoints(self) -> tuple[str, str, str]:
        resolved = self._resolve_local_environment(
            (
                EnvKey(
                    "BROWSER_CDP_URL",
                    EnvClass.ROOKERY_CONFIG,
                    required=True,
                    sources=(EnvSource.DOTENV, EnvSource.PARENT),
                ),
                EnvKey(
                    "BROWSER_GATEWAY_URL",
                    EnvClass.ROOKERY_CONFIG,
                    required=True,
                    sources=(EnvSource.DOTENV, EnvSource.PARENT),
                ),
                EnvKey(
                    "SKILLBIT_URL",
                    EnvClass.ROOKERY_CONFIG,
                    required=True,
                    sources=(EnvSource.DOTENV,),
                ),
            )
        )
        return tuple(
            self._environment_value(resolved, name)
            for name in (
                "BROWSER_CDP_URL",
                "BROWSER_GATEWAY_URL",
                "SKILLBIT_URL",
            )
        )  # type: ignore[return-value]

    def _credentials(self) -> tuple[str, str, str]:
        resolved = self._resolve_local_environment(
            tuple(
                EnvKey(
                    name,
                    EnvClass.ADAPTER_SECRET,
                    required=True,
                    sources=(EnvSource.DOTENV,),
                )
                for name in ("SKILLBIT_USER", "SKILLBIT_EMAIL", "SKILLBIT_PASSWORD")
            )
        )
        user = self._environment_value(resolved, "SKILLBIT_USER")
        email = self._environment_value(resolved, "SKILLBIT_EMAIL")
        password = self._environment_value(resolved, "SKILLBIT_PASSWORD")
        if (
            not user
            or not email
            or not password
            or len(user.encode("utf-8")) > 512
            or len(email.encode("utf-8")) > 512
            or len(password.encode("utf-8")) > 4096
        ):
            raise RuntimeError("skillbit_credentials_invalid")
        return user, email, password

    @staticmethod
    def _environment_value(resolved: Any, name: str) -> str:
        """Return one declared value without assuming mapping semantics."""

        getter = getattr(resolved, "get", None)
        value = getter(name) if callable(getter) else None
        if not isinstance(value, str) or not value:
            raise RuntimeError("skillbit_configuration_invalid")
        return value

    def _session_record(
        self,
        account_id: str,
        event_id: str,
        *,
        authenticated: bool,
        diagnostic: str | None = None,
    ) -> dict[str, Any]:
        participation_mode, expected_team_name, participation_identity = (
            self._participation()
        )
        record: dict[str, Any] = {
            "account_id": account_id,
            "event_id": event_id,
            "authentication": "authenticated" if authenticated else "unavailable",
            "registration": {
                "status": "registered" if authenticated else "unknown",
                "event_id": event_id,
            },
            "participation": {
                "mode": participation_mode,
                "binding": "operator_attested",
                "identity": participation_identity,
            },
            "team": (
                {
                    "status": "operator_attested",
                    "name": expected_team_name,
                }
                if participation_mode == "team"
                else {"status": "attested_individual"}
            ),
        }
        if diagnostic is not None:
            record["diagnostic"] = diagnostic
            record["registration"] = {
                "status": "unknown",
                "event_id": event_id,
                "diagnostic": diagnostic,
            }
        return record

    def _participation(self) -> tuple[str, str, str]:
        mode = self.config.get("participation_mode")
        team_name = self.config.get("expected_team_name", "")
        if (
            mode not in {"individual", "team"}
            or not isinstance(team_name, str)
            or len(team_name.encode("utf-8")) > 512
            or mode == "individual"
            and team_name
            or mode == "team"
            and not team_name
        ):
            raise RuntimeError("skillbit_participation_invalid")
        identity = f"{mode}:{team_name}" if mode == "team" else "individual"
        return str(mode), team_name, identity

    @staticmethod
    def _session_diagnostic(exc: BaseException) -> str:
        if isinstance(exc, BrowserUiCdpError):
            return exc.reason
        if isinstance(exc, EnvironmentPolicyError):
            value = str(exc)
            return value if value.startswith("skillbit_") else "skillbit_session_unavailable"
        value = str(exc)
        return value if value.startswith("skillbit_") else "skillbit_session_unavailable"

    def _gateway_identity(
        self,
        gateway_url: str,
        environment_origin: str,
        *,
        boot_nonce: str | None = None,
    ) -> tuple[str, BrowserGatewayReadiness]:
        try:
            binding = verify_launch_binding_integrity(self.root)
        except EnvironmentPolicyError as exc:
            if str(exc) != "launch_binding_missing" or (self.root / "state").exists():
                raise
            policy = resolve_browser_gateway_policy(
                self.root,
                origin=environment_origin,
            )
            origin = environment_origin
        else:
            if binding.record.get("selected_adapter") != self.id:
                raise RuntimeError("skillbit_gateway_binding_invalid")
            origin = browser_gateway_origin(self.manifest, environment_origin)
            policy = compile_browser_gateway_policy(
                self.manifest,
                baseline_configuration_digest=str(
                    binding.record["baseline_configuration_digest"]
                ),
                origin=origin,
                environment_origin=environment_origin,
            )
        if policy.get("scope_sha256") != scope_sha256(self.scope):
            raise RuntimeError("skillbit_gateway_scope_changed")
        digest = policy_sha256(policy)
        expires_at = policy.get("expires_at")
        if not isinstance(expires_at, str):
            raise RuntimeError("skillbit_gateway_policy_invalid")
        readiness = verify_browser_gateway_endpoint(
            gateway_url,
            expected_policy_sha256=digest,
            expected_expires_at=expires_at,
            expected_boot_nonce=boot_nonce,
        )
        return origin, readiness

    @staticmethod
    def _gateway_scope(port: int) -> dict[str, Any]:
        return {
            "acknowledged": True,
            "generation": 0,
            "expires_at": "unknown",
            "allowed_hosts": ["127.0.0.1"],
            "allowed_cidrs": ["127.0.0.1/32"],
            "allowed_ports": [port],
            "allowed_protocols": ["http"],
            "allowed_file_origins": [],
            "platform_hosts": [],
            "max_attachment_bytes": 0,
        }

    def _gateway_counters(
        self,
        gateway_url: str,
        expected: BrowserGatewayReadiness,
    ) -> dict[str, int]:
        base_url, port = resolve_browser_gateway_endpoint(gateway_url)
        scope = self._gateway_scope(port)
        transport = ExplicitNetworkPolicy.from_child_environment(
            ChildEnvironment({}, "skillbit-gateway-status", ())
        ).scoped_transport(scope)
        request = urllib.request.Request(
            f"{base_url}/status",
            headers={"Accept": "application/json"},
            method="GET",
        )
        try:
            with open_scoped_url(
                scope,
                request,
                timeout=3,
                max_redirects=0,
                transport=transport,
            ) as response:
                if getattr(response, "status", None) != 200:
                    raise RuntimeError("skillbit_gateway_unavailable")
                raw = response.read(_MAX_GATEWAY_STATUS_BYTES + 1)
        except RuntimeError:
            raise
        except (OSError, TimeoutError) as exc:
            raise RuntimeError("skillbit_gateway_unavailable") from exc
        if not isinstance(raw, bytes) or len(raw) > _MAX_GATEWAY_STATUS_BYTES:
            raise RuntimeError("skillbit_gateway_status_invalid")
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("skillbit_gateway_status_invalid") from exc
        listeners = document.get("listeners") if isinstance(document, dict) else None
        counters = document.get("counters") if isinstance(document, dict) else None
        if (
            not isinstance(document, dict)
            or document.get("schema_version") != "1"
            or document.get("boot_nonce") != expected.boot_nonce
            or document.get("policy_sha256") != expected.policy_sha256
            or document.get("expires_at") != expected.expires_at
            or not isinstance(listeners, dict)
            or listeners.get("proxy") != f"127.0.0.1:{expected.proxy_port}"
            or listeners.get("status") != f"127.0.0.1:{expected.status_port}"
            or not isinstance(counters, dict)
            or set(counters)
            != {"accepted", "refused", "connected", "completed", "failed", "bytes"}
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in counters.values()
            )
        ):
            raise RuntimeError("skillbit_gateway_status_invalid")
        return {"connected": counters["connected"], "bytes": counters["bytes"]}

    @staticmethod
    def _require_gateway_transfer(before: dict[str, int], after: dict[str, int]) -> None:
        if after["bytes"] <= before["bytes"]:
            raise RuntimeError("skillbit_gateway_transfer_unverified")

    @staticmethod
    def _runtime_mapping(value: object, *, reason: str) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise RuntimeError(reason)
        return value

    def _page_state(
        self,
        target: OwnedBrowserTarget,
        login_origin: str,
        platform_origin: str,
        event_id: str,
        expected_user: str,
        *,
        deadline: float,
    ) -> dict[str, Any]:
        value = target.channel.call_function(
            _PAGE_STATE_FUNCTION,
            [login_origin, platform_origin, event_id, expected_user],
            deadline=deadline,
        ).value
        return self._runtime_mapping(value, reason="skillbit_page_state_invalid")

    def _wait_state(
        self,
        target: OwnedBrowserTarget,
        login_origin: str,
        platform_origin: str,
        event_id: str,
        expected_user: str,
        expected: set[str],
        *,
        deadline: float,
    ) -> dict[str, Any]:
        unrecognized_since: float | None = None
        unrecognized_kind: str | None = None
        while time.monotonic() < deadline:
            state = self._page_state(
                target,
                login_origin,
                platform_origin,
                event_id,
                expected_user,
                deadline=deadline,
            )
            kind = state.get("kind")
            if kind in expected:
                return state
            typed = {
                "identity_mismatch": "skillbit_identity_mismatch",
                "registration_required": "skillbit_registration_required",
                "event_ambiguous": "skillbit_event_ambiguous",
            }
            if kind in typed:
                raise RuntimeError(typed[kind])
            if kind in {"interaction_required", "unexpected"}:
                now = time.monotonic()
                if kind != unrecognized_kind:
                    unrecognized_kind = str(kind)
                    unrecognized_since = now
                elif unrecognized_since is not None and now - unrecognized_since >= 1.0:
                    raise RuntimeError("skillbit_page_state_unrecognized")
            else:
                unrecognized_kind = None
                unrecognized_since = None
            time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
        raise RuntimeError("skillbit_page_timeout")

    @staticmethod
    def _handoff_url(
        value: object,
        platform_origin: str,
        event_id: str,
        expected_account_id: str,
    ) -> str:
        if not isinstance(value, str) or len(value.encode("utf-8")) > 4096:
            raise RuntimeError("skillbit_handoff_invalid")
        try:
            parsed = urllib.parse.urlsplit(value)
            query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        except ValueError as exc:
            raise RuntimeError("skillbit_handoff_invalid") from exc
        platform = urllib.parse.urlsplit(platform_origin)
        if (
            parsed.scheme != "https"
            or parsed.hostname != platform.hostname
            or parsed.port not in {None, 443}
            or parsed.path != f"/{event_id}/"
            or parsed.fragment
            or set(query) != {"auth", "uid", "tok"}
            or any(
                len(items) != 1 or not items[0] or len(items[0]) > 512
                for items in query.values()
            )
            or query["uid"][0] != expected_account_id
        ):
            raise RuntimeError("skillbit_handoff_invalid")
        return value

    def _inventory_once(
        self,
        target: OwnedBrowserTarget,
        platform_origin: str,
        event_id: str,
        *,
        deadline: float,
    ) -> list[dict[str, Any]]:
        rows: list[object] = []
        total: int | None = None
        offset = 0
        while total is None or offset < total:
            value = target.channel.call_function(
                _INVENTORY_FUNCTION,
                [
                    platform_origin,
                    event_id,
                    _MAX_CHALLENGES,
                    offset,
                    _INVENTORY_PAGE_SIZE,
                ],
                deadline=deadline,
            ).value
            document = self._runtime_mapping(
                value,
                reason="skillbit_inventory_invalid",
            )
            page_rows = document.get("challenges")
            if document.get("ok") is not True:
                reason = document.get("reason")
                allowed = {
                    "binding",
                    "fields",
                    "id",
                    "ids",
                    "page",
                    "registry",
                    "registry_ids",
                    "route",
                }
                suffix = (
                    reason
                    if isinstance(reason, str) and reason in allowed
                    else "unknown"
                )
                raise RuntimeError(f"skillbit_inventory_invalid_{suffix}")
            page_total = document.get("total")
            if (
                isinstance(page_total, bool)
                or not isinstance(page_total, int)
                or not 1 <= page_total <= _MAX_CHALLENGES
                or not isinstance(page_rows, list)
                or not page_rows
                or len(page_rows) > _INVENTORY_PAGE_SIZE
                or offset + len(page_rows) > page_total
                or total is not None
                and page_total != total
            ):
                raise RuntimeError("skillbit_inventory_invalid")
            total = page_total
            rows.extend(page_rows)
            offset += len(page_rows)
        if total is None or len(rows) != total:
            raise RuntimeError("skillbit_inventory_invalid")
        seen: set[str] = set()
        challenges: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                raise RuntimeError("skillbit_inventory_invalid")
            identifier = row.get("id")
            title = row.get("title")
            category = row.get("category")
            points = row.get("points")
            solved = row.get("solved")
            hidden = row.get("hidden")
            recorded = row.get("recorded")
            solvable = row.get("solvable")
            submittable = row.get("submittable")
            platform_submittable = row.get("platformSubmittable")
            submission_mode = row.get("submissionMode")
            if (
                not isinstance(identifier, str)
                or not _CHALLENGE_ID.fullmatch(identifier)
                or identifier in seen
                or not isinstance(title, str)
                or not title
                or len(title.encode("utf-8")) > _MAX_TITLE_BYTES
                or not isinstance(category, str)
                or not category
                or len(category.encode("utf-8")) > _MAX_CATEGORY_BYTES
                or isinstance(points, bool)
                or not isinstance(points, int)
                or not 0 <= points <= 1_000_000
                or not isinstance(solved, bool)
                or not isinstance(hidden, bool)
                or not isinstance(recorded, bool)
                or not isinstance(solvable, bool)
                or not isinstance(submittable, bool)
                or not isinstance(platform_submittable, bool)
                or submission_mode
                not in {
                    "already_solved",
                    "locked",
                    "manual",
                    "multiple_choice",
                    "text",
                    "unsupported",
                }
                or submittable is not (submission_mode == "text")
            ):
                raise RuntimeError("skillbit_inventory_invalid")
            lowered = category.casefold()
            normalized_category = _CATEGORY_MAP.get(lowered, lowered)
            seen.add(identifier)
            challenges.append(
                {
                    "id": identifier,
                    "title": title,
                    "category": normalized_category,
                    "points": points,
                    "solved": solved,
                    "hidden": hidden,
                    "recorded": recorded,
                    "description": "",
                    "files": [],
                    "submittable": submittable,
                    "solvable": solvable,
                    "platform_submittable": platform_submittable,
                    "submission_mode": submission_mode,
                }
            )
        return challenges

    def _inventory(
        self,
        target: OwnedBrowserTarget,
        platform_origin: str,
        event_id: str,
        *,
        deadline: float,
    ) -> list[dict[str, Any]]:
        """Return the best bounded inventory after asynchronous controls settle."""

        best: list[dict[str, Any]] | None = None
        best_pending = _MAX_CHALLENGES + 1
        unchanged = 0
        for attempt in range(8):
            challenges = self._inventory_once(
                target,
                platform_origin,
                event_id,
                deadline=deadline,
            )
            pending = sum(
                item.get("submission_mode") == "unsupported"
                and item.get("platform_submittable") is True
                and item.get("solvable") is True
                and item.get("solved") is False
                for item in challenges
            )
            if best is None or pending < best_pending:
                best = challenges
                best_pending = pending
                unchanged = 0
            else:
                unchanged += 1
            if best_pending == 0 or unchanged >= 2 or attempt == 7:
                assert best is not None
                return best
            time.sleep(min(0.5, max(0.0, deadline - time.monotonic())))
        raise RuntimeError("skillbit_inventory_invalid")

    @staticmethod
    def _metadata_value(value: object) -> Any:
        """Accept a bounded JSON value returned by the fixed page helper."""

        try:
            encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode(
                "utf-8"
            )
        except (TypeError, ValueError) as exc:
            raise RuntimeError("skillbit_detail_invalid") from exc
        if len(encoded) > _MAX_DETAIL_METADATA_BYTES:
            raise RuntimeError("skillbit_detail_invalid")
        return value

    @staticmethod
    def _authenticated_attachment_url(
        item: object,
        *,
        platform_origin: str,
        event_id: str,
    ) -> str:
        if not isinstance(item, dict) or item.get("kind") != "authenticated_file":
            raise RuntimeError("skillbit_attachment_unavailable")
        value = item.get("url")
        if not isinstance(value, str) or len(value.encode("utf-8")) > _MAX_RESOURCE_URL_BYTES:
            raise RuntimeError("skillbit_attachment_unavailable")
        try:
            parsed = urllib.parse.urlsplit(value)
            platform = urllib.parse.urlsplit(platform_origin)
            port = parsed.port
        except ValueError as exc:
            raise RuntimeError("skillbit_attachment_unavailable") from exc
        raw_parts = parsed.path.split("/")
        try:
            parts = [urllib.parse.unquote(part) for part in raw_parts[1:]]
        except (UnicodeError, ValueError) as exc:
            raise RuntimeError("skillbit_attachment_unavailable") from exc
        if (
            parsed.scheme != "https"
            or parsed.hostname != platform.hostname
            or port not in {None, 443}
            or parsed.query
            or parsed.fragment
            or len(raw_parts) != 6
            or len(parts) != 5
            or parts[:3] != [event_id, "api", "attachments"]
            or any(
                not _ATTACHMENT_COMPONENT.fullmatch(part)
                or part in {".", ".."}
                or "/" in part
                or "\\" in part
                for part in parts[3:]
            )
        ):
            raise RuntimeError("skillbit_attachment_unavailable")
        return value

    @staticmethod
    def _public_attachment_url(item: object) -> str:
        if not isinstance(item, dict) or item.get("kind") != "public_file":
            raise RuntimeError("skillbit_attachment_unavailable")
        value = item.get("url")
        if not isinstance(value, str) or len(value.encode("utf-8")) > _MAX_RESOURCE_URL_BYTES:
            raise RuntimeError("skillbit_attachment_unavailable")
        try:
            parsed = urllib.parse.urlsplit(value)
            port = parsed.port
            origin = f"{parsed.scheme}://{parsed.hostname}"
        except (UnicodeError, ValueError) as exc:
            raise RuntimeError("skillbit_attachment_unavailable") from exc
        suffix = Path(urllib.parse.unquote(parsed.path)).suffix.casefold()
        if (
            parsed.scheme != "https"
            or port not in {None, 443}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or origin not in _PUBLIC_FILE_ORIGINS
            or suffix not in _PUBLIC_FILE_SUFFIXES
        ):
            raise RuntimeError("skillbit_attachment_unavailable")
        return value

    @staticmethod
    def _attachment_cookie_headers(value: object) -> dict[str, str]:
        if not isinstance(value, dict):
            raise RuntimeError("skillbit_attachment_cookie_invalid")
        cookies = value.get("cookies")
        if not isinstance(cookies, list) or not 1 <= len(cookies) <= 128:
            raise RuntimeError("skillbit_attachment_authentication_required")
        pairs: list[str] = []
        total = 0
        for cookie in cookies:
            if not isinstance(cookie, dict):
                raise RuntimeError("skillbit_attachment_cookie_invalid")
            name = cookie.get("name")
            item = cookie.get("value")
            if (
                not isinstance(name, str)
                or not _COOKIE_NAME.fullmatch(name)
                or not isinstance(item, str)
                or not item
                or len(item.encode("utf-8")) > 4096
                or any(character in item for character in "\r\n;")
            ):
                raise RuntimeError("skillbit_attachment_cookie_invalid")
            pair = f"{name}={item}"
            total += len(pair.encode("utf-8")) + (2 if pairs else 0)
            if total > 8192:
                raise RuntimeError("skillbit_attachment_cookie_invalid")
            pairs.append(pair)
        return {"Cookie": "; ".join(pairs)}

    def _detail(
        self,
        target: OwnedBrowserTarget,
        *,
        challenge_id: str,
        platform_origin: str,
        event_id: str,
        deadline: float,
    ) -> dict[str, Any]:
        value = target.channel.call_function(
            _DETAIL_FUNCTION,
            [
                platform_origin,
                event_id,
                int(challenge_id),
                _MAX_DETAIL_TEXT_BYTES // 4,
                _MAX_DETAIL_HTML_BYTES // 4,
                _MAX_RESOURCES,
            ],
            deadline=deadline,
        ).value
        document = self._runtime_mapping(value, reason="skillbit_detail_invalid")
        if document.get("ok") is not True or document.get("id") != challenge_id:
            raise RuntimeError("skillbit_detail_unavailable")
        text = document.get("description_text")
        html = document.get("description_html")
        mode = document.get("submission_mode")
        platform_submittable = document.get("platform_submittable")
        resources_complete = document.get("resources_complete")
        resources_truncated = document.get("resources_truncated")
        resources = document.get("resources")
        if (
            not isinstance(text, str)
            or len(text.encode("utf-8")) > _MAX_DETAIL_TEXT_BYTES
            or not isinstance(html, str)
            or len(html.encode("utf-8")) > _MAX_DETAIL_HTML_BYTES
            or mode
            not in {
                "already_solved",
                "locked",
                "manual",
                "multiple_choice",
                "text",
                "unsupported",
            }
            or not isinstance(platform_submittable, bool)
            or not isinstance(resources_complete, bool)
            or not isinstance(resources_truncated, bool)
            or resources_complete is resources_truncated
            or not isinstance(resources, list)
            or len(resources) > _MAX_RESOURCES
        ):
            raise RuntimeError("skillbit_detail_invalid")
        normalized_resources: list[dict[str, str]] = []
        files: list[dict[str, str]] = []
        for resource in resources:
            if not isinstance(resource, dict) or set(resource) != {
                "url",
                "name",
                "kind",
                "source",
            }:
                raise RuntimeError("skillbit_detail_invalid")
            url = resource.get("url")
            name = resource.get("name")
            kind = resource.get("kind")
            source = resource.get("source")
            if (
                not isinstance(url, str)
                or len(url.encode("utf-8")) > _MAX_RESOURCE_URL_BYTES
                or not isinstance(name, str)
                or not name
                or len(name.encode("utf-8")) > 512
                or kind not in {"authenticated_file", "public_file", "link"}
                or not isinstance(source, str)
                or not source
                or len(source.encode("utf-8")) > 32
            ):
                raise RuntimeError("skillbit_detail_invalid")
            normalized = {
                "url": url,
                "name": name,
                "kind": str(kind),
                "source": source,
            }
            normalized_resources.append(normalized)
            if kind == "authenticated_file":
                self._authenticated_attachment_url(
                    normalized,
                    platform_origin=platform_origin,
                    event_id=event_id,
                )
                files.append({"url": url, "name": name, "kind": str(kind)})
            elif kind == "public_file":
                self._public_attachment_url(normalized)
                files.append({"url": url, "name": name, "kind": str(kind)})
        metadata = {
            name: self._metadata_value(document.get(name))
            for name in (
                "manual_grade",
                "manual_grading",
                "points_graded",
                "hints",
                "penalties",
                "ratings",
                "tags",
                "solve_count",
                "solved_by",
                "teammates_solved",
            )
        }
        return {
            "id": challenge_id,
            "description": text,
            "description_text": text,
            "description_html": html,
            "submission_mode": mode,
            "submittable": mode == "text",
            "platform_submittable": platform_submittable,
            "resources": normalized_resources,
            "resources_complete": resources_complete,
            "resources_truncated": resources_truncated,
            "files": files,
            **metadata,
        }

    def detail(self, challenge_id: str) -> dict[str, Any]:
        """Return one fresh, whitespace-preserving challenge detail record."""

        if not _CHALLENGE_ID.fullmatch(str(challenge_id)):
            raise KeyError(challenge_id)
        target: OwnedBrowserTarget | None = None
        try:
            (
                target,
                challenges,
                platform_origin,
                event_id,
                _account_id,
                _gateway_url,
                _gateway,
                _cdp_url,
                _environment_origin,
            ) = self._open_event_session(authenticate=False)
            summary = [item for item in challenges if item["id"] == str(challenge_id)]
            if len(summary) != 1:
                raise KeyError(challenge_id)
            detail = self._detail(
                target,
                challenge_id=str(challenge_id),
                platform_origin=platform_origin,
                event_id=event_id,
                deadline=deadline_after(self._timeout()),
            )
            return {**summary[0], **detail}
        finally:
            if target is not None and not target.closed:
                try:
                    target.close(deadline=deadline_after(2.0))
                except BrowserUiCdpError:
                    pass

    def capture_file(self, item: dict[str, Any], destination: Path) -> dict[str, Any]:
        """Capture one authenticated, exact-event SkillBit attachment."""

        if item.get("kind") == "public_file":
            self._public_attachment_url(item)
            return super().capture_file(item, destination)
        target: OwnedBrowserTarget | None = None
        try:
            (
                target,
                _challenges,
                platform_origin,
                event_id,
                _account_id,
                _gateway_url,
                _gateway,
                _cdp_url,
                _environment_origin,
            ) = self._open_event_session(authenticate=False)
            url = self._authenticated_attachment_url(
                item,
                platform_origin=platform_origin,
                event_id=event_id,
            )
            cookies = target.channel.cookies_for_url(
                url,
                deadline=deadline_after(self._timeout()),
            )
            return capture_adapter_file(
                self.root,
                self.scope,
                item,
                destination,
                headers=self._attachment_cookie_headers(cookies),
                platform=True,
            )
        finally:
            if target is not None and not target.closed:
                target.close(deadline=deadline_after(2.0))

    def session_health(self) -> dict[str, Any]:
        """Check the existing browser session without reading credentials or logging in."""

        target: OwnedBrowserTarget | None = None
        try:
            (
                target,
                _challenges,
                _origin,
                event_id,
                account_id,
                _gateway_url,
                _gateway,
                _cdp_url,
                _environment_origin,
            ) = self._open_event_session(authenticate=False)
            return {
                "availability": "available",
                "health": "healthy",
                "session": self._session_record(
                    account_id,
                    event_id,
                    authenticated=True,
                ),
            }
        except (
            BrowserGatewayPolicyError,
            BrowserUiCdpError,
            EnvironmentPolicyError,
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
        ) as exc:
            diagnostic = self._session_diagnostic(exc)
            try:
                _origin, _login, event_id, account_id = self._configured_origins()
                session = self._session_record(
                    account_id,
                    event_id,
                    authenticated=False,
                    diagnostic=diagnostic,
                )
            except RuntimeError:
                session = {
                    "authentication": "unavailable",
                    "registration": {
                        "status": "unknown",
                        "diagnostic": diagnostic,
                    },
                    "team": {
                        "status": "unverifiable",
                        "reason": "skillbit_team_unverifiable",
                    },
                }
            return {
                "availability": "available",
                "health": "unhealthy",
                "reason": diagnostic,
                "session": session,
            }
        finally:
            if target is not None and not target.closed:
                target.close(deadline=deadline_after(2.0))

    def _open_event_session(
        self,
        *,
        authenticate: bool,
    ) -> tuple[
        OwnedBrowserTarget,
        list[dict[str, Any]],
        str,
        str,
        str,
        str,
        BrowserGatewayReadiness,
        str,
        str,
    ]:
        platform_origin, login_origin, event_id, account_id = self._configured_origins()
        cdp_url, gateway_url, environment_origin = self._endpoints()
        if environment_origin != platform_origin:
            raise RuntimeError("skillbit_origin_invalid")
        verify_browser_cdp_endpoint(cdp_url)
        origin, gateway = self._gateway_identity(gateway_url, environment_origin)
        if origin != platform_origin:
            raise RuntimeError("skillbit_gateway_binding_invalid")
        if authenticate:
            expected_user, email, password = self._credentials()
        else:
            expected_user, email, password = "", "", ""
        before = self._gateway_counters(gateway_url, gateway)
        target = open_owned_browser_target(cdp_url, timeout_seconds=min(10.0, self._timeout()))
        deadline = deadline_after(self._timeout())
        try:
            target.channel.command("Network.enable", {}, deadline=deadline)
            target.channel.command(
                "Network.setBypassServiceWorker",
                {"bypass": True},
                deadline=deadline,
            )
            target.channel.command(
                "Network.setCacheDisabled",
                {"cacheDisabled": True},
                deadline=deadline,
            )
            target.channel.navigate(login_origin + "/", deadline=deadline)
            state = self._wait_state(
                target,
                login_origin,
                platform_origin,
                event_id,
                expected_user,
                {"login", "dashboard"},
                deadline=deadline,
            )
            if state.get("kind") == "login":
                if not authenticate:
                    raise RuntimeError("skillbit_authentication_required")
                submitted = target.channel.call_function(
                    _LOGIN_FUNCTION,
                    [email, password],
                    deadline=deadline,
                ).value
                if submitted is not True:
                    raise RuntimeError("skillbit_login_failed")
                state = self._wait_state(
                    target,
                    login_origin,
                    platform_origin,
                    event_id,
                    expected_user,
                    {"dashboard"},
                    deadline=deadline,
                )
            if authenticate and state.get("identityMatched") is not True:
                raise RuntimeError("skillbit_identity_mismatch")
            if state.get("handoffCount") != 1:
                raise RuntimeError("skillbit_event_ambiguous")
            handoff = self._handoff_url(
                state.get("handoff"),
                platform_origin,
                event_id,
                account_id,
            )
            for handoff_attempt in range(5):
                try:
                    target.channel.navigate(handoff, deadline=deadline)
                    break
                except BrowserUiCdpError as exc:
                    if (
                        not exc.reason.startswith("browser_ui_cdp_navigation_failed:")
                        or handoff_attempt == 4
                    ):
                        raise
                time.sleep(
                    min(
                        0.5 * (handoff_attempt + 1),
                        max(0.0, deadline - time.monotonic()),
                    )
                )
                target.channel.navigate(login_origin + "/", deadline=deadline)
                state = self._wait_state(
                    target,
                    login_origin,
                    platform_origin,
                    event_id,
                    expected_user,
                    {"dashboard"},
                    deadline=deadline,
                )
                if authenticate and state.get("identityMatched") is not True:
                    raise RuntimeError("skillbit_identity_mismatch")
                if state.get("handoffCount") != 1:
                    raise RuntimeError("skillbit_event_ambiguous")
                handoff = self._handoff_url(
                    state.get("handoff"),
                    platform_origin,
                    event_id,
                    account_id,
                )
            self._wait_state(
                target,
                login_origin,
                platform_origin,
                event_id,
                expected_user,
                {"event"},
                deadline=deadline,
            )
            target.channel.navigate(
                f"{platform_origin}/{event_id}/problems",
                deadline=deadline,
            )
            self._wait_state(
                target,
                login_origin,
                platform_origin,
                event_id,
                expected_user,
                {"problems"},
                deadline=deadline,
            )
            challenges = self._inventory(
                target,
                platform_origin,
                event_id,
                deadline=deadline,
            )
            after = self._gateway_counters(gateway_url, gateway)
            self._require_gateway_transfer(before, after)
            return (
                target,
                challenges,
                platform_origin,
                event_id,
                account_id,
                gateway_url,
                gateway,
                cdp_url,
                environment_origin,
            )
        except BaseException:
            target.close(deadline=deadline_after(2.0))
            raise

    def sync(self) -> dict[str, Any]:
        self._dispose_lease()
        transient = {
            "browser_ui_cdp_command_failed",
            "browser_ui_cdp_timeout",
            "skillbit_page_timeout",
        }
        for attempt in range(5):
            target: OwnedBrowserTarget | None = None
            try:
                (
                    target,
                    challenges,
                    _origin,
                    event_id,
                    account_id,
                    _gateway_url,
                    _gateway,
                    _cdp_url,
                    _environment_origin,
                ) = self._open_event_session(authenticate=True)
                target.close(deadline=deadline_after(2.0))
                target = None
                break
            except (
                BrowserGatewayPolicyError,
                BrowserUiCdpError,
                EnvironmentPolicyError,
                OSError,
                RuntimeError,
                TypeError,
                ValueError,
            ) as exc:
                detail = self._session_diagnostic(exc)
                retriable = detail in transient or detail.startswith(
                    "browser_ui_cdp_navigation_failed:"
                )
                if retriable and attempt < 4:
                    time.sleep(0.5 * (attempt + 1))
                    continue
                try:
                    _origin, _login, event_id, account_id = self._configured_origins()
                    session = self._session_record(
                        account_id,
                        event_id,
                        authenticated=False,
                        diagnostic=detail,
                    )
                except RuntimeError:
                    session = {
                        "authentication": "unavailable",
                        "registration": {
                            "status": "unknown",
                            "diagnostic": detail,
                        },
                        "team": {
                            "status": "unverifiable",
                            "reason": "skillbit_team_unverifiable",
                        },
                    }
                return normalized_snapshot(
                    self.id,
                    _unhealthy_capabilities(detail),
                    [],
                    session=session,
                )
            finally:
                if target is not None and not target.closed:
                    try:
                        target.close(deadline=deadline_after(2.0))
                    except BrowserUiCdpError:
                        pass
        else:
            raise RuntimeError("skillbit_session_unavailable")
        freshness = iso_now()
        caps = [
            CapabilityHealth("browser_cdp", "available", "healthy", freshness, "read-only", ()),
            CapabilityHealth("browser_gateway", "available", "healthy", freshness, "read-only", ()),
            CapabilityHealth("session", "available", "healthy", freshness, "credentialed-browser", ()),
            CapabilityHealth("platform_inventory", "available", "healthy", freshness, "read-only", ()),
            CapabilityHealth("challenge_details", "available", "healthy", freshness, "read-only", ()),
            CapabilityHealth(
                "scoring",
                "available",
                "healthy",
                freshness,
                "reviewer-only",
                ("flag", "free_text"),
            ),
        ]
        return normalized_snapshot(
            self.id,
            caps,
            challenges,
            session=self._session_record(
                account_id,
                event_id,
                authenticated=True,
            ),
        )

    def _dispose_lease(self) -> None:
        self._lease = None

    def preflight_action(self, envelope: dict[str, Any]) -> dict[str, Any]:
        self._dispose_lease()
        if envelope.get("action_kind") not in {"flag", "free_text"}:
            return {"ok": False, "reason": "skillbit_action_kind_invalid"}
        objective_id = str(envelope.get("objective_id") or "")
        if not _CHALLENGE_ID.fullmatch(objective_id):
            return {"ok": False, "reason": "skillbit_challenge_id_invalid"}
        target: OwnedBrowserTarget | None = None
        outcome: dict[str, Any]
        try:
            (
                target,
                challenges,
                origin,
                event_id,
                account_id,
                _gateway_url,
                gateway,
                _cdp_url,
                _environment_origin,
            ) = self._open_event_session(authenticate=False)
            matches = [item for item in challenges if item["id"] == objective_id]
            if len(matches) == 1 and matches[0].get("solved") is True:
                outcome = {
                    "ok": False,
                    "reason": "skillbit_challenge_already_solved",
                }
            else:
                if (
                    len(matches) != 1
                    or matches[0].get("hidden") is not False
                    or matches[0].get("solvable") is not True
                    or matches[0].get("submittable") is not True
                    or matches[0].get("submission_mode") != "text"
                ):
                    raise RuntimeError("skillbit_challenge_unavailable")
                self._lease = _SkillBitLease(
                    challenge_id=objective_id,
                    event_id=event_id,
                    account_id=account_id,
                    participation_identity=self._participation()[2],
                    origin=origin,
                    scope_sha256=scope_sha256(self.scope),
                    gateway_boot_nonce=gateway.boot_nonce,
                    gateway_policy_sha256=gateway.policy_sha256,
                    gateway_expires_at=gateway.expires_at,
                    expires_at=time.monotonic() + self._lease_seconds(),
                )
                outcome = {"ok": True, "reason": "skillbit_preflight_passed"}
        except (
            BrowserGatewayPolicyError,
            BrowserUiCdpError,
            EnvironmentPolicyError,
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
        ):
            outcome = {"ok": False, "reason": "skillbit_preflight_failed"}
        finally:
            if target is not None and not target.closed:
                try:
                    target.close(deadline=deadline_after(2.0))
                except BrowserUiCdpError:
                    self._dispose_lease()
                    outcome = {
                        "ok": False,
                        "reason": "skillbit_preflight_cleanup_failed",
                    }
        return outcome

    def _current_lease(self) -> _SkillBitLease:
        lease = self._lease
        self._lease = None
        if lease is None:
            raise RuntimeError("skillbit_preflight_lease_missing")
        if time.monotonic() > lease.expires_at:
            raise RuntimeError("skillbit_preflight_lease_expired")
        return lease

    @staticmethod
    def _submission_request_matches(
        request: object,
        *,
        challenge_id: str,
        candidate: str,
        origin: str,
        event_id: str,
    ) -> bool:
        if not isinstance(request, dict):
            return False
        url = request.get("url")
        method = request.get("method")
        post_data = request.get("postData")
        if not isinstance(url, str) or not isinstance(post_data, str) or method != "POST":
            return False
        try:
            parsed = urllib.parse.urlsplit(url)
            pairs = urllib.parse.parse_qsl(
                post_data,
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=4,
            )
        except (UnicodeError, ValueError):
            return False
        expected_origin = urllib.parse.urlsplit(origin)
        if (
            parsed.scheme != "https"
            or parsed.hostname != expected_origin.hostname
            or parsed.port not in {None, 443}
            or parsed.path != f"/{event_id}/api/submit.php"
            or parsed.query
            or parsed.fragment
            or len(pairs) != 2
        ):
            return False
        values = {key: value for key, value in pairs}
        return (
            set(values) == {"id", "answer"}
            and values["id"] == challenge_id
            and values["answer"] == candidate
        )

    @staticmethod
    def _submission_response_body(
        result: dict[str, Any],
        *,
        maximum: int,
    ) -> dict[str, Any]:
        body = result.get("body")
        encoded = result.get("base64Encoded")
        if not isinstance(body, str) or not isinstance(encoded, bool):
            raise _SkillBitSubmissionError(
                "skillbit_submission_response_invalid",
                committed=True,
            )
        try:
            data = (
                base64.b64decode(body.encode("ascii"), validate=True)
                if encoded
                else body.encode("utf-8")
            )
        except (UnicodeEncodeError, binascii.Error) as exc:
            raise _SkillBitSubmissionError(
                "skillbit_submission_response_invalid",
                committed=True,
            ) from exc
        if not data or len(data) > maximum:
            raise _SkillBitSubmissionError(
                "skillbit_submission_response_invalid",
                committed=True,
            )
        try:
            document = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _SkillBitSubmissionError(
                "skillbit_submission_response_invalid",
                committed=True,
            ) from exc
        if not isinstance(document, dict):
            raise _SkillBitSubmissionError(
                "skillbit_submission_response_invalid",
                committed=True,
            )
        return document

    def _submit_with_fetch(
        self,
        channel: BrowserUiCdpChannel,
        *,
        challenge_id: str,
        candidate: str,
        origin: str,
        event_id: str,
    ) -> dict[str, Any]:
        deadline = deadline_after(self._timeout())
        maximum = self._response_limit()
        committed = False
        fetch_interception_armed = False
        scorer_document: dict[str, Any] | None = None
        request_id: str | None = None
        duplicate_blocked = False
        candidate_cleanup_confirmed: bool | None = None
        response_release_confirmed = True
        post_verdict_monitoring_confirmed = True
        candidate_prepared = False
        pending_error: _SkillBitSubmissionError | None = None
        try:
            channel.command(
                "Fetch.enable",
                {
                    "patterns": [
                        {
                            "urlPattern": f"{origin}/{event_id}/api/submit.php*",
                            "requestStage": "Request",
                        },
                        {
                            "urlPattern": f"{origin}/{event_id}/api/submit.php*",
                            "requestStage": "Response",
                        },
                    ],
                    "handleAuthRequests": False,
                },
                deadline=deadline,
            )
            fetch_interception_armed = True
            prepared = channel.call_function(
                _SET_CANDIDATE_FUNCTION,
                [int(challenge_id), candidate, origin, event_id],
                deadline=deadline,
            ).value
            if not isinstance(prepared, dict) or prepared.get("ok") is not True:
                raise _SkillBitSubmissionError(
                    "skillbit_submission_prepare_failed",
                    committed=False,
            )
            if prepared.get("alreadySolved") is True:
                raise _SkillBitSubmissionError(
                    "skillbit_challenge_solved_before_dispatch",
                    committed=False,
                    fetch_interception_armed=fetch_interception_armed,
                    candidate_cleanup_confirmed=True,
                )
            candidate_prepared = True
            committed = True
            triggered = channel.call_function(
                _TRIGGER_SUBMISSION_FUNCTION,
                [int(challenge_id)],
                deadline=deadline,
            ).value
            if triggered is not True:
                raise _SkillBitSubmissionError(
                    "skillbit_submission_trigger_failed",
                    committed=True,
                )
            while scorer_document is None:
                message = channel.receive_message(deadline=deadline)
                if message.get("method") != "Fetch.requestPaused":
                    continue
                params = message.get("params")
                if not isinstance(params, dict):
                    raise _SkillBitSubmissionError(
                        "skillbit_submission_event_invalid",
                        committed=committed,
                    )
                paused_id = params.get("requestId")
                if not isinstance(paused_id, str) or not paused_id:
                    raise _SkillBitSubmissionError(
                        "skillbit_submission_event_invalid",
                        committed=committed,
                    )
                is_response = "responseStatusCode" in params
                if not is_response:
                    matches = self._submission_request_matches(
                        params.get("request"),
                        challenge_id=challenge_id,
                        candidate=candidate,
                        origin=origin,
                        event_id=event_id,
                    )
                    if request_id is not None or not matches:
                        channel.command(
                            "Fetch.failRequest",
                            {
                                "requestId": paused_id,
                                "errorReason": "BlockedByClient",
                            },
                            deadline=deadline,
                        )
                        if request_id is not None:
                            duplicate_blocked = True
                            continue
                        raise _SkillBitSubmissionError(
                            "skillbit_submission_request_invalid",
                            committed=committed,
                        )
                    request_id = paused_id
                    channel.command(
                        "Fetch.continueRequest",
                        {"requestId": paused_id},
                        deadline=deadline,
                    )
                    continue
                request = params.get("request")
                status_code = params.get("responseStatusCode")
                if (
                    request_id is None
                    or paused_id != request_id
                    or isinstance(status_code, bool)
                    or status_code != 200
                    or not isinstance(request, dict)
                    or request.get("method") != "POST"
                    or request.get("url") != f"{origin}/{event_id}/api/submit.php"
                    or params.get("responseErrorReason") is not None
                    or params.get("resourceType") not in {"XHR", "Fetch"}
                ):
                    raise _SkillBitSubmissionError(
                        "skillbit_submission_response_invalid",
                        committed=True,
                    )
                body_result = channel.command(
                    "Fetch.getResponseBody",
                    {"requestId": paused_id},
                    deadline=deadline,
                )
                scorer_document = self._submission_response_body(
                    body_result,
                    maximum=maximum,
                )
                status = scorer_document.get("status")
                title = scorer_document.get("title", "")
                if (
                    status not in {"success", "error", "info"}
                    or not isinstance(title, str)
                    or len(title.encode("utf-8")) > 512
                ):
                    raise _SkillBitSubmissionError(
                        "skillbit_submission_response_invalid",
                        committed=True,
                    )
                try:
                    channel.command(
                        "Fetch.continueResponse",
                        {"requestId": paused_id},
                        deadline=deadline,
                    )
                except BrowserUiCdpError:
                    response_release_confirmed = False
            quiet_deadline = deadline_after(0.25)
            while True:
                try:
                    message = channel.receive_message(deadline=quiet_deadline)
                except BrowserUiCdpError as exc:
                    if exc.reason == "browser_ui_cdp_timeout":
                        break
                    post_verdict_monitoring_confirmed = False
                    break
                if message.get("method") != "Fetch.requestPaused":
                    continue
                params = message.get("params")
                paused_id = params.get("requestId") if isinstance(params, dict) else None
                if not isinstance(paused_id, str) or not paused_id:
                    post_verdict_monitoring_confirmed = False
                    break
                try:
                    channel.command(
                        "Fetch.failRequest",
                        {
                            "requestId": paused_id,
                            "errorReason": "BlockedByClient",
                        },
                        deadline=deadline_after(1.0),
                    )
                except BrowserUiCdpError:
                    post_verdict_monitoring_confirmed = False
                    break
                duplicate_blocked = True
            for _attempt in range(2):
                try:
                    cleared = channel.call_function(
                        _CLEAR_CANDIDATE_FUNCTION,
                        [int(challenge_id)],
                        deadline=deadline_after(1.0),
                    ).value
                    candidate_cleanup_confirmed = cleared is True
                except BrowserUiCdpError:
                    candidate_cleanup_confirmed = False
                if candidate_cleanup_confirmed:
                    candidate_prepared = False
                    break
            return {
                "status": status,
                "title": title,
                "duplicate_blocked": duplicate_blocked,
                "candidate_cleanup_confirmed": candidate_cleanup_confirmed,
                "fetch_interception_armed_until_close": True,
                "response_release_confirmed": response_release_confirmed,
                "post_verdict_monitoring_confirmed": (
                    post_verdict_monitoring_confirmed
                ),
            }
        except _SkillBitSubmissionError as exc:
            exc.fetch_interception_armed = fetch_interception_armed
            pending_error = exc
            raise
        except (BrowserUiCdpError, OSError, RuntimeError, TypeError, ValueError) as exc:
            pending_error = _SkillBitSubmissionError(
                "skillbit_submission_failed",
                committed=committed,
                fetch_interception_armed=fetch_interception_armed,
                candidate_cleanup_confirmed=candidate_cleanup_confirmed,
            )
            raise pending_error from exc
        finally:
            if candidate_prepared:
                try:
                    cleared = channel.call_function(
                        _CLEAR_CANDIDATE_FUNCTION,
                        [int(challenge_id)],
                        deadline=deadline_after(1.0),
                    ).value
                    candidate_cleanup_confirmed = cleared is True
                except BrowserUiCdpError:
                    candidate_cleanup_confirmed = False
            if pending_error is not None:
                pending_error.candidate_cleanup_confirmed = (
                    candidate_cleanup_confirmed
                )

    @staticmethod
    def _verdict(status: str, response_path: Path) -> dict[str, Any]:
        if status == "success":
            document: dict[str, Any] = {"data": {"correct": True, "status": "correct"}}
        elif status == "error":
            document = {"data": {"correct": False, "status": "incorrect"}}
        else:
            document = {"data": {"status": "unknown"}}
        return parse_verdict(
            document,
            source_path=str(response_path),
            allow_text_fallback=False,
            http_status=200,
        ).to_dict()

    def execute_action(
        self,
        envelope: dict[str, Any],
        evidence_root: Path,
    ) -> dict[str, Any]:
        lease = self._current_lease()
        target: OwnedBrowserTarget | None = None
        response_path = evidence_root / "response.json"
        status = "unknown"
        title = ""
        dispatched = False
        gateway_transfer_verified: bool | None = None
        cleanup_confirmed: bool | None = None
        duplicate_request_blocked: bool | None = None
        candidate_cleanup_confirmed: bool | None = None
        fetch_interception_armed_until_close: bool | None = None
        response_release_confirmed: bool | None = None
        post_verdict_monitoring_confirmed: bool | None = None
        scorer_known = False
        teardown_debt: dict[str, str] | None = None
        try:
            if (
                scope_sha256(self.scope) != lease.scope_sha256
                or str(envelope.get("objective_id") or "") != lease.challenge_id
                or envelope.get("action_kind") not in {"flag", "free_text"}
            ):
                raise RuntimeError("skillbit_lease_binding_changed")
            candidate = envelope.get("exact_value")
            if (
                not isinstance(candidate, str)
                or not candidate
                or "\x00" in candidate
                or len(candidate.encode("utf-8")) > _MAX_CANDIDATE_BYTES
            ):
                raise RuntimeError("skillbit_candidate_invalid")
            (
                target,
                current,
                origin,
                event_id,
                account_id,
                gateway_url,
                gateway,
                _cdp_url,
                _environment_origin,
            ) = self._open_event_session(authenticate=False)
            if (
                origin != lease.origin
                or event_id != lease.event_id
                or account_id != lease.account_id
                or self._participation()[2] != lease.participation_identity
                or gateway.boot_nonce != lease.gateway_boot_nonce
                or gateway.policy_sha256 != lease.gateway_policy_sha256
                or gateway.expires_at != lease.gateway_expires_at
            ):
                raise RuntimeError("skillbit_gateway_binding_changed")
            matches = [item for item in current if item["id"] == lease.challenge_id]
            if (
                len(matches) != 1
                or matches[0].get("hidden") is not False
                or matches[0].get("solvable") is not True
                or matches[0].get("submittable") is not True
                or matches[0].get("submission_mode") != "text"
            ):
                raise RuntimeError("skillbit_challenge_binding_changed")
            if matches[0].get("solved") is True:
                raise RuntimeError("skillbit_challenge_solved_after_preflight")
            ensure_private_dir(evidence_root)
            atomic_write_json(
                evidence_root / "request.json",
                {
                    "adapter_id": self.id,
                    "objective_id": lease.challenge_id,
                    "candidate": candidate,
                    "action_kind": envelope.get("action_kind"),
                    "operation": "skillbit_ui_submit",
                    "gateway_policy_sha256": lease.gateway_policy_sha256,
                },
                mode=0o600,
            )
            before = self._gateway_counters(gateway_url, gateway)
            if time.monotonic() > lease.expires_at:
                raise RuntimeError("skillbit_preflight_lease_expired")
            try:
                submission = self._submit_with_fetch(
                    target.channel,
                    challenge_id=lease.challenge_id,
                    candidate=candidate,
                    origin=lease.origin,
                    event_id=lease.event_id,
                )
            except _SkillBitSubmissionError as exc:
                dispatched = exc.committed
                fetch_interception_armed_until_close = exc.fetch_interception_armed
                candidate_cleanup_confirmed = exc.candidate_cleanup_confirmed
                raise
            status = str(submission["status"])
            title = str(submission["title"])
            dispatched = True
            duplicate_request_blocked = bool(submission["duplicate_blocked"])
            candidate_cleanup_confirmed = bool(
                submission["candidate_cleanup_confirmed"]
            )
            fetch_interception_armed_until_close = bool(
                submission["fetch_interception_armed_until_close"]
            )
            response_release_confirmed = bool(
                submission["response_release_confirmed"]
            )
            post_verdict_monitoring_confirmed = bool(
                submission["post_verdict_monitoring_confirmed"]
            )
            try:
                after = self._gateway_counters(gateway_url, gateway)
                self._require_gateway_transfer(before, after)
                gateway_transfer_verified = True
            except RuntimeError:
                gateway_transfer_verified = False
            scorer_known = status in {"success", "error"}
            try:
                target.close(deadline=deadline_after(2.0))
                cleanup_confirmed = True
            except BrowserUiCdpError as exc:
                cleanup_confirmed = False
                teardown_debt = {
                    "target_id": target.target_id,
                    "reason": exc.reason,
                }
            if cleanup_confirmed:
                target = None
            response = {
                "adapter_id": self.id,
                "objective_id": lease.challenge_id,
                "operation": "skillbit_ui_submit",
                "dispatched": dispatched,
                "skillbit_status": status,
                "title": title,
                "gateway_transfer_verified": gateway_transfer_verified,
                "target_cleanup_confirmed": cleanup_confirmed,
                "duplicate_request_blocked": duplicate_request_blocked,
                "candidate_cleanup_confirmed": candidate_cleanup_confirmed,
                "fetch_interception_armed_until_close": (
                    fetch_interception_armed_until_close
                ),
                "response_release_confirmed": response_release_confirmed,
                "post_verdict_monitoring_confirmed": (
                    post_verdict_monitoring_confirmed
                ),
                "teardown_debt": teardown_debt,
            }
            atomic_write_json(response_path, response, mode=0o600)
            return {
                "response": response,
                "response_path": str(response_path),
                "verdict": self._verdict(status, response_path),
            }
        except (BrowserUiCdpError, OSError, RuntimeError, TypeError, ValueError):
            if dispatched or scorer_known:
                target_id = target.target_id if target is not None else None
                if target is not None and not target.closed:
                    try:
                        target.close(deadline=deadline_after(2.0))
                        cleanup_confirmed = True
                        target = None
                    except BrowserUiCdpError as exc:
                        cleanup_confirmed = False
                        teardown_debt = {
                            "target_id": target_id or "",
                            "reason": exc.reason,
                        }
                ensure_private_dir(evidence_root)
                response = {
                    "adapter_id": self.id,
                    "objective_id": lease.challenge_id,
                    "operation": "skillbit_ui_submit",
                    "dispatched": dispatched,
                    "skillbit_status": status if scorer_known else "unknown",
                    "target_id": target_id,
                    "target_cleanup_confirmed": cleanup_confirmed,
                    "candidate_cleanup_confirmed": candidate_cleanup_confirmed,
                    "fetch_interception_armed_until_close": (
                        fetch_interception_armed_until_close
                    ),
                    "teardown_debt": teardown_debt,
                }
                atomic_write_json(response_path, response, mode=0o600)
                return {
                    "response": response,
                    "response_path": str(response_path),
                    "verdict": self._verdict(
                        status if scorer_known else "unknown",
                        response_path,
                    ),
                }
            raise
        finally:
            if target is not None and not target.closed:
                try:
                    target.close(deadline=deadline_after(2.0))
                except BrowserUiCdpError:
                    if not scorer_known:
                        raise
