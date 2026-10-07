# Configuration

The private `.env` in an installed workspace is Rookery's only normal operator-edited configuration file. Rookery combines shipped profile defaults, the adapter selected by `PLATFORM_ADAPTER`, typed `.env` values, and selected extension overlays into one resolved event.

The reviewed [`.env.example`](../.env.example) is the full key catalog. Adapter-local `env.example` files and READMEs explain selected subsets; copy the needed values into the workspace `.env` rather than editing adapter files. `state/resolved_event.json` and `state/scope.json` are generated runtime views, not configuration inputs.

## Contents

- [Live and release configuration](#live-and-release-configuration)
- [Minimum event decisions](#minimum-event-decisions)
- [Scope](#scope)
- [Codex authentication](#codex-authentication)
- [Autonomous Codex settings](#autonomous-codex-settings)
- [Worker capacity](#worker-capacity)
- [Low-priority compute](#low-priority-compute)
- [Preparation and network acquisition](#preparation-and-network-acquisition)
- [Browser session](#browser-session)
- [Adapters and extensions](#adapters-and-extensions)
- [Queue and authorization](#queue-and-authorization)
- [Configuration changes](#configuration-changes)
- [Legacy event migration](#legacy-event-migration)

## Live and release configuration

A clean source checkout may omit live `.env`. An extracted release already contains a mode-`0600` `.env` synthesized from `.env.example`. For a local source-only workflow, create it without replacing an existing file:

```bash
test ! -e .env && cp .env.example .env
chmod 600 .env
```

The release builder always uses the reviewed example, so local live values never enter the ZIP, release manifest, or build summary. `./go` never creates or replaces `.env`.

The dotenv reader treats assignments as bounded literal data. It never executes expansion, substitutions, or commands. Duplicate names, malformed values, removed selectors, unknown nonblank names, and nonblank fields owned by an unselected adapter fail closed. Blank values and the legacy placeholder `unknown` leave shipped profile defaults in place; required unresolved decisions still block readiness.

The normal sequence is:

1. Edit `.env`.
2. Run `PYTHONDONTWRITEBYTECODE=1 ./bin/rookery validate --release` in the installed release to validate `.env` and the resolved configuration. Use `--source-checkout` only for the separate pre-build source check.
3. Create the private release-bound measurement baseline.
4. Prepare any required external browser, gateway, VPN, or platform session.
5. Run `./go`.

## Minimum event decisions

Before validation and baseline creation, set and review:

1. **Identity:** `EVENT_ID`, `EVENT_NAME`, and the applicable `EVENT_URL`, `EVENT_START`, and `EVENT_END` values.
2. **Adapter and surface:** `PLATFORM_ADAPTER`, plus any `EVENT_EXTENSIONS` and `EVENT_CATEGORIES`.
3. **Scope:** the `ALLOWED_*`, `PLATFORM_HOSTS`, `SCOPE_MAX_BYTES`, and `SCOPE_EXPIRES_AT` keys.
4. **Acknowledgement:** `EVENT_SCOPE_ACK=1` only after the final scope is correct and authorized.
5. **Answer and scoring:** `FLAG_REGEX`, `ANSWER_EXAMPLES_JSON`, `SCORING_ACTION_KINDS`, and `SCORING_COMPLETION_MODE`.
6. **Baseline path:** `ROOKERY_MEASUREMENT_BASELINE_PATH` as an absolute private path outside the workspace.
7. **Capacity:** native workers, background jobs, and spawned threads in the one Codex session.
8. **Preparation:** whether declared package or image acquisition may use the network.

Rookery does not infer event facts. A required value left blank remains governed by the shipped profile and blocks launch when that default is unresolved.

## Scope

The private `.env` is the operator input for scope. `state/scope.json` is a generated checked cache. Scope acknowledgement is authorization metadata, not a discovery shortcut. Raw shell cannot be fully intercepted; Rookery-owned helpers enforce the compiled boundary described in [Event scope](scope.md), and agents remain responsible for that same declared boundary when using raw tools.

## Codex authentication

The default is:

```dotenv
CODEX_AUTH_MODE=local-login
CODEX_PROVIDER_ENV_KEYS=[]
CODEX_NETWORK_ENV_KEYS=[]
```

This requires a successful cached `codex login status` and does not pass provider, proxy, or CA variables to Codex. `CODEX_AUTH_MODE=environment` is an explicit advanced path that requires named provider credentials, strict configuration support from the installed Codex, and a successful login probe using the same filtered environment as the launcher.

Adapter, session, VPN, and unrelated provider secrets are excluded from Codex and unrelated children. A selected adapter or helper receives only declared keys.

## Autonomous Codex settings

[`configs/codex-base.toml`](../configs/codex-base.toml) is rendered into `.codex/config.toml`:

```toml
approval_policy = "never"
sandbox_mode = "danger-full-access"

[agents]
max_concurrent_threads_per_session = 96
max_depth = 2
job_max_runtime_seconds = 5400
```

Before Codex starts, Rookery replaces the safe bootstrap thread value with
`CODEX_SUBAGENT_THREADS`. The configured value is 96 and counts every spawned
agent thread in the one Codex session, excluding the main coordinator thread.
`max_depth = 2` permits challenge coordinators at depth 1 to delegate one level
to bounded workers at depth 2.

Codex can read and write as the operator account, run processes, and use the network without per-action approval. Event scope and Rookery mutation protocols remain binding, but they are not an operating-system sandbox for arbitrary shell commands.

## Worker capacity

Three independent `.env` limits bound work in the single-session model:

| Key | Controls |
| --- | --- |
| `CONCURRENCY_MAX_WORKERS=auto` | Concurrent Rookery-registered native worker attempts. `auto` resolves from affinity-visible logical CPUs; a positive integer is a deliberate fixed cap. |
| `CODEX_SUBAGENT_THREADS=96` | Shared ceiling for all spawned Codex threads, including challenge coordinators and their workers. The depth-0 main coordinator is excluded. |
| `CONCURRENCY_MAX_JOBS` | All Rookery-owned background processes. Native Codex subagents do not consume background-job slots. |

After launch, the main coordinator asks the operator how many challenges to
keep active. It creates that many depth-1 challenge coordinator subagents,
gives each exactly one challenge, and refills a slot after its report is
harvested and its attempt is closed. Challenge coordinators may create bounded
depth-2 workers, but the main coordinator, all challenge coordinators, and all
workers draw from the same 96 spawned-thread slots. The requested active
challenge count therefore remains an operating goal within current shared
capacity, rather than a reserved number of threads per challenge.

Finalize host size and process affinity before the baseline. Affinity-based
auto sizing does not account for cgroup CPU quotas. After launch, inspect
`state/resolved_event.json` for resolved limits and `.codex/config.toml` for
the rendered session cap and depth.

## Low-priority compute

The compute idea queue holds useful, checkpointable work for otherwise idle capacity. It is separate from scoring and grants no platform authority. A coordinator calls `./bin/rookery compute tick` after worker harvests or before an idle wait; the command returns at most one lease or pause request and never starts or signals work itself.

The default best-effort target is 75% across affinity-visible Linux CPUs. Configure it with `COMPUTE_ADMIT_PERCENT`, `COMPUTE_TARGET_PERCENT`, `COMPUTE_CEILING_PERCENT`, and `COMPUTE_BACKOFF_PERCENT`, preserving `0 <= admit < target <= ceiling < backoff <= 100`. `COMPUTE_SAMPLE_SECONDS`, `COMPUTE_ADMISSION_COOLDOWN_SECONDS`, `COMPUTE_LEASE_SECONDS`, and `COMPUTE_DEFAULT_JOB_BUDGET_SECONDS` control timing; `COMPUTE_TOTAL_UNITS` and `COMPUTE_INTERACTIVE_RESERVE` bound capacity. Missing or malformed CPU metrics admit nothing. See [Coordination](coordination.md).

## Preparation and network acquisition

`ROOKERY_ALLOW_INSTALL_NETWORK=0` prevents package downloads and managed image pulls. `ROOKERY_PREPARE_MODE=auto` can still discover installed tools. Set network acquisition to `1` only for an intended run whose environment and event authorization permit it.

An external `SEARXNG_URL` is used unchanged. Without one, the reviewed digest-pinned image can start on loopback only when network acquisition is enabled. Rookery does not download a browser, and VPN lifecycle remains external. See [Preparation](preparation.md).

## Browser session

`BROWSER_MODE=cdp` requires a Chrome DevTools endpoint at the loopback
`BROWSER_CDP_URL`, such as `http://127.0.0.1:9001`. For `ctfd_browser`,
`BROWSER_MODE=bidi` selects the shared Firefox WebDriver BiDi connection at
`BROWSER_BIDI_URL`, such as `ws://127.0.0.1:9223/session`. A sealed browser
gateway also requires `BROWSER_GATEWAY_URL`, normally
`http://127.0.0.1:9003`, and remains CDP-only. Set the selected endpoint
before the baseline and keep it available before `./go`.

For `ctfd_browser_gateway`, keep `CTFD_TOKEN` private and set the selected adapter's typed keys in `.env`: `ADAPTER_CONFIG_BASE_URL`, `ADAPTER_CONFIG_TOKEN_ENV`, `ADAPTER_CONFIG_SCORING_MODE`, `ADAPTER_CONFIG_EXPECTED_ACCOUNT_ID`, conditional `ADAPTER_CONFIG_EXPECTED_TEAM_ID`, `ADAPTER_CONFIG_CSRF_PAGE_PATH`, lease and timeout controls, and `ADAPTER_CONFIG_BROWSER_SUPPORT_ORIGINS`. Authorize every support origin's host separately in `PLATFORM_HOSTS`. Token-first operation does not make Chrome optional; the sealed gateway remains the prepared fallback.

For SkillBit, select the public adapter ID with `PLATFORM_ADAPTER=skillbit`. Set `SKILLBIT_URL` to the exact scoring origin, `SKILLBIT_LOGIN_ORIGIN` to the exact account origin, `SKILLBIT_EVENT_ID` to the authorized numeric event, and `SKILLBIT_ACCOUNT_ID` to the numeric account identifier in that event card's signed handoff URL. Set `SKILLBIT_PARTICIPATION_MODE=individual` or use `team` with an operator-attested `SKILLBIT_TEAM_NAME`; these values are bound by the private baseline. Keep the three credential fields private and leave their values out of reviewed or shared configuration examples:

```dotenv
SKILLBIT_USER=
SKILLBIT_PASSWORD=
SKILLBIT_EMAIL=
```

Declare only the required exact HTTPS support origins in `ADAPTER_CONFIG_BROWSER_SUPPORT_ORIGINS`. Put the hosts for `SKILLBIT_URL`, `SKILLBIT_LOGIN_ORIGIN`, and every support origin in `PLATFORM_HOSTS`; reserve `ALLOWED_HOSTS` and `ALLOWED_CIDRS` for organizer-designated challenge targets. Authorize authenticated SkillBit downloads with an event-specific file pattern rather than the whole origin:

```dotenv
ALLOWED_FILE_ORIGINS=https://compete.metactf.com/289/api/attachments/*,https://cfstatic.mctf.io/*,https://metactf-problems.s3.us-east-1.amazonaws.com/*,https://metachallenge-artifacts-158909019700-us-east-1-an.s3.amazonaws.com/*,https://static.metaproblems.com/*,https://metaproblems.com/*,https://cyberlabhost.com/*
```

Replace `289` with `SKILLBIT_EVENT_ID`. The compiled `SCOPE_MAX_BYTES` limit applies to every capture. The operator must have event authority for the stated human and AI partnership and this bounded UI automation before acknowledging scope. `skillbit` always requires both the dedicated Chrome endpoint and sealed gateway; CDP remains its internal authenticated UI transport for sync, detail, attachment authentication, and reviewed scoring.

Export and operate the Windows components as a versioned, release-verified browser bridge. The [browser bridge runbook](browser_bridge.md) owns its bundle, policy, profile, dynamic WSL resolution, health, stop, upgrade, and restart procedure.

The launch gate performs bounded, no-proxy loopback checks before state is written and immediately before it publishes the launch binding. Read [Preparation](preparation.md) and the selected adapter README for setup and failure behavior.

## Adapters and extensions

`PLATFORM_ADAPTER` selects exactly one packaged adapter or `manual`. Its reviewed descriptor type-checks the selected adapter's documented `ADAPTER_CONFIG_*`, credential, and transport keys. Nonblank fields belonging to another adapter fail validation and are never passed to a child.

`EVENT_EXTENSIONS` selects optional activity modes under `extensions/`. Extension-specific settings are copied into the one workspace `.env`. The resolved event controls which agents and tools appear in generated `ACTIVE_SURFACE.md`.

## Queue and authorization

`QUEUE_AUTOMATION=0` is the default. Enabling it starts one Rookery-owned watcher after the launch gate, but grants no scoring authority. Independent review, exact or bounded operator authorization, cadence, scope, policy generation, and stop generation still apply.

`AUTOMATION_PERMITTED_ACTION_KINDS` declares which action kinds may receive a bounded allowance. It grants nothing by itself; authorization always starts at zero.

## Configuration changes

The measurement baseline and first launch bind the live `.env`, canonical resolved-manifest digest, release, workspace, and Codex executable. Any `.env` change before first launch requires a new no-clobber baseline path and record. This includes a SkillBit credential, identity, event ID, scoring or login origin, support-origin list, attachment-origin pattern, or browser endpoint change; the baseline retains no credential value, but its live `.env` binding must be recreated. After runtime state exists, do not delete the binding or copy state into a differently configured tree; create a clean side-by-side workspace and its matching browser bundle, policy, and profile.

## Legacy event migration

Legacy JSON is not a launch input. The only reader is the explicit offline migration command:

```bash
./bin/rookery config migrate-event \
  --input ./event.json \
  --env ./.env \
  --output ./.env.migrated
```

The command is private, no-clobber, and has no network or launch effect. It leaves both inputs unchanged, rejects conflicts and fields without a documented `.env` equivalent, and writes a draft for operator review. Review the draft, replace the private `.env` with ordinary local file operations, validate, and create a fresh baseline. Removed `EVENT_MANIFEST` and `EVENT_ADAPTER` selectors fail with `event_manifest_removed_use_migrate_event`; they are not compatibility aliases.
