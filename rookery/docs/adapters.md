# Platform Adapters

Rookery is generic until an event selects an adapter. An adapter translates a platform's inventory, session, scoring, and artifact behavior into Rookery's normalized contracts. It cannot expand the event's scope, authorize an action, or bypass the stop barrier.

Select exactly one adapter with `PLATFORM_ADAPTER` in the private `.env`. The [event configuration reference](./event_profiles.md) explains precedence and resolution. The [operator guide](./operator.md) owns the start and stop commands.

## Selected adapter boundary

Packaged adapters have a directory under `adapters/<id>/`. Its descriptor names the implementation, profile, typed environment schema, optional tool and agent catalogues, local documentation, and environment example. Read that selected adapter's `README.md` and `env.example`, then put the required values in the workspace `.env`. The built-in `manual` adapter instead uses [`profiles/manual.json`](../profiles/manual.json) and has no adapter-local directory or environment file. Nonblank keys owned by an unselected adapter fail validation and are never passed to a child.

Optional activity modes belong in `extensions/<id>/`, not in an adapter. They are selected through `EVENT_EXTENSIONS` and may add a declared profile overlay, agents, or tools without turning generic Rookery into a platform-specific system.

## Normalized boundary

The generic controllers consume a normalized snapshot rather than a platform's raw API shape. It covers challenge inventory and details, release changes, capability and session health, collaboration signals, scoring capabilities, and artifact provenance. Each capability states its availability, health, freshness, read/write scope, and permitted mutations.

That separation has two consequences:

- An unavailable adapter capability is visible as unavailable; local analysis can continue without inventing platform facts.
- Scoring still passes through the generic proposal, review, authorization, plan, execution, and reconciliation path described in [Scoring review](./scoring_review.md).

`ACTIVE_SURFACE.md` is the runtime record of the tools and agents selected by the resolved event. It is not a static promise that every optional adapter tool is present.

## Command and environment contract

Command-backed adapters accept inventory and submission commands only as JSON arrays of argv strings. Their typed `.env` fields include `ADAPTER_CONFIG_INVENTORY_ARGV` and `ADAPTER_CONFIG_SUBMIT_ARGV`; string shell templates are rejected. Placeholder substitution occurs within an argv element and the child runs with `shell=False`.

Inventory and submission declare separate exact environment-key arrays. Only the selected child receives those named values. Wildcards, ambient credential inheritance, and string shell commands are rejected. Adapter output is bounded and an overflow is a visible failure rather than an unbounded capture.

For HTTP-backed adapters, URL and credential values are read as bounded dotenv data only when an adapter operation needs them. Requests use the shared scoped transport: it rechecks the event boundary, pins the authorized DNS result, and does not forward platform credentials through a proxy. See [Event scope](./scope.md) for the transport rules.

## Browser-backed adapters

A selected adapter may require a verified loopback browser endpoint. Browser
protocol connection and session reads live in shared browser modules; the
selected adapter retains platform-specific URL, cookie, identity, and scoring
rules. Its local README defines the exact browser authority:

- [`ctfd_browser`](../adapters/ctfd_browser/README.md) selects Chromium CDP or Firefox WebDriver BiDi through `BROWSER_MODE`. It reads the selected page's user agent and applicable cookies without navigation or clicks. Its fixed identity, inventory, anti-forgery, and reviewed submission requests use Rookery's DNS-pinned scoped HTTP transport.
- [`ctfd_browser_gateway`](../adapters/ctfd_browser_gateway/README.md) is token-first with a prepared sealed Chrome gateway fallback. Its read-only preflight first tries fixed, DNS-pinned token requests for account, team when applicable, and inventory. Only HTTP 401 or 403, a bounded successful HTML interstitial, one exact-origin access redirect, or a typed DNS, connection, or timeout failure from those reads may select the browser gateway. Configuration, scope, TLS, identity, successful JSON schema, HTTP 404 or 429, server, and cross-origin redirect failures do not.
- [`skillbit`](../adapters/skillbit/README.md) is the public adapter ID for the SkillBit competition UI. It uses a dedicated, authenticated Chrome session through loopback CDP and the sealed gateway. Its production `sync()` path establishes or refreshes the account session, proves one exact configured event card and account-bound signed handoff, and returns bounded row-local challenge modalities. CDP is its internal transport rather than a generic browser surface.

The shared Firefox BiDi connection is available for adapter-owned reads.
`ctfd_browser` is the current adapter that supports it for a complete scoring
path. `ctfd_browser_gateway` and `skillbit` retain their CDP contracts; their
owned target, gateway, and scorer response checks have not been ported to the
BiDi command and event model. Extending those adapters requires a separately
reviewed implementation of their owned-target, transport, and scorer-evidence
contracts; shared Firefox session access alone does not provide that behavior.

The selected adapter ID remains `ctfd_browser_gateway` whichever internal transport its preflight selects. If token transport is selected, execution may issue exactly one reviewed token POST. Once that POST call starts, every error is potentially committed and the adapter never retries through Chrome. If browser transport is selected, the adapter uses a fresh owned Chrome target for its fixed account, team, anti-forgery, inventory, and reviewed submission requests, then closes that target without reusing or closing the operator's authentication tab.

The `skillbit` adapter constrains top-level UI flow to the configured login origin, scoring origin, one configured event, and the event's Problems view. Its sealed gateway admits only those platform origins and declared support origins. Support origins remain platform infrastructure and never become challenge targets. Inventory comes from the platform-owned challenge registry. Unsupported, manual, choice, lab, or locked challenge modalities remain visible as row-local non-submittable states instead of invalidating otherwise usable inventory. `detail()` performs a fresh bounded challenge read and distinguishes authenticated attachments from other links.

The exact dashboard event card and its account-bound handoff are the registration proof available to the legacy SkillBit UI. Team identity remains explicitly unverified until the platform exposes a stable team or roster field. Registration, team selection, SSO, and other unexpected interactive states are reported without performing those mutations. A stale login is refreshed through `sync()` before a new action review; scoring preflight and execution do not enter credentials.

SkillBit anchors carrying the `mctf-s3dl` class on the configured event's exact attachment route can be captured through an adapter-owned authenticated download. The adapter checks `ALLOWED_FILE_ORIGINS`, reads only cookies applicable to that URL, applies the compiled attachment byte bound and redirect checks, and publishes the file without clobbering an existing path. Scoring invokes the platform submit method once under the reviewed execution plan. Redirect, identity, event, origin, response, or post-dispatch uncertainty fails closed or remains indeterminate under the adapter's typed contract. Definitive scorer truth is retained separately from candidate clearing, duplicate interception, response release, and target teardown state.

None of these adapters exposes generic browser navigation, page interaction, capture, or arbitrary browser fetches to coordinators or workers. There is no operator-UI fallback. Session material stays private, and identity drift, redirects outside the typed token-read access classification, or responses outside an adapter's fixed contract fail closed.

The event's official rules must permit the selected browser automation and scoring path. For `skillbit`, the operator supplies the event authority that permits the stated human and AI partnership and the bounded UI automation. Rookery does not infer that authority from the platform or adapter. Adapter selection does not expand event scope or grant submission authority; reviewed mutations still pass through Rookery's proposal, independent review, authorization, stop-generation check, execution, and reconciliation path.

## Adding an adapter

An adapter is an integration boundary, not a place to copy generic controller logic. A new adapter needs a descriptor, a profile overlay, implementation, local environment reference, and only the tools and agents justified by its capability gap. Keep platform-specific names, requests, session conventions, and credentials in that directory. Keep canonical state, independent review, authorization, and execution in the shared contracts.

The implementation contract is in the [adapter loader](../lib/rookery/portable/adapters.py); the resolver checks the descriptor before it exposes adapter contributions.
