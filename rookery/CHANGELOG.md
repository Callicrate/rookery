# Changelog

This file records operator-visible changes in immutable Rookery releases.

## 2026.10.05.15

- Reissued the audited source under one final immutable identity after the
  Windows bridge contract check. Start, health, and stop each retain one
  mode-specific JSON response, and start output omits the private gateway-policy
  digest.
- Completed the full code, documentation, prompt, skill, security, and release
  audit with no remaining release blocker.

Release `2026.10.05.14` remains an immutable historical candidate. This release
uses a fresh identity so the final source tree and handoff artifacts bind the
same reviewed bytes.

## 2026.10.05.14

- Hardened historical completion reconciliation by checking the exact pinned
  review's event order and generations without allowing later reviews to
  rewrite a completed execution.
- Made `--role challenge-coordinator` the explicit normal registration path in
  generated guidance while retaining compatibility normalization for shipped
  registry aliases.
- Kept Chrome bridge start, health, and stop responses separately structured
  while omitting the private gateway-policy digest from command output.
- Corrected the Chrome bridge upgrade anchor and clarified the current Firefox
  adapter boundary without tying the contract to one browser version.

Release `2026.10.05.13` remains an immutable historical artifact. This release
uses a fresh identity because completion validation and operator guidance
changed.

## 2026.10.05.13

- Kept completed scoring plans bound to the exact approved review event pinned
  in their immutable plan. A later review record can no longer invalidate
  historical scorer truth, completion records, capsules, or closeout writeups.

Release `2026.10.05.12` remains an immutable historical artifact. This release
uses a fresh identity because historical completion reconciliation changed.

## 2026.10.05.12

- Fixed multi-count scoring allowances after their first use by restricting
  plan admission's latest-authority scan to authorization events. Later
  `execution.started` records can no longer mask a re-granted remaining count.

Release `2026.10.05.11` remains an immutable historical artifact. This release
uses a fresh identity because scoring authorization admission changed.

## 2026.10.05.11

- Extended challenge-coordinator role normalization to the shipped
  `ctf_autopilot_coordinator` catalog identifier, allowing its registered
  depth-2 workers to satisfy the same lineage contract.

Release `2026.10.05.10` remains an immutable historical artifact. This release
uses a fresh identity because a second shipped coordinator spelling changed.

## 2026.10.05.10

- Normalized the registry-style `challenge_coordinator` role to the canonical
  `challenge-coordinator` lineage role at admission, so its depth-2 children
  pass parent validation and telemetry retains one stable spelling.

Release `2026.10.05.9` remains an immutable historical artifact. This release
uses a fresh identity because native child-agent admission changed.

## 2026.10.05.9

- Fixed execution-plan compilation for proposals whose solver attempt scope is
  nonempty while the platform challenge has no lifecycle scope. Plans now pin
  the proposal scope consistently and still reject a conflicting live platform
  lifecycle before authority is claimed.

Release `2026.10.05.8` remains an immutable historical artifact. This release
uses a fresh identity because the scoring authority contract changed.

## 2026.10.05.8

- Published the exact allowed artifact roots for structured handoffs and told
  workers to copy state or platform evidence into those roots before harvest.

Release `2026.10.05.7` remains an immutable historical artifact. This release
uses a fresh identity because the model-visible artifact contract changed.

## 2026.10.05.7

- Aligned `report-new` and `report-lint` with the canonical structured handoff
  template, replacing their retired section contract.

Release `2026.10.05.6` remains an immutable historical artifact. This release
uses a fresh identity because the report helper contract changed.

## 2026.10.05.6

- Made report artifact-path containment rules explicit to every worker and
  directed coordinators to the canonical `agent-harvest` integration path.
- Required challenge-linked objective IDs to equal their canonical challenge
  IDs, preventing handoff and outcome mismatches caused by local aliases.

Release `2026.10.05.5` remains an immutable historical artifact. This release
uses a fresh identity because the model-visible report contract changed.

## 2026.10.05.5

- Exposed the canonical review verdict values directly through CLI argument
  choices so reviewers cannot submit the near-miss `approve` value.

Release `2026.10.05.4` remains an immutable historical artifact. This release
uses a fresh identity because the reviewer command contract changed.

## 2026.10.05.4

- Made the canonical lower-case route-key grammar visible in every worker
  contract so completed handoffs can enter exploration without repair.

Release `2026.10.05.3` remains an immutable historical artifact. This release
uses a fresh identity because the model-visible handoff contract changed.

## 2026.10.05.3

- Bound depth-2 worker admission to an active depth-1 challenge coordinator
  for the same challenge, objective, and stop generation, and included role,
  parent, and depth in the signed assignment packet.
- Preserved canonical completion and solve-capsule eligibility when an
  independently reviewed action uses a coordinator allowance explicitly
  enabled by the operator's automation configuration.

Release `2026.10.05.2` remains an immutable historical artifact. This release
uses a fresh identity because worker lineage and completion provenance changed.

## 2026.10.05.2

- Replaced the coordinator subprocess architecture with one Codex session.
  The depth-0 main coordinator now asks how many challenges to keep active,
  uses native depth-1 challenge coordinators, and lets them delegate bounded
  depth-2 workers under one shared `CODEX_SUBAGENT_THREADS=96` ceiling.
- Kept platform synchronization, intake, browser lifecycle, review,
  authorization, scoring execution, and scorer reconciliation with the main
  coordinator while challenge coordinators own only their assigned challenge
  investigations.
- Removed the superseded coordinator-process command surface and persisted
  pool machinery. Coordinator refill now follows native subagent completion,
  report harvest, typed outcome recording, and attempt closure.
- Made sealed Chrome bridge gateway ports configurable and persisted their
  exact values in the guarded ownership record, allowing verified side-by-side
  browser tuples without manual process setup.
- Tightened challenge ownership, successor handoff, and release
  validation coverage found during independent review.

Release `2026.10.05.1` remains an immutable historical artifact. Its
separate-process coordinator design is superseded by the single-session native
subagent architecture in this release. This release uses a fresh identity
because browser ownership and coordinator dispatch behavior changed.

## 2026.10.05.1

- Added the first coordinator-process experiment for concurrent challenges.
  It maintained exclusive challenge ownership and kept platform, browser,
  review, authorization, scoring, and reconciliation as shared event-wide
  services.
- Required report and typed-outcome integration before reassigning an exited
  coordinator's challenge. Release `2026.10.05.2` supersedes this dispatch
  mechanism with native subagents in one Codex session.

Release `2026.10.02.1` remains an immutable historical artifact. This release
uses a fresh identity because coordinator ownership and dispatch behavior
changed.

## 2026.10.02.1

- Added a shared, loopback-only Firefox WebDriver BiDi connection for
  adapter-owned browser session reads.
- Let the browser-session competition adapter select Chromium CDP or Firefox
  BiDi through `BROWSER_MODE` while retaining its scoped HTTP inventory and
  reviewed scoring path.
- Kept the gateway and UI competition adapters on CDP because their required
  target and scorer response operations were not implemented by that release's
  Firefox BiDi adapter path.

Release `2026.09.28.31` remains an immutable historical artifact. This release
uses a fresh identity because the browser transport and adapter contract changed.

## 2026.09.28.31

- Extended verified challenge eligibility through the complete `flag` and
  `free_text` scoring path. Proposal admission, plan publication, authority
  claim, and final adapter dispatch now reject missing, unavailable, partial,
  or changed intake.
- Preserved authorization when challenge eligibility changes before the claim,
  and retained fail-closed final revalidation for the narrow post-claim race.
- Kept `no_submit_evidence` and proof-artifact workflows independent of the
  text-scoring intake gate.

Release `2026.09.28.30` remains an immutable historical artifact. This release
uses a fresh identity because scoring admission behavior changed.

## 2026.09.28.30

- Added verified challenge intake states and enforced solver eligibility before
  challenge-bound agent registration, exploration, compute, and Codex launch.
- Made challenge detail and attachment capture convergent under retries and
  concurrency, with private immutable artifacts, recorded hashes, exact capture
  identity, partial-state recovery, and serialized platform intake.
- Kept platform projections bounded while preserving the full canonical event
  history, and made snapshot artifact names collision resistant.
- Split repository maintainer skills from the four adapter-neutral operational
  skills shipped in every release.
- Removed retired aliases, unused configurations, an orphaned browser role, and
  unreachable legacy `playq` code. Corrected optional adapter and extension
  metadata to point at their actual packaged paths.
- Aligned browser bridge documentation with immutable release bundles and
  guarded lifecycle commands.
- Made release bytes independent of empty checkout directories and corrected
  executable modes for packaged command entry points.

Release `2026.09.28.29` remains an immutable historical artifact. This release
uses a fresh identity because its source and archive contents changed.
