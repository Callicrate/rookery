# Research

Start with local artifacts and the included knowledge corpus. Use public
research only when it can answer a concrete gap. Rookery may make SearXNG
available during preparation; read `PREPARATION.md` and `ACTIVE_SURFACE.md`
instead of assuming an endpoint or tool exists.

## A Useful Research Pass

1. State the question, target, and stop condition in the worker card.
2. Search local evidence and the corpus for established techniques.
3. Record the query family, sources, useful paths, and negative result in the
   assigned report.
4. Use fresh public research for terms, versions, or techniques that local
   evidence cannot settle.
5. Turn the result into a bounded experiment, a new worker question, or a
   documented technical negative.

Preserve query families and negative snapshots so a retry is materially new.
Repeated broad searching is not progress. When research stalls, change the
method: use a fresh naive solver, hard investigation, bounded fuzzing or brute
force, corpus research, or an external-state retry with a named trigger.

Rookery-owned network and attachment helpers enforce the compiled event scope.
Raw-shell network use remains subject to the operator-declared scope and must
be recorded as operator-side research; it is not automatically Rookery
evidence. Generic browser navigation, page interaction, capture, and arbitrary
HTTP capture are unavailable as research tools. When selected, the
`ctfd_browser_gateway` adapter may use Chrome only for its fixed CTFd reads and
one reviewed scoring attempt; that adapter transport is not a general browser
research surface. The public `skillbit` adapter likewise uses CDP only as an
internal authenticated UI transport for exact-origin session establishment,
bounded inventory, and one reviewed scoring attempt. It exposes no generic
browser research tool. The event's official rules and operator-provided event
authority must permit the applicable automation and, for SkillBit, the stated
human and AI partnership. See
[Platform adapters](./adapters.md), [Tools and wrappers](./tools_and_wrappers.md),
and [Scope](./scope.md).
