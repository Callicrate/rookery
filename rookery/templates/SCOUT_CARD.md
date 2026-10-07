# Scout Card

Goal: <one bounded reconnaissance question>
Scope: <targets, files, allowed actions, forbidden actions, and budget>
Source handoff: none for an initial route; otherwise <handoff ID and report path>
Source report SHA-256: none for an initial route; otherwise <exact 64hex report hash>
Report: analysis/<lane>/REPORT.md
Save: <interesting evidence or artifact paths>
Cleanup: <owned process, job, or temporary-artifact responsibility>
Stop: <time, artifact, signal, or exact negative>

Write the report early from `templates/REPORT.md`. Before integration, replace
every placeholder, keep its exact `## Handoff` labels, and finish `## Evidence`
and `## Commands`. Return only new evidence, exact paths, the observed result,
the proof gap, and the next command or return trigger.
