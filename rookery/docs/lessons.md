# Stop-State Lessons

A normal `./go stop` creates exactly one document for the new canonical stop
generation:

```text
docs/retrospectives/lessons-learned-YYYYMMDDThhmmss.md
```

The document includes the immutable Rookery release version and is an input to
the next release. It is not an event handoff or score report.

## What Belongs There

Write reusable, Rookery-level improvements backed by local evidence:

- behavior to preserve;
- capabilities to add;
- changes to make;
- commands, routes, assumptions, or specialists to remove or simplify;
- agent, tooling, protocol, and operator-surface changes;
- adapter, network, and session contract improvements;
- anti-overfit notes; and
- small validation fixtures that would prove the proposed change.

Subtraction is first-class. Name the confusing behavior, why it failed to earn
its complexity, and the check that will keep it from returning.

Do not put flags, candidate answers, challenge solutions, score or frontier
status, raw operator handoff detail, or a run diary in this document. Those
belong in private evidence, reports, and writeups.

Use `./bin/lessons-learned status` to see whether the current generation has a
document. `./bin/lessons-learned create` is idempotent for that generation, but
the normal route is `./go stop`. If emergency stop runs after binding integrity
has failed, Rookery may be able to revoke work but cannot prove normal closeout;
the lessons document can be absent in that case. See
[State, policy, and stop](./state_policy_stop.md).
