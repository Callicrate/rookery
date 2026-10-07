# Flag Review Pattern Seed

Agents propose candidates. The independent review process submits or hoards.

## Good proposals

A useful proposal includes:

- exact candidate string,
- challenge ID/name,
- evidence path,
- confidence,
- verifier report or reproduction path when available,
- rationale for why the answer format is right.

## Suspicious candidates

Hold before submission when:

- it does not match the event flag regex,
- it looks like a placeholder such as `flag`, `test`, `a-flag`, `example`, `sample`,
- it is much shorter/longer than accepted flags,
- it differs sharply from accepted event style,
- the same exact string was rejected before,
- proof is only semantic fit with no artifact/source chain.

## Do not hide candidates

Even suspicious strings should be preserved exactly. Reject or hold them in review logs, not by deleting them.
