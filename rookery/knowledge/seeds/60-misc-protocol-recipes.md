# Misc, Protocol, Infra Recipes

Misc is often an unnamed technical category. Do not over-OSINT it first.

Patterns:

- Custom network protocol: record dialogue, write client, fuzz fields, test state machine.
- Encoding puzzles: identify layers with `file`, entropy, frequency, base encodings, QR, braille, Morse, Bacon, keyboard layouts.
- Games/bots: inspect source/assets, replay protocol, manipulate client state.
- Cloud/infra: exposed buckets, metadata, IAM policy mistakes, SSRF, kube/docker sockets in CTF scope.
- Git challenges: reflog, branches, tags, stashes, deleted blobs, commit history.
- Containers: inspect image layers, env, history, entrypoint, volumes.

Use `ncq`, `runq`, and tiny scripts. Preserve transcripts.
