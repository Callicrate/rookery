# Session / Platform Patterns

When CTF platform state is stale or incomplete, check session health and use read-only captures before solving from old assumptions.

Patterns:

- Cookie/session expiration can make lab actions fail mid-lane. Run credential/session health before long platform operations.
- ActionCable/WebSocket updates may reveal runtime cluster, console, or question metadata missing from initial GraphQL/API responses.
- Preserve raw request/response/transcript artifacts so later agents can resume after credential refresh without repeating discovery.
- Use SSH-terminal console automation for SSH-backed streams; do not use RDP desktop hotkeys or click coordinates for terminal-only consoles.
- Search raw evidence with guards; avoid broad recursive search over streams, transcripts, frontend bundles, source maps, and archives.
- Special platform answer submission should be reviewer-owned and should save request, response, cookie metadata, and summary consistently.

Useful commands:

```bash
./bin/platform-session-health --json
./adapters/immersive/bin/immersive-cluster-capture --activity-id ID --attempt-id ID --seconds 30
./extensions/guacamole/bin/guac-ssh-exec --profile ssh-terminal 'id && hostname' --contact-sheet
./bin/safe-rg 'questionId|activityId|cluster|guacamole' platform analysis
```
