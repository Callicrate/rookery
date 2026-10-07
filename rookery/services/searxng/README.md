# Local SearXNG service

Rookery uses an operator-defined external `SEARXNG_URL` when one is configured. Otherwise `./go` may start a project-owned SearXNG container bound only to `127.0.0.1`. Runtime settings and secrets are generated under `state/services/searxng/` and are never shipped in the release archive.
