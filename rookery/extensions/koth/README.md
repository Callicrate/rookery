# KOTH Extension

Optional King-of-the-Hill scoring extension. It is inactive unless `EVENT_EXTENSIONS=koth`. It adds `handle_write` proposals without changing the generic scoring model. `koth-review` records canonical independent reviews; verified-write aliases accept only an authorized immutable plan ID and delegate to the canonical executor.

See [Live target and KOTH patterns](./knowledge/patterns.md) for the extension's operational guidance.
