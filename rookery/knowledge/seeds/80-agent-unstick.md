# Unstick Tactics

When stuck, change attack style instead of quitting.

Naive reset:
- Give a fresh solver only the challenge prompt, artifacts, and current rejected candidates.
- Forbid long history unless requested.
- Ask for one cheap experiment or candidate family.

Hard investigation:
- Start long brute/fuzz/crack/search jobs with logs.
- Assign a separate interpreter to read outputs.

Knowledge reset:
- Search local corpus for the primitive or error string.
- Search SearXNG for exact error/source snippets.

Verifier reset:
- Ask a skeptic to classify observed fact vs inference vs guess.
- Name the exact missing proof artifact.

Never write unknowable. Write next_retry_style.
