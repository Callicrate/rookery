# Hack The Box adapter

Optional Hack The Box adapter. It is inactive unless `PLATFORM_ADAPTER=htb`.
Rookery never assumes this platform in generic mode.

The adapter uses the generic `CommandAdapter` contract: configured inventory and
submit JSON argv arrays produce normalized platform data. Exact, separate
environment-key arrays are passed only to the selected child command. Scoring
remains canonical-executor-only: a reviewed, authorized execution plan is the
only route that may invoke the configured submit command.

The optional catalog includes an HTB Sherlock analyst for multi-question,
evidence-linked incident reconstruction. No target, event, answer format, or
scope fact is assumed. The HTB profile supplies a 15-second submission cadence
plus deterministic jitter of up to 5 seconds when queue automation is enabled
and the generic environment overrides are left blank.
