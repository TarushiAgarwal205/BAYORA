# SQLite audit storage

Audit events are stored by `backend/audit_store.py`. The SQLite event schema is preserved and extended with additive initialization where needed; hash snapshots live in separate `audit_integrity` and `audit_integrity_meta` tables.

Policy decisions start as `NOT_EXECUTED` and `NOT_VERIFIED`. Resource and LLM operations are recorded as pending, then finalized with an observed outcome. Ambiguous failures remain `UNKNOWN` and `NOT_VERIFIED`. Session IDs are caller-supplied correlation labels scoped by the authenticated role. Reusing an ID under another role does not change caller authority or create a cross-role session binding. Shared role credentials do not identify individual users, so these labels do not provide per-user session isolation.

`GET /audit/integrity` and the dashboard-compatible `GET /audit/verify` verify the append-only SHA-256 snapshot revision chain. Event and detail APIs, anomaly findings, and evidence summaries are scoped to the authenticated caller role. Reports omit Red-run files because those files do not currently carry authenticated role ownership metadata.

The chain is unkeyed. It can detect event changes, omissions, reordered or missing chain entries, and a missing initialization marker, but a privileged editor who can rewrite the SQLite database can recompute the chain. It is not a signed, immutable, or tamper-proof audit service. No event is described as verified unless the resource response is checked against the configured synthetic fixture evidence.

Audit-store tests use temporary SQLite databases. They cover event persistence, state transitions, chain verification, unauthorized event modification/removal, and fail-closed behavior when the integrity marker is missing.

Administrator policy/configuration changes and scenario runs use pending-operation events, then store the final outcome and metadata in the integrity-chained event revision. Prompt inspection evidence stores only outcome, rule identifiers, severity, length, and SHA-256 digest; prompt text is not put in the audit database. The separately authenticated incident workspace can search all roles; the existing caller audit APIs remain role-scoped.
