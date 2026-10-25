# Bayora status

The dashboard remains visually unchanged and continues to display backend health and the `/test` demo stub. **DEMO STUB: `/test` is not a real security test.** Stage 2's policy decision route remains decision-only; the new Blue resource route performs one local synthetic read after policy evaluation.

| Planned component | Status |
|---|---|
| Basic policy decision logic | IMPLEMENTED AND TESTED |
| SQLite decision and operation audit fields | IMPLEMENTED AND TESTED (basic local flow; not tamper-evident) |
| Blue Team service with synthetic protected fixture | IMPLEMENTED AND TESTED (single local fixture) |
| Gateway policy check before Blue resource read | IMPLEMENTED AND TESTED (basic local flow) |
| Direct Blue service authentication | IMPLEMENTED AND TESTED (shared bearer token; not user identity authentication) |
| Red Team test runner | NOT IMPLEMENTED |
| Client LLM integration | NOT IMPLEMENTED |
| Docker containers and Compose integration | NOT IMPLEMENTED |
| Network segmentation and container isolation | NOT IMPLEMENTED |
| Hash chain and integrity verifier | NOT IMPLEMENTED |
| Anomaly detection | NOT IMPLEMENTED |
| CPU and memory limits | NOT IMPLEMENTED |
| Session isolation | NOT IMPLEMENTED |
| Dashboard with live protected-resource data | NOT IMPLEMENTED |
| Automated evidence report | NOT IMPLEMENTED |

## Known limitations

- The gateway role field is self-declared. A caller can claim `blue` under the current rules; the service token prevents unauthenticated direct service calls, but does not authenticate gateway users.
- The Blue service contains one hardcoded synthetic fixture. The gateway verifies its resource identifier and content against a fixed expected SHA-256 digest before returning it. This does not establish general resource protection.
- `operation_executed` is set only after an HTTP response establishes whether the read succeeded or was rejected. Ambiguous failures are recorded as `UNKNOWN` with execution unset. A pending row may remain if the audit database becomes unavailable during finalization; in that case the gateway withholds the resource response.
- Existing audit databases receive only an additive `operation_executed` column. The audit log has no hash chain or tamper-evident verification.
- No Docker isolation, network segmentation, Red runner, LLM service, production authentication, or real security testing is implemented.
