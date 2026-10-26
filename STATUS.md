# Bayora status

The dashboard remains visually unchanged and continues to display backend health and the `/test` demo stub. **DEMO STUB: `/test` is not a real security test.** The policy decision route remains decision-only; the Blue route performs one local synthetic read after policy evaluation, and the OpenRouter route generates model text for policy-approved test IDs only.

| Planned component | Status |
|---|---|
| Basic policy decision logic | IMPLEMENTED AND TESTED |
| SQLite decision and operation audit fields | IMPLEMENTED AND TESTED (basic local flow; not tamper-evident) |
| Blue Team service with synthetic protected fixture | IMPLEMENTED AND TESTED (single local fixture) |
| Gateway policy check before Blue resource read | IMPLEMENTED AND TESTED (basic local flow) |
| Gateway caller authentication for protected resource reads | IMPLEMENTED AND TESTED (separate shared Red/Blue bearer tokens; prototype only) |
| Direct Blue service authentication | IMPLEMENTED AND TESTED (shared bearer token; not user identity authentication) |
| OpenRouter chat-completions client and policy-gated route | IMPLEMENTED AND TESTED (mock HTTP responses; no live provider call) |
| Fixed local Red Team gateway checks | IMPLEMENTED AND TESTED (four deterministic cases; not a general attack runner) |
| Local Docker Compose Gateway and Blue containers | IMPLEMENTED (container build/start not yet verified) |
| Basic Compose bridge networking; Blue port not published | IMPLEMENTED (not strong segmentation or a complete sandbox) |
| Hash chain and integrity verifier | NOT IMPLEMENTED |
| Anomaly detection | NOT IMPLEMENTED |
| CPU and memory limits | NOT IMPLEMENTED |
| Session isolation | NOT IMPLEMENTED |
| Dashboard with live protected-resource data | NOT IMPLEMENTED |
| Automated evidence report | NOT IMPLEMENTED |

## Known limitations

- `/resource/read` derives the policy role from separate shared Gateway bearer tokens; the request body's role is ignored. These prototype tokens do not provide user accounts, expiry, rotation, or production-grade identity verification. `/policy/decide` and `/llm/generate` still accept caller-declared roles.
- The Blue service contains one hardcoded synthetic fixture. The gateway verifies its resource identifier and content against a fixed expected SHA-256 digest before returning it. This does not establish general resource protection.
- `operation_executed` is set only after an HTTP response establishes whether the read succeeded or was rejected. Ambiguous failures are recorded as `UNKNOWN` with execution unset. A pending row may remain if the audit database becomes unavailable during finalization; in that case the gateway withholds the resource response.
- Existing audit databases receive only an additive `operation_executed` column. The audit log has no hash chain or tamper-evident verification.
- Compose places the Gateway and Blue service on one local bridge network and publishes only the Gateway on host loopback. This is basic local separation, not a complete sandbox or strong network segmentation. Container behavior requires verification on a machine with Docker available.
- OpenRouter credentials and requests are wired, but provider behavior has only been tested with mocked responses. Model outputs are not security decisions or verification evidence.
- The LLM endpoint is limited to policy-approved test IDs and is audited. Prompt/output safety, model quality, adversarial robustness, provider reliability, and account-side cost/rate limits are not tested or controlled.
- The Red runner uses fixed inputs and loopback HTTP only. It verifies selected gateway outcomes against audit records; unavailable or ambiguous audit evidence produces INCONCLUSIVE. It does not simulate a general attacker or establish system-wide security.
