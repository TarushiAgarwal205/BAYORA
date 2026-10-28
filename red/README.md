# Controlled local Red Team runner

`red.runner` provides a fixed four-case command-line check suite. Run it from the project root after starting the Blue service and gateway:

```powershell
venv\Scripts\python.exe -m red.runner run
venv\Scripts\python.exe -m red.runner show <run-id>
```

The cases cover an allowed read of Bayora's synthetic resource, a denied Red read with a spoofed Blue body role, an invalid test ID, and a policy-denied LLM generation request. Protected-resource cases require distinct `BAYORA_GATEWAY_BLUE_TOKEN` and `BAYORA_GATEWAY_RED_TOKEN` credentials in the process environment or project `.env`; the runner sends these as bearer credentials and the Gateway audit role must match the credential, not the request body. The allowed positive control uses the Blue token, so the host runner is a trusted local harness and is not an isolated Red identity. The runner accepts only HTTP loopback IP addresses, calls gateway endpoints only, never calls Blue directly, and uses policy/audit preflight before the denied resource and model cases. If policy is not an audited DENY for a negative case, the operation is skipped.

By default, reports are saved under `reports/red-runs/`; `--results-dir` can select another output directory. Reports contain each fixed input, expected behavior, observed HTTP fields, and selected audit fields. Protected resource content and model output are not copied into the report. A case is PASS only when its expected HTTP result and audit evidence agree; absent or ambiguous evidence is INCONCLUSIVE.

The `run` command exits with status 1 when any selected case FAILS or is INCONCLUSIVE, and status 0 only when every selected case passes. The Compose Red service selects the three cases that use the Red identity; the four-case host run also uses the separate Blue credential for its positive control.

The Compose Red container uses a minimal image containing only the runner and its configuration dependency. Its run reports are written under `/tmp/red-runs` on the container's existing temporary filesystem; they are not persisted to or shared with Gateway scenario artifacts.

This is a local deterministic gateway check harness, not a general attack runner or a broad security assessment. Policy-only and LLM cases still use caller-declared roles; the Gateway caller tokens are a prototype shared-secret mechanism, not production identity verification.
