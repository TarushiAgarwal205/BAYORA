Option A: Red Team may request explicitly approved security tests but must not read Blue Team artifacts. All other unapproved operations receive a default DENY from the policy decision endpoint.

`rules.json` contains the policy rules evaluated by `POST /policy/decide` and `POST /resource/read`. The first route records a decision only and accepts a caller-declared role. For resource reads, the Gateway derives the role from separate configured caller bearer tokens, then checks the decision before it calls the Blue service for the single `blue:synthetic-confidential` fixture. These shared prototype tokens are not user authentication.

`POST /llm/generate` is allowed only for the `red` role, `generate_client_response` action, and the exact approved test resources listed by `red-approved-client-llm`. A model response is not evidence of a security outcome.

The local fixed-case runner in `red/runner.py` uses these gateway rules and audit records. It sends a configured Blue caller token for its allowed resource-read control and a Red caller token for the denied read case. The body's `role` field does not choose the resource-read policy role.

The gateway does not call the Blue service on DENY. Blue also requires a shared service token on direct requests. This is a basic local demonstration, not general resource protection.
