# Client LLM integration

`llm/service.py` provides the separate FastAPI LLM service used by Docker Compose. The Gateway's `backend/llm_client.py` calls that service when `BAYORA_LLM_SERVICE_URL` is configured; otherwise it can use its direct OpenRouter client for local development. The LLM service calls OpenRouter's chat-completions endpoint using `BAYORA_OPENROUTER_API_KEY` and `BAYORA_LLM_MODEL`. The default model is `openrouter/free`. Compose requires a separate `BAYORA_LLM_SERVICE_TOKEN`; the provider API key is optional for service startup.

`POST /llm/generate` checks the existing policy rules and records an audit event before making a provider request. It is limited to the `red` role, the `generate_client_response` action, and the approved test resource IDs listed in `policies/rules.json`. Provider tests use mocked HTTP responses; no live provider request is part of the test suite.

The generated text is untrusted model output. The API always marks `security_outcome` as `NOT_EVALUATED` and `verification_result` as `NOT_VERIFIED`. Provider tests use mocked HTTP responses only. Prompt safety, model quality, live provider behavior, and provider account cost or rate limits are not implemented or verified. Prompts are sent to OpenRouter when an authorized request is made.
