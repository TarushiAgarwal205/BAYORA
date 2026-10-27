import os

import httpx


OPENROUTER_CHAT_COMPLETIONS_URL = (
    "https://openrouter.ai/api/v1/chat/completions"
)


class LLMConfigurationError(Exception):
    """The provider client is not configured."""


class LLMProviderError(Exception):
    """The provider failed or returned an unusable response."""

    def __init__(self, operation_executed=None):
        super().__init__()
        self.operation_executed = operation_executed


class LLMServiceClient:
    def __init__(self, service_url, service_token, model="openrouter/free",
                 transport=None, timeout=30.0):
        self.service_url = service_url.rstrip("/")
        self.service_token = service_token
        self.model = model or "openrouter/free"
        self.transport = transport
        self.timeout = timeout

    async def generate(self, prompt):
        if not self.service_url or not self.service_token:
            raise LLMConfigurationError

        try:
            async with httpx.AsyncClient(
                transport=self.transport,
                timeout=self.timeout,
            ) as client:
                response = await client.post(
                    f"{self.service_url}/generate",
                    headers={
                        "Authorization": f"Bearer {self.service_token}",
                        "Content-Type": "application/json",
                    },
                    json={"prompt": prompt},
                )
        except (httpx.ConnectError, httpx.ConnectTimeout) as error:
            raise LLMProviderError(operation_executed=False) from error
        except httpx.RequestError as error:
            raise LLMProviderError from error

        if response.status_code == 503:
            raise LLMConfigurationError

        if response.status_code != 200:
            raise LLMProviderError

        try:
            body = response.json()
            content = body["content"]
            model = body.get("model", self.model)
        except (ValueError, KeyError, TypeError) as error:
            raise LLMProviderError from error

        if (
            not isinstance(content, str)
            or not content.strip()
            or len(content) > 50000
            or not isinstance(model, str)
        ):
            raise LLMProviderError

        self.model = model
        return content


class OpenRouterClient:
    def __init__(self, api_key, model="openrouter/free", transport=None,
                 timeout=30.0):
        self.api_key = api_key
        self.model = model or "openrouter/free"
        self.transport = transport
        self.timeout = timeout

    async def generate(self, prompt):
        if not self.api_key:
            raise LLMConfigurationError

        try:
            async with httpx.AsyncClient(
                transport=self.transport,
                timeout=self.timeout,
            ) as client:
                response = await client.post(
                    OPENROUTER_CHAT_COMPLETIONS_URL,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.model,
                        "messages": [{"role": "user", "content": prompt}],
                        "max_tokens": 2048,
                    },
                )
        except (httpx.ConnectError, httpx.ConnectTimeout) as error:
            raise LLMProviderError(operation_executed=False) from error
        except httpx.RequestError as error:
            raise LLMProviderError from error

        if response.status_code != 200:
            raise LLMProviderError

        try:
            body = response.json()
            if not isinstance(body, dict) or not isinstance(body.get("choices"), list):
                raise ValueError
            content = body["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as error:
            raise LLMProviderError from error

        if not isinstance(content, str) or not content.strip() or len(content) > 50000:
            raise LLMProviderError

        return content


def create_llm_client(*, api_key=None, model=None):
    """Use the separate LLM service when configured; otherwise use OpenRouter directly."""
    service_url = os.environ.get("BAYORA_LLM_SERVICE_URL", "")
    service_token = os.environ.get("BAYORA_LLM_SERVICE_TOKEN", "")
    selected_model = model or os.environ.get("BAYORA_LLM_MODEL", "openrouter/free")

    if service_url:
        return LLMServiceClient(service_url, service_token, selected_model)

    return OpenRouterClient(
        api_key if api_key is not None else os.environ.get("BAYORA_OPENROUTER_API_KEY", ""),
        selected_model,
    )
