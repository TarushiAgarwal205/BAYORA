import httpx


OPENROUTER_CHAT_COMPLETIONS_URL = "https://openrouter.ai/api/v1/chat/completions"


class LLMConfigurationError(Exception):
    """The provider client is not configured."""


class LLMProviderError(Exception):
    """The provider failed or returned an unusable response."""

    def __init__(self, operation_executed=None):
        super().__init__()
        self.operation_executed = operation_executed


class OpenRouterClient:
    def __init__(self, api_key, model="openrouter/free", transport=None, timeout=30.0):
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
