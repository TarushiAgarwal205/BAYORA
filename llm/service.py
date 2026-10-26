import hmac
import os

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field


OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
API_KEY = os.environ.get("BAYORA_OPENROUTER_API_KEY", "")
SERVICE_TOKEN = os.environ.get("BAYORA_LLM_SERVICE_TOKEN", "")
MODEL = os.environ.get("BAYORA_LLM_MODEL", "openrouter/free")


app = FastAPI(title="BAYORA LLM Service")


class GenerateRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=20000)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/generate")
async def generate(
    request: GenerateRequest,
    authorization: str | None = Header(default=None),
):
    if not SERVICE_TOKEN:
        raise HTTPException(status_code=503, detail="LLM service is not configured")

    supplied_token = ""
    if authorization and authorization.startswith("Bearer "):
        supplied_token = authorization[7:]

    if not supplied_token or not hmac.compare_digest(supplied_token, SERVICE_TOKEN):
        raise HTTPException(status_code=401, detail="Unauthorized")

    if not API_KEY:
        raise HTTPException(status_code=503, detail="LLM provider is not configured")

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                OPENROUTER_URL,
                headers={
                    "Authorization": f"Bearer {API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": MODEL,
                    "messages": [{"role": "user", "content": request.prompt}],
                    "max_tokens": 2048,
                },
            )
    except httpx.RequestError:
        raise HTTPException(status_code=502, detail="LLM provider unavailable") from None

    if response.status_code != 200:
        raise HTTPException(status_code=502, detail="LLM provider request failed")

    try:
        body = response.json()
        content = body["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError):
        raise HTTPException(status_code=502, detail="Invalid LLM provider response") from None

    if not isinstance(content, str) or not content.strip() or len(content) > 50000:
        raise HTTPException(status_code=502, detail="Invalid LLM provider response")

    return {"model": MODEL, "content": content}