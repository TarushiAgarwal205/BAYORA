# Blue Team service

`blue.service:app` is a separate FastAPI service that exposes one synthetic protected resource at `GET /internal/resources/blue:synthetic-confidential`.

The fixture is explicitly labelled dummy confidential test data and contains no real personal information. Direct reads require the `Authorization: Bearer ...` value to match `BAYORA_BLUE_SERVICE_TOKEN`. The service does not trust caller-supplied role claims and returns 503 when its token is not configured.

Run from the project root with the same private token configured in the gateway and service environments:

```powershell
venv\Scripts\python.exe -m uvicorn blue.service:app --host 127.0.0.1 --port 8001
```

This is a local prototype. A shared bearer token does not provide user identity, network segmentation, or container isolation.
