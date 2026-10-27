import hmac
import os

from fastapi import FastAPI, Header, HTTPException


RESOURCE_ID = "blue:synthetic-confidential"
RESOURCE_CLASSIFICATION = "SYNTHETIC DUMMY CONFIDENTIAL TEST DATA"
RESOURCE_CONTENT = (
    "SYNTHETIC DUMMY CONFIDENTIAL TEST DATA: BAYORA BLUE FIXTURE 001. "
    "No real personal information."
)
RESOURCE_SHA256 = "03e327a1be953e16fb37a58eb5b43ac213fa613f3a21b4b7a8ce90828bebea49"


def create_blue_app(service_token=None):
    expected_token = service_token if service_token is not None else os.environ.get("BAYORA_BLUE_SERVICE_TOKEN", "")
    app = FastAPI(title="Bayora Blue Team Resource Service")

    @app.get("/health")
    def health():
        return {"status": "healthy"}

    @app.get("/internal/resources/{resource_id}")
    def read_resource(resource_id: str, authorization: str | None = Header(default=None)):
        if not expected_token:
            raise HTTPException(status_code=503, detail="Blue service authentication is not configured")
        supplied = authorization.removeprefix("Bearer ") if authorization else ""
        if not authorization or not authorization.startswith("Bearer ") or not hmac.compare_digest(supplied, expected_token):
            raise HTTPException(status_code=401, detail="service authentication required")
        if resource_id != RESOURCE_ID:
            raise HTTPException(status_code=404, detail="resource not found")
        return {
            "resource_id": RESOURCE_ID,
            "classification": RESOURCE_CLASSIFICATION,
            "content": RESOURCE_CONTENT,
            "sha256": RESOURCE_SHA256,
        }

    return app


app = create_blue_app()
