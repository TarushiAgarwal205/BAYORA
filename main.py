from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Bayora Security Gateway")


class TestRequest(BaseModel):
    session_id: str
    role: str
    resource: str
    action: str


@app.get("/")
def home():
    return {
        "project": "Bayora",
        "status": "running"
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/test")
def run_test(request: TestRequest):
    allowed = (
        request.role == "red"
        and request.resource == "test_endpoint"
        and request.action == "run_test"
    )

    if allowed:
        return {
            "session_id": request.session_id,
            "decision": "ALLOWED",
            "reason": "Policy permits this test"
        }

    return {
        "session_id": request.session_id,
        "decision": "BLOCKED",
        "reason": "Policy does not permit this operation"
    }