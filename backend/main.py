from contextlib import asynccontextmanager
import hashlib
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4

import httpx
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, field_validator
from fastapi.staticfiles import StaticFiles

from backend.audit_store import AuditStore, utc_timestamp
from backend.blue_client import BlueServiceClient
from backend.config import AUDIT_DB_PATH, BLUE_SERVICE_TOKEN, BLUE_SERVICE_URL
from backend.policy import PolicyEngine
from blue.service import RESOURCE_CLASSIFICATION, RESOURCE_ID, RESOURCE_SHA256

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
PROJECT_ROOT = Path(__file__).resolve().parent.parent
RULES_PATH = PROJECT_ROOT / "policies" / "rules.json"
FIELD_PATTERN = r"^[A-Za-z0-9_:.-]{1,64}$"
SESSION_PATTERN = r"^[A-Za-z0-9_-]{1,64}$"


class TestRequest(BaseModel):
    session_id: str
    role: str
    resource: str
    action: str


class PolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str | None = Field(default=None, min_length=1, max_length=64, pattern=SESSION_PATTERN)
    role: str = Field(min_length=1, max_length=64, pattern=FIELD_PATTERN)
    action: str = Field(min_length=1, max_length=64, pattern=FIELD_PATTERN)
    resource: str = Field(min_length=1, max_length=64, pattern=FIELD_PATTERN)

    @field_validator("role", "action", "resource", mode="before")
    @classmethod
    def trim_match_fields(cls, value):
        return value.strip() if isinstance(value, str) else value


def create_app(rules_path=RULES_PATH, audit_db_path=AUDIT_DB_PATH, audit_store=None, blue_client=None):
    store = audit_store or AuditStore(audit_db_path)
    resource_client = blue_client or BlueServiceClient(BLUE_SERVICE_URL, BLUE_SERVICE_TOKEN)

    @asynccontextmanager
    async def lifespan(application):
        store.initialize()
        application.state.policy_engine = PolicyEngine(Path(rules_path))
        application.state.audit_store = store
        yield

    application = FastAPI(title="Bayora Security Gateway", lifespan=lifespan)

    @application.get("/")
    def home():
        return {
            "project": "Bayora",
            "status": "running"
        }

    @application.get("/health")
    def health():
        return {"status": "healthy"}

    @application.post("/test")
    def run_test(request: TestRequest):
        # DEMO STUB: this fixed predicate is not a real security test.
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

    @application.post("/policy/decide")
    def decide_policy(request: PolicyRequest):
        session_id = request.session_id or uuid4().hex
        role = request.role.strip().lower()
        action = request.action.strip().lower()
        resource = request.resource.strip().lower()
        decision = application.state.policy_engine.decide(role, action, resource)
        event = {
            "event_id": str(uuid4()),
            "timestamp_utc": utc_timestamp(),
            "session_id": session_id,
            "role": role,
            "action": action,
            "resource": resource,
            "decision": decision.decision,
            "reason": decision.reason,
            "matched_rule_id": decision.matched_rule_id,
            "observed_outcome": "NOT_EXECUTED",
            "verification_result": "NOT_VERIFIED",
        }
        try:
            application.state.audit_store.record(event)
        except Exception as error:
            raise HTTPException(
                status_code=503,
                detail="audit write failed; no policy decision was returned",
            ) from error
        return {
            key: event[key]
            for key in (
                "event_id", "session_id", "decision", "reason", "matched_rule_id",
                "observed_outcome", "verification_result",
            )
        }

    @application.post("/resource/read")
    async def read_protected_resource(request: PolicyRequest):
        session_id = request.session_id or uuid4().hex
        role = request.role.strip().lower()
        action = request.action.strip().lower()
        resource = request.resource.strip().lower()
        decision = application.state.policy_engine.decide(role, action, resource)
        event = {
            "event_id": str(uuid4()),
            "timestamp_utc": utc_timestamp(),
            "session_id": session_id,
            "role": role,
            "action": action,
            "resource": resource,
            "decision": decision.decision,
            "reason": decision.reason,
            "matched_rule_id": decision.matched_rule_id,
        }

        if decision.decision != "ALLOW":
            try:
                application.state.audit_store.record(event)
            except Exception as error:
                raise HTTPException(status_code=503, detail="audit write failed; resource was not requested") from error
            raise HTTPException(status_code=403, detail={
                "event_id": event["event_id"],
                "decision": "DENY",
                "reason": decision.reason,
                "operation_executed": False,
                "observed_outcome": "NOT_EXECUTED",
                "verification_result": "NOT_VERIFIED",
            })

        try:
            application.state.audit_store.record_pending_operation(event)
        except Exception as error:
            raise HTTPException(status_code=503, detail="audit write failed; resource was not requested") from error

        try:
            response = await resource_client.read_resource(resource)
        except (httpx.ConnectError, httpx.ConnectTimeout) as error:
            await _finish_resource_audit(
                application, event["event_id"], False, "NOT_EXECUTED", "NOT_VERIFIED"
            )
            raise HTTPException(status_code=503, detail="Blue resource service is unavailable") from error
        except Exception as error:
            await _finish_resource_audit(
                application, event["event_id"], None, "UNKNOWN", "NOT_VERIFIED"
            )
            raise HTTPException(status_code=503, detail="Blue resource outcome is unknown") from error

        if response.status_code != 200:
            if response.status_code in (401, 404):
                await _finish_resource_audit(
                    application, event["event_id"], False, "NOT_EXECUTED", "NOT_VERIFIED"
                )
            else:
                await _finish_resource_audit(
                    application, event["event_id"], None, "UNKNOWN", "NOT_VERIFIED"
                )
            status_code = 404 if response.status_code == 404 else 503
            raise HTTPException(status_code=status_code, detail="Blue resource service did not provide the resource")

        try:
            payload = response.json()
            content = payload["content"]
            valid = (
                payload["resource_id"] == RESOURCE_ID
                and isinstance(content, str)
                and payload["classification"] == RESOURCE_CLASSIFICATION
                and hashlib.sha256(content.encode("utf-8")).hexdigest() == RESOURCE_SHA256
                and payload.get("sha256") == RESOURCE_SHA256
            )
        except (ValueError, KeyError, TypeError):
            payload = {}
            content = None
            valid = False

        verification = "VERIFIED" if valid else "FAILED"
        try:
            application.state.audit_store.complete_operation(
                event["event_id"], True, "SUCCEEDED", verification
            )
        except Exception as error:
            raise HTTPException(status_code=503, detail="audit finalization failed; resource withheld") from error
        if not valid:
            raise HTTPException(status_code=502, detail="resource response failed integrity verification")
        return {
            "event_id": event["event_id"],
            "session_id": session_id,
            "decision": "ALLOW",
            "operation_executed": True,
            "observed_outcome": "SUCCEEDED",
            "verification_result": "VERIFIED",
            "resource_id": RESOURCE_ID,
            "classification": payload["classification"],
            "content": content,
        }

    @application.get("/policy/rules")
    def get_policy_rules():
        engine = application.state.policy_engine
        try:
            return engine.get_rules()
        except RuntimeError as error:
            raise HTTPException(status_code=503, detail=f"policy configuration error: {error}") from error

    @application.get("/audit/events")
    def list_audit_events(
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
        session_id: str | None = Query(default=None, min_length=1, max_length=64, pattern=SESSION_PATTERN),
        decision: Literal["ALLOW", "DENY"] | None = None,
    ):
        events = application.state.audit_store.list_events(
            limit=limit,
            offset=offset,
            session_id=session_id,
            decision=decision,
        )
        return {"events": events, "limit": limit, "offset": offset}

    @application.get("/audit/events/{event_id}")
    def get_audit_event(event_id: str):
        try:
            event_id = str(UUID(event_id))
        except ValueError as error:
            raise HTTPException(status_code=404, detail="audit event not found") from error
        event = application.state.audit_store.get_event(event_id)
        if event is None:
            raise HTTPException(status_code=404, detail="audit event not found")
        return event

    application.mount("/dashboard", StaticFiles(directory=FRONTEND_DIR, html=True), name="dashboard")
    return application


async def _finish_resource_audit(application, event_id, operation_executed, outcome, verification):
    try:
        application.state.audit_store.complete_operation(
            event_id, operation_executed, outcome, verification
        )
    except Exception as error:
        raise HTTPException(status_code=503, detail="audit finalization failed") from error


app = create_app()
