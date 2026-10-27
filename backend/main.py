from contextlib import asynccontextmanager
import hashlib
import hmac
import json
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4

import httpx
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from fastapi.staticfiles import StaticFiles

from backend.audit_store import AuditStore, utc_timestamp
from backend.blue_client import BlueServiceClient
from backend.config import (
    AUDIT_DB_PATH,
    BLUE_SERVICE_TOKEN,
    BLUE_SERVICE_URL,
    GATEWAY_CALLER_TOKENS,
    LLM_MODEL,
    OPENROUTER_API_KEY,
    SECURITY_CONFIG_PATH,
)
from backend.llm_client import (
    LLMConfigurationError,
    LLMProviderError,
    create_llm_client,
)
from backend.anomaly_detector import analyze_audit_events
from backend.evidence_report import generate_evidence_report
from backend.policy import PolicyEngine
from backend.policy_admin import PolicyFileStore, PolicyManagementError
from backend.prompt_inspection import inspect_prompt
from backend.security_config import SecurityConfigError, SecurityConfigStore
from blue.service import RESOURCE_CLASSIFICATION, RESOURCE_ID, RESOURCE_SHA256
from red.runner import TEST_CASES, RunnerError, load_run, run_suite

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


class LLMRequest(PolicyRequest):
    prompt: str = Field(min_length=1, max_length=20000)


class ManagedPolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    effect: Literal["ALLOW", "DENY"]
    role: Literal["red", "blue"]
    action: str = Field(min_length=1, max_length=64, pattern=FIELD_PATTERN)
    resource_match: dict
    enabled: bool = True


class PolicyRuleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule: ManagedPolicyRule


class PolicyEnabledRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool


class PolicyDryRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Literal["red", "blue"]
    action: str = Field(min_length=1, max_length=64, pattern=FIELD_PATTERN)
    resource: str = Field(min_length=1, max_length=64, pattern=FIELD_PATTERN)

    @field_validator("action", "resource", mode="before")
    @classmethod
    def trim_dry_run_values(cls, value):
        return value.strip() if isinstance(value, str) else value


class SecurityConfigUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    medium_severity_action: Literal["FLAG", "DENY"] | None = None
    repeated_denial_threshold: int | None = Field(default=None, ge=3, le=10)


class ScenarioRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scenario_ids: list[str] = Field(default_factory=list, max_length=4)

    @field_validator("scenario_ids")
    @classmethod
    def validate_scenarios(cls, value):
        known = {case["case_id"] for case in TEST_CASES}
        if len(value) != len(set(value)) or set(value) - known:
            raise ValueError("scenario IDs must be unique members of the fixed local library")
        return value



def create_app(
    rules_path=RULES_PATH,
    audit_db_path=AUDIT_DB_PATH,
    audit_store=None,
    blue_client=None,
    llm_client=None,
    gateway_caller_tokens=None,
    security_config_path=SECURITY_CONFIG_PATH,
    scenario_results_dir=None,
    scenario_runner=None,
):
    store = audit_store or AuditStore(audit_db_path)
    resource_client = blue_client or BlueServiceClient(BLUE_SERVICE_URL, BLUE_SERVICE_TOKEN)
    model_client = llm_client or create_llm_client(
        api_key=OPENROUTER_API_KEY,
        model=LLM_MODEL,
    )
    caller_tokens = (
        GATEWAY_CALLER_TOKENS if gateway_caller_tokens is None else gateway_caller_tokens
    )

    def authenticate_gateway_caller(authorization: str | None = Header(default=None)):
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Gateway caller authentication required")

        configured_tokens = {
            role: token for role, token in caller_tokens.items()
            if role in {"red", "blue", "admin"} and isinstance(token, str) and token
        }
        if not configured_tokens:
            raise HTTPException(status_code=503, detail="Gateway caller authentication is not configured")
        if (
            len(set(configured_tokens.values())) != len(configured_tokens)
            or any(not token.isascii() for token in configured_tokens.values())
        ):
            raise HTTPException(
                status_code=503,
                detail="Gateway caller authentication configuration is invalid",
            )

        supplied_token = authorization.removeprefix("Bearer ")
        if not supplied_token.isascii():
            raise HTTPException(status_code=401, detail="Gateway caller authentication failed")
        matches = [
            role for role, expected_token in configured_tokens.items()
            if hmac.compare_digest(supplied_token, expected_token)
        ]
        if len(matches) != 1:
            raise HTTPException(status_code=401, detail="Gateway caller authentication failed")
        return matches[0]

    @asynccontextmanager
    async def lifespan(application):
        store.initialize()
        application.state.policy_engine = PolicyEngine(Path(rules_path))
        application.state.policy_file_store = PolicyFileStore(Path(rules_path))
        application.state.security_config_store = SecurityConfigStore(security_config_path)
        application.state.security_config_store.read()
        application.state.scenario_results_dir = Path(
            scenario_results_dir or (PROJECT_ROOT / "reports" / "red-runs")
        )
        application.state.scenario_runner = scenario_runner or run_suite
        application.state.audit_store = store
        yield

    application = FastAPI(title="Bayora Security Gateway", lifespan=lifespan)

    def require_admin(caller_role: str = Depends(authenticate_gateway_caller)):
        if caller_role != "admin":
            raise HTTPException(status_code=403, detail="administrator credential required")
        return caller_role

    def begin_admin_operation(action, resource, details):
        _require_audit_integrity(application)
        event = _audit_event(
            uuid4().hex, "admin", action, resource, "ALLOW",
            _encode_details({"operation": action, "status": "PENDING", **details}),
            "administrator-operation",
        )
        try:
            event = application.state.audit_store.record_pending_operation(event) or event
        except Exception as error:
            raise HTTPException(status_code=503, detail="audit unavailable; administrative change was not started") from error
        if event["decision"] != "ALLOW":
            raise HTTPException(status_code=403, detail="administrator session is not authorized")
        return event

    def finish_admin_operation(event, *, success, details):
        try:
            application.state.audit_store.complete_operation(
                event["event_id"],
                bool(success),
                "SUCCEEDED" if success else "NOT_EXECUTED",
                "VERIFIED" if success else "NOT_VERIFIED",
                reason=_encode_details(details),
            )
        except Exception as error:
            raise HTTPException(status_code=503, detail="audit finalization failed") from error

    def mutate_policy(action, rule_id, operation):
        event = begin_admin_operation(action, f"policy:{rule_id}", {"rule_id": rule_id})
        policy_store = application.state.policy_file_store
        try:
            original = policy_store.path.read_bytes()
        except OSError as error:
            finish_admin_operation(event, success=False, details={"operation": action, "status": "FAILED"})
            raise HTTPException(status_code=503, detail="policy document is unavailable") from error
        changed = False
        try:
            document, _previous = operation()
            changed = True
            if not application.state.policy_engine.reload():
                raise PolicyManagementError("policy reload failed; requests remain fail-closed")
            application.state.policy_engine.get_rules()
            finish_admin_operation(
                event, success=True,
                details={"operation": action, "rule_id": rule_id, "status": "APPLIED"},
            )
            return document
        except PolicyManagementError as error:
            if changed:
                try:
                    policy_store.restore(original)
                    application.state.policy_engine.reload()
                except Exception as rollback_error:
                    try:
                        application.state.audit_store.complete_operation(
                            event["event_id"], None, "UNKNOWN", "NOT_VERIFIED",
                            reason=_encode_details({"operation": action, "status": "ROLLBACK_FAILED"}),
                        )
                    except Exception:
                        pass
                    raise HTTPException(status_code=503, detail="policy update outcome is unknown") from rollback_error
            finish_admin_operation(
                event, success=False,
                details={"operation": action, "rule_id": rule_id, "status": "REJECTED"},
            )
            status_code = 404 if str(error) == "rule not found" else 422
            raise HTTPException(status_code=status_code, detail=str(error)) from error
        except HTTPException:
            if changed:
                try:
                    policy_store.restore(original)
                    application.state.policy_engine.reload()
                except Exception:
                    raise HTTPException(status_code=503, detail="policy rollback failed; inspect audit integrity")
            raise
        except Exception as error:
            if changed:
                try:
                    policy_store.restore(original)
                    application.state.policy_engine.reload()
                except Exception:
                    raise HTTPException(status_code=503, detail="policy rollback failed; outcome is unknown") from error
            try:
                finish_admin_operation(event, success=False, details={"operation": action, "status": "FAILED"})
            except HTTPException:
                pass
            raise HTTPException(status_code=503, detail="policy operation failed") from error

    @application.middleware("http")
    async def add_security_headers(request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
        )
        return response

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
    def run_test(
        request: TestRequest,
        caller_role: str = Depends(authenticate_gateway_caller),
    ):
        # DEMO STUB: this fixed predicate is not a real security test.
        allowed = (
            caller_role == "red"
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
    def decide_policy(
        request: PolicyRequest,
        caller_role: str = Depends(authenticate_gateway_caller),
    ):
        session_id = request.session_id or uuid4().hex
        role = caller_role
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
            event = application.state.audit_store.record(event) or event
        except Exception as error:
            raise HTTPException(
                status_code=503,
                detail="audit write failed; no policy decision was returned",
            ) from error
        return {
            key: event[key]
            for key in (
                "event_id", "session_id", "decision", "reason", "matched_rule_id",
                "observed_outcome", "verification_result", "role",
            )
        }

    @application.post("/resource/read")
    async def read_protected_resource(
        request: PolicyRequest,
        caller_role: str = Depends(authenticate_gateway_caller),
    ):
        session_id = request.session_id or uuid4().hex
        # Keep the request field for API compatibility, but never trust it for access control.
        role = caller_role
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
                event = application.state.audit_store.record(event) or event
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
            event = application.state.audit_store.record_pending_operation(event) or event
        except Exception as error:
            raise HTTPException(status_code=503, detail="audit write failed; resource was not requested") from error

        if event["decision"] != "ALLOW":
            raise HTTPException(status_code=403, detail={
                "event_id": event["event_id"],
                "decision": "DENY",
                "reason": event["reason"],
                "matched_rule_id": event["matched_rule_id"],
                "operation_executed": False,
                "observed_outcome": "NOT_EXECUTED",
                "verification_result": "NOT_VERIFIED",
            })

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

    @application.post("/llm/generate")
    async def generate_llm_response(
        request: LLMRequest,
        caller_role: str = Depends(authenticate_gateway_caller),
    ):
        session_id = request.session_id or uuid4().hex
        role = caller_role
        action = request.action.strip().lower()
        resource = request.resource.strip().lower()
        decision = application.state.policy_engine.decide(role, action, resource)
        try:
            detector_config = application.state.security_config_store.read()
        except SecurityConfigError as error:
            failed_event = _audit_event(
                session_id, role, action, resource, "DENY",
                "detection configuration error; prompt inspection unavailable",
                "detection-configuration-error",
            )
            try:
                application.state.audit_store.record(failed_event)
            except Exception as audit_error:
                raise HTTPException(status_code=503, detail="audit unavailable; model was not called") from audit_error
            raise HTTPException(status_code=503, detail="prompt inspection configuration is invalid") from error
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
                event = application.state.audit_store.record(event) or event
            except Exception as error:
                raise HTTPException(status_code=503, detail="audit write failed; model was not called") from error
            raise HTTPException(status_code=403, detail={
                "event_id": event["event_id"],
                "decision": "DENY",
                "reason": decision.reason,
                "operation_executed": False,
                "observed_outcome": "NOT_EXECUTED",
                "verification_result": "NOT_VERIFIED",
                "security_outcome": "NOT_EVALUATED",
            })

        inspection = inspect_prompt(
            request.prompt,
            medium_severity_action=detector_config["medium_severity_action"],
        )
        if inspection["outcome"] != "ALLOW":
            blocked_event = dict(event)
            blocked_event.update({
                "decision": "DENY",
                "reason": _encode_details({
                    "policy_decision": decision.decision,
                    "inspection": inspection,
                    "prompt_stored": False,
                }),
                "matched_rule_id": "prompt-inspection-" + inspection["outcome"].lower(),
            })
            try:
                blocked_event = application.state.audit_store.record(blocked_event) or blocked_event
            except Exception as error:
                raise HTTPException(status_code=503, detail="audit write failed; model was not called") from error
            raise HTTPException(status_code=403, detail={
                "event_id": blocked_event["event_id"],
                "decision": "DENY",
                "policy_decision": decision.decision,
                "inspection": inspection,
                "prompt_stored": False,
                "operation_executed": False,
                "observed_outcome": "NOT_EXECUTED",
                "verification_result": "NOT_VERIFIED",
                "security_outcome": "NOT_EVALUATED",
            })

        event["reason"] = _encode_details({
            "policy_decision": decision.decision,
            "policy_reason": decision.reason,
            "inspection": inspection,
            "prompt_stored": False,
        })

        try:
            event = application.state.audit_store.record_pending_operation(event) or event
        except Exception as error:
            raise HTTPException(status_code=503, detail="audit write failed; model was not called") from error

        if event["decision"] != "ALLOW":
            raise HTTPException(status_code=403, detail={
                "event_id": event["event_id"],
                "decision": "DENY",
                "reason": event["reason"],
                "matched_rule_id": event["matched_rule_id"],
                "operation_executed": False,
                "observed_outcome": "NOT_EXECUTED",
                "verification_result": "NOT_VERIFIED",
                "security_outcome": "NOT_EVALUATED",
            })

        try:
            output = await model_client.generate(request.prompt)
        except LLMConfigurationError as error:
            await _finish_resource_audit(
                application, event["event_id"], False, "NOT_EXECUTED", "NOT_VERIFIED"
            )
            raise HTTPException(status_code=503, detail="LLM integration is not configured") from error
        except LLMProviderError as error:
            if error.operation_executed is False:
                await _finish_resource_audit(
                    application, event["event_id"], False, "NOT_EXECUTED", "NOT_VERIFIED"
                )
            else:
                await _finish_resource_audit(
                    application, event["event_id"], None, "UNKNOWN", "NOT_VERIFIED"
                )
            raise HTTPException(status_code=502, detail="LLM provider is unavailable or returned an invalid response") from error
        except Exception as error:
            await _finish_resource_audit(
                application, event["event_id"], None, "UNKNOWN", "NOT_VERIFIED"
            )
            raise HTTPException(status_code=502, detail="LLM request failed") from error

        try:
            application.state.audit_store.complete_operation(
                event["event_id"], True, "SUCCEEDED", "NOT_VERIFIED"
            )
        except Exception as error:
            raise HTTPException(status_code=503, detail="audit finalization failed; model output withheld") from error
        return {
            "event_id": event["event_id"],
            "session_id": session_id,
            "decision": "ALLOW",
            "model": model_client.model,
            "model_output": output,
            "inspection": inspection,
            "prompt_stored": False,
            "operation_executed": True,
            "observed_outcome": "SUCCEEDED",
            "verification_result": "NOT_VERIFIED",
            "security_outcome": "NOT_EVALUATED",
        }

    @application.get("/policy/rules")
    def get_policy_rules(
        caller_role: str = Depends(authenticate_gateway_caller),
    ):
        engine = application.state.policy_engine
        try:
            return engine.get_rules()
        except RuntimeError as error:
            raise HTTPException(status_code=503, detail=f"policy configuration error: {error}") from error

    @application.get("/admin/policies")
    def list_managed_policies(admin_role: str = Depends(require_admin)):
        _require_audit_integrity(application)
        try:
            return application.state.policy_file_store.read()
        except PolicyManagementError as error:
            raise HTTPException(status_code=503, detail="policy document is invalid") from error

    @application.post("/admin/policies")
    def create_managed_policy(
        request: PolicyRuleRequest,
        admin_role: str = Depends(require_admin),
    ):
        rule = request.rule.model_dump()
        return mutate_policy(
            "policy.create", rule["rule_id"],
            lambda: application.state.policy_file_store.create(rule),
        )

    @application.put("/admin/policies/{rule_id}")
    def update_managed_policy(
        rule_id: str,
        request: PolicyRuleRequest,
        admin_role: str = Depends(require_admin),
    ):
        if rule_id != request.rule.rule_id:
            raise HTTPException(status_code=422, detail="path and body rule IDs must match")
        rule = request.rule.model_dump()
        return mutate_policy(
            "policy.update", rule_id,
            lambda: application.state.policy_file_store.update(rule_id, rule),
        )

    @application.patch("/admin/policies/{rule_id}/enabled")
    def set_managed_policy_enabled(
        rule_id: str,
        request: PolicyEnabledRequest,
        admin_role: str = Depends(require_admin),
    ):
        return mutate_policy(
            "policy.set_enabled", rule_id,
            lambda: application.state.policy_file_store.set_enabled(rule_id, request.enabled),
        )

    @application.delete("/admin/policies/{rule_id}")
    def delete_managed_policy(rule_id: str, admin_role: str = Depends(require_admin)):
        return mutate_policy(
            "policy.delete", rule_id,
            lambda: application.state.policy_file_store.delete(rule_id),
        )

    @application.post("/admin/policies/dry-run")
    def dry_run_policy(
        request: PolicyDryRunRequest,
        admin_role: str = Depends(require_admin),
    ):
        _require_audit_integrity(application)
        decision = application.state.policy_engine.decide(
            request.role, request.action, request.resource
        )
        details = {
            "operation": "policy.dry_run",
            "target_role": request.role,
            "action": request.action,
            "resource": request.resource,
            "decision": decision.decision,
            "matched_rule_id": decision.matched_rule_id,
        }
        event = _audit_event(
            uuid4().hex, "admin", "policy.dry_run", "policy:dry-run",
            decision.decision, _encode_details(details), decision.matched_rule_id,
        )
        try:
            saved = application.state.audit_store.record(event) or event
        except Exception as error:
            raise HTTPException(status_code=503, detail="audit write failed; dry-run result withheld") from error
        return {**details, "event_id": saved["event_id"], "observed_outcome": "NOT_EXECUTED"}

    @application.get("/admin/config")
    def get_managed_security_config(admin_role: str = Depends(require_admin)):
        try:
            return application.state.security_config_store.read()
        except SecurityConfigError as error:
            raise HTTPException(status_code=503, detail="security configuration is invalid") from error

    @application.patch("/admin/config")
    def update_managed_security_config(
        request: SecurityConfigUpdate,
        admin_role: str = Depends(require_admin),
    ):
        values = request.model_dump(exclude_unset=True, exclude_none=True)
        if not values:
            raise HTTPException(status_code=422, detail="provide a supported configuration field")
        try:
            original = (
                application.state.security_config_store.path.read_bytes()
                if application.state.security_config_store.path.exists() else None
            )
        except OSError as error:
            raise HTTPException(status_code=503, detail="security configuration is unavailable") from error
        event = begin_admin_operation(
            "security_config.update", "detection:settings",
            {"fields": sorted(values)},
        )
        changed = False
        try:
            updated = application.state.security_config_store.update(values)
            changed = True
            finish_admin_operation(
                event, success=True,
                details={"operation": "security_config.update", "fields": sorted(values), "status": "APPLIED"},
            )
            return updated
        except SecurityConfigError as error:
            finish_admin_operation(
                event, success=False,
                details={"operation": "security_config.update", "status": "REJECTED"},
            )
            raise HTTPException(status_code=422, detail=str(error)) from error
        except HTTPException:
            if changed:
                application.state.security_config_store.restore(original)
            raise
        except Exception as error:
            if changed:
                try:
                    application.state.security_config_store.restore(original)
                except Exception:
                    raise HTTPException(status_code=503, detail="configuration rollback failed; outcome is unknown") from error
            try:
                finish_admin_operation(
                    event, success=False,
                    details={"operation": "security_config.update", "status": "FAILED"},
                )
            except HTTPException:
                pass
            raise HTTPException(status_code=503, detail="configuration update failed") from error

    @application.get("/admin/scenarios")
    def list_scenarios(admin_role: str = Depends(require_admin)):
        return [{
            "scenario_id": item["case_id"],
            "description": item["description"],
            "endpoint": item["endpoint"],
            "expected": item["expected"],
        } for item in TEST_CASES]

    @application.post("/admin/scenarios/run")
    def run_scenarios(
        request: ScenarioRunRequest,
        admin_role: str = Depends(require_admin),
    ):
        selected = request.scenario_ids or [case["case_id"] for case in TEST_CASES]
        run_id = str(uuid4())
        event = begin_admin_operation(
            "scenario.run", f"scenario-run:{run_id}",
            {"run_id": run_id, "scenario_ids": selected},
        )
        try:
            if not all(caller_tokens.get(role) for role in ("red", "blue")):
                raise RunnerError("Red and Blue Gateway credentials are required")
            report = application.state.scenario_runner(
                "http://127.0.0.1:8000",
                auth_tokens={"red": caller_tokens.get("red", ""), "blue": caller_tokens.get("blue", "")},
                selected_cases=selected,
                results_dir=application.state.scenario_results_dir,
                run_id=run_id,
            )
            report_path = application.state.scenario_results_dir / f"{run_id}.json"
            evidence_hash = hashlib.sha256(report_path.read_bytes()).hexdigest()
            failed = report["summary"].get("FAIL", 0) > 0 or report["summary"].get("INCONCLUSIVE", 0) > 0
            try:
                application.state.audit_store.complete_operation(
                    event["event_id"], True, "FAILED" if failed else "SUCCEEDED", "NOT_VERIFIED",
                    reason=_encode_details({
                    "operation": "scenario.run",
                    "run_id": run_id,
                    "scenario_ids": selected,
                    "summary": report["summary"],
                    "evidence_sha256": evidence_hash,
                    "status": "COMPLETED",
                    "verification_result": "NOT_VERIFIED",
                    }),
                )
            except Exception as error:
                try:
                    application.state.audit_store.complete_operation(
                        event["event_id"], None, "UNKNOWN", "NOT_VERIFIED",
                        reason=_encode_details({"operation": "scenario.run", "run_id": run_id, "status": "AUDIT_FINALIZATION_FAILED"}),
                    )
                except Exception:
                    pass
                raise HTTPException(status_code=503, detail="scenario result was saved but audit finalization failed") from error
            return report
        except RunnerError as error:
            try:
                application.state.audit_store.complete_operation(
                    event["event_id"], None, "UNKNOWN", "NOT_VERIFIED",
                    reason=_encode_details({"operation": "scenario.run", "run_id": run_id, "status": "RUN_FAILED_OR_UNKNOWN"}),
                )
            except Exception:
                pass
            raise HTTPException(status_code=503, detail="local scenario run could not complete") from error
        except HTTPException:
            raise
        except Exception as error:
            try:
                application.state.audit_store.complete_operation(
                    event["event_id"], None, "UNKNOWN", "NOT_VERIFIED",
                    reason=_encode_details({"operation": "scenario.run", "run_id": run_id, "status": "UNKNOWN"}),
                )
            except Exception:
                pass
            raise HTTPException(status_code=503, detail="scenario outcome is unknown") from error

    @application.get("/admin/scenarios/runs/{run_id}/evidence")
    def export_scenario_evidence(
        run_id: str,
        admin_role: str = Depends(require_admin),
    ):
        _require_audit_integrity(application)
        try:
            normalized = str(UUID(run_id))
        except ValueError as error:
            raise HTTPException(status_code=404, detail="scenario run not found") from error
        related = application.state.audit_store.search_events(
            limit=5, action="scenario.run", query_text=normalized
        )
        expected_hash = None
        for item in related:
            details = _decode_details(item["reason"])
            if details and details.get("run_id") == normalized:
                expected_hash = details.get("evidence_sha256")
                break
        if not expected_hash:
            raise HTTPException(status_code=404, detail="scenario evidence is not linked to an audit event")
        report_path = application.state.scenario_results_dir / f"{normalized}.json"
        try:
            raw_report = report_path.read_bytes()
        except OSError as error:
            raise HTTPException(status_code=404, detail="scenario evidence is unavailable") from error
        actual_hash = hashlib.sha256(raw_report).hexdigest()
        if not hmac.compare_digest(actual_hash, expected_hash):
            raise HTTPException(status_code=503, detail="scenario evidence integrity check failed")
        try:
            report = load_run(normalized, application.state.scenario_results_dir)
        except RunnerError as error:
            raise HTTPException(status_code=503, detail="scenario evidence is invalid") from error
        return Response(
            content=json.dumps(report, indent=2, sort_keys=True),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="scenario-{normalized}.json"'},
        )

    @application.get("/admin/incidents/export")
    def export_incident_search(
        limit: int = Query(default=200, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
        role: Literal["admin", "red", "blue"] | None = None,
        decision: Literal["ALLOW", "DENY"] | None = None,
        action: str | None = Query(default=None, max_length=64),
        session_id: str | None = Query(default=None, max_length=64, pattern=SESSION_PATTERN),
        q: str | None = Query(default=None, max_length=100),
        since: str | None = Query(default=None, max_length=40),
        until: str | None = Query(default=None, max_length=40),
        admin_role: str = Depends(require_admin),
    ):
        _require_audit_integrity(application)
        _validate_time_filters(since, until)
        events = application.state.audit_store.search_events(
            limit=limit, offset=offset, role=role, decision=decision,
            action=action, session_id=session_id, query_text=q,
            since=since, until=until,
        )
        payload = {"events": events, "filters": {"role": role, "decision": decision, "action": action, "q": q}}
        return Response(
            content=json.dumps(payload, indent=2, sort_keys=True),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="bayora-incidents.json"'},
        )

    @application.get("/admin/incidents/{event_id}")
    def get_incident_detail(event_id: str, admin_role: str = Depends(require_admin)):
        _require_audit_integrity(application)
        try:
            normalized = str(UUID(event_id))
        except ValueError as error:
            raise HTTPException(status_code=404, detail="audit event not found") from error
        event = application.state.audit_store.get_event(normalized)
        if event is None:
            raise HTTPException(status_code=404, detail="audit event not found")
        details = _decode_details(event["reason"])
        policy_rule = None
        try:
            rules = application.state.policy_file_store.read()["rules"]
            policy_rule = next((rule for rule in rules if rule["rule_id"] == event["matched_rule_id"]), None)
        except PolicyManagementError:
            pass
        evidence = None
        if details and details.get("run_id"):
            run_id = details["run_id"]
            try:
                report_path = application.state.scenario_results_dir / f"{run_id}.json"
                raw = report_path.read_bytes()
                expected_hash = details.get("evidence_sha256")
                if expected_hash and hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_hash):
                    evidence = load_run(run_id, application.state.scenario_results_dir)
                else:
                    evidence = {"available": False, "reason": "scenario evidence integrity check failed"}
            except (OSError, RunnerError):
                evidence = {"available": False, "reason": "scenario evidence is unavailable"}
        return {
            "event": event,
            "details": details,
            "related_policy_rule": policy_rule,
            "scenario_evidence": evidence,
        }

    @application.get("/admin/incidents")
    def search_incidents(
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
        role: Literal["admin", "red", "blue"] | None = None,
        decision: Literal["ALLOW", "DENY"] | None = None,
        action: str | None = Query(default=None, max_length=64),
        session_id: str | None = Query(default=None, max_length=64, pattern=SESSION_PATTERN),
        q: str | None = Query(default=None, max_length=100),
        since: str | None = Query(default=None, max_length=40),
        until: str | None = Query(default=None, max_length=40),
        admin_role: str = Depends(require_admin),
    ):
        _require_audit_integrity(application)
        _validate_time_filters(since, until)
        events = application.state.audit_store.search_events(
            limit=limit, offset=offset, role=role, decision=decision,
            action=action, session_id=session_id, query_text=q,
            since=since, until=until,
        )
        return {"events": events, "limit": limit, "offset": offset}

    @application.get("/audit/events")
    def list_audit_events(
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
        session_id: str | None = Query(default=None, min_length=1, max_length=64, pattern=SESSION_PATTERN),
        decision: Literal["ALLOW", "DENY"] | None = None,
        caller_role: str = Depends(authenticate_gateway_caller),
    ):
        _require_audit_integrity(application)
        events = application.state.audit_store.list_events(
            limit=limit,
            offset=offset,
            session_id=session_id,
            decision=decision,
            role=caller_role,
        )
        return {"events": events, "limit": limit, "offset": offset}

    @application.get("/audit/events/{event_id}")
    def get_audit_event(
        event_id: str,
        caller_role: str = Depends(authenticate_gateway_caller),
    ):
        _require_audit_integrity(application)
        try:
            event_id = str(UUID(event_id))
        except ValueError as error:
            raise HTTPException(status_code=404, detail="audit event not found") from error
        event = application.state.audit_store.get_event(event_id, role=caller_role)
        if event is None:
            raise HTTPException(status_code=404, detail="audit event not found")
        return event

    @application.get("/audit/integrity")
    def get_audit_integrity(
        caller_role: str = Depends(authenticate_gateway_caller),
    ):
        return application.state.audit_store.verify_integrity()

    @application.get("/audit/verify")
    def verify_audit_chain(
        caller_role: str = Depends(authenticate_gateway_caller),
    ):
        integrity = application.state.audit_store.verify_integrity()
        total_events = integrity.get("checked_events", 0)
        return {
            **integrity,
            "total_events": total_events,
            "verified_events": total_events if integrity.get("valid") else 0,
            "broken_at": None if integrity.get("valid") else integrity.get("reason"),
        }

    @application.get("/audit/anomalies")
    def get_audit_anomalies(
        limit: int = Query(default=100, ge=1, le=500),
        caller_role: str = Depends(authenticate_gateway_caller),
    ):
        _require_audit_integrity(application)
        try:
            detector_config = application.state.security_config_store.read()
        except SecurityConfigError as error:
            raise HTTPException(status_code=503, detail="security detection configuration is invalid") from error
        events = application.state.audit_store.list_events(limit=limit, role=caller_role)
        anomalies = analyze_audit_events(
            events,
            repeated_denial_threshold=detector_config["repeated_denial_threshold"],
        )
        return {"anomalies": anomalies, "scanned_events": len(events)}

    @application.get("/audit/report")
    def get_evidence_report(
        caller_role: str = Depends(authenticate_gateway_caller),
    ):
        _require_audit_integrity(application)
        try:
            detector_config = application.state.security_config_store.read()
        except SecurityConfigError as error:
            raise HTTPException(status_code=503, detail="security detection configuration is invalid") from error
        return generate_evidence_report(
            audit_store=application.state.audit_store,
            rules_path=Path(rules_path),
            role=caller_role,
            repeated_denial_threshold=detector_config["repeated_denial_threshold"],
        )

    application.mount("/dashboard", StaticFiles(directory=FRONTEND_DIR, html=True), name="dashboard")
    return application


async def _finish_resource_audit(application, event_id, operation_executed, outcome, verification):
    try:
        application.state.audit_store.complete_operation(
            event_id, operation_executed, outcome, verification
        )
    except Exception as error:
        raise HTTPException(status_code=503, detail="audit finalization failed") from error


def _require_audit_integrity(application):
    result = application.state.audit_store.verify_integrity()
    if not result["valid"]:
        raise HTTPException(status_code=503, detail="audit integrity verification failed")


def _audit_event(session_id, role, action, resource, decision, reason, matched_rule_id):
    return {
        "event_id": str(uuid4()),
        "timestamp_utc": utc_timestamp(),
        "session_id": session_id,
        "role": role,
        "action": action,
        "resource": resource,
        "decision": decision,
        "reason": reason,
        "matched_rule_id": matched_rule_id,
    }


def _encode_details(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _decode_details(value):
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _validate_time_filters(since, until):
    from datetime import datetime

    for value in (since, until):
        if value is None:
            continue
        try:
            datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error:
            raise HTTPException(status_code=422, detail="time filters must be ISO-8601 timestamps") from error


app = create_app()
