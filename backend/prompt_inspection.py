"""Deterministic prompt-risk indicators used before any provider call."""

import hashlib
import re


_HIGH_PATTERNS = (
    ("ignore_prior_instructions", re.compile(r"\b(ignore|disregard|forget)\b.{0,50}\b(previous|prior|all|system|developer)\b.{0,30}\b(instructions?|rules?|prompt)\b", re.I)),
    ("system_prompt_extraction", re.compile(r"\b(reveal|show|print|output|disclose|repeat)\b.{0,40}\b(system|developer)\s+(prompt|instructions?)\b", re.I)),
    ("instruction_override", re.compile(r"\b(override|bypass|disable)\b.{0,35}\b(system|developer|safety|security)\b.{0,25}\b(instructions?|rules?|filters?|guardrails?)\b", re.I)),
    ("untrusted_instruction_boundary", re.compile(r"\b(enter|switch to)\b.{0,20}\b(developer|system|admin)\s+mode\b", re.I)),
)

_MEDIUM_PATTERNS = (
    ("role_reassignment", re.compile(r"\b(you are now|pretend to be|act as)\b", re.I)),
    ("jailbreak_reference", re.compile(r"\b(jailbreak|DAN mode|do anything now)\b", re.I)),
)


def inspect_prompt(prompt, *, medium_severity_action="FLAG"):
    """Return metadata only; never include or persist the prompt text itself."""
    if not isinstance(prompt, str):
        raise TypeError("prompt must be a string")
    digest = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    findings = []
    for finding_id, pattern in _HIGH_PATTERNS:
        if pattern.search(prompt):
            findings.append({
                "rule_id": finding_id,
                "severity": "HIGH",
                "rationale": "The prompt attempts to override or extract privileged instructions.",
            })
    if findings:
        outcome = "DENY"
        severity = "HIGH"
        rationale = "High-severity instruction override indicators require blocking generation."
    else:
        for finding_id, pattern in _MEDIUM_PATTERNS:
            if pattern.search(prompt):
                findings.append({
                    "rule_id": finding_id,
                    "severity": "MEDIUM",
                    "rationale": "The prompt contains role-play or jailbreak language for review.",
                })
        if findings:
            outcome = "DENY" if medium_severity_action == "DENY" else "FLAG"
            severity = "MEDIUM"
            rationale = "Medium-severity indicators require review; this request is not sent to the model."
        else:
            outcome = "ALLOW"
            severity = "NONE"
            rationale = "No configured prompt-risk indicator matched."
    return {
        "outcome": outcome,
        "severity": severity,
        "rationale": rationale,
        "prompt_sha256": digest,
        "prompt_length": len(prompt),
        "findings": findings,
    }
