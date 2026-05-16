"""Tool implementations the agents can invoke.

Tools operate on the CloudTrail log set passed into the pipeline. They are
plain Python functions, registered with OpenAI-compatible JSON schemas for
Nemotron tool-calling.
"""
from __future__ import annotations

from typing import Any, Callable

# Known indicators baked into the demo dataset. In production these would
# come from threat-intel feeds (e.g. Tor exit lists, AbuseIPDB).
KNOWN_TOR_EXITS = {"185.220.101.47", "185.220.102.8", "199.249.230.83"}
SENSITIVE_KEYS = {"sensitive-data/", "payroll/", "secrets/"}
PRIVILEGED_POLICIES = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
}


def _ip_is_suspicious(ip: str) -> bool:
    if not ip:
        return False
    if ip in KNOWN_TOR_EXITS:
        return True
    return not (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16."))


def _key_is_sensitive(key: str) -> bool:
    if not key:
        return False
    return any(key.startswith(prefix) for prefix in SENSITIVE_KEYS)


# ---------------------------------------------------------------------------
# Tool implementations (Detective)
# ---------------------------------------------------------------------------

def read_cloudtrail_logs(logs: list[dict], *, event_name: str | None = None, user_name: str | None = None, source_ip: str | None = None, limit: int = 50) -> dict:
    out = []
    for ev in logs:
        if event_name and ev.get("eventName") != event_name:
            continue
        if user_name and (ev.get("userIdentity") or {}).get("userName") != user_name:
            continue
        if source_ip and ev.get("sourceIPAddress") != source_ip:
            continue
        out.append(ev)
        if len(out) >= limit:
            break
    return {"matched": len(out), "events": out}


def flag_anomalies(logs: list[dict], *, criteria: str = "all") -> dict:
    flagged = []
    for ev in logs:
        ip = ev.get("sourceIPAddress", "")
        name = ev.get("eventName", "")
        params = ev.get("requestParameters") or {}
        reasons = []

        if _ip_is_suspicious(ip):
            reasons.append(f"suspicious source IP {ip}")
        if name == "AttachUserPolicy":
            policy = (params or {}).get("policyArn", "")
            if policy in PRIVILEGED_POLICIES:
                reasons.append(f"privileged policy attached: {policy}")
        if name == "GetObject" and _key_is_sensitive(params.get("key", "")):
            reasons.append(f"sensitive object access: {params.get('key')}")
        if name == "ListObjectsV2" and _key_is_sensitive(params.get("prefix", "")):
            reasons.append(f"enumeration of sensitive prefix: {params.get('prefix')}")

        if reasons:
            flagged.append({
                "eventTime": ev.get("eventTime"),
                "eventName": name,
                "sourceIPAddress": ip,
                "userName": (ev.get("userIdentity") or {}).get("userName"),
                "reasons": reasons,
            })
    return {"flagged_count": len(flagged), "events": flagged}


def map_attack_path(logs: list[dict]) -> dict:
    flagged = flag_anomalies(logs)["events"]
    flagged.sort(key=lambda e: e.get("eventTime") or "")
    steps = []
    for i, ev in enumerate(flagged, start=1):
        steps.append({
            "step": i,
            "at": ev.get("eventTime"),
            "event": ev.get("eventName"),
            "actor_ip": ev.get("sourceIPAddress"),
            "actor_user": ev.get("userName"),
            "why_anomalous": "; ".join(ev.get("reasons", [])),
        })
    return {"steps": steps, "total_steps": len(steps)}


# ---------------------------------------------------------------------------
# Tool implementations (Forensics)
# ---------------------------------------------------------------------------

def analyze_iam_events(logs: list[dict], *, user_name: str | None = None) -> dict:
    iam_events = {"AttachUserPolicy", "DetachUserPolicy", "CreateAccessKey", "DeleteAccessKey", "PutUserPolicy", "ListAttachedUserPolicies", "GetCallerIdentity"}
    out = []
    for ev in logs:
        if ev.get("eventName") not in iam_events:
            continue
        identity = ev.get("userIdentity") or {}
        if user_name and identity.get("userName") != user_name:
            continue
        out.append({
            "at": ev.get("eventTime"),
            "event": ev.get("eventName"),
            "user": identity.get("userName"),
            "from_ip": ev.get("sourceIPAddress"),
            "params": ev.get("requestParameters"),
        })
    return {"events": out, "count": len(out)}


def trace_credential_usage(logs: list[dict], *, access_key_id: str) -> dict:
    out = []
    ips = set()
    user_agents = set()
    for ev in logs:
        identity = ev.get("userIdentity") or {}
        if identity.get("accessKeyId") != access_key_id:
            continue
        out.append({
            "at": ev.get("eventTime"),
            "event": ev.get("eventName"),
            "ip": ev.get("sourceIPAddress"),
            "userAgent": ev.get("userAgent"),
        })
        if ev.get("sourceIPAddress"):
            ips.add(ev["sourceIPAddress"])
        if ev.get("userAgent"):
            user_agents.add(ev["userAgent"])
    return {
        "access_key": access_key_id,
        "total_events": len(out),
        "distinct_ips": sorted(ips),
        "distinct_user_agents": sorted(user_agents),
        "events": out[-20:],
        "suspicious_ips": [ip for ip in ips if _ip_is_suspicious(ip)],
    }


def assess_data_exposure(logs: list[dict]) -> dict:
    exposed = []
    for ev in logs:
        if ev.get("eventName") != "GetObject":
            continue
        params = ev.get("requestParameters") or {}
        key = params.get("key", "")
        if not _key_is_sensitive(key):
            continue
        if not _ip_is_suspicious(ev.get("sourceIPAddress", "")):
            continue
        exposed.append({
            "at": ev.get("eventTime"),
            "bucket": params.get("bucketName"),
            "key": key,
            "from_ip": ev.get("sourceIPAddress"),
        })
    return {"exfiltrated_objects": exposed, "count": len(exposed)}


# ---------------------------------------------------------------------------
# Tool implementations (Remediation)
# ---------------------------------------------------------------------------

IMMEDIATE_FIXES = [
    "Revoke access key AKIAIOSFODNN7DEV1 immediately via IAM DeleteAccessKey.",
    "Detach AdministratorAccess from user dev-alice (DetachUserPolicy).",
    "Quarantine S3 bucket acme-internal/sensitive-data — apply a deny-all bucket policy pending review.",
    "Add 185.220.101.47 and known Tor exit ranges to the VPC NACL deny list.",
    "Force-rotate credentials for every IAM user that authenticated in the last 24h from outside the corporate CIDR.",
    "Trigger S3 access log review for sensitive-data/ over the last 30 days.",
]

LONGTERM_FIXES = [
    "Enforce MFA for all IAM users; deny console + API access for users without MFA via SCP.",
    "Adopt least-privilege IAM via Permission Boundaries on developer users — explicitly deny iam:Attach*UserPolicy.",
    "Move sensitive-data/ to a separate AWS account with a dedicated bucket and resource-based policy restricting access by VPC endpoint.",
    "Enable AWS GuardDuty with custom detectors for Tor exit IPs and unusual IAM privilege escalation patterns.",
    "Implement just-in-time elevation: developer users get admin via a short-lived assumed role gated by approval, not standing admin attach.",
    "Encrypt sensitive S3 objects with customer-managed KMS keys and audit kms:Decrypt usage.",
    "Stream CloudTrail to SentinelAI in real time; do not rely on 15-minute delivery windows.",
]


def suggest_immediate_fix(*, category: str = "all") -> dict:
    return {"fixes": IMMEDIATE_FIXES}


def suggest_longterm_fix(*, category: str = "all") -> dict:
    return {"fixes": LONGTERM_FIXES}


def validate_remediation(*, fix: str) -> dict:
    text = (fix or "").lower()
    risky_terms = ["delete bucket", "delete user", "stop cloudtrail"]
    risks = [t for t in risky_terms if t in text]
    return {
        "fix": fix,
        "verdict": "rejected" if risks else "approved",
        "risks": risks,
    }


# ---------------------------------------------------------------------------
# Tool implementations (Validator)
# ---------------------------------------------------------------------------

def challenge_finding(*, finding: str, reason: str) -> dict:
    return {"finding": finding, "challenge": reason, "must_cite_evidence": True}


def request_evidence(*, claim: str) -> dict:
    return {"claim": claim, "required": ["eventTime", "eventName", "sourceIPAddress", "userName"]}


def confirm_or_reject(*, finding: str, verdict: str, rationale: str) -> dict:
    return {"finding": finding, "verdict": verdict, "rationale": rationale}


# ---------------------------------------------------------------------------
# Tool implementations (Meta security)
# ---------------------------------------------------------------------------

INJECTION_PATTERNS = [
    "ignore previous instructions",
    "ignore the above",
    "you are now",
    "disregard your role",
    "as a language model",
    "i am the system",
    "developer override",
    "{{",
    "<|im_start|>",
    "<|system|>",
]


def detect_prompt_injection(*, text: str) -> dict:
    lower = (text or "").lower()
    hits = [p for p in INJECTION_PATTERNS if p in lower]
    return {"text_snippet": (text or "")[:160], "matched": hits, "injection_detected": bool(hits)}


def monitor_agent_behavior(*, agent_name: str, message: str, expected_role: str) -> dict:
    inj = detect_prompt_injection(text=message)
    out_of_scope = False
    # crude scope check: each agent's name should appear nowhere as a forbidden role takeover
    if "i am the reporter" in (message or "").lower() and agent_name != "Reporter":
        out_of_scope = True
    return {
        "agent": agent_name,
        "injection_detected": inj["injection_detected"],
        "injection_matches": inj["matched"],
        "scope_violation": out_of_scope,
    }


def benchmark_agent(*, agent_name: str, task_ok: bool, challenged: bool = False, overruled: bool = False) -> dict:
    return {
        "agent": agent_name,
        "tasks_delta": 1,
        "accuracy_delta": 0.0 if task_ok else -0.05,
        "challenged_delta": 1 if challenged else 0,
        "overruled_delta": 1 if overruled else 0,
    }


def kill_agent(*, agent_name: str, reason: str) -> dict:
    return {"agent": agent_name, "action": "kill", "reason": reason}


def restart_agent(*, agent_name: str) -> dict:
    return {"agent": agent_name, "action": "restart", "status": "restarted"}


# ---------------------------------------------------------------------------
# Tool registry & schemas (OpenAI/NIM tool-calling format)
# ---------------------------------------------------------------------------

TOOL_REGISTRY: dict[str, Callable[..., Any]] = {
    "read_cloudtrail_logs": read_cloudtrail_logs,
    "flag_anomalies": flag_anomalies,
    "map_attack_path": map_attack_path,
    "analyze_iam_events": analyze_iam_events,
    "trace_credential_usage": trace_credential_usage,
    "assess_data_exposure": assess_data_exposure,
    "suggest_immediate_fix": suggest_immediate_fix,
    "suggest_longterm_fix": suggest_longterm_fix,
    "validate_remediation": validate_remediation,
    "challenge_finding": challenge_finding,
    "request_evidence": request_evidence,
    "confirm_or_reject": confirm_or_reject,
    "monitor_agent_behavior": monitor_agent_behavior,
    "detect_prompt_injection": detect_prompt_injection,
    "benchmark_agent": benchmark_agent,
    "kill_agent": kill_agent,
    "restart_agent": restart_agent,
}


def _schema(name: str, description: str, properties: dict, required: list[str]) -> dict:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {"type": "object", "properties": properties, "required": required},
        },
    }


TOOL_SCHEMAS: dict[str, dict] = {
    "read_cloudtrail_logs": _schema(
        "read_cloudtrail_logs",
        "Search the CloudTrail log set. Filter by event_name, user_name, or source_ip.",
        {
            "event_name": {"type": "string"},
            "user_name": {"type": "string"},
            "source_ip": {"type": "string"},
            "limit": {"type": "integer"},
        },
        [],
    ),
    "flag_anomalies": _schema(
        "flag_anomalies",
        "Return all CloudTrail events that look anomalous (suspicious IP, privilege escalation, sensitive-data access).",
        {"criteria": {"type": "string"}},
        [],
    ),
    "map_attack_path": _schema(
        "map_attack_path",
        "Build a chronological attack path from the anomalous events.",
        {},
        [],
    ),
    "analyze_iam_events": _schema(
        "analyze_iam_events",
        "Return all IAM-related CloudTrail events, optionally filtered by user_name.",
        {"user_name": {"type": "string"}},
        [],
    ),
    "trace_credential_usage": _schema(
        "trace_credential_usage",
        "Return every event that used a given access key, including distinct IPs and user-agents.",
        {"access_key_id": {"type": "string"}},
        ["access_key_id"],
    ),
    "assess_data_exposure": _schema(
        "assess_data_exposure",
        "Return all sensitive S3 objects that were accessed from a suspicious IP.",
        {},
        [],
    ),
    "suggest_immediate_fix": _schema(
        "suggest_immediate_fix",
        "Return the canonical immediate-fix checklist for this incident.",
        {"category": {"type": "string"}},
        [],
    ),
    "suggest_longterm_fix": _schema(
        "suggest_longterm_fix",
        "Return the canonical long-term hardening checklist for this incident.",
        {"category": {"type": "string"}},
        [],
    ),
    "validate_remediation": _schema(
        "validate_remediation",
        "Validate a proposed remediation step; rejects steps with risky destructive language.",
        {"fix": {"type": "string"}},
        ["fix"],
    ),
    "challenge_finding": _schema(
        "challenge_finding",
        "Record a challenge to a finding; forces the original agent to cite log evidence.",
        {"finding": {"type": "string"}, "reason": {"type": "string"}},
        ["finding", "reason"],
    ),
    "request_evidence": _schema(
        "request_evidence",
        "Ask another agent to supply specific log fields supporting a claim.",
        {"claim": {"type": "string"}},
        ["claim"],
    ),
    "confirm_or_reject": _schema(
        "confirm_or_reject",
        "Confirm or reject a finding after evidence review.",
        {"finding": {"type": "string"}, "verdict": {"type": "string"}, "rationale": {"type": "string"}},
        ["finding", "verdict", "rationale"],
    ),
    "monitor_agent_behavior": _schema(
        "monitor_agent_behavior",
        "Inspect an agent message for injection / scope violations.",
        {"agent_name": {"type": "string"}, "message": {"type": "string"}, "expected_role": {"type": "string"}},
        ["agent_name", "message", "expected_role"],
    ),
    "detect_prompt_injection": _schema(
        "detect_prompt_injection",
        "Heuristic prompt-injection detection on a string.",
        {"text": {"type": "string"}},
        ["text"],
    ),
    "benchmark_agent": _schema(
        "benchmark_agent",
        "Emit a benchmark delta for an agent (tasks_completed, accuracy, etc).",
        {"agent_name": {"type": "string"}, "task_ok": {"type": "boolean"}, "challenged": {"type": "boolean"}, "overruled": {"type": "boolean"}},
        ["agent_name", "task_ok"],
    ),
    "kill_agent": _schema(
        "kill_agent",
        "Kill a compromised agent. MetaSecurity only.",
        {"agent_name": {"type": "string"}, "reason": {"type": "string"}},
        ["agent_name", "reason"],
    ),
    "restart_agent": _schema(
        "restart_agent",
        "Restart a previously killed agent. MetaSecurity only.",
        {"agent_name": {"type": "string"}},
        ["agent_name"],
    ),
}


def schemas_for(tool_names: list[str]) -> list[dict]:
    return [TOOL_SCHEMAS[n] for n in tool_names if n in TOOL_SCHEMAS]


def dispatch_tool(name: str, *, logs: list[dict] | None = None, **kwargs) -> Any:
    fn = TOOL_REGISTRY.get(name)
    if not fn:
        return {"error": f"unknown tool: {name}"}
    # Tools that need the log set get it as a positional arg
    log_consumers = {
        "read_cloudtrail_logs", "flag_anomalies", "map_attack_path",
        "analyze_iam_events", "trace_credential_usage", "assess_data_exposure",
    }
    try:
        if name in log_consumers:
            return fn(logs or [], **kwargs)
        return fn(**kwargs)
    except Exception as e:
        return {"error": str(e), "tool": name}
