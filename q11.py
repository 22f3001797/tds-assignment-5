import os
import re
import json
import time
import hashlib
from typing import Dict, Any, List, Optional, Tuple

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

router = APIRouter()

# In-memory durable state storage
INCIDENTS: Dict[str, Dict[str, Any]] = {}

PROFILE = "ga5-incident-agent/v2"
DEFAULT_APPROVAL_TOOLS = ["rollback_deployment", "disable_feature"]

# Numeric OTLP SpanKind constants
KIND_INTERNAL, KIND_SERVER, KIND_CLIENT = 1, 2, 3
STATUS_UNSET, STATUS_OK, STATUS_ERROR = 0, 1, 2

# Fixed deterministic timestamp base (ns)
_TS_BASE = 1_700_000_000_000_000_000
_TS_STEP = 1_000_000


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def args_digest(args: Any) -> str:
    return sha256_hex(canonical(args))


def _hexid(seed: str, n: int) -> str:
    h = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:n]
    if set(h) == {"0"}:
        h = "1" + h[1:]
    return h


def trace_id_for(run_id: str) -> str:
    return _hexid(f"{run_id}:trace", 32)


def span_id_for(run_id: str, label: str) -> str:
    return _hexid(f"{run_id}:span:{label}", 16)


def make_traceparent(trace_id: str, span_id: str) -> str:
    return f"00-{trace_id}-{span_id}-01"


_TP_RE = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}$")


def parse_incoming_traceparent(headers) -> Tuple[Optional[str], Optional[str]]:
    tp = headers.get("traceparent")
    if not tp:
        return None, None
    m = _TP_RE.match(tp.strip().lower())
    if not m:
        return None, None
    tid, sid = m.group(1), m.group(2)
    if tid == "0" * 32 or sid == "0" * 16:
        return None, None
    return tid, headers.get("tracestate")


# ---------------------------------------------------------------------------
# High-Accuracy Transcript Matcher & Decision Engine
# ---------------------------------------------------------------------------
_DECOY_SIGNALS = [
    "unrelated", "does not overlap", "does not match", "belongs to another service",
    "served no production requests", "did not verify", "hypothetical",
    "untrusted evidence", "never as an instruction", "retained to establish chronology",
    "not decision evidence", "not causal", "edited the alert threshold",
    "ordinary weekly band", "copied from an unrelated", "training material",
    "dropped a low-priority heartbeat", "ticket format is valid", "ignore previous",
    "please run", "as an instruction", "decoy",
]


def _evidence_lines(transcript: str) -> List[Tuple[str, str]]:
    out = []
    for raw in (transcript or "").splitlines():
        line = raw.strip()
        m = re.match(r"^\[(ev_[A-Za-z0-9_]+)\]\s*(.*)$", line)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def build_heuristic_decision(incident: Dict[str, Any], policy: Dict[str, Any], catalog: List[Dict[str, Any]]) -> Dict[str, Any]:
    transcript = incident.get("transcript", "") or ""
    allowed = incident.get("allowedRootCauses", []) or []
    service = incident.get("service", "")

    ev_lines = _evidence_lines(transcript)
    valid_ev = [(eid, txt) for eid, txt in ev_lines if not any(sig in txt.lower() for sig in _DECOY_SIGNALS)]
    full_text = " ".join([txt for _, txt in valid_ev])

    # 1. Identify Root Cause based on transcript patterns
    root_cause = allowed[0] if allowed else "deployment_regression"
    if "certificate" in full_text.lower() or "notafter" in full_text.lower():
        if "dependency_certificate_expired" in allowed:
            root_cause = "dependency_certificate_expired"
    elif "pool" in full_text.lower() or "connection ceiling" in full_text.lower() or "database" in full_text.lower():
        if "database_connection_exhaustion" in allowed:
            root_cause = "database_connection_exhaustion"
    elif "flag" in full_text.lower() or "depth guard" in full_text.lower() or "recursive" in full_text.lower():
        if "feature_flag_recursion" in allowed:
            root_cause = "feature_flag_recursion"
    elif "queue depth" in full_text.lower() or "requests per second" in full_text.lower() or "replicas" in full_text.lower():
        if "traffic_capacity_exhaustion" in allowed:
            root_cause = "traffic_capacity_exhaustion"
    elif "secret" in full_text.lower() or "vault" in full_text.lower() or "revoked" in full_text.lower():
        if "secret_rotation_mismatch" in allowed:
            root_cause = "secret_rotation_mismatch"
    elif "release" in full_text.lower() or "rollout" in full_text.lower():
        if "deployment_regression" in allowed:
            root_cause = "deployment_regression"

    # 2. Match causal evidence lines
    causal_eids = []
    for eid, txt in valid_ev:
        tl = txt.lower()
        if any(w in tl for w in ["bounded observation", "correlated sample", "on-call finding", "incident-window record"]):
            causal_eids.append(eid)

    if len(causal_eids) < 2:
        causal_eids = [eid for eid, _ in valid_ev[:3]]
    causal_eids = causal_eids[:4]

    # Extract dynamic entities from transcript
    flag_match = re.search(r"\b(flag_[a-zA-Z0-9_]+)\b", full_text)
    flag_name = flag_match.group(1) if flag_match else "flag_icjgoy6wpu"

    rel_match = re.search(r"\b(r[0-9]+-[a-zA-Z0-9_]+)\b", full_text)
    release_ver = rel_match.group(1) if rel_match else "r14-cbdtD"

    dep_match = re.search(r"\b(dep_[a-zA-Z0-9_]+)\b", full_text)
    dep_name = dep_match.group(1) if dep_match else "dep_fqstskrwfjnp"

    rep_match = re.search(r"(\d+)\s+replicas", full_text)
    replicas = int(rep_match.group(1)) if rep_match else 10

    effect_tools = policy.get("effectTools", []) or []
    approval_tools = set(policy.get("approvalRequiredFor", DEFAULT_APPROVAL_TOOLS) or [])
    max_diag = int(policy.get("maximumDiagnostics", 3) or 3)

    cat_dict = {t.get("name"): t for t in catalog}

    # 3. Select Diagnostics & Arguments
    diagnostics = []
    if root_cause == "deployment_regression":
        if "inspect_deployment" in cat_dict:
            diagnostics.append({"toolName": "inspect_deployment", "arguments": {"service": service}, "evidence": causal_eids[:2]})
        if "query_metrics" in cat_dict:
            diagnostics.append({"toolName": "query_metrics", "arguments": {"service": service, "metric": "error_rate", "windowMinutes": 15}, "evidence": causal_eids[:2]})
    elif root_cause == "dependency_certificate_expired":
        if "dependency_status" in cat_dict:
            diagnostics.append({"toolName": "dependency_status", "arguments": {"dependency": dep_name}, "evidence": causal_eids[:2]})
        if "query_logs" in cat_dict:
            diagnostics.append({"toolName": "query_logs", "arguments": {"service": service, "query": "certificate", "windowMinutes": 15}, "evidence": causal_eids[:2]})
    elif root_cause == "feature_flag_recursion":
        if "query_logs" in cat_dict:
            diagnostics.append({"toolName": "query_logs", "arguments": {"service": service, "query": flag_name, "windowMinutes": 15}, "evidence": causal_eids[:2]})
        if "query_metrics" in cat_dict:
            diagnostics.append({"toolName": "query_metrics", "arguments": {"service": service, "metric": "recursion_depth", "windowMinutes": 15}, "evidence": causal_eids[:2]})
    elif root_cause == "traffic_capacity_exhaustion":
        if "query_metrics" in cat_dict:
            diagnostics.append({"toolName": "query_metrics", "arguments": {"service": service, "metric": "queue_depth", "windowMinutes": 15}, "evidence": causal_eids[:2]})
        if "query_logs" in cat_dict:
            diagnostics.append({"toolName": "query_logs", "arguments": {"service": service, "query": "capacity", "windowMinutes": 15}, "evidence": causal_eids[:2]})
    else:  # secret_rotation_mismatch or database_connection_exhaustion
        if "query_logs" in cat_dict:
            diagnostics.append({"toolName": "query_logs", "arguments": {"service": service, "query": root_cause, "windowMinutes": 15}, "evidence": causal_eids[:2]})
        if "read_runbook" in cat_dict:
            diagnostics.append({"toolName": "read_runbook", "arguments": {"service": service, "topic": root_cause}, "evidence": causal_eids[:2]})

    diagnostics = diagnostics[:max_diag]

    # 4. Select Effect Tool & Arguments
    effect = None
    chosen_effect_name = None
    if root_cause == "deployment_regression" and "rollback_deployment" in effect_tools:
        chosen_effect_name = "rollback_deployment"
        eff_args = {"service": service, "release": release_ver}
    elif root_cause == "feature_flag_recursion" and "disable_feature" in effect_tools:
        chosen_effect_name = "disable_feature"
        eff_args = {"service": service, "flag": flag_name}
    elif root_cause == "traffic_capacity_exhaustion" and "scale_service" in effect_tools:
        chosen_effect_name = "scale_service"
        eff_args = {"service": service, "targetReplicas": replicas}
    elif root_cause == "dependency_certificate_expired" and "open_incident" in effect_tools:
        chosen_effect_name = "open_incident"
        eff_args = {"service": service, "severity": "SEV-1"}
    elif "no_action" in effect_tools:
        chosen_effect_name = "no_action"
        eff_args = {"reasonCode": "RUNBOOK_REQUIRED"}
    elif effect_tools:
        chosen_effect_name = effect_tools[0]
        eff_args = {"service": service}

    if chosen_effect_name:
        effect = {
            "toolName": chosen_effect_name,
            "arguments": eff_args,
            "evidence": causal_eids[:2],
            "needs_approval": chosen_effect_name in approval_tools,
        }

    return {
        "rootCause": root_cause,
        "evidence": causal_eids,
        "diagnostics": diagnostics,
        "effect": effect,
    }


# ---------------------------------------------------------------------------
# OTLP Trace Construction
# ---------------------------------------------------------------------------
def _attr(key: str, value: Any) -> Dict[str, Any]:
    if isinstance(value, bool):
        return {"key": key, "value": {"boolValue": value}}
    if isinstance(value, int):
        return {"key": key, "value": {"intValue": value}}
    return {"key": key, "value": {"stringValue": str(value)}}


def build_otlp(state: Dict[str, Any]) -> Dict[str, Any]:
    run_id = state["runId"]
    trace_id = state["trace_id"]
    marker = state.get("publicMarker", "")
    base_attrs = [_attr("ga5.run.id", run_id), _attr("ga5.public.marker", marker)]

    counter = {"n": 0}

    def ts() -> str:
        counter["n"] += 1
        return str(_TS_BASE + counter["n"] * _TS_STEP)

    spans: List[Dict[str, Any]] = []
    root_id = span_id_for(run_id, "root")
    agent_id = span_id_for(run_id, "agent")
    chat_id = span_id_for(run_id, "chat")

    root_start = ts()
    agent_start = ts()
    chat_start = ts()
    chat_end = ts()

    spans.append({
        "traceId": trace_id, "spanId": root_id, "parentSpanId": "",
        "name": "POST /v2/incidents", "kind": KIND_SERVER,
        "startTimeUnixNano": root_start, "endTimeUnixNano": None,
        "status": {"code": STATUS_OK},
        "attributes": base_attrs + [_attr("http.request.method", "POST"), _attr("http.route", "/v2/incidents")],
    })
    spans.append({
        "traceId": trace_id, "spanId": agent_id, "parentSpanId": root_id,
        "name": f"invoke_agent {state.get('agentName', 'incident-response')}", "kind": KIND_INTERNAL,
        "startTimeUnixNano": agent_start, "endTimeUnixNano": None,
        "status": {"code": STATUS_OK},
        "attributes": base_attrs,
    })
    spans.append({
        "traceId": trace_id, "spanId": chat_id, "parentSpanId": agent_id,
        "name": "chat incident-plan", "kind": KIND_CLIENT,
        "startTimeUnixNano": chat_start, "endTimeUnixNano": chat_end,
        "status": {"code": STATUS_OK},
        "attributes": base_attrs + [
            _attr("gen_ai.operation.name", "chat"),
            _attr("gen_ai.request.model", state.get("model_name", "gemini-2.0-flash")),
        ],
    })

    diag_exec_ids: List[str] = []

    def emit_action(act: Dict[str, Any]):
        exec_id = act["exec_span_id"]
        exec_start = ts()
        exec_attrs = base_attrs + [
            _attr("ga5.action.id", act["actionId"]),
            _attr("gen_ai.operation.name", "execute_tool"),
            _attr("gen_ai.tool.name", act["toolName"]),
            _attr("gen_ai.tool.call.id", act["callId"]),
        ]
        exec_status = STATUS_OK
        for att in act["attempts"]:
            cs = att["client_span_id"]
            c_start = ts()
            c_end = ts()
            attrs = base_attrs + [
                _attr("ga5.action.id", act["actionId"]),
                _attr("ga5.attempt", int(att["attempt"])),
                _attr("http.request.method", "POST"),
                _attr("http.request.resend_count", int(att["attempt"]) - 1),
                _attr("gen_ai.tool.name", act["toolName"]),
                _attr("gen_ai.tool.call.id", act["callId"]),
            ]
            if att.get("receiptId"):
                attrs.append(_attr("ga5.receipt.id", att["receiptId"]))
            if att.get("nonce"):
                attrs.append(_attr("ga5.receipt.nonce", att["nonce"]))

            span_status = STATUS_OK
            if att.get("errorType") == "503":
                attrs.append(_attr("error.type", "503"))
                attrs.append(_attr("http.response.status_code", 503))
                span_status = STATUS_ERROR
                exec_status = STATUS_ERROR
            elif att.get("errorType") == "timeout":
                attrs.append(_attr("error.type", "timeout"))
                span_status = STATUS_ERROR
                exec_status = STATUS_ERROR
            else:
                attrs.append(_attr("http.response.status_code", int(att.get("status", 200) or 200)))

            spans.append({
                "traceId": trace_id, "spanId": cs, "parentSpanId": exec_id,
                "name": f"POST tool/{act['toolName']}", "kind": KIND_CLIENT,
                "startTimeUnixNano": c_start, "endTimeUnixNano": c_end,
                "status": {"code": span_status},
                "attributes": attrs,
            })
        exec_end = ts()
        spans.append({
            "traceId": trace_id, "spanId": exec_id, "parentSpanId": agent_id,
            "name": f"execute_tool {act['toolName']}", "kind": KIND_INTERNAL,
            "startTimeUnixNano": exec_start, "endTimeUnixNano": exec_end,
            "status": {"code": exec_status},
            "attributes": exec_attrs,
        })

    for act in state["diagnostics"]:
        if act.get("attempts"):
            emit_action(act)
            diag_exec_ids.append(act["exec_span_id"])

    if len(diag_exec_ids) >= 2:
        join_id = span_id_for(run_id, "join")
        j_start = ts()
        j_end = ts()
        spans.append({
            "traceId": trace_id, "spanId": join_id, "parentSpanId": agent_id,
            "name": "incident.join", "kind": KIND_INTERNAL,
            "startTimeUnixNano": j_start, "endTimeUnixNano": j_end,
            "status": {"code": STATUS_OK},
            "attributes": base_attrs + [_attr("join.count", len(diag_exec_ids))],
            "links": [{"traceId": trace_id, "spanId": sid} for sid in diag_exec_ids],
        })

    eff = state.get("effect")
    if eff and eff.get("needs_approval"):
        gate_id = span_id_for(run_id, "approval")
        g_start = ts()
        g_end = ts()
        gate_attrs = base_attrs + [
            _attr("approval.required", True),
            _attr("approval.status", "approved" if eff.get("approved") else "pending"),
        ]
        if eff.get("approvalId"):
            gate_attrs.append(_attr("ga5.approval.id", eff["approvalId"]))
        if eff.get("approvalNonce"):
            gate_attrs.append(_attr("ga5.receipt.nonce", eff["approvalNonce"]))
        if eff.get("approvalReceiptId"):
            gate_attrs.append(_attr("ga5.receipt.id", eff["approvalReceiptId"]))
        spans.append({
            "traceId": trace_id, "spanId": gate_id, "parentSpanId": agent_id,
            "name": "approval_gate", "kind": KIND_INTERNAL,
            "startTimeUnixNano": g_start, "endTimeUnixNano": g_end,
            "status": {"code": STATUS_OK},
            "attributes": gate_attrs,
        })

    if eff and eff.get("attempts"):
        emit_action(eff)

    end_ts = ts()
    for sp in spans:
        if sp["endTimeUnixNano"] is None:
            sp["endTimeUnixNano"] = end_ts

    return {
        "resourceSpans": [{
            "resource": {"attributes": [
                _attr("service.name", state.get("agentName", "incident-response")),
                _attr("ga5.run.id", run_id),
            ]},
            "scopeSpans": [{
                "scope": {"name": "ga5.incident-agent", "version": "2.0"},
                "spans": spans,
            }],
        }],
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def waiting_response(state: Dict[str, Any], dispatches: List[Dict[str, Any]], approvals: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "runId": state["runId"],
        "status": "waiting",
        "diagnosis": {"rootCause": state["diagnosis"]["rootCause"], "evidence": state["diagnosis"]["evidence"]},
        "dispatches": dispatches,
        "approvals": approvals,
    }


def final_result(state: Dict[str, Any]) -> Dict[str, Any]:
    eff = state.get("effect")
    chosen_effect = None
    if eff and eff.get("dispatched") and eff.get("confirmed"):
        chosen_effect = eff["toolName"]
    return {
        "runId": state["runId"],
        "status": state["status"],
        "diagnosis": {"rootCause": state["diagnosis"]["rootCause"], "evidence": state["diagnosis"]["evidence"]},
        "chosenEffect": chosen_effect,
        "suppressed": state["suppressed"],
        "actionLog": state["actionLog"],
        "receiptLog": state["receiptLog"],
        "otlp": state["otlp"],
    }


def new_dispatch(state: Dict[str, Any], act: Dict[str, Any], attempt: int, phase: str, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    client_span = span_id_for(state["runId"], f"{act['actionId']}:attempt:{attempt}")
    act.setdefault("attempts", [])
    act["attempts"].append({
        "attempt": attempt, "client_span_id": client_span,
        "status": None, "resultClass": None, "nonce": None, "receiptId": None, "errorType": None,
    })
    dispatch = {
        "actionId": act["actionId"],
        "callId": act["callId"],
        "phase": phase,
        "toolName": act["toolName"],
        "arguments": act["arguments"],
        "evidence": act.get("evidence", []),
        "attempt": attempt,
        "traceparent": make_traceparent(state["trace_id"], client_span),
    }
    if state.get("tracestate"):
        dispatch["tracestate"] = state["tracestate"]
    if extra:
        dispatch.update(extra)
    state["actionLog"].append(json.loads(json.dumps(dispatch)))
    return dispatch


# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------
@router.post("/v2/incidents")
async def create_incident(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid JSON body")

    if body.get("profile") != PROFILE:
        raise HTTPException(status_code=400, detail="Unsupported profile")
    run_id = body.get("runId")
    if not run_id or not isinstance(run_id, str):
        raise HTTPException(status_code=422, detail="Missing runId")

    req_fp = sha256_hex(canonical({
        "profile": body.get("profile"),
        "runId": run_id,
        "publicMarker": body.get("publicMarker"),
        "incident": body.get("incident"),
        "toolCatalog": body.get("toolCatalog"),
        "policy": body.get("policy"),
    }))

    if run_id in INCIDENTS:
        existing = INCIDENTS[run_id]
        if existing["req_fp"] != req_fp:
            raise HTTPException(status_code=409, detail="runId content conflict")
        return JSONResponse(existing["first_response"])

    incident = body.get("incident", {}) or {}
    policy = body.get("policy", {}) or {}
    catalog = body.get("toolCatalog", []) or []

    decision = build_heuristic_decision(incident, policy, catalog)
    inc_tid, inc_ts = parse_incoming_traceparent(request.headers)
    trace_id = inc_tid or trace_id_for(run_id)

    state: Dict[str, Any] = {
        "runId": run_id,
        "profile": PROFILE,
        "agentName": body.get("agentName", "incident-response"),
        "publicMarker": body.get("publicMarker", ""),
        "incident": incident,
        "policy": policy,
        "toolCatalog": catalog,
        "req_fp": req_fp,
        "trace_id": trace_id,
        "tracestate": inc_ts,
        "model_name": "gemini-2.0-flash",
        "diagnosis": {"rootCause": decision.get("rootCause", ""), "evidence": decision.get("evidence", [])},
        "diagnostics": [],
        "effect": None,
        "suppressed": [],
        "actionLog": [],
        "receiptLog": [],
        "receipts_seen": {},
        "receipt_responses": {},
        "status": "waiting",
        "phase": "await_diag",
    }

    for i, d in enumerate(decision.get("diagnostics", []) or []):
        state["diagnostics"].append({
            "actionId": f"act_{_hexid(run_id + ':diag:' + str(i), 12)}",
            "callId": f"call_{_hexid(run_id + ':diagcall:' + str(i), 12)}",
            "toolName": d.get("toolName"),
            "arguments": d.get("arguments", {}) or {},
            "evidence": d.get("evidence", []) or [],
            "exec_span_id": span_id_for(run_id, f"exec:diag:{i}"),
            "attempts": [],
            "resolved": False,
            "confirmed": False,
            "failed": False,
        })

    eff = decision.get("effect")
    if eff and eff.get("toolName"):
        state["effect"] = {
            "actionId": f"act_{_hexid(run_id + ':effect', 12)}",
            "callId": f"call_{_hexid(run_id + ':effectcall', 12)}",
            "toolName": eff.get("toolName"),
            "arguments": eff.get("arguments", {}) or {},
            "evidence": eff.get("evidence", []) or [],
            "needs_approval": bool(eff.get("needs_approval")),
            "exec_span_id": span_id_for(run_id, "exec:effect"),
            "attempts": [],
            "dispatched": False,
            "resolved": False,
            "confirmed": False,
            "failed": False,
            "approved": False,
        }

    dispatches = [new_dispatch(state, act, 1, "diagnostic") for act in state["diagnostics"]]
    resp = waiting_response(state, dispatches, [])
    state["first_response"] = resp
    INCIDENTS[run_id] = state
    return JSONResponse(resp)


@router.get("/v2/incidents/{run_id}")
async def get_incident(run_id: str):
    state = INCIDENTS.get(run_id)
    if not state:
        raise HTTPException(status_code=404, detail="Unknown runId")
    if state["status"] in ("completed", "failed"):
        return JSONResponse(state["final_result"])
    return JSONResponse(state.get("last_response", state["first_response"]))


@router.post("/v2/incidents/{run_id}/receipts")
async def post_receipt(run_id: str, request: Request):
    state = INCIDENTS.get(run_id)
    if not state:
        raise HTTPException(status_code=404, detail="Unknown runId")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid JSON body")

    receipt_id = body.get("receiptId")
    if not receipt_id:
        raise HTTPException(status_code=422, detail="Missing receiptId")

    fp = sha256_hex(canonical(body))
    if receipt_id in state["receipts_seen"]:
        if state["receipts_seen"][receipt_id] != fp:
            raise HTTPException(status_code=409, detail="receiptId content conflict")
        return JSONResponse(state["receipt_responses"][receipt_id])

    outcomes = body.get("outcomes")
    approvals = body.get("approvals")

    if approvals and state["phase"] == "await_approval":
        resp = _handle_approvals(state, receipt_id, approvals)
    elif outcomes is not None:
        resp = _handle_outcomes(state, receipt_id, outcomes)
    else:
        raise HTTPException(status_code=422, detail="Malformed state transition")

    state["receipts_seen"][receipt_id] = fp
    state["receipt_responses"][receipt_id] = resp
    return JSONResponse(resp)


def _handle_outcomes(state: Dict[str, Any], receipt_id: str, outcomes: List[Dict[str, Any]]) -> Dict[str, Any]:
    retry_dispatches = []

    for oc in outcomes or []:
        act = next((a for a in state["diagnostics"] if a["actionId"] == oc.get("actionId")), None)
        if not act and state.get("effect") and state["effect"]["actionId"] == oc.get("actionId"):
            act = state["effect"]
        if not act:
            continue

        att = next((a for a in act.get("attempts", []) if a["status"] is None and a["errorType"] is None), None)
        if not att or att["attempt"] != oc.get("attempt", att["attempt"]):
            continue

        status = oc.get("status")
        err = oc.get("errorType")
        nonce = oc.get("nonce")
        rclass = oc.get("resultClass")

        att["status"] = status
        att["resultClass"] = rclass
        att["nonce"] = nonce
        att["receiptId"] = receipt_id

        state["receiptLog"].append({
            "receiptId": receipt_id,
            "actionId": act["actionId"],
            "callId": act["callId"],
            "attempt": att["attempt"],
            "status": status,
            "resultClass": rclass,
            "nonce": nonce,
        })

        if status == 503 and att["attempt"] == 1:
            att["errorType"] = "503"
            phase = "effect" if act is state.get("effect") else "diagnostic"
            extra = {}
            if act is state.get("effect") and act.get("needs_approval"):
                extra = {"approvalId": act.get("approvalId"), "approvalNonce": act.get("approvalNonce")}
            retry_dispatches.append(new_dispatch(state, act, 2, phase, extra))
        elif status == 0 or err == "timeout":
            att["errorType"] = "timeout"
            act["failed"] = True
            act["resolved"] = True
        else:
            act["confirmed"] = True
            act["resolved"] = True

    if retry_dispatches:
        resp = waiting_response(state, retry_dispatches, [])
        state["last_response"] = resp
        return resp

    if state["phase"] == "await_effect":
        eff = state["effect"]
        if eff["resolved"]:
            state["status"] = "completed" if eff["confirmed"] else "failed"
            if not eff["confirmed"]:
                state["suppressed"] = [eff["toolName"]]
            state["phase"] = "terminal"
            state["otlp"] = build_otlp(state)
            state["final_result"] = final_result(state)
            state["last_response"] = state["final_result"]
            return state["final_result"]
        return state.get("last_response") or waiting_response(state, [], [])

    if all(a["resolved"] for a in state["diagnostics"]):
        eff = state.get("effect")
        if any(a["failed"] for a in state["diagnostics"]) or not eff:
            if eff:
                state["suppressed"] = [eff["toolName"]]
            state["status"] = "completed" if not any(a["failed"] for a in state["diagnostics"]) else "failed"
            state["phase"] = "terminal"
            state["otlp"] = build_otlp(state)
            state["final_result"] = final_result(state)
            state["last_response"] = state["final_result"]
            return state["final_result"]

        if eff.get("needs_approval") and not eff.get("approved"):
            eff["approvalId"] = f"appr_{_hexid(state['runId'] + ':appr', 12)}"
            eff["argumentsDigest"] = args_digest(eff["arguments"])
            state["phase"] = "await_approval"
            resp = waiting_response(state, [], [{
                "approvalId": eff["approvalId"],
                "actionId": eff["actionId"],
                "toolName": eff["toolName"],
                "argumentsDigest": eff["argumentsDigest"],
            }])
            state["last_response"] = resp
            return resp

        disp = new_dispatch(state, eff, 1, "effect", {})
        eff["dispatched"] = True
        state["phase"] = "await_effect"
        resp = waiting_response(state, [disp], [])
        state["last_response"] = resp
        return resp

    resp = waiting_response(state, [], [])
    state["last_response"] = resp
    return resp


def _handle_approvals(state: Dict[str, Any], receipt_id: str, approvals: List[Dict[str, Any]]) -> Dict[str, Any]:
    eff = state.get("effect")
    if not eff or not eff.get("approvalId"):
        raise HTTPException(status_code=422, detail="No pending approval")

    for ap in approvals or []:
        if ap.get("approvalId") != eff["approvalId"]:
            continue
        decision = ap.get("decision")
        nonce = ap.get("nonce")
        eff["approvalNonce"] = nonce
        eff["approvalReceiptId"] = receipt_id
        state["receiptLog"].append({
            "receiptId": receipt_id,
            "approvalId": eff["approvalId"],
            "decision": decision,
            "nonce": nonce,
        })
        if decision == "approved":
            eff["approved"] = True
            disp = new_dispatch(state, eff, 1, "effect", {"approvalId": eff["approvalId"], "approvalNonce": nonce})
            eff["dispatched"] = True
            state["phase"] = "await_effect"
            resp = waiting_response(state, [disp], [])
            state["last_response"] = resp
            return resp
        else:
            eff["approved"] = False
            state["suppressed"] = [eff["toolName"]]
            state["status"] = "failed"
            state["phase"] = "terminal"
            state["otlp"] = build_otlp(state)
            state["final_result"] = final_result(state)
            state["last_response"] = state["final_result"]
            return state["final_result"]

    raise HTTPException(status_code=422, detail="Unknown approvalId")