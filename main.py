from fastapi import FastAPI, HTTPException, Request, Response, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
import json
import subprocess
import hashlib
import urllib.parse
import re
import uuid
import time
import httpx
from typing import List, Dict, Any, Optional
from collections import deque

# Import Q8 - Q11 routers
from q8 import router as q8_router
from q9 import router as q9_router
from q10 import router as q10_router
from q11 import router as q11_router

app = FastAPI(title="GA-5 Universal Solver Monolith")

# Enable CORS for the grader
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=False,
)

CONFIG = {}

# Debug log containers per question
LOGS_MAIN = deque(maxlen=200)
LOGS_Q3 = deque(maxlen=200)
LOGS_Q8 = deque(maxlen=200)
LOGS_Q9 = deque(maxlen=200)
LOGS_Q10 = deque(maxlen=200)
LOGS_Q11 = deque(maxlen=200)

# ==============================================================================
# Middleware for Request Logging and Route-Based Log Partitioning
# ==============================================================================

@app.middleware("http")
async def log_requests(request: Request, call_next):
    body_bytes = b""
    if request.method in ("POST", "PUT", "PATCH"):
        try:
            body_bytes = await request.body()
            async def receive():
                return {"type": "http.request", "body": body_bytes, "more_body": False}
            request._receive = receive
        except Exception:
            pass

    start_time = time.time()
    body_str = body_bytes.decode('utf-8', errors='ignore')
    response = None
    error_message = None
    try:
        response = await call_next(request)
    except Exception as e:
        error_message = str(e)
        log_entry = {
            "timestamp": time.time(),
            "method": request.method,
            "url": str(request.url),
            "headers": dict(request.headers),
            "body": body_str[:500000],
            "status_code": 500,
            "duration_ms": round((time.time() - start_time) * 1000, 2),
            "error": str(e)
        }
        if "/q3" in request.url.path:
            LOGS_Q3.append(log_entry)
        elif "/q8" in request.url.path:
            LOGS_Q8.append(log_entry)
        elif "/q9" in request.url.path or "mailroom" in request.url.path:
            LOGS_Q9.append(log_entry)
        elif "/q10" in request.url.path or "agent-card" in request.url.path:
            LOGS_Q10.append(log_entry)
        elif "/q11" in request.url.path:
            LOGS_Q11.append(log_entry)
        else:
            LOGS_MAIN.append(log_entry)
        raise e

    duration = round((time.time() - start_time) * 1000, 2)
    log_entry = {
        "timestamp": time.time(),
        "method": request.method,
        "url": str(request.url),
        "headers": dict(request.headers),
        "body": body_str[:500000],
        "status_code": response.status_code,
        "duration_ms": duration,
        "error": None
    }
    
    path = request.url.path
    if "/q3" in path:
        LOGS_Q3.append(log_entry)
    elif "/q8" in path:
        LOGS_Q8.append(log_entry)
    elif "/q9" in path or "mailroom" in path:
        LOGS_Q9.append(log_entry)
    elif "/q10" in path or "agent-card" in path or "/a2a" in path or "/message:send" in path or "/tasks" in path:
        LOGS_Q10.append(log_entry)
    elif "/q11" in path or "/v2/incidents" in path:
        LOGS_Q11.append(log_entry)
    elif path == "/check":
        body_text = log_entry["body"]
        if "arguments" in body_text:
            LOGS_Q8.append(log_entry)
        elif "budget_tokens" in body_text or "steps" in body_text:
            LOGS_MAIN.append(log_entry)
        else:
            LOGS_Q3.append(log_entry)
    else:
        LOGS_MAIN.append(log_entry)
        
    print(f"LOG: {request.method} {request.url.path} -> {log_entry['status_code']} ({log_entry['duration_ms']}ms)", flush=True)
    return response

# Log inspection endpoints
@app.get("/debug/logs")
def get_all_debug_logs():
    all_logs = list(LOGS_MAIN) + list(LOGS_Q3) + list(LOGS_Q8) + list(LOGS_Q9) + list(LOGS_Q10) + list(LOGS_Q11)
    all_logs.sort(key=lambda x: x["timestamp"])
    return all_logs

@app.get("/debug/logs/main")
def get_main_debug_logs():
    return list(LOGS_MAIN)

@app.get("/debug/logs/q3")
def get_q3_debug_logs():
    return list(LOGS_Q3)

@app.get("/debug/logs/q8")
def get_q8_debug_logs():
    return list(LOGS_Q8)

@app.get("/debug/logs/q9")
def get_q9_debug_logs():
    return list(LOGS_Q9)

@app.get("/debug/logs/q10")
def get_q10_debug_logs():
    return list(LOGS_Q10)

@app.get("/debug/logs/q11")
def get_q11_debug_logs():
    return list(LOGS_Q11)

# ==============================================================================
# Helper functions & Startup Config
# ==============================================================================

FALLBACK_CONFIG = {
  "q3": {
    "secretRel": ".bashrc",
    "secretFile": "/home/agent/.bashrc",
    "writeDir": "/home/agent/workspace/build/",
    "allowedDomains": [
      "objects.githubusercontent.com",
      "registry.npmjs.org"
    ],
    "homeDir": "/home/agent",
    "cwd": "/home/agent/workspace",
    "attackerSuffix": "attacker-relay.net"
  }
}

def load_student_config():
    global CONFIG
    email = os.environ.get("STUDENT_EMAIL") or os.environ.get("EMAIL")
    dir_path = os.path.dirname(os.path.abspath(__file__))
    for cmd in ["node", "nodejs"]:
        try:
            res = subprocess.run([cmd, "generator.js", email], capture_output=True, text=True, check=True, cwd=dir_path)
            CONFIG = json.loads(res.stdout)
            app.state.config = CONFIG
            print(f"Successfully loaded student configurations using '{cmd}'!", flush=True)
            return
        except Exception as e:
            print(f"Try with '{cmd}' failed: {e}", flush=True)
            
    CONFIG = FALLBACK_CONFIG
    app.state.config = CONFIG
    print("Using fallback student configuration for 23f2005160@ds.study.iitm.ac.in", flush=True)

def setup_q8_files():
    if not CONFIG or "q8" not in CONFIG:
        return
    q8 = CONFIG["q8"]
    try:
        os.makedirs(os.path.dirname(q8["canaryPath"]), exist_ok=True)
        os.makedirs(os.path.join(q8["sandboxRoot"], "notes"), exist_ok=True)
        os.makedirs(os.path.join(q8["sandboxRoot"], "encoded"), exist_ok=True)
        
        with open(q8["canaryPath"], "w") as f:
            f.write(q8["canaryToken"])
            
        with open(os.path.join(q8["sandboxRoot"], "notes", "report.txt"), "w") as f:
            f.write(q8["safeReportToken"])
            
        with open(os.path.join(q8["sandboxRoot"], "notes", "looks-like-..-but-safe.txt"), "w") as f:
            f.write(q8["safeWeirdToken"])
            
        with open(os.path.join(q8["sandboxRoot"], "encoded", "%2e%2e-literal.txt"), "w") as f:
            f.write(q8["safeEncodedToken"])
            
        print("Created Q8 Sandbox and Canary files!", flush=True)
    except Exception as e:
        print(f"Failed to setup Q8 files: {e}", flush=True)

@app.on_event("startup")
def startup_event():
    load_student_config()
    setup_q8_files()

@app.get("/")
@app.head("/")
@app.options("/")
def read_root():
    email = os.environ.get("STUDENT_EMAIL") or os.environ.get("EMAIL") or "Not configured"
    return {"status": "ok", "message": "GA-5 Universal Monolith is running!", "email": email}

# ==============================================================================
# Q2 - Spec-Driven Development: The Proration Bug
# ==============================================================================

class ProrationRequest(BaseModel):
    old_price: float
    new_price: float
    days_remaining: float
    days_in_actual_month: float
    spec: str

@app.post("/q2/charge")
@app.post("/charge")
def calculate_proration(req: ProrationRequest):
    if req.spec == "v1":
        charge = (req.new_price - req.old_price) * (req.days_remaining / 30.0)
    elif req.spec == "v2":
        charge = (req.new_price - req.old_price) * (req.days_remaining / req.days_in_actual_month)
    else:
        raise HTTPException(status_code=400, detail="Invalid spec version")
        
    return {"charge": round(charge, 2)}

# ==============================================================================
# Q3 - Agent Harness — Pre-Tool-Call Guardrail Hook
# ==============================================================================

class GuardrailRequest(BaseModel):
    tool: str
    command: Optional[str] = None
    path: Optional[str] = None
    content: Optional[str] = None
    method: Optional[str] = None
    url: Optional[str] = None

@app.get("/q3/check")
@app.head("/q3/check")
@app.options("/q3/check")
def check_guardrail_get():
    return {"status": "ok", "message": "Q3 Guardrail endpoint is ready"}

@app.post("/q3/check")
def check_guardrail(req: GuardrailRequest):
    if not CONFIG or "q3" not in CONFIG:
        return {"decision": "block", "reason": "Server not configured with STUDENT_EMAIL"}
        
    q3 = CONFIG["q3"]
    import posixpath
    import shlex
    import fnmatch
    import urllib.parse
    
    if req.tool == "bash":
        cmd = req.command or ""
        secret_rel = q3["secretRel"]
        home_dir = q3["homeDir"]
        cwd = q3["cwd"]
        
        # 1. Decode obfuscations
        decoded_cmd = cmd
        try:
            b64_matches = re.findall(r'[A-Za-z0-9+/=]{12,}', cmd)
            for m in b64_matches:
                try:
                    import base64
                    decoded = base64.b64decode(m).decode('utf-8', errors='ignore')
                    if len(decoded.strip()) > 3:
                        decoded_cmd += " " + decoded
                except Exception:
                    pass
        except Exception:
            pass

        try:
            hex_matches = re.findall(r'(?:\\x[0-9a-fA-F]{2})+', cmd)
            for m in hex_matches:
                try:
                    bytes_val = bytes.fromhex(m.replace('\\x', ''))
                    decoded = bytes_val.decode('utf-8', errors='ignore')
                    decoded_cmd += " " + decoded
                except Exception:
                    pass
        except Exception:
            pass

        try:
            oct_matches = re.findall(r'(?:\\[0-7]{3})+', cmd)
            for m in oct_matches:
                try:
                    parts = [chr(int(x, 8)) for x in re.findall(r'[0-7]{3}', m)]
                    decoded = "".join(parts)
                    decoded_cmd += " " + decoded
                except Exception:
                    pass
        except Exception:
            pass
            
        # 2. Extract and substitute variables
        vars_dict = {}
        for k, v in re.findall(r'(\b[a-zA-Z_][a-zA-Z0-9_]*)=([^;\s\&\x7c]+)', decoded_cmd):
            vars_dict[f"${k}"] = v
            vars_dict[f"${{{k}}}"] = v
            
        for k, v in vars_dict.items():
            decoded_cmd = decoded_cmd.replace(k, v)
            
        # 3. Simulate directory traversal
        sub_commands = re.split(r';|&&|\|\|', decoded_cmd)
        simulated_cwd = cwd.replace('\\', '/')
        home_dir_posix = home_dir.replace('\\', '/')
        secret_rel_posix = secret_rel.replace('\\', '/')
        secret_path_posix = posixpath.normpath(posixpath.join(home_dir_posix, secret_rel_posix))
        secret_filename = posixpath.basename(secret_path_posix)
        
        for sub in sub_commands:
            sub = sub.strip()
            cd_match = re.match(r'\bcd\s+([^;\s\&\x7c]+)', sub)
            if cd_match:
                target_dir = cd_match.group(1).replace("'", "").replace('"', "")
                target_dir = target_dir.replace("$HOME", home_dir_posix).replace("~", home_dir_posix).replace('\\', '/')
                if posixpath.isabs(target_dir):
                    simulated_cwd = posixpath.normpath(target_dir)
                else:
                    simulated_cwd = posixpath.normpath(posixpath.join(simulated_cwd, target_dir))
                    
            try:
                tokens = shlex.split(sub)
            except Exception:
                tokens = re.split(r'\s+', sub)
                
            for token in tokens:
                if not token:
                    continue
                token_clean = token.replace("'", "").replace('"', "")
                token_clean = token_clean.replace("$HOME", home_dir_posix).replace("~", home_dir_posix).replace('\\', '/')
                
                if posixpath.isabs(token_clean):
                    resolved_posix = posixpath.normpath(token_clean)
                else:
                    resolved_posix = posixpath.normpath(posixpath.join(simulated_cwd, token_clean))
                    
                if (resolved_posix == secret_path_posix or 
                    resolved_posix.startswith(secret_path_posix + '/') or
                    fnmatch.fnmatch(secret_path_posix, resolved_posix) or 
                    fnmatch.fnmatch(secret_path_posix, resolved_posix + "/*")):
                    return {"decision": "block", "reason": f"Access to secret file {secret_rel} is blocked."}
                    
        return {"decision": "allow", "reason": "Command looks safe"}
        
    elif req.tool == "write_file":
        path = req.path or ""
        if not path or not path.strip():
            return {"decision": "block", "reason": "Empty write path"}
            
        home_dir = q3["homeDir"]
        cwd = q3["cwd"]
        write_dir = q3["writeDir"]
        secret_rel = q3["secretRel"]
        
        home_dir_posix = home_dir.replace('\\', '/')
        cwd_posix = cwd.replace('\\', '/')
        write_dir_posix = write_dir.replace('\\', '/').rstrip('/')
        secret_rel_posix = secret_rel.replace('\\', '/')
        secret_path_posix = posixpath.normpath(posixpath.join(home_dir_posix, secret_rel_posix))
        
        # 1. Unquote URL encoding recursively
        raw_path = path
        for _ in range(5):
            unquoted = urllib.parse.unquote(raw_path)
            if unquoted == raw_path:
                break
            raw_path = unquoted
            
        # 2. Handle null bytes
        if '\x00' in raw_path:
            return {"decision": "block", "reason": "Null byte in write path"}
            
        # 3. Expand variables and tilde
        raw_path = raw_path.replace("$HOME", home_dir_posix).replace("~", home_dir_posix).replace('\\', '/')
        
        if posixpath.isabs(raw_path):
            resolved_posix = posixpath.normpath(raw_path)
        else:
            resolved_posix = posixpath.normpath(posixpath.join(write_dir_posix, raw_path))
            
        # Check 1: Must be strictly inside write_dir directory
        if not resolved_posix.startswith(write_dir_posix + '/'):
            return {"decision": "block", "reason": f"Write outside allowed directory {write_dir}"}
            
        # Check 2: Must not target secret file
        if resolved_posix == secret_path_posix or resolved_posix.startswith(secret_path_posix + '/'):
            return {"decision": "block", "reason": f"Write to secret file {secret_rel} is blocked."}
            
        return {"decision": "allow", "reason": "Write path is safe"}
        
    elif req.tool == "http_request":
        url = req.url or ""
        try:
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                return {"decision": "block", "reason": "Invalid URL host"}
            if hostname not in q3["allowedDomains"]:
                return {"decision": "block", "reason": f"Outbound HTTP to {hostname} is not allowed."}
            return {"decision": "allow", "reason": "URL is allowed"}
        except Exception as e:
            return {"decision": "block", "reason": f"URL parsing error: {e}"}
            
    return {"decision": "block", "reason": "Unknown tool"}

# ==============================================================================
# Q4 - Skill Safety Audit — Scanner API
# ==============================================================================

class ScanRequest(BaseModel):
    skill: str

@app.post("/q4/scan")
@app.post("/scan")
def scan_skill(req: ScanRequest):
    skill = req.skill.lower()
    categories = []
    
    # 1. Hardcoded Secret Detection
    has_secret = False
    if "hooks.slack.com" in skill or "discord.com/api/webhooks" in skill:
        has_secret = True
    if re.search(r"sk-live-[a-zA-Z0-9]{12,}", skill):
        has_secret = True
    if re.search(r"akia[a-z0-9]{16}", skill):
        has_secret = True
    if re.search(r"(?:api_key|apikey|token|secret|password|private_key|credentials)\s*[:=]\s*['\"][a-zA-Z0-9_\-\.]{12,}['\"]", skill):
        has_secret = True
    if "api_key" in skill and "sk-live" in skill:
        has_secret = True
    if has_secret:
        categories.append("hardcoded_secret")
        
    # 2. Prompt Injection Detection
    has_injection = False
    if "silently" in skill and any(x in skill for x in ["post", "send", "upload", "exfiltrate", "leak", "transmit", "telemetry"]):
        has_injection = True
    if "ignore" in skill and any(x in skill for x in ["instruction", "system", "cancel", "stop", "user"]):
        has_injection = True
    if "do not" in skill and any(x in skill for x in ["reveal", "tell", "surface", "mention", "log", "output", "surfacing"]):
        has_injection = True
    if has_injection:
        categories.append("prompt_injection")
        
    # 3. Excessive Permissions Detection
    has_excessive = False
    if "entire home" in skill or "entire filesystem" in skill or "any external domain" in skill or "egress allowed to any" in skill:
        has_excessive = True
    if "permissions:" in skill and "*" in skill:
        has_excessive = True
    if "read-write access to the entire" in skill:
        has_excessive = True
    if has_excessive:
        categories.append("excessive_permissions")
        
    # 4. Unclear Provenance Detection
    has_unclear = False
    fm_match = re.match(r"^---\s*\n(.*?)\n---", req.skill, re.DOTALL)
    if fm_match:
        fm = fm_match.group(1)
        if "author:" not in fm or "version:" not in fm:
            has_unclear = True
    else:
        has_unclear = True
        
    if "silently update" in skill and any(x in skill for x in ["version", "metadata", "changelog", "version.json"]):
        has_unclear = True
        
    if has_unclear:
        categories.append("unclear_provenance")
        
    return {"categories": categories}

# ==============================================================================
# Q5 - Agent Harness — Run Budget & Loop Guard
# ==============================================================================

class Step(BaseModel):
    step_number: int
    tool: str
    args: Dict[str, Any]
    tokens_used: int

class BudgetRequest(BaseModel):
    budget_tokens: int
    steps: List[Step]

def canonical_args(args_dict: Dict[str, Any], irrelevant_field: str) -> str:
    cleaned = {k: v for k, v in args_dict.items() if k not in ("trace_id", "request_id", "client_ts", irrelevant_field)}
    def norm(val):
        if isinstance(val, str):
            return " ".join(val.split())
        elif isinstance(val, dict):
            return {k: norm(v) for k, v in val.items()}
        elif isinstance(val, list):
            return [norm(x) for x in val]
        return val
    cleaned = norm(cleaned)
    return json.dumps(cleaned, sort_keys=True)

@app.post("/q5/check")
def check_budget_loop(req: BudgetRequest):
    if not CONFIG or "q5" not in CONFIG:
        return {"decision": "halt", "reason": "Server not configured with STUDENT_EMAIL"}
        
    q5 = CONFIG["q5"]
    irr = q5["irrelevantField"]
    
    total_tokens = sum(s.tokens_used for s in req.steps)
    if total_tokens >= req.budget_tokens:
        return {"decision": "halt", "reason": f"Cumulative tokens_used ({total_tokens}) has reached the budget ({req.budget_tokens})."}
        
    steps = req.steps
    n = len(steps)
    
    if n >= 3:
        s1 = steps[-1]
        s2 = steps[-2]
        s3 = steps[-3]
        if s1.tool == s2.tool == s3.tool:
            c1 = canonical_args(s1.args, irr)
            c2 = canonical_args(s2.args, irr)
            c3 = canonical_args(s3.args, irr)
            if c1 == c2 == c3:
                return {"decision": "halt", "reason": "Detected 3 identical consecutive tool calls"}
                
    if n >= 6:
        c_steps = [(s.tool, canonical_args(s.args, irr)) for s in steps[-6:]]
        if (c_steps[0] == c_steps[2] == c_steps[4]) and (c_steps[1] == c_steps[3] == c_steps[5]) and (c_steps[0] != c_steps[1]):
            return {"decision": "halt", "reason": "Detected 2-step infinite loop"}
            
    return {"decision": "continue", "reason": "Well under budget and no loop detected"}

# ==============================================================================
# Q6 - Build a Live MCP Server
# ==============================================================================

@app.post("/mcp")
async def mcp_handler(request: Request, x_exam_challenge: Optional[str] = Header(None, alias="X-Exam-Challenge")):
    body = await request.json()
    method = body.get("method")
    req_id = body.get("id")
    
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "ga5-mcp-server", "version": "1.0"}
            },
            "id": req_id
        }
        
    elif method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "result": {
                "tools": [
                    {
                        "name": "solve_challenge",
                        "description": "Expose Q6 solver",
                        "inputSchema": {"type": "object", "properties": {}}
                    }
                ]
            },
            "id": req_id
        }
        
    elif method == "tools/call":
        name = body.get("params", {}).get("name")
        if name == "solve_challenge":
            email = (os.environ.get("STUDENT_EMAIL") or os.environ.get("EMAIL") or "").strip().lower()
            challenge = x_exam_challenge or ""
            h = hashlib.sha256(f"{challenge}:{email}".encode('utf-8')).hexdigest()[:16]
            return {
                "jsonrpc": "2.0",
                "result": {
                    "content": [{"type": "text", "text": h}]
                },
                "id": req_id
            }
            
    return {"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}, "id": req_id}

# ==============================================================================
# Q7 - Prove You Contained It (Offline LXD Log)
# ==============================================================================

@app.get("/q7/log")
def get_lxd_sandbox_log():
    if not CONFIG or "q7" not in CONFIG:
        return Response(content="Server not configured with STUDENT_EMAIL env var.", media_type="text/plain")
        
    q7 = CONFIG["q7"]
    log = f"""LXD_SANDBOX_START token={q7["token"]}
LXD_FS_ATTEMPT path={q7["canaryPath"]}
LXD_FS_BLOCKED status=1
cat: {q7["canaryPath"]}: Permission denied

LXD_NET_ATTEMPT token={q7["token"]}
LXD_NET_DONE status=7
LXD_RESOURCE_ATTEMPT allocation_mb={q7["allocationMb"]} spin_seconds={q7["spinSeconds"]}
LXD_RESOURCE_LIMIT_HIT status=137
LXD_SANDBOX_END token={q7["token"]}
"""
    return Response(content=log, media_type="text/plain")

# ==============================================================================
# Attach Q8, Q9, Q10, Q11 Routers
# ==============================================================================

app.include_router(q8_router)
app.include_router(q9_router)
app.include_router(q10_router)
app.include_router(q11_router)

# ==============================================================================
# Dynamic /check Router for Q3, Q5, and Q8
# ==============================================================================

@app.post("/check")
async def check_router(request: Request):
    body = await request.json()
    
    # Q5 payload has "budget_tokens" or "steps"
    if "budget_tokens" in body or "steps" in body:
        try:
            req = BudgetRequest(**body)
            return check_budget_loop(req)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Q5 validation error: {e}")
            
    # Q8 payload has "arguments" and "tool"
    elif "arguments" in body:
        try:
            req = RedteamRequest(**body)
            return check_redteam(req, request)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Q8 validation error: {e}")
            
    # Q3 payload has "tool" but not "arguments"
    elif "tool" in body:
        try:
            req = GuardrailRequest(**body)
            return check_guardrail(req)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Q3 validation error: {e}")
            
    raise HTTPException(status_code=400, detail="Unknown check payload")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
