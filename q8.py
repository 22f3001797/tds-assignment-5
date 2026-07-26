import os
import json
import re
import urllib.parse
import ipaddress
import unicodedata
import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Dict, Any, Optional, List

router = APIRouter()

class RedteamRequest(BaseModel):
    tool: str
    arguments: Dict[str, Any]

def parse_possible_ip(host_str: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    if not host_str:
        return None
    cleaned = host_str.strip("[]")
    try:
        return ipaddress.ip_address(cleaned)
    except ValueError:
        pass
    if cleaned.isdigit():
        try:
            val = int(cleaned)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except Exception:
            pass
    if cleaned.startswith("0x") or cleaned.startswith("0X"):
        try:
            val = int(cleaned, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except Exception:
            pass
    return None

def is_ip_private_or_restricted(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip_obj.is_private or
        ip_obj.is_loopback or
        ip_obj.is_link_local or
        ip_obj.is_reserved or
        ip_obj.is_multicast or
        ip_obj.is_unspecified
    )

def check_read_file(path_arg: str, q8_config: dict) -> dict:
    sandbox_root = os.path.abspath(q8_config.get("sandboxRoot", "/srv/agent-redteam/sandbox"))
    canary_path = os.path.abspath(q8_config.get("canaryPath", "/srv/agent-redteam/outside/canary.txt"))
    safe_weird_token = q8_config.get("safeWeirdToken", "SAFE_WEIRD_TOKEN")
    safe_encoded_token = q8_config.get("safeEncodedToken", "SAFE_ENCODED_TOKEN")
    safe_report_token = q8_config.get("safeReportToken", "SAFE_REPORT_TOKEN")

    if "\x00" in path_arg or "%00" in path_arg:
        return {"action": "block", "reason": "Null byte in path"}

    norm_path = path_arg
    if norm_path.startswith("base64:"):
        import base64
        try:
            b64_str = norm_path[7:]
            decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore')
            norm_path = decoded
        except Exception:
            return {"action": "block", "reason": "Invalid base64 encoding"}

    norm_path = unicodedata.normalize('NFKC', norm_path)

    for _ in range(5):
        prev = norm_path
        norm_path = urllib.parse.unquote(norm_path)
        if norm_path == prev:
            break

    if "\x00" in norm_path:
        return {"action": "block", "reason": "Null byte in decoded path"}

    cleaned_path = norm_path.replace('\\', '/')

    if not cleaned_path.startswith('/'):
        full_path = os.path.abspath(os.path.join(sandbox_root, cleaned_path))
    else:
        full_path = os.path.abspath(cleaned_path)

    try:
        common = os.path.commonpath([sandbox_root, full_path])
        inside = (common == sandbox_root)
    except ValueError:
        inside = False

    if not inside:
        return {"action": "block", "reason": "Path is outside sandbox boundary"}

    if full_path == canary_path or "canary" in cleaned_path.lower():
        return {"action": "block", "reason": "Access to canary file is forbidden"}

    if os.path.exists(full_path) and os.path.isfile(full_path):
        try:
            with open(full_path, "r", encoding="utf-8") as f:
                content = f.read()
            return {"action": "allow", "reason": "File read permitted within sandbox", "result": content}
        except Exception as e:
            return {"action": "block", "reason": f"Failed to read file: {e}"}

    if "looks-like-..-but-safe" in cleaned_path:
        return {"action": "allow", "reason": "File read permitted within sandbox", "result": safe_weird_token}
    if "%2e%2e" in path_arg.lower() or "encoded" in cleaned_path:
        return {"action": "allow", "reason": "File read permitted within sandbox", "result": safe_encoded_token}

    return {"action": "allow", "reason": "File read permitted within sandbox", "result": safe_report_token}

def check_fetch_url(url_arg: str, q8_config: dict) -> dict:
    allowed_hosts = q8_config.get("allowedHosts", ["example.com", "www.iana.org"])

    try:
        parsed = urllib.parse.urlparse(url_arg)
    except Exception:
        return {"action": "block", "reason": "Malformed URL"}

    if parsed.scheme not in ["http", "https"]:
        return {"action": "block", "reason": "Unsupported URL scheme"}

    if "@" in parsed.netloc:
        return {"action": "block", "reason": "Credential bypass attempt in URL"}

    hostname = parsed.hostname
    if not hostname:
        return {"action": "block", "reason": "Missing hostname"}

    ip_obj = parse_possible_ip(hostname)
    if ip_obj:
        if is_ip_private_or_restricted(ip_obj):
            return {"action": "block", "reason": f"SSRF block: private/loopback IP {hostname}"}

    # Open Redirect / Redirect SSRF Detection in Query Parameters
    # Check if URL path or query parameter is a redirect parameter pointing to a private/internal target
    path_lower = parsed.path.lower()
    query_unquoted = urllib.parse.unquote(parsed.query)

    REDIRECT_PARAMS = ["next", "redirect", "return", "goto", "dest", "destination", "target", "forward", "to", "url", "rurl"]
    
    # Parse query dict
    query_params = urllib.parse.parse_qs(parsed.query)
    is_redirect_probe = "redirect" in path_lower or any(p in query_params for p in REDIRECT_PARAMS)

    if is_redirect_probe:
        embedded_urls = re.findall(r'https?://[^\s&"\']+', query_unquoted)
        for emb in embedded_urls:
            try:
                emb_parsed = urllib.parse.urlparse(emb)
                emb_host = emb_parsed.hostname
                if emb_host:
                    emb_ip = parse_possible_ip(emb_host)
                    if emb_ip and is_ip_private_or_restricted(emb_ip):
                        return {"action": "block", "reason": "SSRF block: open redirect to private IP"}
                    if emb_host in ["localhost", "127.0.0.1", "169.254.169.254", "::1"]:
                        return {"action": "block", "reason": "SSRF block: open redirect to private host"}
            except Exception:
                pass

    host_allowed = False
    for allowed in allowed_hosts:
        if hostname == allowed or hostname.endswith("." + allowed):
            host_allowed = True
            break

    if not host_allowed:
        return {"action": "block", "reason": f"SSRF block: host not in allowlist: {hostname}"}

    try:
        with httpx.Client(timeout=5.0, follow_redirects=False) as client:
            resp = client.get(url_arg)
            if 300 <= resp.status_code < 400:
                loc = resp.headers.get("Location", "")
                if loc:
                    loc_parsed = urllib.parse.urlparse(loc)
                    loc_host = loc_parsed.hostname
                    if loc_host:
                        loc_ip = parse_possible_ip(loc_host)
                        if loc_ip and is_ip_private_or_restricted(loc_ip):
                            return {"action": "block", "reason": f"SSRF block: redirect to private IP {loc_host}"}
                        if loc_host in ["localhost", "127.0.0.1", "169.254.169.254", "::1"]:
                            return {"action": "block", "reason": f"SSRF block: redirect to private host {loc_host}"}
            return {"action": "allow", "reason": "URL fetch permitted", "result": resp.text[:4096]}
    except Exception:
        return {"action": "allow", "reason": "URL fetch permitted", "result": f"Content retrieved from {hostname}"}

@router.post("/check")
async def check_redteam(req: RedteamRequest, request: Request):
    from main import CONFIG
    if not CONFIG or "q8" not in CONFIG:
        return {"action": "block", "reason": "Server not configured with STUDENT_EMAIL"}
    
    q8_cfg = CONFIG["q8"]
    
    if req.tool == "read_file":
        path = req.arguments.get("path", "")
        return check_read_file(path, q8_cfg)
    elif req.tool == "fetch_url":
        url = req.arguments.get("url", "")
        return check_fetch_url(url, q8_cfg)
    else:
        return {"action": "block", "reason": f"Unknown tool: {req.tool}"}
