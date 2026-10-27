"""Shared, dependency-free execution and output contract for DevOps Doctor."""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

MASK = "[REDACTED]"
_COMMAND_SLOTS = threading.BoundedSemaphore(8)
_PAGING_KEYS = {"nexttoken", "nextpagetoken", "continuationtoken", "nextcontinuationtoken", "startingtoken"}
_SECRET_KEY = re.compile(r"(?:password|passwd|secret|token|authorization|credential|privatekey|accesskey|apikey|webhook|cookie)", re.I)
_ASSIGNMENT = re.compile(r'''(?ix)(["']?(?:[\w.-]*(?:token|password|passwd|secret|api[_-]?key|access[_-]?key|credential)|authorization|cookie)["']?\s*[:=]\s*)("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;}]+)''')
_HEADER = re.compile(r"(?im)((?:authorization|proxy-authorization|private-token|cookie|set-cookie)\s*[:=]\s*)[^\r\n]+")
_URL = re.compile(r"(?:https?|postgres(?:ql)?|mysql|redis(?:s)?)://[^\s<>\"']+", re.I)
_PEM = re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", re.S)
_KNOWN_TOKEN = re.compile(r"\b(?:(?:AKIA|ASIA)[A-Z0-9]{16}|glpat-[A-Za-z0-9_-]{10,}|gh[pousr]_[A-Za-z0-9_]{20,}|eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b")
_CLI_SECRET = re.compile(r'''(?ix)
    (--[\w-]*(?:token|password|passwd|secret|api[_-]?key|access[_-]?key|credential|authorization|cookie)[\w-]*)
    ((?:\s+|=)(?:[\\`]\r?\n[ \t]*)*)
    ((?:\\"(?:`\\"|\\\\.|\\[^"]|[^\\])*(?:\\"|$)
       |"(?:[\\`][\s\S]|[^"\\`])*(?:"|$)
       |'(?:[\\`][\s\S]|[^'\\`])*(?:'|$)
       |[\\`](?:\r?\n|[^\r\n])|[^\s"'\\`])+)
''')


def secret_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", key.lower())
    return normalized not in _PAGING_KEYS and bool(_SECRET_KEY.search(normalized))


def _safe_url(match: re.Match[str]) -> str:
    original = match.group(0)
    try:
        parts = urlsplit(original)
        netloc = parts.netloc.rsplit("@", 1)[-1]
        if "@" in parts.netloc:
            netloc = MASK + "@" + netloc
        hostname = (parts.hostname or "").lower()
        if hostname in {"hooks.slack.com", "discord.com", "discordapp.com"} and ("webhook" in parts.path or "/services/" in parts.path):
            return urlunsplit((parts.scheme, netloc, "/" + MASK, "", ""))
        query = [(key, MASK if secret_key(key) or key.lower() in {"key", "sig", "signature", "x-amz-signature", "x-amz-credential", "x-goog-signature", "x-goog-credential"} else val) for key, val in parse_qsl(parts.query, keep_blank_values=True)]
        return urlunsplit((parts.scheme, netloc, parts.path, urlencode(query, safe="[]"), parts.fragment))
    except ValueError:
        return MASK


def redact(text: str) -> str:
    """Best-effort text sanitization; never a guarantee for arbitrary private data."""
    cleaned = _PEM.sub(MASK, str(text))
    cleaned = _URL.sub(_safe_url, cleaned)
    cleaned = _HEADER.sub(lambda m: m.group(1) + MASK, cleaned)
    cleaned = _CLI_SECRET.sub(lambda m: m.group(1) + m.group(2) + MASK if secret_key(m.group(1)) else m.group(0), cleaned)
    cleaned = _ASSIGNMENT.sub(lambda m: m.group(1) + MASK, cleaned)
    return _KNOWN_TOKEN.sub(MASK, cleaned)


def redacted_command(command: list[str]) -> str:
    """Mask secret arguments before joining; argv values may contain whitespace."""
    safe = []
    hide_next = False
    for argument in command:
        if hide_next:
            safe.append(MASK)
            hide_next = False
            continue
        flag, separator, _ = argument.partition("=")
        if flag.startswith("--") and secret_key(flag):
            safe.append(flag + "=" + MASK if separator else flag)
            hide_next = not separator
        else:
            safe.append(redact(argument))
    return " ".join(safe)


def sanitize(value: Any) -> Any:
    """Sanitize before printing or persistence, including JSON embedded in strings."""
    if isinstance(value, dict):
        named_key = value.get("Name", value.get("name", value.get("Key", value.get("key"))))
        result = {}
        for key, item in value.items():
            label = str(key)
            if secret_key(label) or (label.lower() == "value" and isinstance(named_key, str) and secret_key(named_key)):
                result[key] = MASK if item is not None else None
            elif label.lower() in {"environment", "env"} and isinstance(item, dict):
                result[key] = {k: MASK for k in item}
            elif label.lower() in {"environment", "env"} and isinstance(item, list):
                result[key] = [{k: MASK if str(k).lower() == "value" else sanitize(v) for k, v in entry.items()} if isinstance(entry, dict) else MASK for entry in item]
            else:
                result[key] = sanitize(item)
        return result
    if isinstance(value, (list, tuple)):
        return [sanitize(item) for item in value]
    if isinstance(value, str):
        if value.lstrip().startswith(("{", "[")):
            try:
                nested = json.loads(value)
                if isinstance(nested, (dict, list)):
                    return json.dumps(sanitize(nested), ensure_ascii=False)
            except (ValueError, RecursionError):
                pass
        return redact(value)
    return value


def configure_concurrency(max_workers: int) -> None:
    """Set once before starting collectors; bounds nested executor command fan-out."""
    global _COMMAND_SLOTS
    if not 1 <= max_workers <= 32:
        raise ValueError("max_workers must be between 1 and 32")
    _COMMAND_SLOTS = threading.BoundedSemaphore(max_workers)


def run_command(command: list[str], *, timeout: int = 60, parse_json: bool = True, text_limit: int | None = None) -> dict[str, Any]:
    started = time.monotonic()
    result: dict[str, Any] = {"ok": False, "command": redacted_command(command), "returncode": None, "truncated": False}
    env = dict(os.environ)
    env.update({"AWS_PAGER": "", "AWS_CLI_AUTO_PROMPT": "off", "GLAB_PAGER": "", "GIT_PAGER": "cat", "GIT_TERMINAL_PROMPT": "0"})
    try:
        with _COMMAND_SLOTS:
            proc = subprocess.run(command, check=False, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, env=env)
        result["returncode"] = proc.returncode
        if proc.returncode:
            result["error"] = redact(proc.stderr or proc.stdout or f"command exited {proc.returncode}")[-2000:]
        elif parse_json:
            try:
                result["data"] = sanitize(json.loads(proc.stdout))
                result["ok"] = True
                if isinstance(result["data"], dict):
                    result["truncated"] = any(result["data"].get(k) for k in ("NextToken", "nextToken", "NextPageToken", "next_page_token", "NextContinuationToken"))
            except (ValueError, RecursionError):
                result["error"] = "invalid or empty JSON response"
        else:
            data = redact(proc.stdout.strip())
            result["truncated"] = text_limit is not None and len(data) > text_limit
            result["data"] = data[-text_limit:] if result["truncated"] and text_limit else data
            result["ok"] = True
    except subprocess.TimeoutExpired:
        result["error"] = f"timeout after {timeout}s"
    except OSError as exc:
        result["error"] = redact(str(exc))
    result["duration_ms"] = round((time.monotonic() - started) * 1000, 2)
    return result


def collect_status(result: Any) -> str:
    """Collection completeness, independent of the severity of findings."""
    successes = failures = 0
    partial = False
    def visit(item: Any) -> None:
        nonlocal successes, failures, partial
        if isinstance(item, dict):
            if item.get("ok") is True:
                successes += 1
            elif item.get("ok") is False:
                failures += 1
            if item.get("truncated") is True or item.get("complete") is False or item.get("blockers"):
                partial = True
            for child in item.values():
                visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)
    visit(result)
    if failures and not successes:
        return "failed"
    if failures or partial:
        return "partial"
    return "complete"


def run_ecs_read(command: list[str], *, timeout: int = 60) -> dict[str, Any]:
    """Preserve ECS per-resource failures when using a projected resource list."""
    cmd = list(command)
    operation = cmd[2] if len(cmd) > 2 and cmd[1] == "ecs" else None
    if operation not in {"describe-services", "describe-tasks"} or "--query" not in cmd:
        return run_command(cmd, timeout=timeout)
    index = cmd.index("--query") + 1
    query = cmd[index]
    if not query.startswith(("services[", "tasks[")):
        return run_command(cmd, timeout=timeout)
    cmd[index] = "{items:" + query + ",failures:failures}"
    result = run_command(cmd, timeout=timeout)
    if not result.get("ok"):
        return result
    payload = result.get("data")
    if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
        return {**result, "ok": False, "error": "invalid ECS resource response", "data": []}
    items, failures = payload["items"], payload.get("failures") or []
    flag = "--services" if operation == "describe-services" else "--tasks"
    count = 0
    if flag in cmd:
        for value in cmd[cmd.index(flag) + 1:]:
            if value.startswith("--"):
                break
            count += 1
    result.update(data=items, failures=failures)
    if failures or len(items) < count:
        result.update(ok=False, error="ECS did not return every requested resource; inspect failures", expected_resources=count, returned_resources=len(items))
    return result


def emit_result(result: dict[str, Any], output: str | Path | None = None) -> int:
    clean = sanitize(result)
    status = collect_status(clean)
    weights = {"complete": 0, "partial": 1, "failed": 2}
    requested = clean.get("status", "complete")
    if weights.get(requested, 0) > weights[status]:
        status = requested
    clean["status"] = status
    clean.setdefault("schema_version", "2.0")
    clean.setdefault("generated_at", datetime.now(timezone.utc).isoformat())
    clean.setdefault("collection", {})["complete"] = status == "complete"
    payload = json.dumps(clean, indent=2, sort_keys=True, default=str, ensure_ascii=False) + "\n"
    if output:
        target = Path(output)
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix=".doctor-", suffix=".tmp", dir=target.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(payload)
            os.replace(temp_name, target)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)
    else:
        print(payload, end="")
    return weights[status]
