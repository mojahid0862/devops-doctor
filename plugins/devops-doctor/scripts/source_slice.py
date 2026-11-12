"""Bounded, redacted line ranges from immutable local Git objects.

Requests are JSON lists of {path, start, end}, with inclusive one-based lines.
The JSON response, including escaping and its newline, fits --max-chars.
Pending ranges remain explicit; increase the budget or split the next request.
Ends beyond EOF are explicitly clamped; starts beyond EOF fail.
No cross-process receipt is trusted as proof of delivery, so there is no state
file. Overlapping ranges are merged within each response only. Redaction is
best effort, not permission to read credential files or a guarantee that
arbitrary private values can be identified. Source files are never executed.
"""
from __future__ import annotations

import argparse
import bisect
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import doctor_common as common

MIN_BUDGET = 1024
MAX_REQUEST_BYTES = 262144
MAX_BLOB_BYTES = 33554432
_REVISION = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\Z")


class SourceError(Exception):
    """A fixed diagnostic code, without potentially sensitive Git output."""


def encode(result: dict[str, Any]) -> str:
    # ASCII encoding makes the character budget also an exact UTF-8 byte bound.
    return json.dumps(result, ensure_ascii=True, separators=(",", ":")) + "\n"


def _git(root: Path, *args: str) -> bytes:
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_NO_LAZY_FETCH="1", GIT_ALLOW_PROTOCOL="", GIT_TERMINAL_PROMPT="0", GIT_PAGER="cat")
    command = ["git", "--no-optional-locks", "--no-replace-objects", "--literal-pathspecs",
               "-c", "core.fsmonitor=false", "-c", "protocol.allow=never", "-C", str(root), *args]
    try:
        proc = subprocess.run(command, capture_output=True, timeout=30, env=env, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SourceError("git_unavailable_or_timeout") from exc
    if proc.returncode:
        raise SourceError("git_object_unavailable")
    return proc.stdout


def _identity(root: str | Path, revision: str) -> tuple[Path, str]:
    if not isinstance(revision, str) or not _REVISION.fullmatch(revision):
        raise SourceError("revision_requires_full_commit_hash")
    try:
        resolved = Path(root).resolve(strict=True)
        if not resolved.is_dir():
            raise SourceError("root_requires_repository_directory")
        actual = Path(_git(resolved, "rev-parse", "--show-toplevel").decode("utf-8").strip()).resolve(strict=True)
    except (OSError, UnicodeError, ValueError) as exc:
        raise SourceError("invalid_repository_root") from exc
    if resolved != actual:
        raise SourceError("root_must_be_repository_toplevel")
    revision = revision.lower()
    if _git(resolved, "cat-file", "-t", revision).strip() != b"commit":
        raise SourceError("revision_is_not_commit")
    if _git(resolved, "rev-parse", "--verify", revision).decode("ascii").strip() != revision:
        # Forty hex characters can still abbreviate an object in SHA-256 repos.
        raise SourceError("revision_requires_full_commit_hash")
    return resolved, revision


def _path(value: Any) -> str:
    if not isinstance(value, str) or not value or value.startswith(("/", "-")):
        raise SourceError("invalid_relative_path")
    if any(char in value for char in "\\:\x00\r\n") or any(part in ("", ".", "..") for part in value.split("/")):
        raise SourceError("invalid_relative_path")
    name = value.rsplit("/", 1)[-1].lower()
    if name == ".env" or name.startswith(".env.") or name in {"credentials", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".netrc", ".npmrc", ".pypirc"} or name.endswith((".pem", ".key", ".p12", ".pfx")):
        raise SourceError("credential_file_not_read")
    return value


def merge_ranges(ranges: list[list[int]]) -> list[list[int]]:
    merged: list[list[int]] = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1] + 1:
            merged[-1][1] = max(end, merged[-1][1])
        else:
            merged.append([start, end])
    return merged


def subtract_ranges(requested: list[list[int]], delivered: list[list[int]]) -> list[list[int]]:
    remaining = []
    for start, end in requested:
        cursor = start
        for first, last in delivered:
            if last < cursor:
                continue
            if first > end:
                break
            if cursor < first:
                remaining.append([cursor, first - 1])
            cursor = max(cursor, last + 1)
        if cursor <= end:
            remaining.append([cursor, end])
    return remaining


def _safe_lines(raw: str) -> list[dict[str, Any]]:
    # Sanitizing each line alone misses PEM/quoted secrets spanning lines.
    # Mark whole lines touched by multiline secret matches before per-line
    # redaction, preserving original numbering even when redact() removes LF.
    starts = [0] + [match.end() for match in re.finditer("\n", raw)]
    original = raw.split("\n")
    if original[-1] == "":
        original.pop()
    masked: set[int] = set()
    for pattern in (common._PEM, common._CLI_SECRET, common._ASSIGNMENT):
        for match in pattern.finditer(raw):
            if "\n" in match.group(0) or "\r" in match.group(0):
                first = bisect.bisect_right(starts, match.start()) - 1
                last = bisect.bisect_right(starts, match.end() - 1) - 1
                masked.update(range(first, last + 1))
    assignments = re.compile(r'''(?m)^([ \t]*)(?:(?:const|let|var)[ \t]+)?(["']?[\w.-]+["']?)[ \t]*[:=][ \t]*([^\n]*)''')
    for match in assignments.finditer(raw):
        if not common.secret_key(match[2].strip("\"'")):
            continue
        first = bisect.bisect_right(starts, match.start()) - 1
        last = first
        # Indented scalar/continuation bodies include YAML | and > values.
        indent = len(match[1].expandtabs(8))
        for index in range(first + 1, len(original)):
            line = original[index]
            expanded = line.expandtabs(8)
            if line.strip() and len(expanded) - len(expanded.lstrip(" ")) <= indent:
                break
            last = index
        tail = match[3]
        unprefixed = tail.lstrip("rRuUbBfF")
        delimiter = next((quote for quote in ('"""', "'''", "`") if unprefixed.startswith(quote)), None)
        if delimiter:
            begin = match.start(3) + len(tail) - len(unprefixed) + len(delimiter)
            close = raw.find(delimiter, begin)
            while close >= 0:
                cursor = close
                while cursor > begin and raw[cursor - 1] == "\\":
                    cursor -= 1
                if (close - cursor) % 2 == 0:
                    break
                close = raw.find(delimiter, close + len(delimiter))
            final = len(raw) - 1 if close < 0 else close + len(delimiter) - 1
            last = max(last, bisect.bisect_right(starts, final) - 1)
        if last > first or delimiter:
            masked.update(range(first, last + 1))
    result = []
    for index, line in enumerate(original):
        line = line.removesuffix("\r")
        safe = common.MASK if index in masked else common.redact(line)
        result.append({"number": index + 1, "text": safe, "redacted": safe != line})
    return result


def _blob(root: Path, revision: str, path: str) -> tuple[str, list[dict[str, Any]]]:
    entry = _git(root, "ls-tree", "-z", "--full-tree", revision, "--", path)
    records = [record for record in entry.split(b"\0") if record]
    if len(records) != 1:
        raise SourceError("path_not_found_at_revision")
    metadata, found_path = records[0].split(b"\t", 1)
    mode, kind, oid = metadata.split(b" ")
    if found_path != path.encode("utf-8") or kind != b"blob" or mode not in (b"100644", b"100755"):
        raise SourceError("path_requires_regular_file_blob")
    blob = oid.decode("ascii")
    if int(_git(root, "cat-file", "-s", blob)) > MAX_BLOB_BYTES:
        raise SourceError("blob_exceeds_32MiB_local_reader_limit_use_another_bounded_reader")
    content = _git(root, "cat-file", "blob", blob)
    if b"\x00" in content:
        raise SourceError("binary_blob_not_read")
    try:
        return blob, _safe_lines(content.decode("utf-8"))
    except UnicodeError as exc:
        raise SourceError("non_utf8_blob_not_read") from exc


def _refresh(item: dict[str, Any]) -> None:
    item["delivered"] = merge_ranges([[line["number"], line["number"]] for line in item["lines"]])
    item["remaining"] = subtract_ranges(item.get("effective", item["requested"]), item["delivered"])
    item["status"] = "failed" if item.get("error") and not item["lines"] else "partial" if item["remaining"] or item.get("error") else "complete"


def _status(result: dict[str, Any]) -> None:
    items = result["items"]
    if all(item["status"] == "complete" for item in items):
        result["status"] = "complete"
    elif any(item["status"] == "failed" for item in items) and not any(item["lines"] for item in items):
        result["status"] = "failed"
    else:
        result["status"] = "partial"


def _pointer(item: dict[str, Any], available: list[dict[str, Any]], source: dict[str, str], budget: int) -> None:
    item.pop("next_line", None)
    for start, end in item["remaining"]:
        if start <= len(available):
            line = available[start - 1]
            single = {"path": item["path"], "blob_sha": item["blob_sha"], "requested": [[start, start]],
                      "effective": [[start, start]], "source_line_count": len(available),
                      "delivered": [[start, start]], "remaining": [], "lines": [line], "status": "complete"}
            minimum = max(MIN_BUDGET, len(encode({"status": "complete", "source": source, "items": [single]})))
            item["next_line"] = {"number": start, "serialized_line_chars": len(encode(line)) - 1,
                                 "minimum_max_chars_for_single_line_request": minimum,
                                 "reason": "oversized_line" if minimum > budget else "response_budget"}
            break


def read_ranges(root: str | Path, revision: str, requests: Any, max_chars: int = 12000) -> dict[str, Any]:
    """Return complete lines only, with explicit unsatisfied ranges and errors."""
    if type(max_chars) is not int or max_chars < MIN_BUDGET:
        raise ValueError("max_chars must be an integer at least 1024")
    if not isinstance(requests, list) or not requests:
        return {"status": "failed", "error": "request_requires_nonempty_json_list", "remaining": "entire_request"}
    try:
        resolved, revision = _identity(root, revision)
    except SourceError as exc:
        return {"status": "failed", "error": str(exc), "remaining": "entire_request"}
    result: dict[str, Any] = {"status": "partial", "source": {"root": common.redact(str(resolved)), "revision": revision}, "items": []}
    grouped: dict[str, dict[str, Any]] = {}
    for index, request in enumerate(requests):
        try:
            if not isinstance(request, dict) or set(request) != {"path", "start", "end"}:
                raise SourceError("request_requires_path_start_end")
            path = _path(request["path"])
            start, end = request["start"], request["end"]
            if type(start) is not int or type(end) is not int or not 1 <= start <= end <= 2147483647:
                raise SourceError("invalid_inclusive_line_range")
            if path not in grouped:
                grouped[path] = {"path": common.redact(path), "requested": [], "delivered": [], "remaining": [], "lines": [], "status": "partial"}
                result["items"].append(grouped[path])
            grouped[path]["requested"].append([start, end])
        except SourceError as exc:
            result["items"].append({"request_index": index, "status": "failed", "error": str(exc), "remaining": "request_unread", "lines": []})
    available: dict[str, list[dict[str, Any]]] = {}
    for path, item in grouped.items():
        original_requested = item["requested"]
        item["requested"] = merge_ranges(item["requested"])
        try:
            item["blob_sha"], available[path] = _blob(resolved, revision, path)
            count = len(available[path])
            item["source_line_count"] = count
            item["effective"] = [[start, min(end, count)] for start, end in item["requested"] if start <= count]
            clipped = [[start, end] for start, end in original_requested if start <= count < end]
            unavailable = [[start, end] for start, end in original_requested if start > count]
            if clipped:
                item["eof_clipped"] = merge_ranges(clipped)
            if unavailable:
                item.update(error="empty_source_file" if count == 0 else "requested_start_past_eof", unavailable=merge_ranges(unavailable))
        except (SourceError, ValueError) as exc:
            item["error"] = str(exc) if isinstance(exc, SourceError) else "invalid_git_object_response"
        _refresh(item)
        if path in available:
            _pointer(item, available[path], result["source"], max_chars)
    _status(result)
    # Never hide failed/pending items to make room for source. If the metadata
    # itself cannot fit, deliver nothing and identify the entire original batch.
    needed = len(encode(result))
    if needed > max_chars:
        return {"status": "failed", "error": "request_metadata_exceeds_budget", "remaining": "entire_request",
                "required_metadata_chars": needed, "request_count": len(requests),
                "failed_items": sum(item["status"] == "failed" for item in result["items"])}
    for path, item in grouped.items():
        lines = available.get(path)
        if lines is None:
            continue
        stopped = False
        for start, end in item["requested"]:
            for number in range(start, min(end, len(lines)) + 1):
                item["lines"].append(lines[number - 1])
                _refresh(item)
                _pointer(item, lines, result["source"], max_chars)
                _status(result)
                if len(encode(result)) > max_chars:
                    item["lines"].pop()
                    _refresh(item)
                    _pointer(item, lines, result["source"], max_chars)
                    _status(result)
                    stopped = True
                    break
            if stopped:
                break
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, help="Exact local repository top-level directory")
    parser.add_argument("--revision", required=True, help="Full immutable 40- or 64-hex commit hash")
    parser.add_argument("--request", required=True, help="JSON request file, or - to read JSON from stdin")
    parser.add_argument("--max-chars", type=int, default=12000, help="Entire JSON response budget (minimum 1024)")
    args = parser.parse_args(argv)
    if args.max_chars < MIN_BUDGET:
        parser.error("--max-chars must be at least 1024")
    try:
        if args.request == "-":
            data = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        else:
            with Path(args.request).open("rb") as stream:
                data = stream.read(MAX_REQUEST_BYTES + 1)
        if len(data) > MAX_REQUEST_BYTES:
            raise SourceError("request_exceeds_256KiB_split_batch")
        requests = json.loads(data)
        result = read_ranges(args.root, args.revision, requests, args.max_chars)
    except (OSError, ValueError, RecursionError, SourceError) as exc:
        result = {"status": "failed", "error": str(exc) if isinstance(exc, SourceError) else "invalid_or_unreadable_request_json", "remaining": "entire_request"}
    # Bypass Windows text newline translation: the final LF is budgeted once.
    sys.stdout.buffer.write(encode(result).encode("ascii"))
    return {"complete": 0, "partial": 1, "failed": 2}[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
