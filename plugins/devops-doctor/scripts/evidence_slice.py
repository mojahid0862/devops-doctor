"""Bounded views of already-sanitized, saved local collector artifacts.

No collection, source rewriting, summarization, or network access. Redaction is
best effort; this is not permission to read credentials or arbitrary private data.
Use source_slice.py for pinned Git source. Output is compact JSON plus LF, fully
bounded by --max-bytes. Complete means selection delivery, not complete collection.
Keep source.sha256 and pass --sha256 on subsequent reads to reject source drift.

Examples (global options precede the mode):
  evidence_slice.py --file saved.log lines --range 1:40 --pack-runs
  evidence_slice.py --file saved.json json --pointer /data --array-range 0:9

Line ranges are one-based inclusive; array ranges are zero-based inclusive.
RFC6901 pointers use ~0 for ~ and ~1 for /; the empty pointer selects the root.
Whole values/records only: follow remaining selections or increase the budget.
Run packing is opt-in and compares original adjacent lines including their EOL
before redaction. Counts describe the saved artifact, not unique real-world events.
"""
from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import doctor_common as common
import source_slice

MIN_BUDGET = 1024
MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_LINES = 100000
MAX_SELECTIONS = 128
_CONTEXT = {
    "status", "collectionstatus", "collection", "collectedat", "collectiontime",
    "generatedat", "scope", "window", "truncated", "partial", "error", "errors",
    "failures", "warnings", "pagination", "nexttoken", "nextpagetoken",
    "nextcontinuationtoken", "continuationtoken", "nextpage", "hasmore",
    "totalcount", "total", "returnedcount", "expectedresources", "returnedresources",
}


class EvidenceError(Exception):
    """Fixed diagnostic code; never include file contents or OS error text."""


@dataclass(frozen=True)
class Number:
    """Validated JSON numeric token, emitted without float conversion/rounding."""
    text: str


def _json(value: Any) -> str:
    if isinstance(value, Number):
        return value.text
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(key, ensure_ascii=True) + ":" + _json(item)
                               for key, item in value.items()) + "}"
    if isinstance(value, list):
        return "[" + ",".join(_json(item) for item in value) + "]"
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))


def encode_bytes(value: Any) -> bytes:
    return (_json(value) + "\n").encode("utf-8")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("duplicate_json_key")
        result[key] = value
    return result


def _nonfinite(_: str) -> None:
    raise EvidenceError("nonfinite_json_number")


def _parse_json(text: str) -> Any:
    try:
        return json.loads(text, object_pairs_hook=_pairs, parse_int=Number,
                          parse_float=Number, parse_constant=_nonfinite)
    except (ValueError, RecursionError) as exc:
        raise EvidenceError("invalid_or_too_deep_json") from exc


def _sanitize(value: Any) -> Any:
    # Keep numeric lexemes and ordinary strings intact. In particular, don't let
    # parsing JSON embedded in strings round its numbers or rewrite harmless text.
    if isinstance(value, dict):
        named = value.get("Name", value.get("name", value.get("Key", value.get("key"))))
        result = {}
        for key, child in value.items():
            if common.redact(key) != key:
                raise EvidenceError("json_key_requires_redaction")
            if common.secret_key(key) or (key.lower() == "value" and isinstance(named, str) and common.secret_key(named)):
                result[key] = None if child is None else common.MASK
            elif key.lower() in {"env", "environment"} and isinstance(child, dict):
                result[key] = {k: common.MASK for k in child}
                if any(common.redact(k) != k for k in child):
                    raise EvidenceError("json_key_requires_redaction")
            elif key.lower() in {"env", "environment"} and isinstance(child, list):
                result[key] = [{k: common.MASK if k.lower() == "value" else _sanitize(v)
                                for k, v in entry.items()} if isinstance(entry, dict) else common.MASK
                               for entry in child]
                if any(isinstance(entry, dict) and any(common.redact(k) != k for k in entry) for entry in child):
                    raise EvidenceError("json_key_requires_redaction")
            else:
                result[key] = _sanitize(child)
        return result
    if isinstance(value, list):
        return [_sanitize(child) for child in value]
    if isinstance(value, str):
        if re.search(r"-----BEGIN [^-\n]*PRIVATE KEY-----", value):
            return common.MASK
        if value.lstrip().startswith(("{", "[")):
            try:
                nested = _parse_json(value)
                clean = _sanitize(nested)
                if _json(clean) != _json(nested):
                    return _json(clean)
            except EvidenceError:
                # Malformed embedded data is still text: preserve unless redacted.
                pass
        return common.redact(value)
    return value


def _credential_path(path: Path) -> bool:
    parts = [part.lower() for part in path.parts]
    name = path.name.lower()
    return (name == ".env" or name.startswith(".env.") or
            name in {"credentials", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
                     ".netrc", ".npmrc", ".pypirc", ".git-credentials", "auth.json",
                     "application_default_credentials.json", "accesstokens.json"} or
            name.endswith((".pem", ".key", ".p12", ".pfx")) or
            any(part in {".ssh", ".aws", ".kube", ".azure"} for part in parts))


def _load(path: str | Path, sha256: str | None) -> tuple[dict[str, Any], str]:
    if sha256 is not None and (not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", sha256)):
        raise EvidenceError("sha256_requires_64_hex_characters")
    try:
        supplied = Path(path)
        if _credential_path(supplied):
            raise EvidenceError("credential_file_not_read")
        resolved = supplied.resolve(strict=True)
        if _credential_path(resolved):
            raise EvidenceError("credential_file_not_read")
        if not resolved.is_file():
            raise EvidenceError("source_requires_regular_file")
        with resolved.open("rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise EvidenceError("source_requires_regular_file")
            if before.st_size > MAX_INPUT_BYTES:
                raise EvidenceError("source_exceeds_8MiB_limit")
            raw = stream.read(MAX_INPUT_BYTES + 1)
            after = os.fstat(stream.fileno())
        current = resolved.stat()
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
        if identity(before) != identity(after) or identity(after) != identity(current):
            raise EvidenceError("source_changed_during_read")
        if len(raw) > MAX_INPUT_BYTES:
            raise EvidenceError("source_exceeds_8MiB_limit")
        digest = hashlib.sha256(raw).hexdigest()
        if sha256 is not None and digest != sha256.lower():
            raise EvidenceError("source_sha256_mismatch")
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise EvidenceError("source_requires_utf8") from exc
    except (OSError, ValueError, TypeError) as exc:
        raise EvidenceError("source_unavailable") from exc
    shown_path = common.redact(str(resolved))
    return {"path": shown_path, "path_redacted": shown_path != str(resolved),
            "sha256": digest, "bytes": len(raw)}, text


def _lines(text: str) -> tuple[list[tuple[str, str]], list[dict[str, Any]]]:
    line_count = text.count("\n") + text.count("\r") - text.count("\r\n") + bool(text and text[-1] not in "\r\n")
    if line_count > MAX_LINES:
        raise EvidenceError("source_exceeds_100000_lines")
    rows = [(match[1], match[2]) for match in re.finditer(r"([^\r\n]*)(\r\n|\r|\n|$)", text)
            if match[1] or match[2]]
    if len(rows) > MAX_LINES:
        raise EvidenceError("source_exceeds_100000_lines")
    normalized = "\n".join(row[0] for row in rows) + ("\n" if rows and rows[-1][1] else "")
    safe = source_slice._safe_lines(normalized)
    # The established source reader handles complete blocks and quoted/YAML
    # continuations. Also mask incomplete private-key blocks through EOF.
    starts = [0] + [match.end() for match in re.finditer("\n", normalized)]
    for match in re.finditer(r"-----BEGIN [^-\n]*PRIVATE KEY-----", normalized):
        end = re.search(r"-----END [^-\n]*PRIVATE KEY-----", normalized[match.end():])
        stop = match.end() + end.end() if end else len(normalized)
        first = bisect.bisect_right(starts, match.start()) - 1
        last = bisect.bisect_right(starts, max(match.start(), stop - 1)) - 1
        for index in range(first, min(last + 1, len(safe))):
            safe[index].update(text=common.MASK, redacted=True)
    return rows, safe


def _pointer_tokens(pointer: str) -> list[str]:
    if not isinstance(pointer, str) or (pointer and not pointer.startswith("/")) or re.search(r"~(?:[^01]|$)", pointer):
        raise EvidenceError("invalid_rfc6901_pointer")
    return [] if pointer == "" else [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]


def _resolve(root: Any, tokens: list[str]) -> Any:
    for token in tokens:
        if isinstance(root, dict) and token in root:
            root = root[token]
        elif isinstance(root, list) and re.fullmatch(r"0|[1-9][0-9]*", token) and len(token) <= 10 and int(token) < len(root):
            root = root[int(token)]
        else:
            raise EvidenceError("pointer_not_found")
    return root


def _range(value: Any, minimum: int) -> tuple[int, int]:
    if not isinstance(value, (list, tuple)) or len(value) != 2 or any(type(n) is not int for n in value):
        raise EvidenceError("invalid_inclusive_range")
    start, end = value
    if not minimum <= start <= end <= 2147483647:
        raise EvidenceError("invalid_inclusive_range")
    return start, end


def _plan_lines(text: str, ranges: list[Any], pack: bool) -> tuple[list[dict[str, Any]], list[list[list[dict[str, Any]]]]]:
    rows, safe = _lines(text)
    items, plans = [], []
    for bounds in ranges:
        start, end = _range(bounds, 1)
        item = {"requested": {"lines": [start, end]}, "delivered": [], "remaining": [[start, end]], "records": []}
        units = []
        if end > len(rows):
            item.update(error="line_range_outside_source", source_line_count=len(rows))
        else:
            cursor = start
            while cursor <= end:
                last = cursor
                if pack:
                    while last < end and rows[last] == rows[cursor - 1]:
                        last += 1
                expanded = [{"line": number, "text": safe[number - 1]["text"], "eol": rows[number - 1][1],
                             "redacted": safe[number - 1]["redacted"]} for number in range(cursor, last + 1)]
                # Context-dependent redaction can differ even for identical lines.
                same_view = all(record["text"] == expanded[0]["text"] and record["redacted"] == expanded[0]["redacted"]
                                for record in expanded)
                packed = [{"start": cursor, "end": last, "count": last - cursor + 1,
                           "text": expanded[0]["text"], "eol": rows[cursor - 1][1],
                           "redacted": expanded[0]["redacted"]}]
                if pack and same_view and len(encode_bytes(packed)) < len(encode_bytes(expanded)):
                    units.append(packed)
                else:
                    units.extend([[record] for record in expanded])
                cursor = last + 1
        items.append(item)
        plans.append(units)
    return items, plans


def _plan_json(text: str, pointers: list[str], array_range: Any) -> tuple[list[dict[str, Any]], list[list[list[dict[str, Any]]]], dict[str, Any]]:
    root = _parse_json(text)
    clean = _sanitize(root)
    context = {}
    if isinstance(root, dict):
        fields = {key: clean[key] for key in root if re.sub(r"[^a-z0-9]", "", key.lower()) in _CONTEXT}
        if fields:
            context = {"fields": fields, "redacted": any(_json(root[key]) != _json(value) for key, value in fields.items())}
    items, plans = [], []
    if array_range is not None and len(pointers) != 1:
        raise EvidenceError("array_range_requires_one_pointer")
    for pointer in pointers:
        tokens = _pointer_tokens(pointer)
        shown = common.redact(pointer)
        requested = {"pointer": shown}
        if array_range is not None:
            start, end = _range(array_range, 0)
            requested["records"] = [start, end]
        item = {"requested": requested, "delivered": [], "remaining": [shown] if array_range is None else [[start, end]], "records": []}
        units = []
        try:
            value = _resolve(root, tokens)
            try:
                safe = _resolve(clean, tokens)
            except EvidenceError:
                safe = common.MASK  # A containing secret/env subtree was masked.
            if array_range is None:
                units = [[{"pointer": shown, "value": safe, "redacted": _json(safe) != _json(value)}]]
            elif not isinstance(value, list):
                raise EvidenceError("array_range_requires_array")
            elif end >= len(value):
                item["source_record_count"] = len(value)
                raise EvidenceError("array_range_outside_source")
            else:
                units = [[{"index": index, "value": safe[index] if isinstance(safe, list) else common.MASK,
                           "redacted": not isinstance(safe, list) or _json(safe[index]) != _json(value[index])}]
                         for index in range(start, end + 1)]
        except EvidenceError as exc:
            item["error"] = str(exc)
        items.append(item)
        plans.append(units)
    return items, plans, context


def _refresh(item: dict[str, Any], units: list[list[dict[str, Any]]], position: int) -> None:
    item.pop("next", None)
    request = item["requested"]
    if "lines" in request or "records" in request:
        start, end = request.get("lines", request.get("records"))
        records = item["records"]
        last = (records[-1].get("end", records[-1].get("line", records[-1].get("index")))) if records else start - 1
        item["delivered"] = [[start, last]] if records else []
        item["remaining"] = [[last + 1, end]] if last < end else []
    else:
        item["delivered"] = [request["pointer"]] if item["records"] else []
        item["remaining"] = [] if item["records"] else [request["pointer"]]
    item["status"] = "failed" if item.get("error") else "partial" if item["remaining"] else "complete"
    if position < len(units):
        first = units[position][0]
        selector = {key: first[key] for key in ("line", "start", "index", "pointer") if key in first}
        item["next"] = {**selector, "serialized_record_bytes": len(encode_bytes(units[position])), "oversized_record": False}


def _status(packet: dict[str, Any]) -> None:
    items = packet["items"]
    packet["status"] = ("complete" if all(item["status"] == "complete" for item in items) else
                        "failed" if all(item["status"] == "failed" for item in items) else "partial")


def _failure(code: str) -> dict[str, Any]:
    return {"schema": "evidence_slice_v1", "status": "failed", "error": code, "remaining": "entire_request"}


def read_evidence(path: str | Path, mode: str, *, ranges: list[Any] | None = None,
                  pointers: list[str] | None = None, array_range: Any = None, pack_runs: bool = False,
                  sha256: str | None = None, max_bytes: int = 12000) -> dict[str, Any]:
    """Read one immutable-in-this-response local snapshot; never write source/state."""
    if type(max_bytes) is not int or max_bytes < MIN_BUDGET:
        raise ValueError("max_bytes must be at least 1024")
    try:
        if mode not in {"lines", "json"}:
            raise EvidenceError("explicit_mode_required")
        selections = ranges if mode == "lines" else pointers
        if not isinstance(selections, list) or not 1 <= len(selections) <= MAX_SELECTIONS:
            raise EvidenceError("requires_1_to_128_explicit_selections")
        if (mode == "lines" and (pointers is not None or array_range is not None)) or (mode == "json" and (ranges is not None or pack_runs)):
            raise EvidenceError("options_do_not_match_mode")
        source, text = _load(path, sha256)
        packet = {"schema": "evidence_slice_v1", "status": "partial", "mode": mode, "source": source}
        if mode == "lines":
            items, plans = _plan_lines(text, selections, pack_runs)
        else:
            items, plans, context = _plan_json(text, selections, array_range)
            if context:
                packet["context"] = context
        packet["items"] = items
        for item, units in zip(items, plans):
            _refresh(item, units, 0)
        _status(packet)
        if len(encode_bytes(packet)) > max_bytes:
            return _failure("request_metadata_exceeds_budget")
        for item, units in zip(items, plans):
            for index, records in enumerate(units):
                previous = dict(item)
                item["records"] = [*item["records"], *records]
                _refresh(item, units, index + 1)
                _status(packet)
                if len(encode_bytes(packet)) <= max_bytes:
                    continue
                item.clear()
                item.update(previous)
                # Check one remaining unit in isolation with the same provenance
                # and required context. It may need a larger budget even alone.
                first, last = records[0], records[-1]
                if "lines" in item["requested"]:
                    span = [first.get("start", first.get("line")), last.get("end", last.get("line"))]
                    request, delivered = {"lines": span}, [span]
                elif "records" in item["requested"]:
                    span = [first["index"], last["index"]]
                    request, delivered = {"pointer": item["requested"]["pointer"], "records": span}, [span]
                else:
                    request, delivered = item["requested"], [item["requested"]["pointer"]]
                single = {"requested": request, "delivered": delivered, "remaining": [], "records": records, "status": "complete"}
                item["next"]["oversized_record"] = len(encode_bytes({**packet, "items": [single]})) > max_bytes
                _status(packet)
                break
        _status(packet)
        return packet
    except EvidenceError as exc:
        return _failure(str(exc))
    except (RecursionError, UnicodeError):
        return _failure("input_too_deep_or_invalid_unicode")


def _cli_range(value: str) -> list[int]:
    if not re.fullmatch(r"[0-9]{1,10}:[0-9]{1,10}", value):
        raise argparse.ArgumentTypeError("range requires START:END inclusive")
    return [int(part) for part in value.split(":")]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--file", required=True, help="Already-sanitized saved local artifact (8 MiB maximum)")
    parser.add_argument("--sha256", help="Expected source SHA256; use returned digest on subsequent reads")
    parser.add_argument("--max-bytes", type=int, default=12000, help="Entire JSON UTF-8 response including LF (minimum 1024)")
    modes = parser.add_subparsers(dest="mode", required=True)
    lines = modes.add_parser("lines", help="One-based inclusive line selections, retaining EOL")
    lines.add_argument("--range", type=_cli_range, action="append", required=True, dest="ranges")
    lines.add_argument("--pack-runs", action="store_true", help="Pack exact adjacent repeats only when serialized output shrinks")
    objects = modes.add_parser("json", help="Exact RFC6901 pointers and optional whole array records")
    objects.add_argument("--pointer", action="append", required=True, dest="pointers")
    objects.add_argument("--array-range", type=_cli_range, help="Zero-based inclusive range; requires exactly one array pointer")
    args = parser.parse_args(argv)
    if args.max_bytes < MIN_BUDGET:
        parser.error("--max-bytes must be at least 1024")
    result = read_evidence(args.file, args.mode, ranges=getattr(args, "ranges", None),
                           pointers=getattr(args, "pointers", None), array_range=getattr(args, "array_range", None),
                           pack_runs=getattr(args, "pack_runs", False), sha256=args.sha256, max_bytes=args.max_bytes)
    sys.stdout.buffer.write(encode_bytes(result))
    return {"complete": 0, "partial": 1, "failed": 2}[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
