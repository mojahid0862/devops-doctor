#!/usr/bin/env python3
"""Review saved CloudFormation templates, change sets, and stack events offline."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aws_stack_snapshot import bounded_int
from doctor_common import emit_result, redact
from evidence_slice import EvidenceError, encode_bytes, read_local_text
from terraform_plan_guard import iam_wildcards, policy_statements


MAX_NODES = 100_000
MAX_DEPTH = 64
LOGICAL_ID = re.compile(r"[A-Za-z0-9]{1,255}")
RESOURCE_TYPE = re.compile(r"(?:[A-Za-z0-9]+::){2}[A-Za-z0-9]+|Custom::[A-Za-z0-9_@-]+")
STATEFUL = {
    "AWS::S3::Bucket", "AWS::RDS::DBInstance", "AWS::RDS::DBCluster", "AWS::DynamoDB::Table",
    "AWS::EC2::Volume", "AWS::EFS::FileSystem", "AWS::OpenSearchService::Domain", "AWS::Redshift::Cluster",
}
SHORT_TAGS = {"Ref", "Condition", "Base64", "Cidr", "FindInMap", "GetAtt", "GetAZs", "ImportValue", "Join",
              "Select", "Split", "Sub", "Transform", "And", "Equals", "If", "Not", "Or", "Length", "ToJsonString"}
CHANGE_ACTIONS = {"Add", "Modify", "Remove", "Import", "Dynamic", "SyncWithActual"}
POLICIES = {"Delete", "Retain", "Snapshot", "RetainExceptOnCreate"}
POLICY_ACTIONS = {"Delete", "Retain", "Snapshot", "ReplaceAndDelete", "ReplaceAndRetain", "ReplaceAndSnapshot"}
CHANGE_STATUSES = {"CREATE_PENDING", "CREATE_IN_PROGRESS", "CREATE_COMPLETE", "FAILED",
                   "DELETE_PENDING", "DELETE_IN_PROGRESS", "DELETE_COMPLETE", "DELETE_FAILED"}
EXECUTION_STATUSES = {"UNAVAILABLE", "AVAILABLE", "EXECUTE_IN_PROGRESS", "EXECUTE_COMPLETE", "EXECUTE_FAILED", "OBSOLETE"}
EVENT_STATUS = re.compile(r"(?:CREATE|DELETE|UPDATE|IMPORT|EXPORT|ROLLBACK|UPDATE_ROLLBACK|IMPORT_ROLLBACK|EXPORT_ROLLBACK)"
                          r"_(?:IN_PROGRESS|FAILED|COMPLETE|COMPLETE_CLEANUP_IN_PROGRESS|SKIPPED)")
PROPERTY_CHECKS = {
    "AWS::RDS::DBInstance": "StorageEncrypted", "AWS::RDS::DBCluster": "StorageEncrypted",
    "AWS::EC2::Volume": "Encrypted", "AWS::EFS::FileSystem": "Encrypted",
    "AWS::OpenSearchService::Domain": "EncryptionAtRestOptions.Enabled",
}


class ReviewError(Exception):
    """Fixed diagnostic code. Keep source content out of exceptions shown to users."""


def object_pairs(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if not isinstance(key, str) or key in result:
            raise ReviewError("non_string_or_duplicate_mapping_key")
        result[key] = value
    return result


def reject_number(_: str) -> None:
    raise ReviewError("invalid_json_number")


def load_yaml(text: str) -> dict:
    try:
        import yaml
    except ImportError as exc:
        raise ReviewError("optional_yaml_parser_unavailable") from exc

    class Loader(yaml.SafeLoader):
        # CloudFormation uses JSON-compatible values and does not support YAML aliases or merge keys.
        yaml_implicit_resolvers = {
            key: [(tag, pattern) for tag, pattern in rules if tag.rsplit(":", 1)[-1] not in {"timestamp", "bool"}]
            for key, rules in yaml.SafeLoader.yaml_implicit_resolvers.items()
        }
        nodes = depth = 0

        def compose_node(self, parent, index):
            event = self.peek_event()
            self.nodes += 1
            if self.nodes > MAX_NODES or self.depth >= MAX_DEPTH:
                raise ReviewError("document_complexity_limit")
            if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None) is not None:
                raise ReviewError("yaml_alias_or_anchor_unsupported")
            self.depth += 1
            try:
                return super().compose_node(parent, index)
            finally:
                self.depth -= 1

        def construct_mapping(self, node, deep=False):
            if any(key.tag == "tag:yaml.org,2002:merge" for key, _ in node.value):
                raise ReviewError("yaml_merge_unsupported")
            return object_pairs(self.construct_pairs(node, deep=deep))

    Loader.add_implicit_resolver("tag:yaml.org,2002:bool", re.compile(r"^(?:true|false)$", re.I), list("tTfF"))

    def intrinsic(loader, suffix, node):
        if suffix not in SHORT_TAGS:
            raise ReviewError("unsupported_yaml_tag")
        if isinstance(node, yaml.ScalarNode):
            value = loader.construct_scalar(node)
            if suffix == "GetAtt":
                value = value.split(".", 1)
        elif isinstance(node, yaml.SequenceNode):
            value = loader.construct_sequence(node, deep=True)
        else:
            value = loader.construct_mapping(node, deep=True)
        return {suffix if suffix in {"Ref", "Condition"} else f"Fn::{suffix}": value}

    Loader.add_multi_constructor("!", intrinsic)
    try:
        return yaml.load(text, Loader=Loader)
    except (yaml.YAMLError, ValueError, OverflowError, RecursionError) as exc:
        raise ReviewError("invalid_yaml") from exc


def walk(value: Any):
    pending = [(value, 0)]
    count = 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if depth >= MAX_DEPTH or count > MAX_NODES:
            raise ReviewError("document_complexity_limit")
        yield node
        if isinstance(node, (dict, list)):
            if len(node) > MAX_NODES - count - len(pending):
                raise ReviewError("document_complexity_limit")
            children = node.values() if isinstance(node, dict) else node
            pending.extend((child, depth + 1) for child in children)
        elif node is not None and type(node) not in {str, int, float, bool}:
            raise ReviewError("unsupported_document_value")
        elif isinstance(node, float) and not -float("inf") < node < float("inf"):
            raise ReviewError("invalid_numeric_value")


def read_document(path: Path, mode: str, sha256: str | None) -> tuple[dict, dict]:
    try:
        source, text = read_local_text(path, sha256, follow_symlinks=False)
    except RuntimeError as exc:
        raise ReviewError("source_unavailable") from exc
    text = text.removeprefix("\ufeff")
    try:
        data = json.loads(text, object_pairs_hook=object_pairs, parse_constant=reject_number)
    except json.JSONDecodeError as exc:
        if mode != "template" or path.suffix.lower() == ".json":
            raise ReviewError("invalid_json") from exc
        data = load_yaml(text)
    except (ValueError, RecursionError) as exc:
        raise ReviewError("invalid_json") from exc
    if not isinstance(data, dict):
        raise ReviewError("expected_document_object")
    for _ in walk(data):
        pass
    # Preserve the digest without exposing a path that may contain resource names or secrets.
    return {key: source[key] for key in ("sha256", "bytes")}, data


def unresolved(value: Any) -> bool:
    return ((isinstance(value, dict) and any(key in {"Ref", "Condition"} or key.startswith("Fn::") for key in value))
            or (isinstance(value, str) and "{{resolve:" in value))


def known(value: Any, allowed) -> Any:
    return value if isinstance(value, str) and value in allowed else None


def resource_type(value: Any) -> str:
    if (isinstance(value, str) and len(value) <= 128 and RESOURCE_TYPE.fullmatch(value)
            and redact(value) == value):
        return value if value.startswith("AWS::") else "Custom"
    return "Unknown"


def issue(report: dict, scope: str, reason: str) -> None:
    entry = {"scope": scope, "reason": reason}
    if entry not in report["blockers"]:
        report["blockers"].append(entry)


def finding(report: dict, alias: str, kind: str, severity: str, rule: str, **context) -> None:
    report["findings"].append({"resource": alias, "resource_type": kind, "severity": severity, "rule": rule, **context})


def internet_wide(value: Any, version: int) -> bool:
    if not isinstance(value, str) or not value.endswith("/0"):
        return False
    try:
        return ipaddress.ip_network(value, strict=False).version == version
    except ValueError:
        return False


def literal_boolean(value: Any) -> bool | None:
    if isinstance(value, str):
        return {"true": True, "false": False}.get(value.casefold())
    return value if isinstance(value, bool) else None


def inspect_resource(report: dict, alias: str, kind: str, resource: dict, props: dict) -> None:
    reported = set()

    def add(severity: str, rule: str, property_name: str) -> None:
        key = (severity, rule, property_name)
        if key not in reported:
            finding(report, alias, kind, severity, rule, property=property_name,
                    conditional="Condition" in resource)
            reported.add(key)

    if kind in {"AWS::EC2::SecurityGroup", "AWS::EC2::SecurityGroupIngress"}:
        ingress = props.get("SecurityGroupIngress", []) if kind.endswith("SecurityGroup") else [props]
        if isinstance(ingress, list):
            for rule in ingress:
                if not isinstance(rule, dict):
                    continue
                if internet_wide(rule.get("CidrIp"), 4) or internet_wide(rule.get("CidrIpv6"), 6):
                    protocol = rule.get("IpProtocol")
                    start, end = rule.get("FromPort"), rule.get("ToPort")
                    admin_port = (protocol in ("tcp", "6", 6) and type(start) is int and type(end) is int
                                  and any(start <= port <= end for port in (22, 3389)))
                    add("high" if protocol in ("-1", -1) or admin_port else "medium",
                        "internet_wide_ingress", "SecurityGroupIngress")
    if kind == "AWS::S3::Bucket":
        if props.get("AccessControl") in ("PublicRead", "PublicReadWrite"):
            add("high", "public_acl_requested_effective_access_unverified", "AccessControl")
        public = props.get("PublicAccessBlockConfiguration")
        if public is None or isinstance(public, dict) and not unresolved(public) and any(
            literal_boolean(public.get(key)) is False or key not in public
            for key in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
        ):
            add("medium", "bucket_public_access_block_not_fully_declared", "PublicAccessBlockConfiguration")
    if kind in {"AWS::RDS::DBInstance", "AWS::RDS::DBCluster"} and literal_boolean(props.get("PubliclyAccessible")) is True:
        add("high", "public_database_requested_network_access_unverified", "PubliclyAccessible")
    prop = PROPERTY_CHECKS.get(kind)
    if prop:
        parent, _, leaf = prop.partition(".")
        container = props.get(parent) if leaf else props
        configured = container.get(leaf or parent) if isinstance(container, dict) else None
        if literal_boolean(configured) is False:
            add("high", "at_rest_encryption_explicitly_disabled", prop)
        elif configured is None and (container is None or isinstance(container, dict) and not unresolved(container)):
            add("medium", "at_rest_encryption_not_declared_verify_defaults", prop)
    if kind in {"AWS::RDS::DBInstance", "AWS::RDS::DBCluster"} and literal_boolean(props.get("DeletionProtection")) is False:
        add("medium", "deletion_protection_explicitly_disabled", "DeletionProtection")
    if kind in STATEFUL:
        for attribute in ("DeletionPolicy", "UpdateReplacePolicy"):
            if attribute not in resource or resource[attribute] == "Delete":
                add("medium", "state_retention_requires_review", attribute)
    policies = []
    if kind.startswith("AWS::IAM::") or kind in {"AWS::S3::BucketPolicy", "AWS::SQS::QueuePolicy", "AWS::SNS::TopicPolicy"}:
        policies.extend(props.get(key) for key in ("PolicyDocument", "AssumeRolePolicyDocument") if isinstance(props.get(key), dict))
        if isinstance(props.get("Policies"), list):
            policies.extend(item["PolicyDocument"] for item in props["Policies"] if isinstance(item, dict)
                            and isinstance(item.get("PolicyDocument"), dict))
    for policy in policies:
        if not unresolved(policy):
            for statement in policy_statements({"Statement": policy.get("Statement")}):
                if any(unresolved(node) for node in walk(statement)):
                    continue
                for result in iam_wildcards({"Statement": statement}):
                    add("medium" if result["conditions_present"] else "high",
                        "wildcard_allow_review_effective_permissions", "PolicyDocument")


def review_template(report: dict, template: dict, limit: int) -> None:
    resources = template.get("Resources")
    if not isinstance(resources, dict) or not resources:
        raise ReviewError("missing_or_invalid_template_resources")
    if "AWSTemplateFormatVersion" in template and template["AWSTemplateFormatVersion"] != "2010-09-09":
        issue(report, "template", "unsupported_template_format_version")
    if "Transform" in template or any(
        isinstance(node, dict) and ("Fn::Transform" in node or any(key.startswith("Fn::ForEach::") for key in node))
        for node in walk(template)
    ):
        issue(report, "template", "transforms_not_expanded")
    if any(isinstance(value, dict) and value.get("Type") in ("AWS::CloudFormation::Stack", "AWS::Serverless::Application")
           for value in resources.values()):
        issue(report, "template", "nested_template_not_read")
    if any(unresolved(node) for node in walk(template)):
        issue(report, "template", "intrinsics_or_dynamic_references_unresolved")
    if "Conditions" in template or any(isinstance(value, dict) and "Condition" in value for value in resources.values()):
        issue(report, "template", "resource_conditions_not_evaluated")
    if len(resources) > limit:
        issue(report, "template", "item_limit")
    reviewed = 0
    for index, (name, value) in enumerate(resources.items(), 1):
        if index > limit:
            break
        if (not LOGICAL_ID.fullmatch(name) or not isinstance(value, dict)
                or resource_type(value.get("Type")) == "Unknown" or not isinstance(value.get("Properties", {}), dict)):
            issue(report, "template", "invalid_or_unexpanded_resource")
            continue
        kind = resource_type(value["Type"])
        for attr, allowed in (("DeletionPolicy", POLICIES), ("UpdateReplacePolicy", POLICIES - {"RetainExceptOnCreate"})):
            if attr in value and not unresolved(value[attr]) and known(value[attr], allowed) is None:
                issue(report, "template", "invalid_retention_policy")
        if kind in {"Custom", "AWS::CloudFormation::CustomResource"}:
            issue(report, "template", "custom_or_nested_resources_not_expanded")
        reviewed += 1
        inspect_resource(report, f"r{index}", kind, value, value.get("Properties", {}))
    report["summary"].update(resources_in_file=len(resources), resources_reviewed=reviewed)


def page_coverage(report: dict, data: dict) -> None:
    if any(key in data and data[key] is not None for key in ("NextToken", "nextToken", "NextMarker", "ContinuationToken")):
        issue(report, "export", "continuation_present")
    collection = data.get("collection")
    if (data.get("truncated") is True or data.get("partial") is True or data.get("status") in ("partial", "failed")
            or data.get("HasMore") is True or data.get("IsTruncated") is True
            or isinstance(collection, dict) and collection.get("complete") is False):
        issue(report, "export", "upstream_coverage_incomplete")


def review_changes(report: dict, data: dict, limit: int) -> None:
    page_coverage(report, data)
    changes = data.get("Changes")
    status = known(data.get("Status"), CHANGE_STATUSES)
    execution = known(data.get("ExecutionStatus"), EXECUTION_STATUSES)
    if status != "CREATE_COMPLETE":
        issue(report, "change_set", "change_set_not_confirmed_ready")
    if execution is None:
        issue(report, "change_set", "execution_status_unavailable")
    if data.get("IncludeNestedStacks") is True:
        issue(report, "change_set", "nested_changes_not_reviewed")
    if changes is None and status and status != "CREATE_COMPLETE":
        changes = []
    if not isinstance(changes, list):
        raise ReviewError("missing_or_invalid_changes")
    if len(changes) > limit:
        issue(report, "change_set", "item_limit")
    actions: Counter = Counter()
    replacements: Counter = Counter()
    seen = set()
    for index, change in enumerate(changes[:limit], 1):
        row = change.get("ResourceChange") if isinstance(change, dict) else None
        action = known(row.get("Action"), CHANGE_ACTIONS) if isinstance(row, dict) else None
        kind = resource_type(row.get("ResourceType")) if isinstance(row, dict) else "Unknown"
        logical = row.get("LogicalResourceId") if isinstance(row, dict) else None
        if (not isinstance(change, dict) or change.get("Type", "Resource") != "Resource"
                or action is None or kind == "Unknown" or not isinstance(logical, str) or not LOGICAL_ID.fullmatch(logical)):
            issue(report, "change_set", "invalid_or_unknown_change")
            continue
        if logical in seen:
            issue(report, "change_set", "duplicate_change_logical_id")
            continue
        seen.add(logical)
        actions[action] += 1
        replacement = known(row.get("Replacement"), {"True", "False", "Conditional"})
        policy = known(row.get("PolicyAction"), POLICY_ACTIONS)
        if action == "Modify":
            replacement = {"True": "definite", "False": "none", "Conditional": "conditional"}.get(replacement, "unknown")
            if policy and policy.startswith("ReplaceAnd") and replacement == "none":
                replacement = "unknown"
                issue(report, "change_set", "conflicting_replacement_evidence")
            replacements[replacement] += 1
        elif action == "Dynamic":
            replacement = "unknown"
            replacements[replacement] += 1
        else:
            replacement = "not_applicable"
        if replacement == "unknown":
            issue(report, "change_set", "replacement_unresolved")
        if row.get("PolicyAction") is not None and policy is None:
            issue(report, "change_set", "unknown_policy_action")
        if kind == "AWS::CloudFormation::Stack" or row.get("ChangeSetId"):
            issue(report, "change_set", "nested_changes_not_reviewed")
        risk = []
        if action == "Remove" or replacement in {"definite", "conditional", "unknown"}:
            risk.append("service_interruption_possible")
            if policy in {"Delete", "ReplaceAndDelete"}:
                risk.append("old_resource_deletion_indicated")
            if kind in STATEFUL:
                risk.append("verify_retention_backup_and_restore_before_execution")
                if policy in {"Delete", "ReplaceAndDelete"}:
                    risk.append("old_state_deletion_indicated")
            finding(report, f"r{index}", kind, "high" if action == "Remove" or replacement == "definite" else "medium",
                    "review_disruption_and_rollback", action=action, replacement=replacement)
        report["evidence"]["changes"].append({"resource": f"r{index}", "resource_type": kind, "action": action,
                                                "replacement": replacement, "policy_action": policy, "risk": risk})
    report["summary"].update(change_set_status=status, execution_status=execution, changes_in_file=len(changes),
                             changes_reviewed=sum(actions.values()),
                             actions=dict(actions), replacements=dict(replacements))


def parse_timestamp(value: Any) -> datetime | None:
    if isinstance(value, str) and len(value) <= 40:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.utcoffset() is not None:
                return parsed.astimezone(timezone.utc)
        except (ValueError, OverflowError):
            pass
    return None


def reason_category(message: Any) -> str | None:
    if not isinstance(message, str) or not message:
        return None
    text = message[:8192].casefold()
    for category, markers in (
        ("cancelled", ("cancelled", "canceled")),
        ("authorization", ("accessdenied", "access denied", "not authorized", "unauthorized")),
        ("quota", ("quota", "limitexceeded", "limit exceeded", "throttl")),
        ("conflict", ("already exists", "alreadyexists", "conflict")),
        ("dependency", ("dependency", "dependenc", "not found", "does not exist")),
        ("timeout", ("timed out", "timeout", "did not stabilize")),
        ("validation", ("invalid", "validation", "unsupported")),
    ):
        if any(marker in text for marker in markers):
            return category
    return "other"


def review_events(report: dict, data: dict, limit: int) -> None:
    page_coverage(report, data)
    events = data.get("StackEvents")
    if not isinstance(events, list):
        raise ReviewError("missing_or_invalid_stack_events")
    if len(events) > limit:
        issue(report, "events", "item_limit")
    seen = {}
    rows = []
    for event in events[:limit]:
        if not isinstance(event, dict):
            issue(report, "events", "invalid_event")
            continue
        date = parse_timestamp(event.get("Timestamp"))
        status = event.get("ResourceStatus")
        hook = known(event.get("HookStatus"), {"HOOK_COMPLETE_FAILED", "HOOK_FAILED"})
        hook_mode = known(event.get("HookFailureMode"), {"FAIL", "WARN"})
        kind = resource_type(event.get("ResourceType"))
        identifiers = [event.get(key) for key in ("StackId", "LogicalResourceId", "EventId", "OperationId", "ClientRequestToken")]
        stack, logical, event_id, operation, token = (
            value if isinstance(value, str) and 0 < len(value) <= 2048 else None for value in identifiers
        )
        if not date or (not hook and not (isinstance(status, str) and EVENT_STATUS.fullmatch(status))):
            issue(report, "events", "invalid_event")
            continue
        if not isinstance(status, str) or not EVENT_STATUS.fullmatch(status):
            status = None
            if event.get("ResourceStatus") is not None:
                issue(report, "events", "unknown_resource_status")
        if kind == "Unknown":
            issue(report, "events", "resource_type_unavailable")
        if not (stack and logical and event_id):
            issue(report, "events", "event_identity_incomplete")
        key = (stack, event_id)
        if event_id and key in seen:
            if event != seen[key]:
                issue(report, "events", "conflicting_duplicate_event")
            continue
        if event_id:
            seen[key] = event
        message = event.get("ResourceStatusReason")
        if not status or not status.endswith("_FAILED"):
            message = event.get("HookStatusReason") if hook else message
        rows.append((date, status, kind, hook, hook_mode, stack, logical, operation, token, reason_category(message)))
    rows.sort(key=lambda row: row[0])
    stacks: dict = {}
    resources: dict = {}
    operations: dict = {}
    candidates: dict = {}
    token_candidates: dict = {}
    token_operations: dict = {}
    for _, _, _, _, _, stack, _, operation, token, _ in rows:
        if stack and token and operation:
            token_operations.setdefault((stack, token), set()).add(operation)
    counts: Counter = Counter()
    for index, (date, status, kind, hook, hook_mode, stack, logical, operation, token, reason) in enumerate(rows, 1):
        resource = resources.setdefault((stack, logical), f"r{len(resources) + 1}") if stack and logical else None
        stack_alias = stacks.setdefault(stack, f"s{len(stacks) + 1}") if stack else None
        token_key = (stack, token) if stack and token else None
        token_ops = token_operations.get(token_key, set())
        if not operation and len(token_ops) == 1:
            operation = next(iter(token_ops))
        op_key = (stack, operation) if stack and operation else None
        op_alias = operations.setdefault(op_key, f"o{len(operations) + 1}") if op_key else None
        if token_key and not op_key and not token_ops:
            op_alias = operations.setdefault(token_key + ("request",), f"o{len(operations) + 1}")
        failed = bool(status and status.endswith("_FAILED")) or bool(hook and hook_mode == "FAIL")
        rollback = bool(status and "ROLLBACK" in status)
        counts["failures"] += failed
        counts["rollback_events"] += rollback
        counts["hook_failures"] += bool(hook)
        item = {"event": f"e{index}", "timestamp": date.isoformat().replace("+00:00", "Z"), "status": status,
                "resource_type": kind, "resource": resource, "stack": stack_alias, "operation": op_alias}
        if failed:
            item.update(failed=True, reason_category=reason)
        if hook:
            item.update(hook_status=hook, hook_failure_mode=hook_mode)
            item.setdefault("reason_category", reason)
            if hook_mode is None and not failed:
                issue(report, "events", "hook_impact_unverified")
        if rollback:
            item["rollback"] = True
            candidate = candidates.get(op_key) if op_key else None
            if candidate is None and token_key and not token_ops:
                candidate = token_candidates.get(token_key)
            if candidate and candidate[0] < date:
                item["earlier_failure_same_operation"] = candidate[1]
        if failed and not rollback and reason != "cancelled":
            if op_key:
                candidates[op_key] = (date, item["event"])
            elif token_key and not token_ops:
                token_candidates[token_key] = (date, item["event"])
        report["evidence"]["events"].append(item)
    report["summary"].update(events_in_file=len(events), events_reviewed=len(rows), failures=counts["failures"],
                             rollback_events=counts["rollback_events"], hook_failures=counts["hook_failures"])


def validator(tool: str, args: list[str], cwd: Path, timeout: int) -> str:
    executable = shutil.which(tool)
    if not executable or not Path(executable).is_absolute() or (
        os.name == "nt" and Path(executable).suffix.lower() != ".exe"
    ):
        return "unavailable"
    # Do not pass repository or cloud configuration to the optional validators.
    env = {key: value for key, value in os.environ.items()
           if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR"}}
    env.update({"HOME": str(cwd), "USERPROFILE": str(cwd), "PYTHONNOUSERSITE": "1",
                "AWS_EC2_METADATA_DISABLED": "true", "AWS_CONFIG_FILE": str(cwd / "no-aws-config"),
                "AWS_SHARED_CREDENTIALS_FILE": str(cwd / "no-aws-credentials")})
    try:
        result = subprocess.run([executable, *args], cwd=cwd, env=env, timeout=timeout, check=False,
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return "timed_out"
    except OSError:
        return "failed"
    if result.returncode == 0:
        return "passed"
    if (tool == "cfn-lint" and result.returncode in {2, 4, 6, 8, 10, 12, 14}) or (
        tool == "cfn-guard" and result.returncode == 19
    ):
        return "findings"
    return "failed"


def run_validators(report: dict, template: dict, rules: Path | None, timeout: int) -> None:
    lint = "not_run"
    guard = "rules_not_supplied" if rules is None else "not_run"
    # Avoid writing template copies on older Windows versions without private temp directories.
    minimum = {(3, 10): (3, 10, 15), (3, 11): (3, 11, 10), (3, 12): (3, 12, 4)}
    if os.name == "nt" and sys.version_info[:3] < minimum.get(sys.version_info[:2], (3, 13, 0)):
        report["validation"] = {"cfn-lint": "private_workspace_unavailable", "cfn-guard": "private_workspace_unavailable"}
        issue(report, "validation", "private_workspace_unavailable")
        return
    try:
        with tempfile.TemporaryDirectory(prefix="doctor-cfn-") as directory:
            root = Path(directory)
            path = root / "template.json"
            # Metadata can supply cfn-lint plugin paths or rule overrides. Use neutral lint inputs.
            clean = {key: value for key, value in template.items() if key != "Metadata"}
            clean["Resources"] = {
                key: {k: v for k, v in value.items() if k != "Metadata"} if isinstance(value, dict) else value
                for key, value in template["Resources"].items()
            }
            path.write_bytes(encode_bytes(clean))
            config = root / "lint-config.json"
            config.write_text("{}", encoding="utf-8")
            if any(item["reason"] == "transforms_not_expanded" for item in report["blockers"]):
                lint = "transform_not_evaluated"
            elif any(item["reason"] == "nested_template_not_read" for item in report["blockers"]):
                lint = "nested_template_not_evaluated"
            else:
                lint = validator("cfn-lint", ["--config-file", str(config), "--template", str(path)], root, timeout)
            if rules is not None:
                try:
                    _, rule_text = read_local_text(rules, follow_symlinks=False)
                except (EvidenceError, RuntimeError):
                    guard = "rules_unreadable"
                else:
                    rule_copy = root / "policy.guard"
                    rule_copy.write_bytes(rule_text.encode("utf-8"))
                    path.write_bytes(encode_bytes(template))
                    guard = validator("cfn-guard", ["validate", "--rules", str(rule_copy), "--data", str(path)], root, timeout)
    except (OSError, ValueError):
        issue(report, "validation", "local_validator_workspace_failed")
    report["validation"] = {"cfn-lint": lint, "cfn-guard": guard}
    for name, outcome in report["validation"].items():
        if outcome == "findings":
            finding(report, "template", "CloudFormation", "review", f"{name}_reported_findings")
        elif outcome != "passed":
            issue(report, name, outcome)


def bound_report(report: dict, limit: int) -> None:
    # The shared emitter pretty-prints ASCII-only fields. Reserve CRLF and final status framing.
    def size(value: dict) -> int:
        return len((json.dumps(value, indent=2, sort_keys=True) + "\n").replace("\n", os.linesep).encode("utf-8"))

    if size(report) + 128 <= limit:
        return
    issue(report, "output", "output_byte_limit")
    report["coverage"]["truncated"] = True
    evidence, findings = report["evidence"], report["findings"]
    report["evidence"], report["findings"] = {}, []
    report["coverage"]["omitted_rows"] = sum(map(len, evidence.values())) + len(findings)
    used = size(report) + 128
    for name, rows in [("findings", findings), *evidence.items()]:
        target = report["findings"] if name == "findings" else report["evidence"].setdefault(name, [])
        used += 64
        for row in rows:
            # Account for indentation, array separators, and CRLF without serializing prior rows.
            row_bytes = size(row)
            overhead = 8 * (json.dumps(row, indent=2).count("\n") + 1) + 8
            if used + row_bytes + overhead > limit:
                break
            target.append(row)
            used += row_bytes + overhead
            report["coverage"]["omitted_rows"] -= 1


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["template", "change-set", "events"])
    parser.add_argument("--file", required=True, type=Path, help="Local template or saved AWS JSON export.")
    parser.add_argument("--sha256", help="Require the saved input to match this SHA-256.")
    parser.add_argument("--guard-rules", type=Path, help="Optional local Guard rules file for template review.")
    parser.add_argument("--max-items", type=bounded_int(1, 2000), default=500)
    parser.add_argument("--max-output-bytes", type=bounded_int(4096, 1048576), default=65536)
    parser.add_argument("--validator-timeout", type=bounded_int(1, 60), default=15, help="Seconds per validator.")
    parser.add_argument("--output", type=Path, help="Optional path for the redacted report.")
    args = parser.parse_args(argv)
    if args.guard_rules is not None and args.mode != "template":
        parser.error("--guard-rules requires template mode")
    try:
        if args.output:
            sources = [path for path in (args.file, args.guard_rules) if path]
            if any(args.output.resolve() == path.resolve() for path in sources):
                parser.error("output must be different from input and rules")
            if args.output.exists() and any(path.exists() and args.output.samefile(path) for path in sources):
                parser.error("output must be different from input and rules")
    except (OSError, RuntimeError, ValueError):
        parser.error("could not resolve review paths")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    report = {"schema_version": "2.0", "generated_at": datetime.now(timezone.utc).isoformat(),
              "scope": {"collector": "cloudformation_review", "mode": args.mode},
              "coverage": {"basis": "saved_input_only", "deployment_outcome_verified": False,
                           "truncated": False}, "summary": {}, "findings": [], "blockers": [],
              "evidence": {"changes": []} if args.mode == "change-set" else {"events": []} if args.mode == "events" else {}}
    try:
        source, data = read_document(args.file, args.mode, args.sha256)
        report["scope"]["source"] = source
        {"template": review_template, "change-set": review_changes, "events": review_events}[args.mode](
            report, data, args.max_items)
        if args.mode == "template":
            run_validators(report, data, args.guard_rules, args.validator_timeout)
    except (EvidenceError, ReviewError) as exc:
        issue(report, args.mode, str(exc))
        report["status"] = "failed"
    report["coverage"]["truncated"] |= any(
        item["reason"] in {"item_limit", "continuation_present", "upstream_coverage_incomplete"} for item in report["blockers"])
    bound_report(report, args.max_output_bytes)
    try:
        return emit_result(report, args.output)
    except OSError:
        issue(report, "output", "report_write_failed")
        report["status"] = "failed"
        bound_report(report, args.max_output_bytes)
        return emit_result(report)


if __name__ == "__main__":
    raise SystemExit(main())
