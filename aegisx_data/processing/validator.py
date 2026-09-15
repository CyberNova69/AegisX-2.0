"""Schema and structural validation for DatasetRecord.

Validates required fields, types, ranges, and referential integrity.
Produces a list of issues per record without rejecting — the pipeline
decides the rejection policy.
"""

from __future__ import annotations

import ipaddress
from typing import List, Optional

from ..core.types import (
    AttackCategory,
    Classification,
    DatasetRecord,
    RecordStatus,
    Severity,
)


# ---------------------------------------------------------------------------
# Validation issue
# ---------------------------------------------------------------------------

class ValidationIssue:
    """A single validation finding."""

    __slots__ = ("code", "message", "field", "severity")

    def __init__(self, code: str, message: str,
                 field: Optional[str] = None, severity: str = "error"):
        self.code = code
        self.message = message
        self.field = field
        self.severity = severity  # "error" or "warning"

    def __repr__(self) -> str:
        return f"ValidationIssue({self.code}, {self.field}, {self.severity})"

    def to_dict(self):
        return {
            "code": self.code,
            "message": self.message,
            "field": self.field,
            "severity": self.severity,
        }


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

class RecordValidator:
    """Validate DatasetRecord structural and semantic integrity.

    Errors → record is invalid (rejected unless overridden).
    Warnings → record is valid but has quality issues.
    """

    def __init__(self, strict: bool = True):
        self.strict = strict

    def validate(self, record: DatasetRecord) -> List[ValidationIssue]:
        """Validate a record and return all issues found."""
        issues: List[ValidationIssue] = []

        # --- Required fields ---
        if not record.record_id:
            issues.append(ValidationIssue(
                "missing_record_id", "record_id is required", "record_id"))

        if not record.source:
            issues.append(ValidationIssue(
                "missing_source", "source is required", "source"))

        # --- IP validation ---
        for field_name in ("src_ip", "dst_ip"):
            value = getattr(record, field_name)
            if value is not None:
                try:
                    ipaddress.ip_address(value)
                except ValueError:
                    issues.append(ValidationIssue(
                        "invalid_ip",
                        f"{field_name} is not a valid IP address: {value}",
                        field_name))

        # --- Port validation ---
        for field_name in ("src_port", "dst_port"):
            value = getattr(record, field_name)
            if value is not None:
                if not isinstance(value, int) or not (0 <= value <= 65535):
                    issues.append(ValidationIssue(
                        "invalid_port",
                        f"{field_name} must be 0..65535, got {value}",
                        field_name))

        # --- Numeric field validation ---
        for field_name in ("bytes_sent", "bytes_recv", "packets_sent", "packets_recv"):
            value = getattr(record, field_name)
            if value is not None:
                if not isinstance(value, (int, float)) or value < 0:
                    issues.append(ValidationIssue(
                        "invalid_numeric",
                        f"{field_name} must be non-negative, got {value}",
                        field_name))

        if record.duration is not None:
            if not isinstance(record.duration, (int, float)) or record.duration < 0:
                issues.append(ValidationIssue(
                    "invalid_duration",
                    f"duration must be non-negative, got {record.duration}",
                    "duration"))

        # --- Confidence validation ---
        if not isinstance(record.confidence, (int, float)) or \
           not (0.0 <= record.confidence <= 1.0):
            issues.append(ValidationIssue(
                "invalid_confidence",
                f"confidence must be 0.0..1.0, got {record.confidence}",
                "confidence"))

        # --- Enum validation ---
        if record.classification is not None:
            if not isinstance(record.classification, Classification):
                issues.append(ValidationIssue(
                    "invalid_classification",
                    f"invalid classification: {record.classification}",
                    "classification"))

        if record.severity is not None:
            if not isinstance(record.severity, Severity):
                issues.append(ValidationIssue(
                    "invalid_severity",
                    f"invalid severity: {record.severity}",
                    "severity"))

        if record.attack_category is not None:
            if not isinstance(record.attack_category, AttackCategory):
                issues.append(ValidationIssue(
                    "invalid_attack_category",
                    f"invalid attack_category: {record.attack_category}",
                    "attack_category"))

        # --- Hash validation ---
        if record.file_hash is not None:
            import re
            if not re.match(r"^[0-9a-f]{32,64}$", record.file_hash):
                issues.append(ValidationIssue(
                    "invalid_hash",
                    f"file_hash must be hex MD5/SHA-1/SHA-256, got {record.file_hash[:20]}...",
                    "file_hash"))

        # --- Warnings (non-blocking quality signals) ---
        if not record.timestamp:
            issues.append(ValidationIssue(
                "missing_timestamp",
                "timestamp could not be established",
                "timestamp", "warning"))

        if not record.source_label:
            issues.append(ValidationIssue(
                "missing_source_label",
                "no source label available for harmonization",
                "source_label", "warning"))

        # Low-context warning: no network or endpoint identifiers
        has_context = any([
            record.src_ip, record.dst_ip, record.hostname,
            record.username, record.process_name, record.file_path,
        ])
        if not has_context:
            issues.append(ValidationIssue(
                "low_context",
                "record has no network or endpoint identifiers",
                severity="warning"))

        # Apply issues to record
        error_messages = [f"[{i.severity}] {i.code}: {i.message}" for i in issues]
        record.validation_issues.extend(error_messages)

        has_errors = any(i.severity == "error" for i in issues)
        if has_errors:
            record.status = RecordStatus.REJECTED
        elif record.status == RecordStatus.NORMALIZED:
            record.status = RecordStatus.VALIDATED

        return issues

    def is_valid(self, record: DatasetRecord) -> bool:
        """Quick check: does the record have any error-level issues?"""
        issues = self.validate(record)
        return not any(i.severity == "error" for i in issues)
