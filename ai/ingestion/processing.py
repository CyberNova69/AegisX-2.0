"""Trusted event processing: normalization -> validation -> exact deduplication.

This module is deliberately independent from parsing and LLM code. It accepts a
CanonicalEvent, produces an auditable processing outcome, and yields only trusted
NormalizedEvent instances to downstream stages. Every rejected or duplicate event
remains represented in an outcome/report; nothing is silently discarded.
"""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, Iterable, Iterator, List, Optional

from .normalize import (
    hash_algorithm, is_valid_ip, normalize_domain, normalize_hash, normalize_hostname,
    normalize_ip, normalize_protocol, normalize_severity, normalize_status,
    normalize_timestamp, normalize_whitespace,
)
from .types import CanonicalEvent, EVENT_TYPES, SEVERITIES


@dataclass
class ValidationIssue:
    """One deterministic processing finding."""

    code: str
    message: str
    field: Optional[str] = None
    severity: str = "error"  # error | warning

    def to_dict(self) -> Dict[str, Optional[str]]:
        return {
            "code": self.code,
            "message": self.message,
            "field": self.field,
            "severity": self.severity,
        }


@dataclass
class NormalizedEvent:
    """Canonical event after safe normalizations and structural validation.

    `event` retains the original CanonicalEvent provenance (`raw`, source name,
    source format and index). `normalization_actions` makes every changed field
    explicit. This object does not claim that an event is malicious or an alert.
    """

    event: CanonicalEvent
    normalization_actions: List[str] = field(default_factory=list)
    validation_issues: List[ValidationIssue] = field(default_factory=list)
    fingerprint: Optional[str] = None
    duplicate_of: Optional[str] = None

    @property
    def validation_status(self) -> str:
        """Explicit validation state, independent of deduplication status."""
        if any(issue.severity == "error" for issue in self.validation_issues):
            return "INVALID"
        if self.validation_issues:
            return "VALID_WITH_WARNINGS"
        return "VALID"

    @property
    def trusted(self) -> bool:
        return not self.duplicate_of and self.validation_status != "INVALID"

    @property
    def event_id(self) -> str:
        return self.event.event_id

    def to_dict(self) -> Dict[str, object]:
        return {
            "event": self.event.to_dict(),
            "normalization_actions": self.normalization_actions,
            "validation_issues": [i.to_dict() for i in self.validation_issues],
            "fingerprint": self.fingerprint,
            "duplicate_of": self.duplicate_of,
            "validation_status": self.validation_status,
            "trusted": self.trusted,
        }

    def to_alert_input(self) -> Dict[str, object]:
        """Delegate to the existing canonical-to-agent boundary bridge."""
        return self.event.to_alert_input()


@dataclass
class ProcessingOutcome:
    """Full per-event audit record, including rejected and duplicate events."""

    normalized: NormalizedEvent
    status: str  # trusted | rejected | duplicate

    def to_dict(self) -> Dict[str, object]:
        payload = self.normalized.to_dict()
        payload["status"] = self.status
        return payload


@dataclass
class ProcessingReport:
    input_events: int = 0
    trusted_events: int = 0
    rejected_events: int = 0
    duplicate_events: int = 0
    warnings: int = 0
    errors: int = 0
    dedup_evictions: int = 0

    def to_dict(self) -> Dict[str, int]:
        return {
            "input_events": self.input_events,
            "trusted_events": self.trusted_events,
            "rejected_events": self.rejected_events,
            "duplicate_events": self.duplicate_events,
            "warnings": self.warnings,
            "errors": self.errors,
            "dedup_evictions": self.dedup_evictions,
        }


class EventNormalizer:
    """Apply only safe, deterministic field normalization.

    Ambiguous values are retained rather than guessed. For example, usernames are
    whitespace-normalized but not lower-cased because user identity may be
    case-sensitive in a source system.
    """

    _TRIM_FIELDS = (
        "username", "source_ip", "dest_ip", "process_name", "command_line",
        "file_path", "file_hash",
    )

    def normalize(self, source: CanonicalEvent) -> NormalizedEvent:
        event = copy.deepcopy(source)
        actions: List[str] = []

        # Timestamp is re-checked because callers may construct CanonicalEvent
        # directly instead of entering via Task 1 mapping.
        before = event.timestamp
        if before is not None:
            after = normalize_timestamp(before)
            if after:
                if after != before:
                    event.timestamp = after
                    actions.append("timestamp: normalized to ISO-8601 UTC")
            else:
                # Never retain an unparseable value as if it were trustworthy.
                # Keep the exact source value in attributes for audit, and surface
                # the missing canonical timestamp as a validator warning.
                event.attributes.setdefault("_unparsed_timestamp", str(before))
                event.timestamp = None
                actions.append("timestamp: unparseable source value retained in attributes")

        for name in self._TRIM_FIELDS:
            before = getattr(event, name)
            if isinstance(before, str):
                after = normalize_whitespace(before)
                if after != before:
                    setattr(event, name, after)
                    actions.append(f"{name}: normalized whitespace")

        for name, fn, label in (
            ("hostname", normalize_hostname, "normalized hostname"),
            ("domain", normalize_domain, "normalized domain"),
            ("severity", normalize_severity, "normalized severity"),
            ("file_hash", normalize_hash, "normalized hash"),
            ("protocol", normalize_protocol, "normalized protocol"),
            ("status", normalize_status, "normalized status"),
        ):
            before = getattr(event, name)
            if before is not None:
                after = fn(before)
                if after is not None and after != before:
                    setattr(event, name, after)
                    actions.append(f"{name}: {label}")

        for name in ("source_ip", "dest_ip"):
            before = getattr(event, name)
            if before is not None:
                after = normalize_ip(before)
                if after is not None and after != before:
                    setattr(event, name, after)
                    actions.append(f"{name}: normalized IP")

        # Stable whitespace normalization in attributes only; preserve rich values
        # and nesting rather than coercing/flattening data late in the pipeline.
        for key, value in list(event.attributes.items()):
            if isinstance(value, str):
                normalized = normalize_whitespace(value)
                if normalized != value:
                    event.attributes[key] = normalized
                    actions.append(f"attributes.{key}: normalized whitespace")

        return NormalizedEvent(event=event, normalization_actions=actions)


class EventValidator:
    """Validate the trusted-event contract without inventing missing fields."""

    def validate(self, normalized: NormalizedEvent) -> List[ValidationIssue]:
        event = normalized.event
        issues: List[ValidationIssue] = []

        if not event.event_id:
            issues.append(ValidationIssue("missing_event_id", "event_id is required", "event_id"))
        if not event.source_name:
            issues.append(ValidationIssue("missing_source_name", "source_name is required", "source_name"))
        if event.source_format.value == "unknown":
            issues.append(ValidationIssue("unknown_source_format", "source format is unknown", "source_format"))
        if event.event_type not in EVENT_TYPES:
            issues.append(ValidationIssue(
                "invalid_event_type", f"unsupported event_type '{event.event_type}'", "event_type"
            ))
        if event.severity is not None and event.severity not in SEVERITIES:
            issues.append(ValidationIssue(
                "invalid_severity", f"unsupported severity '{event.severity}'", "severity"
            ))
        for field in ("source_ip", "dest_ip"):
            value = getattr(event, field)
            if value is not None and not is_valid_ip(value):
                issues.append(ValidationIssue("invalid_ip", f"{field} is not a valid IPv4 or IPv6 address", field))
        for field in ("_invalid_source_ip", "_invalid_dest_ip"):
            if field in event.attributes:
                issues.append(ValidationIssue("invalid_ip", f"source supplied invalid value '{event.attributes[field]}'", field))
        for field in ("port", "dest_port"):
            value = getattr(event, field)
            if value is not None and not (0 <= value <= 65535):
                issues.append(ValidationIssue("invalid_port", f"{field} must be 0..65535", field))
            invalid_key = f"_invalid_{field}"
            if invalid_key in event.attributes:
                issues.append(ValidationIssue("invalid_port", f"source supplied non-numeric {field} '{event.attributes[invalid_key]}'", field))
        if event.file_hash is not None and hash_algorithm(event.file_hash) is None:
            issues.append(ValidationIssue(
                "invalid_hash", "file_hash must be hexadecimal MD5, SHA-1, or SHA-256", "file_hash"
            ))
        if event.protocol is not None and event.protocol not in ("tcp", "udp", "icmp", "icmpv6", "sctp", "http", "https", "dns", "tls"):
            issues.append(ValidationIssue(
                "unknown_protocol", f"protocol '{event.protocol}' is not in the controlled vocabulary", "protocol", "warning"
            ))
        if event.raw.get("_parse_error"):
            issues.append(ValidationIssue(
                "source_parse_error", str(event.raw["_parse_error"]), "raw", "error"
            ))

        # Warnings do not reject. They expose uncertainty to the next pipeline
        # stage rather than silently manufacturing source context.
        if not event.timestamp:
            issues.append(ValidationIssue(
                "missing_timestamp", "timestamp could not be established", "timestamp", "warning"
            ))
        if event.event_type == "generic":
            issues.append(ValidationIssue(
                "generic_event_type", "event type could not be determined", "event_type", "warning"
            ))
        if not any((event.hostname, event.username, event.source_ip, event.dest_ip,
                    event.domain, event.process_name, event.file_path)):
            issues.append(ValidationIssue(
                "low_context", "event has no recognized host, user, network, process, or file context",
                severity="warning",
            ))
        normalized.validation_issues = issues
        return issues


class EventDeduplicator:
    """Exact, deterministic deduplicator over trusted normalized event content.

    Default `max_fingerprints=None` means exact global deduplication for the run.
    Supply a positive bound for a memory-constrained rolling window. Eviction is
    visible through `evictions`; after eviction, an old duplicate may be accepted,
    so callers must not describe bounded mode as global deduplication.
    """

    _FINGERPRINT_FIELDS = (
        "timestamp", "event_type", "hostname", "username", "source_ip", "dest_ip",
        "domain", "process_name", "command_line", "file_path", "file_hash", "port",
        "severity", "attributes",
    )

    def __init__(self, max_fingerprints: Optional[int] = None):
        if max_fingerprints is not None and max_fingerprints < 1:
            raise ValueError("max_fingerprints must be positive or None")
        self.max_fingerprints = max_fingerprints
        self._seen: Dict[str, str] = {}
        self._order: List[str] = []
        self.evictions = 0

    def fingerprint(self, normalized: NormalizedEvent) -> str:
        event = normalized.event
        payload = {name: getattr(event, name) for name in self._FINGERPRINT_FIELDS}
        encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str,
                             separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def check(self, normalized: NormalizedEvent) -> Optional[str]:
        """Return first event ID if duplicate, otherwise register and return None."""
        fp = self.fingerprint(normalized)
        normalized.fingerprint = fp
        original = self._seen.get(fp)
        if original:
            normalized.duplicate_of = original
            return original

        self._seen[fp] = normalized.event_id
        self._order.append(fp)
        if self.max_fingerprints and len(self._order) > self.max_fingerprints:
            old = self._order.pop(0)
            self._seen.pop(old, None)
            self.evictions += 1
        return None


class EventProcessor:
    """Reusable normalized-event processing chain.

    `process_outcomes()` is the full audit stream. `process()` yields only trusted
    events for downstream enrichment/detection. Both are generator-based.
    """

    def __init__(self, normalizer: Optional[EventNormalizer] = None,
                 validator: Optional[EventValidator] = None,
                 deduplicator: Optional[EventDeduplicator] = None):
        self.normalizer = normalizer or EventNormalizer()
        self.validator = validator or EventValidator()
        self.deduplicator = deduplicator or EventDeduplicator()

    def process_one(self, event: CanonicalEvent) -> ProcessingOutcome:
        normalized = self.normalizer.normalize(event)
        issues = self.validator.validate(normalized)
        if any(i.severity == "error" for i in issues):
            return ProcessingOutcome(normalized, "rejected")
        if self.deduplicator.check(normalized):
            return ProcessingOutcome(normalized, "duplicate")
        return ProcessingOutcome(normalized, "trusted")

    def process_outcomes(self, events: Iterable[CanonicalEvent]) -> Iterator[ProcessingOutcome]:
        for event in events:
            yield self.process_one(event)

    def process(self, events: Iterable[CanonicalEvent]) -> Iterator[NormalizedEvent]:
        for outcome in self.process_outcomes(events):
            if outcome.status == "trusted":
                yield outcome.normalized

    def collect(self, events: Iterable[CanonicalEvent]) -> tuple[List[NormalizedEvent], ProcessingReport, List[ProcessingOutcome]]:
        """In-memory convenience for tests/moderate inputs; not for huge datasets."""
        trusted: List[NormalizedEvent] = []
        outcomes: List[ProcessingOutcome] = []
        report = ProcessingReport()
        for outcome in self.process_outcomes(events):
            outcomes.append(outcome)
            report.input_events += 1
            report.warnings += sum(i.severity == "warning" for i in outcome.normalized.validation_issues)
            report.errors += sum(i.severity == "error" for i in outcome.normalized.validation_issues)
            if outcome.status == "trusted":
                trusted.append(outcome.normalized)
                report.trusted_events += 1
            elif outcome.status == "duplicate":
                report.duplicate_events += 1
            else:
                report.rejected_events += 1
        report.dedup_evictions = self.deduplicator.evictions
        return trusted, report, outcomes
