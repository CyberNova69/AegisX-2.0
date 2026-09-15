"""Core data types for the AegisX Data Platform.

All domain objects use Python dataclasses for consistency with the existing
AegisX codebase (ai/ingestion/types.py, ai/ingestion/processing.py).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Classification(str, Enum):
    """Unified AegisX triage classification taxonomy (5-class SOC).

    The canonical 5-class SOC taxonomy:
      benign, suspicious, likely_malicious, confirmed_malicious,
      insufficient_evidence

    MALICIOUS is kept for backward compatibility with external datasets
    (CICIDS, UNSW-NB15, CTU-13, EMBER) where the source does not
    distinguish likely vs confirmed.

    REVIEW_REQUIRED is an internal pipeline state for records needing
    human review — not a model prediction target.
    """
    BENIGN = "benign"
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    LIKELY_MALICIOUS = "likely_malicious"
    CONFIRMED_MALICIOUS = "confirmed_malicious"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    REVIEW_REQUIRED = "review_required"


class Severity(str, Enum):
    """Severity levels, consistent with ai/ingestion/types.py SEVERITIES."""
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackCategory(str, Enum):
    """High-level attack categories for label harmonization."""
    NONE = "none"
    DDOS = "ddos"
    DOS = "dos"
    BRUTE_FORCE = "brute_force"
    WEB_ATTACK = "web_attack"
    INFILTRATION = "infiltration"
    BOTNET = "botnet"
    PORT_SCAN = "port_scan"
    MALWARE = "malware"
    EXPLOIT = "exploit"
    BACKDOOR = "backdoor"
    RECONNAISSANCE = "reconnaissance"
    SHELLCODE = "shellcode"
    WORM = "worm"
    GENERIC_ATTACK = "generic_attack"
    FUZZERS = "fuzzers"
    ANALYSIS = "analysis"
    OTHER = "other"


class DatasetSourceType(str, Enum):
    """Well-known external dataset sources.

    This enum provides constants for well-known sources. However,
    DatasetRecord.source is a plain string, so arbitrary source
    identifiers (e.g. "my_custom_dataset_v2") are also valid.
    Use these constants for sources with dedicated parsers.
    """
    CICIDS_2017 = "cicids_2017"
    CICIDS_2018 = "cicids_2018"
    CTU_13 = "ctu_13"
    UNSW_NB15 = "unsw_nb15"
    EMBER = "ember"
    MITRE_ATTACK = "mitre_attack"
    CUSTOM_CSV = "custom_csv"
    HUGGINGFACE = "huggingface"
    AEGISX_SOC = "aegisx_soc"


class HarmonizationStatus(str, Enum):
    """Label harmonization outcome for provenance tracking."""
    MAPPED = "mapped"          # Deterministic mapping found
    UNKNOWN = "unknown"        # No mapping exists for this label
    AMBIGUOUS = "ambiguous"    # Fuzzy/partial match — may be wrong
    NO_LABEL = "no_label"      # Source record had no label


class RecordStatus(str, Enum):
    """Processing status of a dataset record."""
    RAW = "raw"
    NORMALIZED = "normalized"
    VALIDATED = "validated"
    ENRICHED = "enriched"
    HARMONIZED = "harmonized"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"
    REVIEW_REQUIRED = "review_required"


class RunStatus(str, Enum):
    """Training run lifecycle status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ModelLifecycle(str, Enum):
    """Model artifact lifecycle."""
    TRAINED = "trained"
    EVALUATED = "evaluated"
    PROMOTED = "promoted"
    DEPRECATED = "deprecated"


# ---------------------------------------------------------------------------
# Core Data Types
# ---------------------------------------------------------------------------

@dataclass
class DatasetRecord:
    """A single record from an external cybersecurity dataset.

    This is the platform's internal representation. It carries the original
    source label AND the harmonized AegisX classification, plus network flow
    features common to most cybersecurity datasets.
    """
    record_id: str
    source: str  # Source identifier (use DatasetSourceType values or any string)
    source_file: str = ""
    record_index: int = 0

    # Temporal
    timestamp: Optional[str] = None  # ISO-8601 UTC

    # Network flow features (common across CICIDS, CTU-13, UNSW-NB15)
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    duration: Optional[float] = None
    bytes_sent: Optional[int] = None
    bytes_recv: Optional[int] = None
    packets_sent: Optional[int] = None
    packets_recv: Optional[int] = None

    # Endpoint features (EMBER, Sysmon)
    hostname: Optional[str] = None
    username: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    file_path: Optional[str] = None
    file_hash: Optional[str] = None

    # Labels
    source_label: Optional[str] = None        # Original label from dataset
    attack_category: Optional[AttackCategory] = None
    classification: Optional[Classification] = None  # Harmonized AegisX label
    severity: Optional[Severity] = None
    confidence: float = 1.0                   # Label confidence

    # MITRE ATT&CK enrichment
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    mitre_tactic: Optional[str] = None

    # Processing state
    status: RecordStatus = RecordStatus.RAW
    fingerprint: Optional[str] = None
    normalization_actions: List[str] = field(default_factory=list)
    validation_issues: List[str] = field(default_factory=list)
    enrichment_tags: Dict[str, Any] = field(default_factory=dict)

    # Raw data preserved for provenance
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "record_id": self.record_id,
            "source": self.source.value if isinstance(self.source, Enum) else self.source,
            "source_file": self.source_file,
            "record_index": self.record_index,
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "duration": self.duration,
            "bytes_sent": self.bytes_sent,
            "bytes_recv": self.bytes_recv,
            "packets_sent": self.packets_sent,
            "packets_recv": self.packets_recv,
            "hostname": self.hostname,
            "username": self.username,
            "process_name": self.process_name,
            "command_line": self.command_line,
            "file_path": self.file_path,
            "file_hash": self.file_hash,
            "source_label": self.source_label,
            "attack_category": self.attack_category.value if self.attack_category else None,
            "classification": self.classification.value if self.classification else None,
            "severity": self.severity.value if self.severity else None,
            "confidence": self.confidence,
            "mitre_technique_id": self.mitre_technique_id,
            "mitre_technique_name": self.mitre_technique_name,
            "mitre_tactic": self.mitre_tactic,
            "status": self.status.value,
            "fingerprint": self.fingerprint,
            "normalization_actions": self.normalization_actions,
            "validation_issues": self.validation_issues,
            "enrichment_tags": self.enrichment_tags,
            "raw": self.raw,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DatasetRecord":
        """Deserialize from dictionary."""
        # Accept any string for source — not just DatasetSourceType values
        source_val = data["source"]
        try:
            source_val = DatasetSourceType(source_val)
        except ValueError:
            pass  # Keep as plain string for non-standard sources
        record = cls(
            record_id=data["record_id"],
            source=source_val,
        )
        # Simple fields
        for fld in ("source_file", "record_index", "timestamp", "src_ip", "dst_ip",
                     "src_port", "dst_port", "protocol", "duration", "bytes_sent",
                     "bytes_recv", "packets_sent", "packets_recv", "hostname",
                     "username", "process_name", "command_line", "file_path",
                     "file_hash", "source_label", "confidence",
                     "mitre_technique_id", "mitre_technique_name", "mitre_tactic",
                     "fingerprint"):
            if fld in data and data[fld] is not None:
                setattr(record, fld, data[fld])
        # Enum fields
        if data.get("attack_category"):
            record.attack_category = AttackCategory(data["attack_category"])
        if data.get("classification"):
            record.classification = Classification(data["classification"])
        if data.get("severity"):
            record.severity = Severity(data["severity"])
        if data.get("status"):
            record.status = RecordStatus(data["status"])
        # Collection fields
        record.normalization_actions = data.get("normalization_actions", [])
        record.validation_issues = data.get("validation_issues", [])
        record.enrichment_tags = data.get("enrichment_tags", {})
        record.raw = data.get("raw", {})
        return record

    def compute_fingerprint(self) -> str:
        """Compute a SHA-256 fingerprint over canonical fields for deduplication."""
        payload = {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "timestamp": self.timestamp,
            "source_label": self.source_label,
            "hostname": self.hostname,
            "process_name": self.process_name,
            "command_line": self.command_line,
            "file_path": self.file_path,
            "file_hash": self.file_hash,
            "duration": self.duration,
            "bytes_sent": self.bytes_sent,
            "bytes_recv": self.bytes_recv,
        }
        encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False,
                             default=str, separators=(",", ":"))
        self.fingerprint = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        return self.fingerprint


@dataclass
class DatasetMetadata:
    """Metadata for a processed dataset version."""
    name: str
    version: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    description: str = ""
    sources: List[str] = field(default_factory=list)
    record_count: int = 0
    class_distribution: Dict[str, int] = field(default_factory=dict)
    quality_score: Optional[float] = None
    file_hashes: Dict[str, str] = field(default_factory=dict)
    processing_config: Dict[str, Any] = field(default_factory=dict)
    schema_version: str = "1.0"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "created_at": self.created_at,
            "description": self.description,
            "sources": self.sources,
            "record_count": self.record_count,
            "class_distribution": self.class_distribution,
            "quality_score": self.quality_score,
            "file_hashes": self.file_hashes,
            "processing_config": self.processing_config,
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DatasetMetadata":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class QualityReport:
    """Dataset quality analysis report."""
    dataset_version: str
    analyzed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    total_records: int = 0
    valid_records: int = 0
    invalid_records: int = 0
    duplicate_records: int = 0
    class_distribution: Dict[str, int] = field(default_factory=dict)
    class_balance_score: float = 0.0  # 0=completely imbalanced, 1=perfectly balanced
    completeness_scores: Dict[str, float] = field(default_factory=dict)  # field -> % non-null
    overall_quality_score: float = 0.0
    issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dataset_version": self.dataset_version,
            "analyzed_at": self.analyzed_at,
            "total_records": self.total_records,
            "valid_records": self.valid_records,
            "invalid_records": self.invalid_records,
            "duplicate_records": self.duplicate_records,
            "class_distribution": self.class_distribution,
            "class_balance_score": self.class_balance_score,
            "completeness_scores": self.completeness_scores,
            "overall_quality_score": self.overall_quality_score,
            "issues": self.issues,
            "recommendations": self.recommendations,
        }


@dataclass
class TrainingRun:
    """Training run metadata and state."""
    run_id: str
    status: RunStatus = RunStatus.PENDING
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    dataset_version: str = ""
    base_model: str = ""
    config: Dict[str, Any] = field(default_factory=dict)
    metrics: Dict[str, Any] = field(default_factory=dict)  # epoch -> {loss, accuracy, ...}
    gpu_info: Dict[str, Any] = field(default_factory=dict)
    adapter_path: Optional[str] = None
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "status": self.status.value,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "dataset_version": self.dataset_version,
            "base_model": self.base_model,
            "config": self.config,
            "metrics": self.metrics,
            "gpu_info": self.gpu_info,
            "adapter_path": self.adapter_path,
            "error_message": self.error_message,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TrainingRun":
        run = cls(run_id=data["run_id"])
        if data.get("status"):
            run.status = RunStatus(data["status"])
        for fld in ("created_at", "started_at", "completed_at", "dataset_version",
                     "base_model", "adapter_path", "error_message"):
            if fld in data and data[fld] is not None:
                setattr(run, fld, data[fld])
        run.config = data.get("config", {})
        run.metrics = data.get("metrics", {})
        run.gpu_info = data.get("gpu_info", {})
        return run


@dataclass
class ModelArtifact:
    """Registered model artifact."""
    model_id: str
    run_id: str
    base_model: str
    lifecycle: ModelLifecycle = ModelLifecycle.TRAINED
    registered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    dataset_version: str = ""
    adapter_path: str = ""
    eval_metrics: Dict[str, Any] = field(default_factory=dict)
    tags: Dict[str, str] = field(default_factory=dict)
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_id": self.model_id,
            "run_id": self.run_id,
            "base_model": self.base_model,
            "lifecycle": self.lifecycle.value,
            "registered_at": self.registered_at,
            "dataset_version": self.dataset_version,
            "adapter_path": self.adapter_path,
            "eval_metrics": self.eval_metrics,
            "tags": self.tags,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ModelArtifact":
        artifact = cls(
            model_id=data["model_id"],
            run_id=data["run_id"],
            base_model=data["base_model"],
        )
        if data.get("lifecycle"):
            artifact.lifecycle = ModelLifecycle(data["lifecycle"])
        for fld in ("registered_at", "dataset_version", "adapter_path", "description"):
            if fld in data and data[fld] is not None:
                setattr(artifact, fld, data[fld])
        artifact.eval_metrics = data.get("eval_metrics", {})
        artifact.tags = data.get("tags", {})
        return artifact
